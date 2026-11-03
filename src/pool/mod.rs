//! 串发拨号：路由表（plans.json `routes`）唯一权威。成功驻留游标、失败前移；SNI 与校验名解耦。
pub mod dial;
pub mod route;

use crate::util::{lock, LogFn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialPlan {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
}

/// 旧版三池名：只用于首启迁移读取。
/// 旧版白名单：host → 段。迁移时一次性摊进各自的路由行，之后代码不再需要它。
const LEGACY_WHITELIST: &[(&str, &str)] = &[
    ("docs.github.com", "154"),
    ("support.github.com", "133"),
    ("resources.github.com", "133"),
    ("desktop.github.com", "153"),
    ("pages.github.com", "153"),
    ("skills.github.com", "153"),
    ("archiveprogram.github.com", "153"),
    ("socialimpact.github.com", "153"),
    ("raw.github.com", "133"),
    ("copilot-proxy.githubusercontent.com", "4.249"),
];

/// 旧版直连白名单（迁移成 action: direct 的路由行）。
const LEGACY_DIRECT: &[&str] = &[
    "objects-origin.githubusercontent.com",
    "uploads.github.com",
    "viewscreen.githubusercontent.com",
    "api.mcp.github.com",
];

/// 游标键：每条路由两把（主键 / `~2` 副键），双通道各记各的。
pub fn circle_keys() -> Vec<String> {
    route::cursor_keys()
}

const SEEDS_JSON: &str = include_str!("seeds.json");

pub const CONTENT_HOSTS: &[&str] = &[
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "avatars.githubusercontent.com",
    "user-images.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "media.githubusercontent.com",
];

/// 种子只剩两个用途：全新安装引导、给已有路由补 IP（不新建路由）。
fn seed_db() -> PlansFile {
    serde_json::from_str(SEEDS_JSON).unwrap_or_default()
}

const SERIAL_MAX_PLANS: usize = 512;

struct SerialTab {
    /// TCP 层死亡退避 60s→5min→30min，成功拨号清除。
    dead: HashMap<String, (Instant, u32)>,
    mirrors: HashMap<String, Vec<String>>,
    /// 每路由（`pattern[~slot]`）一个游标记号；表序冻结，不随游标重排。
    cursor: HashMap<String, String>,
}

static SERIAL_COOL: Breaker = Breaker::new(30);

/// 测试专用：路由表/串发表都是进程级全局态，跨模块的用例靠它串行。
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

/// plans.json 的解析结果：新格式给 routes，旧格式给 pools；镜像链两边通用。
#[derive(Default)]
struct PlansDoc {
    routes: Option<Vec<route::RouteSpec>>,
    pools: HashMap<String, Vec<SerialPlan>>,
    chains: HashMap<String, Vec<String>>,
}

/// seeds.json 的形状（旧三池 + 镜像链）。
#[derive(serde::Deserialize, Clone, Default)]
struct PlansFile {
    #[serde(default)]
    mirrors_big: HashMap<String, Vec<String>>,
    #[serde(default)]
    mirrors_small: HashMap<String, Vec<String>>,
    #[serde(default)]
    mirrors: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    pools: HashMap<String, Vec<SerialPlan>>,
}

impl PlansFile {
    /// 种子只用来取 IP 表；镜像链那套走 Doc。
    fn chains(&self) -> HashMap<String, Vec<String>> {
        merged_chains(&self.mirrors_big, &self.mirrors_small, &self.mirrors)
    }
}

/// 合并为运行时单表；旧键不覆盖新键已声明的 host。
fn merged_chains(
    big: &HashMap<String, Vec<String>>,
    small: &HashMap<String, Vec<String>>,
    legacy: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    let mut out = big.clone();
    for (h, c) in small {
        out.insert(h.clone(), c.clone());
    }
    for (h, c) in legacy {
        out.entry(h.clone()).or_insert_with(|| c.clone());
    }
    out
}

/// 容错解析：坏段只丢那一段；salvaged = 有段被丢弃，调用方备份原文件。
fn parse_plans_tolerant(raw: &str, log: Option<&LogFn>) -> Option<(PlansDoc, bool)> {
    let root: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = root.as_object()?;
    let mut doc = PlansDoc::default();
    let mut big = HashMap::new();
    let mut small = HashMap::new();
    let mut legacy = HashMap::new();
    let mut salvaged = false;

    if let Some(routes) = obj.get("routes") {
        let Some(list) = routes.as_array() else {
            if let Some(l) = log {
                l("[串发] plans.json routes 不是数组, 本次按种子重建");
            }
            return None;
        };
        let mut rows = Vec::new();
        for (i, v) in list.iter().enumerate() {
            match serde_json::from_value::<route::RouteSpec>(v.clone()) {
                Ok(spec) => rows.push(spec),
                Err(e) => {
                    salvaged = true;
                    if let Some(l) = log {
                        l(&format!("[串发] plans.json routes[{i}] 写坏({e}), 该行丢弃"));
                    }
                }
            }
        }
        doc.routes = Some(rows);
    } else {
        for (k, v) in obj {
            if k.starts_with("mirrors") {
                continue;
            }
            match serde_json::from_value::<Vec<SerialPlan>>(v.clone()) {
                Ok(p) => {
                    doc.pools.insert(k.clone(), p);
                }
                Err(e) => {
                    salvaged = true;
                    if let Some(l) = log {
                        l(&format!(
                            "[串发] plans.json 池 {k} 写坏({e}), 该池按种子重建(其余表保留)"
                        ));
                    }
                }
            }
        }
    }

    for (k, v) in obj {
        if !k.starts_with("mirrors") {
            continue;
        }
        let Some(m) = v.as_object() else {
            salvaged = true;
            if let Some(l) = log {
                l(&format!(
                    "[串发] plans.json {k} 段不是对象, 该段丢弃(镜像链按注册表重建)"
                ));
            }
            continue;
        };
        let slot = match k.as_str() {
            "mirrors_big" => &mut big,
            "mirrors_small" => &mut small,
            _ => &mut legacy,
        };
        for (host, chain) in m {
            match serde_json::from_value::<Vec<String>>(chain.clone()) {
                Ok(c) => {
                    slot.insert(host.clone(), c);
                }
                Err(e) => {
                    salvaged = true;
                    if let Some(l) = log {
                        l(&format!("[串发] plans.json 镜像链 {host} 写坏({e}), 该链丢弃"));
                    }
                }
            }
        }
    }
    doc.chains = merged_chains(&big, &small, &legacy);
    Some((doc, salvaged))
}

/// 落盘：routes 逐行、IP 一条一行；镜像链按 CONTENT_HOSTS 序。
fn encode_plans(mirrors: &HashMap<String, Vec<String>>) -> String {
    let rows: Vec<String> = route::snapshot()
        .iter()
        .map(|r| {
            let mut parts: Vec<String> = vec![format!("\"match\": {}", json_of(&r.pattern))];
            if let Some(pac) = &r.pac {
                parts.push(format!("\"pac\": {}", json_of(pac)));
            }
            if r.flags.direct {
                parts.push("\"action\": \"direct\"".to_string());
            }
            if r.flags.real {
                parts.push("\"real\": true".to_string());
            }
            if r.flags.content {
                parts.push("\"content\": true".to_string());
            }
            if r.flags.donor {
                parts.push("\"donor\": true".to_string());
            }
            if r.fallback == route::Fallback::MirrorDns {
                parts.push("\"fallback\": \"mirror\"".to_string());
            }
            for (key, list) in [("plans", &r.plans), ("realPlans", &r.real_plans)] {
                if list.is_empty() {
                    continue;
                }
                let items: Vec<String> = list.iter().map(json_of).collect();
                parts.push(format!(
                    "\"{key}\": [\n        {}\n      ]",
                    items.join(",\n        ")
                ));
            }
            format!("    {{\n      {}\n    }}", parts.join(",\n      "))
        })
        .collect();
    let mut blocks = vec![format!("  \"routes\": [\n{}\n  ]", rows.join(",\n"))];

    // 镜像链双字典：按 host 归类。
    let mut big_rows: Vec<String> = Vec::new();
    let mut small_rows: Vec<String> = Vec::new();
    for h in CONTENT_HOSTS {
        let Some(c) = mirrors.get(*h) else { continue };
        let items: Vec<String> = c.iter().map(json_of).collect();
        let row = format!("    {}: [{}]", json_of(h), items.join(", "));
        if route::is_big_file_host(h) {
            big_rows.push(row);
        } else {
            small_rows.push(row);
        }
    }
    if !big_rows.is_empty() {
        blocks.push(format!("  \"mirrors_big\": {{\n{}\n  }}", big_rows.join(",\n")));
    }
    if !small_rows.is_empty() {
        blocks.push(format!(
            "  \"mirrors_small\": {{\n{}\n  }}",
            small_rows.join(",\n")
        ));
    }
    format!("{{\n{}\n}}\n", blocks.join(",\n"))
}

fn json_of<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("JSON 序列化不会失败")
}

fn write_plans_file(path: &Path, mirrors: &HashMap<String, Vec<String>>) {
    let data = encode_plans(mirrors);
    let _ = crate::fsx::write_atomic(path, data.as_bytes());
}

fn plans_path() -> PathBuf {
    let dir = lock(&SERIAL_DIR)
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("plans.json")
}

pub fn serial_load(data_dir: &Path, last_ip: Vec<(String, String)>, log: Option<LogFn>) {
    *lock(&SERIAL_DIR) = Some(data_dir.to_path_buf());
    *lock(&SERIAL_LOG) = log.clone();
    let path = plans_path();
    let raw = std::fs::read_to_string(&path).ok();
    let parsed = raw
        .as_deref()
        .and_then(|b| parse_plans_tolerant(b, log.as_ref()));
    // 有段落坏/整份读不了：先备份原文件再重建，用户手排表可从 .bak 捡回。
    let bak_why = match (&raw, &parsed) {
        (Some(_), None) => Some("解析失败, 本次按种子重建"),
        (Some(_), Some((_, true))) => Some("有段落坏已按种子重建"),
        _ => None,
    };
    if let Some(why) = bak_why {
        if std::fs::copy(&path, path.with_extension("json.bak")).is_ok() {
            if let Some(l) = log.as_ref() {
                l(&format!("[串发] plans.json {why}, 原文件已备份为 plans.json.bak"));
            }
        }
    }

    let seeds = seed_db();
    let seed_rows = legacy_routes(&seeds.pools);
    let doc = parsed.map(|(d, _)| d).unwrap_or_else(|| PlansDoc {
        routes: None,
        pools: seeds.pools.clone(),
        chains: seeds.chains(),
    });
    // 新格式直接用；旧三池走一次性迁移；迁移结果之后写回文件，下次就是新格式。
    let migrated = doc.routes.is_none();
    let mut specs = match doc.routes {
        Some(rows) => rows,
        None => legacy_routes(&doc.pools),
    };
    topup_from_seeds(&mut specs, &seed_rows, log.as_ref());
    if migrated {
        if let Some(l) = log.as_ref() {
            l(&format!(
                "[串发] plans.json 迁移为 routes 表({} 条路由), 旧三池格式不再使用",
                specs.len()
            ));
        }
    }

    let total = specs.len();
    let mut rows = Vec::with_capacity(total);
    for (i, spec) in specs.into_iter().enumerate() {
        match route::RouteRow::new(spec) {
            Ok(row) => rows.push(row),
            Err(e) => {
                if let Some(l) = log.as_ref() {
                    l(&format!("[串发] routes[{i}] 丢弃: {e}"));
                }
            }
        }
    }
    // 有行被丢弃：同样先备份，用户写的正则/标记还能从 .bak 捡回。
    if rows.len() < total && !path.with_extension("json.bak").exists() {
        let _ = std::fs::copy(&path, path.with_extension("json.bak"));
    }
    route::install(rows);

    let mut tab = SerialTab {
        dead: HashMap::new(),
        mirrors: HashMap::new(),
        cursor: HashMap::new(),
    };
    // 游标圈预写空记号；settings.last_ip 非空值覆盖（表外旧键直接丢）。
    for key in circle_keys() {
        tab.cursor.insert(key, String::new());
    }
    for (key, ip) in &last_ip {
        if !ip.is_empty() && tab.cursor.contains_key(key) {
            tab.cursor.insert(key.clone(), ip.clone());
        }
    }
    for (host, chain) in doc.chains {
        if !CONTENT_HOSTS.contains(&host.as_str()) {
            if let Some(l) = log.as_ref() {
                l(&format!(
                    "[串发] plans.json 镜像链 {host} 不在支持列表, 已丢弃(其余链保留)"
                ));
            }
            continue;
        }
        // 数据权威：不设白名单，自部署镜像可用；坏镜像运行期自然沉底。
        let vc: Vec<String> = chain
            .into_iter()
            .filter(|m| m.starts_with("https://") && !m.contains(' '))
            .collect();
        if !vc.is_empty() {
            tab.mirrors.insert(host, vc);
        }
    }
    // 非内置镜像收编进注册表(幂等)：手改塞进来的自建节点重启不丢。
    {
        let builtin = builtin_mirror_urls();
        let mut registry = crate::settings::worker_mirrors();
        let mut adopted = false;
        // host 排序仅为确定性。
        let mut hosts: Vec<&String> = tab.mirrors.keys().collect();
        hosts.sort();
        for h in hosts {
            for u in &tab.mirrors[h] {
                if builtin.contains(u) {
                    continue;
                }
                if registry.iter().any(|w| w.url == *u) {
                    continue;
                }
                registry.push(crate::settings::WorkerMirror {
                    url: u.clone(),
                    on: true,
                    trusted: false,
                });
                adopted = true;
            }
        }
        if adopted {
            crate::settings::save_worker_mirrors(registry);
        }
    }
    *lock(&SERIAL) = Some(tab);
    sync_custom_mirrors(&[]); // 自定义镜像注册表对齐：启用中的自建节点确保在链中（幂等）
    write_plans_file(&path, &mirror_chains_snapshot());
}

/// 旧三池 → routes 表。这段硬编码知识只用于迁移，跑完就写回文件，之后不再参与运行。
fn legacy_routes(pools: &HashMap<String, Vec<SerialPlan>>) -> Vec<route::RouteSpec> {
    let empty: Vec<SerialPlan> = Vec::new();
    let core = pools.get("core").unwrap_or(&empty);
    let api = pools.get("api").unwrap_or(&empty);
    let edge = pools.get("edge").unwrap_or(&empty);
    let seg = |want: &str| -> Vec<SerialPlan> {
        edge.iter()
            .filter(|p| fastly_seg(&p.ip) == Some(want))
            .cloned()
            .collect()
    };
    let i133 = seg("133");
    let i153 = seg("153");
    let i154 = seg("154");
    let i215 = seg("215");
    let mut assets = i154.clone();
    assets.extend(i215.iter().cloned());
    let azure: Vec<SerialPlan> = edge
        .iter()
        .filter(|p| p.ip.starts_with("4.249."))
        .cloned()
        .collect();
    let other: Vec<SerialPlan> = edge
        .iter()
        .filter(|p| fastly_seg(&p.ip).is_none() && !p.ip.starts_with("4.249."))
        .cloned()
        .collect();

    let mut rows = Vec::new();
    // 直连行排最前：任何通配都不能把它们吞进代理。
    for h in LEGACY_DIRECT {
        rows.push(route::RouteSpec {
            matcher: regex_escape(h),
            pac: Some((*h).to_string()),
            action: Some("direct".to_string()),
            real: false,
            content: false,
            donor: false,
            fallback: None,
            plans: Vec::new(),
            real_plans: Vec::new(),
        });
    }
    // 精确项压通配：api 与白名单必须先于 github.com 通配。
    rows.push(plain(r"api\.github\.com", "api.github.com", api.to_vec()));
    for (h, s) in LEGACY_WHITELIST {
        let plans = match *s {
            "154" => i154.clone(),
            "153" => i153.clone(),
            "133" => i133.clone(),
            _ => azure.clone(),
        };
        rows.push(route::RouteSpec {
            matcher: regex_escape(h),
            pac: Some((*h).to_string()),
            action: None,
            real: true,
            content: false,
            donor: false,
            fallback: None,
            plans,
            real_plans: Vec::new(),
        });
    }
    rows.push(plain(r"(.*\.)?github\.com", "github.com", core.to_vec()));
    // 内容域：伪装腿只认默认证书覆盖的那段；真名腿（隧道）额外可用 assets 段。
    rows.push(route::RouteSpec {
        matcher: r".*\.githubusercontent\.com".to_string(),
        pac: Some("githubusercontent.com".to_string()),
        action: None,
        real: false,
        content: true,
        donor: false,
        fallback: Some("mirror".to_string()),
        plans: i133,
        real_plans: assets.clone(),
    });
    rows.push(route::RouteSpec {
        matcher: r"(.*\.)?githubassets\.com".to_string(),
        pac: Some("githubassets.com".to_string()),
        action: None,
        real: false,
        content: false,
        donor: true,
        fallback: None,
        plans: assets,
        real_plans: Vec::new(),
    });
    rows.push(plain(r"(.*\.)?github\.io", "github.io", i153));
    rows.push(plain(r"(.*\.)?githubapp\.com", "githubapp.com", other));
    rows
}

fn plain(matcher: &str, pac: &str, plans: Vec<SerialPlan>) -> route::RouteSpec {
    route::RouteSpec {
        matcher: matcher.to_string(),
        pac: Some(pac.to_string()),
        action: None,
        real: false,
        content: false,
        donor: false,
        fallback: None,
        plans,
        real_plans: Vec::new(),
    }
}

/// 测试专用：装一份种子路由表，供 certgen/settings 这类不经过 plans.json 的用例。
#[cfg(test)]
pub(crate) fn install_seed_routes() {
    let seeds = seed_db();
    let rows: Vec<route::RouteRow> = legacy_routes(&seeds.pools)
        .into_iter()
        .filter_map(|s| route::RouteRow::new(s).ok())
        .collect();
    route::install(rows);
}

/// 种子只补已有路由的 IP，不新建路由：用户删掉的行不该被程序加回来。
fn topup_from_seeds(
    specs: &mut [route::RouteSpec],
    seeds: &[route::RouteSpec],
    log: Option<&LogFn>,
) {
    let mut added = 0usize;
    for row in specs.iter_mut() {
        let Some(seed) = seeds.iter().find(|s| s.matcher == row.matcher) else {
            continue;
        };
        added += topup_list(&mut row.plans, &seed.plans);
        added += topup_list(&mut row.real_plans, &seed.real_plans);
    }
    if added > 0 {
        if let Some(l) = log {
            l(&format!("[串发] 路由种子补缺 {added} 条(新边缘 IP 上线)"));
        }
    }
}

fn topup_list(dst: &mut Vec<SerialPlan>, src: &[SerialPlan]) -> usize {
    let mut added = 0;
    for p in src {
        if dst.len() >= SERIAL_MAX_PLANS {
            break;
        }
        if dst.iter().any(|x| x.ip == p.ip) {
            continue;
        }
        dst.push(p.clone());
        added += 1;
    }
    added
}

/// Fastly 四段的末段；迁移时用来把旧 edge 池拆回各族。
fn fastly_seg(ip: &str) -> Option<&str> {
    let mut o = ip.split('.');
    match (o.next(), o.next(), o.next(), o.next()) {
        (Some("185"), Some("199"), Some("108" | "109" | "110" | "111"), Some(last)) => Some(last),
        _ => None,
    }
}

fn regex_escape(host: &str) -> String {
    host.replace('.', "\\.")
}

/// 数据层结果回写游标：成功驻留、失败前移，零写盘。
pub fn cursor_note(host: &str, ip: &str, ok: bool, slot: u8) {
    let Some(row) = route::route_for(host) else {
        return;
    };
    if row.flags.direct {
        return;
    }
    let key = cursor_key(&row.pattern, slot);
    let plans = &row.plans;
    if plans.is_empty() {
        return;
    }
    let mut g = lock(&SERIAL);
    let Some(t) = g.as_mut() else { return };
    if ok {
        t.dead.remove(ip);
        t.cursor.insert(key, ip.to_string());
        return;
    }
    // 失败：前移到下一候选(整圈后自然复测)。
    if let Some(pos) = plans.iter().position(|p| p.ip == ip) {
        let next = &plans[(pos + 1) % plans.len()];
        t.cursor.insert(key, next.ip.clone());
    }
}

fn cursor_key(pattern: &str, slot: u8) -> String {
    if slot > 1 {
        format!("{pattern}~{slot}")
    } else {
        pattern.to_string()
    }
}

/// 冷启动竞速的互斥圈：同 IP 只认领一次，Arc 归零整组消亡。
pub struct DialCrew {
    claimed: Mutex<HashSet<String>>,
}
impl DialCrew {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { claimed: Mutex::new(HashSet::new()) })
    }
    pub fn claim(&self, ip: &str) -> bool {
        self.claimed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(ip.to_string())
    }
}

/// 串发请求描述：拨哪个池的哪个 host、怎么拨。
pub struct DialSkip<'a> {
    pub host: &'a str,
    pub tls_handshake: bool,
    pub skip_ips: &'a [String],
    /// 隧道腿：客户端自己带真名，候选可加 realPlans。
    pub tunnel: bool,
    pub slot: u8,
    pub crew: Option<&'a DialCrew>,
}

/// 圈式串发：从游标起步逐个试，成功驻留、失败前移、整圈全灭冷却 30s；skip_ips 是双通道硬排除。
pub async fn serial_dial_skip(
    req: DialSkip<'_>,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    let DialSkip {
        host,
        tls_handshake,
        skip_ips,
        tunnel,
        slot,
        crew,
    } = req;
    if SERIAL_COOL.open(host) {
        return Err("串发冷却中(全灭后 30s 内), 快速失败".to_string());
    }
    let Some(row) = route::route_for(host) else {
        return Err(format!("域名不在路由表({host})"));
    };
    if row.flags.direct {
        return Err(format!("直连域不进拨号({host})"));
    }
    let pattern = row.pattern.clone();
    // 真名腿（隧道 / real 路由）额外带上 realPlans。
    let mut circle = row.dial_plans(row.flags.real || tunnel);
    if !skip_ips.is_empty() {
        let filtered: Vec<SerialPlan> = circle
            .iter()
            .filter(|p| !skip_ips.iter().any(|s| s == &p.ip))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            circle = filtered;
        }
    }
    if circle.is_empty() {
        return Err(format!("路由 [{pattern}] 没有候选 IP({host})"));
    }
    let cursor_key = cursor_key(&pattern, slot);

    // 起点 = 记号(上次驻留/尝试的 IP);找不到则从 0 号位起步。
    let start = {
        let g = lock(&SERIAL);
        g.as_ref()
            .unwrap()
            .cursor
            .get(&cursor_key)
            .and_then(|m| circle.iter().position(|p| &p.ip == m))
            .unwrap_or(0)
    };

    let mut last_err: Option<String> = None;
    let mut tried = 0usize;
    let mut dead_skipped = 0usize;
    let budget_deadline =
        Instant::now() + Duration::from_secs(crate::config::SERIAL_DIAL_BUDGET_SECS);
    let mut budget_hit = false;
    for i in 0..circle.len() {
        if Instant::now() >= budget_deadline {
            budget_hit = true;
            break;
        }
        let p = &circle[(start + i) % circle.len()];
        {
            let g = lock(&SERIAL);
            if let Some((until, _)) = g.as_ref().unwrap().dead.get(&p.ip) {
                if Instant::now() < *until {
                    dead_skipped += 1;
                    continue;
                }
            }
        }
        // 同组互斥：对方试过/在试的 IP 绕行。
        if let Some(crew) = crew {
            if !crew.claim(&p.ip) {
                continue;
            }
        }
        tried += 1;
        let mode = p.sni.trim();
        let result = dial::dial_one(host, &p.ip, mode, row.flags.real, tls_handshake).await;
        match result {
            Ok(conn) => {
                // 成功驻留；变更落盘 settings.last_ip（set_last_ips 未变化时 no-op）。
                let snap = {
                    let mut g = lock(&SERIAL);
                    let t = g.as_mut().unwrap();
                    t.cursor.insert(cursor_key.clone(), p.ip.clone());
                    t.cursor
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };
                crate::settings::set_last_ips(snap);
                return Ok((conn, p.ip.clone(), p.sni.clone()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
                // 前移到下一候选；物理顺序不动，零写盘。
                {
                    let mut g = lock(&SERIAL);
                    let n = circle.len();
                    let next = &circle[(start + i + 1) % n];
                    if let Some(t) = g.as_mut() {
                        t.cursor.insert(cursor_key.clone(), next.ip.clone());
                    }
                }
                // TCP 失败 = IP 对谁都死，进死亡退避；TLS 失败是按域干扰，只前移。
                let msg = e.to_string();
                let tcp_level = msg.starts_with("TCP")
                    || matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    );
                if tcp_level {
                    {
                        let mut g = lock(&SERIAL);
                        if let Some(t) = g.as_mut() {
                            let n = t.dead.get(&p.ip).map(|(_, n)| *n).unwrap_or(0) + 1;
                            let secs = match n {
                                1 => 60,
                                2 => 300,
                                _ => 1800,
                            };
                            t.dead.insert(
                                p.ip.clone(),
                                (Instant::now() + Duration::from_secs(secs), n),
                            );
                        }
                    }
                }
                continue;
            }
        }
    }

    if budget_hit {
        // 预算烧满 = 同等退避，防重试每次再烧一遍；有镜像兜底的 host 豁免。
        if mirror_chain(host).is_empty() {
            SERIAL_COOL.set(host);
        }
        if let Some(log) = log {
            log(&format!(
                "[串发] {host} [{pattern}] 耗时预算({}s)到期(试 {tried} 个), 冷却退避, 剩余候选稍后复测",
                crate::config::SERIAL_DIAL_BUDGET_SECS
            ));
        }
        return Err(format!(
            "串发耗时预算到期({}s)",
            crate::config::SERIAL_DIAL_BUDGET_SECS
        ));
    }
    if tried == 0 {
        return Err(format!(
            "全部 {} 个候选处于死亡冷却([{pattern}], {host})",
            circle.len()
        ));
    }
    // 绕表全灭：无镜像兜底才冷却（camo 无链，豁免会让每张徽章重烧整表）。
    let has_mirror = !mirror_chain(host).is_empty();
    if !has_mirror {
        SERIAL_COOL.set(host);
    }
    if let Some(log) = log {
        let tail = if has_mirror {
            "不冷却(有镜像兜底)".to_string()
        } else {
            "无镜像兜底, 冷却 30s 快速失败".to_string()
        };
        log(&format!(
            "[串发] {host} [{pattern}] 全灭({tried} 试 / {dead_skipped} 冷却中, 累计 {:?}), {tail}",
            last_err.as_deref().unwrap_or("未知")
        ));
    }
    Err(last_err.unwrap_or_else(|| "串发全灭".to_string()))
}


/// 按清单对齐镜像链（幂等）：已有成员位置不动，缺的追加链尾；大文件链受开关控制，小文件链只摘已删除项。
pub fn align_custom_mirrors(
    mirrors: &mut HashMap<String, Vec<String>>,
    enabled: &[String],
    disabled: &[String],
    small_enabled: &[String],
    small_disabled: &[String],
) -> bool {
    let mut changed = false;
    for (h, chain) in mirrors.iter_mut() {
        let (en, dis) = if route::is_big_file_host(h) {
            (enabled, disabled)
        } else {
            (small_enabled, small_disabled)
        };
        // 移除：该摘的且仍在链中的
        for u in dis {
            if chain.iter().any(|m| m == u) {
                chain.retain(|m| m != u);
                changed = true;
            }
        }
        // 注入：该进的但链里还没有的 → 追加到链尾
        for u in en {
            if !chain.iter().any(|m| m == u) {
                chain.push(u.clone());
                changed = true;
            }
        }
    }
    changed
}

/// seeds 里的内置镜像地址（区分公共镜像与用户自建）。
fn builtin_mirror_urls() -> std::collections::HashSet<String> {
    seed_db().mirrors.into_values().flatten().collect()
}

/// 按注册表对齐全部镜像链（幂等）；开关只管大文件链，小文件链全量保留、仅摘已删除地址。
pub fn sync_custom_mirrors(removed: &[String]) {
    let registry = crate::settings::worker_mirrors();
    let enabled: Vec<String> = registry
        .iter()
        .filter(|w| w.on)
        .map(|w| w.url.clone())
        .collect();
    let mut disabled: Vec<String> = registry
        .iter()
        .filter(|w| !w.on)
        .map(|w| w.url.clone())
        .collect();
    disabled.extend(removed.iter().cloned());
    let all: Vec<String> = registry.iter().map(|w| w.url.clone()).collect();
    let mut g = lock(&SERIAL);
    let tab = match g.as_mut() {
        Some(t) => t,
        None => return,
    };
    // 链全空时先按 CONTENT_HOSTS 建键，否则镜像永远落不进链。
    if !all.is_empty() {
        for h in CONTENT_HOSTS {
            tab.mirrors.entry(h.to_string()).or_default();
        }
    }
    let changed = align_custom_mirrors(&mut tab.mirrors, &enabled, &disabled, &all, removed);
    // 建了键但没启用镜像的 host 留空链无害(无链=回落语义)，不必回收。
    drop(g);
    if changed {
        write_plans_file(&plans_path(), &mirror_chains_snapshot());
    }
}

pub fn mirror_chain(host: &str) -> Vec<String> {
    let g = lock(&SERIAL);
    // None = 池未初始化(单测独立跑 chain_fetch 时)——空链等价"无镜像腿"。
    g.as_ref()
        .and_then(|t| t.mirrors.get(host))
        .cloned()
        .unwrap_or_default()
}

pub fn set_mirror_chain(host: &str, chain: &[String], why: &str) -> bool {
    if !CONTENT_HOSTS.contains(&host) {
        return false;
    }
    let vc: Vec<String> = chain
        .iter()
        .filter(|m| m.starts_with("https://") && !m.contains(' '))
        .cloned()
        .collect();
    if vc.is_empty() {
        return false;
    }
    {
        let mut g = lock(&SERIAL);
        let tab = g.as_mut().unwrap();
        if tab.mirrors.get(host).map(|c| c == &vc).unwrap_or(false) {
            return false;
        }
        tab.mirrors.insert(host.to_string(), vc);
    }
    // 写者唯一（手动校准）：先放锁再同步落盘，写盘期间不挡拨号。
    write_plans_file(&plans_path(), &mirror_chains_snapshot());
    if let Some(log) = lock(&SERIAL_LOG).as_ref() {
        log(&format!("[镜像] {host} 链序更新({why})"));
    }
    true
}

pub fn mirror_chains_snapshot() -> HashMap<String, Vec<String>> {
    let g = lock(&SERIAL);
    g.as_ref().unwrap().mirrors.clone()
}


/// 熔断：按 host 记账（全局单值会被别的域反复清掉）；过期惰性清除，硬顶防沉淀。
pub struct Breaker {
    ttl_secs: u64,
    map: std::sync::OnceLock<Mutex<HashMap<String, Instant>>>,
}
impl Breaker {
    pub const fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            map: std::sync::OnceLock::new(),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        self.map
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }
    pub fn open(&self, host: &str) -> bool {
        let mut m = self.lock();
        match m.get(host) {
            Some(until) if Instant::now() < *until => true,
            Some(_) => {
                m.remove(host);
                false
            }
            None => false,
        }
    }
    pub fn set(&self, host: &str) {
        let mut m = self.lock();
        const HARD_CAP: usize = 4096;
        if m.len() >= HARD_CAP {
            let now = Instant::now();
            m.retain(|_, until| now < *until);
            if m.len() >= HARD_CAP {
                m.clear();
            }
        }
        m.insert(host.to_string(), Instant::now() + Duration::from_secs(self.ttl_secs));
    }
    pub fn clear(&self, host: &str) {
        self.lock().remove(host);
    }
}

/// 内容域直连熔断 120s。
pub static CONTENT_BREAKER: Breaker = Breaker::new(120);
/// 镜像链全灭熔断 60s。
pub static MIRROR_BREAKER: Breaker = Breaker::new(60);

#[cfg(test)]
#[path = "../tests/pool/dial_crew_tests.rs"]
mod dial_crew_tests;

#[cfg(test)]
#[path = "../tests/pool/mod.rs"]
mod tests;
