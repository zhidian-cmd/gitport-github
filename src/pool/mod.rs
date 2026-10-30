//! 串发拨号：plans.json 唯一权威。成功驻留游标、失败前移；SNI 文件权威、与校验名解耦。
pub mod dial;
pub mod route;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 锁中毒自愈：表只有内容语义，无半写坏中间态，取内层值继续。
pub(crate) fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialPlan {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
}

pub const SERIAL_POOLS: &[&str] = &["core", "api", "edge"];

/// 游标圈规范键序；每族两把钥匙(主键/`~2` 副键)恒相邻，双通道各记各的。
pub fn circle_keys() -> Vec<String> {
    let mut out = Vec::new();
    for pool in SERIAL_POOLS {
        if let Some(pr) = route::pool_route(pool) {
            for f in pr.families {
                let base = format!("{pool}/{}", f.name);
                out.push(base.clone());
                out.push(format!("{base}~2"));
            }
        }
    }
    out
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

/// 种子快照：全新安装引导 + 池补缺。
fn seed_db() -> PlansFile {
    serde_json::from_str(SEEDS_JSON).unwrap_or_default()
}

const SERIAL_MAX_PLANS: usize = 512;

struct SerialTab {
    pools: HashMap<String, Vec<SerialPlan>>,
    /// TCP 层死亡退避 60s→5min→30min，成功拨号清除。
    dead: HashMap<String, (Instant, u32)>,
    mirrors: HashMap<String, Vec<String>>,
    /// 每"池/族[/通道]"一个游标记号；表序冻结，不随游标重排。
    cursor: HashMap<String, String>,
}

static SERIAL_COOL: Breaker = Breaker::new(30);

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

/// 镜像链双字典(大文件/小文件分治)；旧单字典 `mirrors` 仅兼容读。
/// 分类权在 host(is_big_file_host)，条目放错字典也会被归位。
#[derive(serde::Deserialize, Clone, Default)]
struct PlansFile {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    mirrors_big: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    mirrors_small: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    mirrors: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    pools: HashMap<String, Vec<SerialPlan>>,
}

impl PlansFile {
    /// 合并为运行时单表；旧键不覆盖新键已声明的 host。
    fn merged_chains(&self) -> HashMap<String, Vec<String>> {
        let mut out = self.mirrors_big.clone();
        for (h, c) in &self.mirrors_small {
            out.insert(h.clone(), c.clone());
        }
        for (h, c) in &self.mirrors {
            out.entry(h.clone()).or_insert_with(|| c.clone());
        }
        out
    }
}

/// 容错解析：坏段只丢那一段；salvaged = 有段被丢弃，调用方备份原文件。
fn parse_plans_tolerant(raw: &str, log: Option<&LogFn>) -> Option<(PlansFile, bool)> {
    if let Ok(pf) = serde_json::from_str::<PlansFile>(raw) {
        return Some((pf, false));
    }
    // 快路失败：连合法 JSON 对象都不是 → 真没救
    let root: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = root.as_object()?;
    let mut pf = PlansFile::default();
    let mut pools: HashMap<String, Vec<SerialPlan>> = HashMap::new();
    let mut salvaged = false;
    for (k, v) in obj {
        if k == "mirrors" || k == "mirrors_big" || k == "mirrors_small" {
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
                "mirrors_big" => &mut pf.mirrors_big,
                "mirrors_small" => &mut pf.mirrors_small,
                _ => &mut pf.mirrors,
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
            continue;
        }
        match serde_json::from_value::<Vec<SerialPlan>>(v.clone()) {
            Ok(p) => {
                pools.insert(k.clone(), p);
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
    pf.pools = pools;
    Some((pf, salvaged))
}

pub fn plans_snapshot() -> HashMap<String, Vec<SerialPlan>> {
    let g = lock(&SERIAL);
    let tab = g.as_ref().unwrap();
    let mut out = HashMap::new();
    for name in SERIAL_POOLS {
        if let Some(plans) = tab.pools.get(*name) {
            out.insert(name.to_string(), plans.clone());
        }
    }
    out
}

/// 落盘：条目单行；池按 SERIAL_POOLS 序、链按 CONTENT_HOSTS 序。
fn encode_plans(
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) -> String {
    let mut blocks: Vec<String> = SERIAL_POOLS
        .iter()
        .map(|name| {
            let rows: Vec<String> = tab
                .get(*name)
                .map(|ps| ps.iter().map(json_of).collect())
                .unwrap_or_default();
            if rows.is_empty() {
                format!("  \"{name}\": []")
            } else {
                format!("  \"{name}\": [\n    {}\n  ]", rows.join(",\n    "))
            }
        })
        .collect();
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

fn write_plans_file(
    path: &Path,
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) {
    let data = encode_plans(tab, mirrors);
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
    // 容错解析：坏段只丢那一段，不连坐整表。
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
    // plans.json 缺失：按种子快照引导。
    let seeds = seed_db();
    let loaded: PlansFile = parsed
        .map(|(pf, _)| pf)
        .unwrap_or_else(|| seeds.clone());
    let loaded_chains = loaded.merged_chains();
    let plans_map = loaded.pools;

    let mut tab = SerialTab {
        pools: HashMap::new(),
        dead: HashMap::new(),
        mirrors: HashMap::new(),
        cursor: HashMap::new(),
    };
    // 游标圈预写空记号；settings.last_ip 非空值覆盖。
    for key in circle_keys() {
        tab.cursor.insert(key, String::new());
    }
    for (key, ip) in &last_ip {
        if !ip.is_empty() {
            tab.cursor.insert(key.clone(), ip.clone());
        }
    }
    for name in SERIAL_POOLS {
        let ps = plans_map.get(*name).cloned().unwrap_or_default();
        let mut plans = Vec::new();
        for p in ps {
            if p.ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            // sni 原样透传；空串 = 无 SNI 扩展，字符白名单防注入。
            let bare = p.sni.trim();
            if !bare.is_empty()
                && !bare
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                if let Some(log) = log.as_ref() {
                    log(&format!(
                        "[串发] {} sni 含非法字符({:?}), 条目剥除",
                        p.ip, p.sni
                    ));
                }
                continue;
            }
            plans.push(SerialPlan {
                ip: p.ip,
                sni: bare.to_string(),
            });
        }
        if let Some(ips) = seeds.pools.get(*name) {
            let mut added = 0usize;
            for sp in ips {
                if sp.ip.parse::<std::net::IpAddr>().is_err()
                    || plans.iter().any(|p| p.ip == sp.ip)
                    || plans.len() >= SERIAL_MAX_PLANS
                {
                    continue;
                }
                plans.push(SerialPlan {
                    ip: sp.ip.clone(),
                    sni: sp.sni.clone(),
                });
                added += 1;
            }
            if added > 0 {
                if let Some(log) = log.as_ref() {
                    log(&format!(
                        "[串发] {name} 种子补缺 {added} 条(新边缘 IP 上线)"
                    ));
                }
            }
        }
        tab.pools.insert((*name).to_string(), plans);
    }
    for (host, chain) in loaded_chains {
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
    let snap = plans_snapshot();
    let chains = mirror_chains_snapshot();
    write_plans_file(&path, &snap, &chains);
}

/// 数据层结果回写游标：成功驻留该 IP，失败前移一格；零写盘。
/// passthrough 须与产生结果的腿一致，否则记到对方圈外。
pub fn cursor_note(pool_name: &str, host: &str, ip: &str, ok: bool, passthrough: bool, slot: u8) {
    let family = route::serial_family(pool_name, host, passthrough);
    let mut key = format!("{pool_name}/{}", family.map_or("", |f| f.name));
    if slot > 1 {
        key.push_str(&format!("~{slot}"));
    }
    let mut g = lock(&SERIAL);
    let Some(t) = g.as_mut() else { return };
    let Some(ps) = t.pools.get(pool_name) else { return };
    let circle: Vec<&SerialPlan> = ps
        .iter()
        .filter(|p| family.is_none_or(|f| (f.serves)(host, p)))
        .collect();
    if circle.is_empty() {
        return;
    }
    if ok {
        t.dead.remove(ip);
        t.cursor.insert(key, ip.to_string());
        return;
    }
    // 失败：前移到下一候选(整圈后自然复测)。
    if let Some(pos) = circle.iter().position(|p| p.ip == ip) {
        let next = &circle[(pos + 1) % circle.len()];
        t.cursor.insert(key, next.ip.clone());
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

/// 串发请求描述：拨哪个池的哪个 host、怎么拨；ctx/log 横切参数留函数位。
pub struct DialSkip<'a> {
    pub pool_name: &'a str,
    pub host: &'a str,
    pub tls_handshake: bool,
    pub skip_ips: &'a [String],
    pub passthrough: bool,
    pub slot: u8,
    pub crew: Option<&'a DialCrew>,
}

/// 圈式串发：从游标起步逐个试，成功驻留、失败前移、整圈全灭冷却 30s。
/// skip_ips = 双通道硬排除(两条通道不落同一 IP)；全被排除时忽略 skip。
/// slot：1 = 主键游标, 2 = `~2` 副键，双通道各记各的。
pub async fn serial_dial_skip(
    req: DialSkip<'_>,
    ctx: CancellationToken,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    let DialSkip {
        pool_name,
        host,
        tls_handshake,
        skip_ips,
        passthrough,
        slot,
        crew,
    } = req;
    {
        let g = lock(&SERIAL);
        let tab = g.as_ref().unwrap();
        if SERIAL_COOL.open(host) {
            return Err("串发冷却中(全灭后 30s 内), 快速失败".to_string());
        }
        if tab
            .pools
            .get(pool_name)
            .map(|p| p.is_empty())
            .unwrap_or(true)
        {
            return Err(format!("串发表为空({pool_name})"));
        }
    }

    let snapshot = {
        let g = lock(&SERIAL);
        g.as_ref().unwrap().pools.get(pool_name).unwrap().clone()
    };

    // 族圈 = 对口条目按表序(运行时永不重排)。
    let family = route::serial_family(pool_name, host, passthrough);
    let serves = family.map(|f| f.serves);
    let family_name = family.map_or("", |f| f.name);
    let mut circle: Vec<&SerialPlan> = snapshot
        .iter()
        .filter(|p| serves.is_none_or(|s| s(host, p)))
        .collect();
    if !skip_ips.is_empty() {
        let filtered: Vec<&SerialPlan> = circle
            .iter()
            .copied()
            .filter(|p| !skip_ips.iter().any(|s| s == &p.ip))
            .collect();
        if !filtered.is_empty() {
            circle = filtered;
        }
    }
    if circle.is_empty() {
        return Err(format!("无对口 SNI 形态的候选({pool_name}, {host})"));
    }
    let mut cursor_key = format!("{pool_name}/{family_name}");
    if slot > 1 {
        cursor_key.push_str(&format!("~{slot}"));
    }

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
        let p = circle[(start + i) % circle.len()];
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
        let attempt = dial::dial_one(host, &p.ip, mode, tls_handshake);
        let result = tokio::select! {
            _ = ctx.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "请求预算到期")),
            r = attempt => r,
        };
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
                if ctx.is_cancelled() {
                    break; // 预算到期：没试完 ≠ 全灭，不冷却
                }
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

    if ctx.is_cancelled() {
        return Err("请求预算到期".to_string());
    }
    if budget_hit {
        // 预算烧满 = 同等退避，防重试每次再烧一遍；有镜像兜底的 host 豁免。
        if mirror_chain(host).is_empty() {
            SERIAL_COOL.set(host);
        }
        if let Some(log) = log {
            log(&format!(
                "[串发] {host} {pool_name}/{family_name} 耗时预算({}s)到期(试 {tried} 个), 冷却退避, 剩余候选稍后复测",
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
            "全部 {} 个对口候选处于死亡冷却({pool_name}, {host})",
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
            "[串发] {host} {pool_name}/{family_name} 全灭({tried} 试 / {dead_skipped} 冷却中, 累计 {:?}), {tail}",
            last_err.as_deref().unwrap_or("未知")
        ));
    }
    Err(last_err.unwrap_or_else(|| "串发全灭".to_string()))
}


/// 按清单对齐镜像链（幂等）：enabled 追加链尾，disabled 移除；链内已有成员位置不动。
pub fn align_custom_mirrors(
    mirrors: &mut HashMap<String, Vec<String>>,
    enabled: &[String],
    disabled: &[String],
) -> bool {
    let mut changed = false;
    for chain in mirrors.values_mut() {
        // 移除：停用/已删且仍在链中的
        for u in disabled {
            if chain.iter().any(|m| m == u) {
                chain.retain(|m| m != u);
                changed = true;
            }
        }
        // 注入：启用中但链里还没有的 → 追加到链尾
        for u in enabled {
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

/// 按注册表对齐全部镜像链（幂等）；removed = 本次删除的地址。
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
    let mut g = lock(&SERIAL);
    let tab = match g.as_mut() {
        Some(t) => t,
        None => return,
    };
    // 链全空时(全新安装)先按 CONTENT_HOSTS 建键：values_mut() 对空表遍历不到
    // 任何东西，没有这步启用中的镜像永远落不进链(校准/大文件全哑)。
    if !enabled.is_empty() {
        for h in CONTENT_HOSTS {
            tab.mirrors.entry(h.to_string()).or_default();
        }
    }
    let changed = align_custom_mirrors(&mut tab.mirrors, &enabled, &disabled);
    // 建了键但没启用镜像的 host 留空链无害(无链=回落语义)，不必回收。
    drop(g);
    if changed {
        write_plans_file(&plans_path(), &plans_snapshot(), &mirror_chains_snapshot());
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
    write_plans_file(&plans_path(), &plans_snapshot(), &mirror_chains_snapshot());
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
    const fn new(ttl_secs: u64) -> Self {
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
mod dial_crew_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 互斥语义:同一 IP 首次认领成功,重复认领被拒;不同 IP 不受影响。
    #[test]
    fn dial_crew_claim_excludes_peer() {
        let crew = DialCrew::new();
        assert!(crew.claim("1.2.3.4"), "首次认领应成功");
        assert!(!crew.claim("1.2.3.4"), "重复认领应被拒");
        assert!(crew.claim("5.6.7.8"), "不同 IP 不受同组互避影响");
    }

    /// 并发竞争:两个线程对同一 IP 各认领 5000 次,成功总数恰为 1。
    /// 这是冷启动双任务"不同 IP"保证的根基——互斥坏了会静默退化成同 IP 双连。
    #[test]
    fn dial_crew_claim_race_yields_exactly_one_winner() {
        let crew = DialCrew::new();
        let ok = std::sync::Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let crew = crew.clone();
            let ok = ok.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..5000 {
                    if crew.claim("10.0.0.1") {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            ok.load(Ordering::Relaxed),
            1,
            "并发认领同一 IP 必须恰有一个胜者"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
    // SERIAL/SERIAL_DIR 是进程级全局态，测试并行会互相踩踏 → 需要全局态的测试串行
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tmpdir() -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("gitport_test_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn reset_state(dir: &Path) {
        serial_load(dir, Vec::new(), None);
    }

    #[test]
    fn breakers_open_set_clear_by_host() {
        let raw = "raw.githubusercontent.com";
        let camo = "camo.githubusercontent.com";
        assert!(!CONTENT_BREAKER.open(raw));
        CONTENT_BREAKER.set(raw);
        assert!(CONTENT_BREAKER.open(raw));
        assert!(
            !CONTENT_BREAKER.open(camo),
            "熔断按 host 记账，不得串到同池其他域"
        );
        CONTENT_BREAKER.clear(raw);
        assert!(!CONTENT_BREAKER.open(raw));

        assert!(!MIRROR_BREAKER.open(camo));
        MIRROR_BREAKER.set(camo);
        assert!(MIRROR_BREAKER.open(camo));
        MIRROR_BREAKER.clear(camo);
        assert!(!MIRROR_BREAKER.open(camo));
    }

    #[test]
    fn breaker_expired_entry_lazily_removed() {
        // ttl=0：set 后立即过期。open 必须判 false 并把条目清掉——
        // 过期条目沉淀在表里只进不出（修复前 open 只读不删）。
        let b = Breaker::new(0);
        b.set("expired.example");
        assert!(!b.open("expired.example"), "过期条目不得判熔断中");
        assert!(b.lock().is_empty(), "过期条目应被惰性清除");
        // 活条目不受影响：open 通过且仍留在表里
        let live = Breaker::new(600);
        live.set("live.example");
        assert!(live.open("live.example"));
        assert!(
            live.lock().contains_key("live.example"),
            "活条目应保留在表里"
        );
        live.clear("live.example");
        assert!(!live.open("live.example"));
    }

    #[test]
    fn plans_json_single_bad_pool_does_not_wipe_table() {
        // 单池写坏只丢该池（按种子补缺），其余池与镜像链原样保留——
        // 旧行为是 flatten 全有或全无：一处笔误 → 整表按种子重建。
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        // 隔离：自定义镜像注册表经 settings.json 跨测试/跨轮次持久化，别处收养的
        // 自建镜像会被 sync_custom_mirrors 追加回既有链——先清空，本断言只验
        // plans.json 里的链是否原样保留，不掺注册表状态。
        crate::settings::save_worker_mirrors(Vec::new());
        std::fs::write(
            dir.join("plans.json"),
            r#"{
  "core": [{"ip": "1.2.3.4", "sni": "baidu.com"}],
  "edge": "写坏了-不是数组",
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org"]
  }
}"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Vec::new(), Some(log));
        // 好池的用户条目保留（+ 种子补缺）
        let core = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        assert_eq!(core[0].ip, "1.2.3.4", "好池必须保留: {core:?}");
        assert!(core.len() > 1, "好池应叠加种子补缺: {core:?}");
        // 整个写坏的池 → 按种子重建（不连坐）
        let edge_n = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("edge").unwrap().len()
        };
        assert!(edge_n > 0, "坏池应按种子重建: {edge_n}");
        // 镜像链保留
        assert_eq!(
            mirror_chain("raw.githubusercontent.com"),
            vec!["https://v4.gh-proxy.org".to_string()],
            "镜像链必须保留"
        );
        // 日志指明哪个池坏了；原文件备份（坏段可从 .bak 捡回）
        assert!(
            seen.lock().unwrap().iter().any(|l| l.contains("池 edge 写坏")),
            "应记录坏池名: {:?}",
            seen.lock().unwrap()
        );
        assert!(
            dir.join("plans.json.bak").exists(),
            "有段落坏应备份原文件"
        );
    }

    #[test]
    fn direct_hosts_never_pooled() {
        for host in [
            "objects-origin.githubusercontent.com",
            "uploads.github.com",
            "viewscreen.githubusercontent.com",
        ] {
            assert!(crate::config::is_direct(host), "{host} 应在直连白名单");
            assert_eq!(crate::config::pool_for(host), "", "{host} 不应归任何池");
        }
    }

    #[test]
    fn fastly_pools_no_longer_serial() {
        assert!(!SERIAL_POOLS.contains(&"fastly"));
        assert!(!SERIAL_POOLS.contains(&"codeload"));
        for p in ["core", "api", "edge"] {
            assert!(SERIAL_POOLS.contains(&p), "{p} 应为串发池");
        }
        assert!(!SERIAL_POOLS.contains(&"uploads"));
    }

    #[test]
    fn migrate_drops_stats_and_normalizes_shapes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        std::fs::write(
            dir.join("plans.json"),
            r#"{
  "core": [
    {"ip": "1.2.3.4", "sni": "ech", "成功次数": "9/9", "分数": 99},
    {"ip": "5.6.7.8", "sni": "real"},
    {"ip": "bad-ip", "sni": "real"}
  ],
  "edge": [
    {"ip": "140.82.112.29", "sni": "real"},
    {"ip": "185.199.108.154", "sni": "sni"},
    {"ip": "185.199.109.153", "sni": "sni"}
  ],
  "ghapp": [{"ip": "9.9.9.9", "sni": "baidu.com"}],
  "assets": [{"ip": "8.8.8.8", "sni": "sni"}]
}"#,
        )
        .unwrap();
        reset_state(&dir);
        let ps = {
            let g = SERIAL.lock().unwrap();
            let tab = g.as_ref().unwrap();
            tab.pools.get("core").unwrap().clone()
        };
        let core_seed_n = seed_db().pools.get("core").map(|v| v.len()).unwrap_or(0);
        assert_eq!(
            ps.len(),
            2 + core_seed_n,
            "补缺后 = 用户条目 + 全部种子: {ps:?}"
        );
        assert_eq!(
            ps[0],
            SerialPlan {
                ip: "1.2.3.4".into(),
                sni: "ech".into()
            },
            "sni 原样透传(写什么传什么)"
        );
        assert_eq!(
            ps[1],
            SerialPlan {
                ip: "5.6.7.8".into(),
                sni: "real".into()
            },
            "sni 原样透传(写什么传什么, 含真名写法)"
        );
        let edge_ps = {
            let g = SERIAL.lock().unwrap();
            let tab = g.as_ref().unwrap();
            tab.pools.get("edge").unwrap().clone()
        };
        assert!(edge_ps.len() >= 3, "edge 至少含旧表 3 条: {edge_ps:?}");
        assert!(
            edge_ps.contains(&SerialPlan {
                ip: "140.82.112.29".into(),
                sni: "real".into()
            }),
            "ghapp 条目保留, sni 原样透传: {edge_ps:?}"
        );
        assert!(
            edge_ps.contains(&SerialPlan {
                ip: "185.199.108.154".into(),
                sni: "sni".into()
            }) && edge_ps.contains(&SerialPlan {
                ip: "185.199.109.153".into(),
                sni: "sni".into()
            }),
            "sni 文件权威——旧表显式真名写法原样保留: {edge_ps:?}"
        );
        assert!(
            edge_ps
                .iter()
                .any(|p| route::fastly_last_octet(&p.ip) == Some("133") && p.sni == "baidu.com"),
            "种子补缺应追加 .133 伪装内容域条目: {edge_ps:?}"
        );
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(!b.contains("成功次数") && !b.contains("分数"));
        let back: serde_json::Value = serde_json::from_str(&b).unwrap();
        for gone in ["fastly", "codeload", "ghapp", "assets"] {
            assert!(back.get(gone).is_none(), "{gone} 不应再落盘: {back}");
        }
        assert!(back.get("edge").is_some(), "edge 池应落盘: {back}");
    }

    #[test]
    fn seed_topup_appends_missing_and_keeps_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        std::fs::write(
            dir.join("plans.json"),
            r#"{ "edge": [{"ip": "140.82.112.29", "sni": "baidu.com"}] }"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Vec::new(), Some(log));
        let ps = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("edge").unwrap().clone()
        };
        assert_eq!(
            ps[0].ip, "140.82.112.29",
            "用户手排顺序保留, 补缺只追加尾部"
        );
        let seeds = seed_db();
        let seed = seeds.pools.get("edge").unwrap();
        assert_eq!(ps.len(), seed.len(), "补缺后应覆盖全部种子: {ps:?}");
        assert!(
            seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
            "补缺应打一行日志"
        );
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(b.contains("185.199.110.133"), "补缺应落盘: {b}");
        // 2026-10-19 起三个 .133 复活移出退役清单、入种子——应随补缺落盘（伪装形态）
        assert!(
            b.contains("185.199.108.133")
                && b.contains("185.199.109.133")
                && b.contains("185.199.111.133"),
            "复活的内容边缘应随种子补缺落盘: {b}"
        );
    }

    #[test]
    fn encode_plans_roundtrip() {
        let mut tab = HashMap::new();
        tab.insert(
            "core".into(),
            vec![
                SerialPlan {
                    ip: "1.2.3.4".into(),
                    sni: "baidu.com".into(),
                },
                SerialPlan {
                    ip: "5.6.7.8".into(),
                    sni: "baidu.com".into(),
                },
            ],
        );
        tab.insert(
            "api".into(),
            vec![SerialPlan {
                ip: "140.82.112.5".into(),
                sni: "baidu.com".into(),
            }],
        );
        tab.insert(
            "edge".into(),
            vec![
                SerialPlan {
                    ip: "185.199.108.154".into(),
                    sni: "sni".into(),
                },
                SerialPlan {
                    ip: "140.82.112.29".into(),
                    sni: "baidu.com".into(),
                },
            ],
        );
        let mut mirrors = HashMap::new();
        mirrors.insert(
            "raw.githubusercontent.com".to_string(),
            vec![
                "https://axisnow.gh-proxy.org".to_string(),
                "https://v4.gh-proxy.org".to_string(),
            ],
        );
        let b = encode_plans(&tab, &mirrors);
        for line in b.lines() {
            let t = line.trim();
            if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
                panic!("条目被展开成多行: {line:?}");
            }
        }
        assert!(b.contains("\"mirrors_small\""), "镜像链板块应落盘: {b}");
        assert!(b.contains("raw.githubusercontent.com"));
        let back_file: PlansFile = serde_json::from_str(&b).unwrap();
        assert_eq!(
            back_file
                .mirrors_small
                .get("raw.githubusercontent.com")
                .map(|c| c.len()),
            Some(2),
            "镜像链应可读回(小文件域落 mirrors_small): {:?}",
            back_file.mirrors_small
        );
        let back: HashMap<String, Vec<SerialPlan>> = back_file.pools;
        assert_eq!(back["core"].len(), 2);
        assert_eq!(back["core"][0].sni, "baidu.com");
        assert_eq!(back["edge"].len(), 2);
        assert_eq!(back["edge"][0].sni, "sni");
        assert!(!b.contains("fastly") && !b.contains("codeload"));
    }

    #[test]
    fn cursor_park_is_memory_only_and_freezes_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        serial_load(&dir, Vec::new(), None);
        let head_before = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[0].ip.clone()
        };
        let target = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[2].ip.clone()
        };
        assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
        let file_before = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        cursor_note("core", "github.com", &target, true, false, 1);
        // 表序冻结:成功驻留只动内存游标,不动物理顺序、不触发写盘
        assert_eq!(
            SERIAL.lock().unwrap().as_ref().unwrap().pools.get("core").unwrap()[0].ip,
            head_before,
            "表序冻结"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("plans.json")).unwrap(),
            file_before,
            "游标驻留零写盘"
        );
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
            Some(target.as_str()),
            "游标应驻留 target"
        );
    }

    #[test]
    fn custom_mirrors_align() {
        // 清单对齐：启用的置前（按清单序），停用的移除，其余成员相对顺序不变
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        m.insert(
            "github.com".into(),
            vec![
                "https://pub1".into(),
                "https://customA".into(),
                "https://pub2".into(),
            ],
        );
        m.insert("raw.githubusercontent.com".into(), vec!["https://pub1".into()]);
        let enabled = vec!["https://customB".to_string(), "https://customA".to_string()];
        let disabled = vec!["https://customC".to_string()];
        assert!(align_custom_mirrors(&mut m, &enabled, &disabled));
        // github.com：链里没有的 customB 追加到链尾；已在链中的成员位置不动
        assert_eq!(
            m["github.com"],
            vec![
                "https://pub1".to_string(),
                "https://customA".to_string(),
                "https://pub2".to_string(),
                "https://customB".to_string(),
            ]
        );
        // raw：customB、customA 都追加到链尾，customC 本就不在链中无影响
        assert_eq!(
            m["raw.githubusercontent.com"],
            vec!["https://pub1".to_string(), "https://customB".to_string(), "https://customA".to_string()]
        );
        // 幂等：再跑一次无变更
        assert!(!align_custom_mirrors(&mut m, &enabled, &disabled));
        // 删除：customB 移出启用清单（进 disabled）→ 从全部链消失；其余不动
        let enabled2 = vec!["https://customA".to_string()];
        let disabled2 = vec!["https://customB".to_string(), "https://customC".to_string()];
        assert!(align_custom_mirrors(&mut m, &enabled2, &disabled2));
        assert!(!m["github.com"].iter().any(|x| x == "https://customB"));
        assert_eq!(
            m["github.com"],
            vec![
                "https://pub1".to_string(),
                "https://customA".to_string(),
                "https://pub2".to_string(),
            ]
        );
    }

    #[test]
    fn worker_chain_replace_old_url() {
        // 换地址：新地址追加到链尾的同时旧地址必须移除（防新旧并存）
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        m.insert("github.com".into(), vec!["https://old.worker".into(), "https://a.example".into()]);
        let new = vec!["https://new.worker".to_string()];
        let old = vec!["https://old.worker".to_string()];
        align_custom_mirrors(&mut m, &new, &old);
        let c = &m["github.com"];
        assert_eq!(
            c,
            &vec!["https://a.example".to_string(), "https://new.worker".to_string()]
        );
        assert!(!c.iter().any(|x| x.contains("old.worker")));
    }

    /// 双字典合并优先级：同 host 三处都有时，mirrors_big/small 赢、旧 mirrors 不覆盖；
    /// 仅旧字典有的 host 照常并入（升级兼容的钉子）。
    #[test]
    fn merged_chains_prefers_typed_dictionaries_over_legacy() {
        let _guard = TEST_LOCK.lock().unwrap();
        // 隔离：.example 自建镜像会被收编进注册表并跨测试持久化，先清空。
        crate::settings::save_worker_mirrors(Vec::new());
        let dir = tmpdir();
        std::fs::write(
            dir.join("plans.json"),
            r#"{
  "core": [],
  "mirrors_big":   {"codeload.github.com": ["https://big.example"]},
  "mirrors_small": {"raw.githubusercontent.com": ["https://small.example"]},
  "mirrors": {
    "codeload.github.com": ["https://legacy-wrong.example"],
    "raw.githubusercontent.com": ["https://legacy-wrong.example"],
    "gist.githubusercontent.com": ["https://legacy-only.example"]
  }
}"#,
        )
        .unwrap();
        serial_load(&dir, Vec::new(), None);
        // 断言只锁"优先级"这一点：自建镜像收编(sync_custom_mirrors)会把非内置
        // 镜像追加进所有链尾，属既有设计，不在本测试射程。
        // ① 旧 mirrors 不得覆盖新字典 → codeload 链里绝不允许出现 legacy-wrong。
        // ② 新字典成员在前 → 链头必须是 big/small；旧字典独有成员追加在尾。
        let big = mirror_chain("codeload.github.com");
        assert_eq!(
            big.first(),
            Some(&"https://big.example".to_string()),
            "mirrors_big 赢, 旧 mirrors 不得覆盖(legacy-wrong 缺席且 big 居首): {big:?}"
        );
        assert!(
            !big.contains(&"https://legacy-wrong.example".to_string()),
            "旧 mirrors 不得覆盖新字典已声明的 host: {big:?}"
        );
        let small = mirror_chain("raw.githubusercontent.com");
        assert_eq!(
            small.first(),
            Some(&"https://small.example".to_string()),
            "mirrors_small 赢: {small:?}"
        );
        assert!(
            !small.contains(&"https://legacy-wrong.example".to_string()),
            "旧 mirrors 不得覆盖新字典已声明的 host: {small:?}"
        );
        let legacy = mirror_chain("gist.githubusercontent.com");
        assert!(
            legacy.contains(&"https://legacy-only.example".to_string()),
            "仅旧字典有的 host 照常并入: {legacy:?}"
        );
        // 清场：正规路径删除自建镜像（注册表 + 全部链），不给后续测试留全局残留。
        crate::settings::set_worker_mirrors(Vec::new()).ok();
    }

    /// 全新安装(链全空) + 添加镜像 → 启用中的镜像必须落进全部 8 条链。
    /// v0.5.0 回归：values_mut() 对空表遍历不到任何东西，镜像只进注册表不进链。
    #[test]
    fn fresh_install_mirror_lands_in_all_chains() {
        let _guard = TEST_LOCK.lock().unwrap();
        crate::settings::save_worker_mirrors(Vec::new());
        let dir = tmpdir();
        std::fs::write(dir.join("plans.json"), r#"{"core": []}"#).unwrap();
        serial_load(&dir, Vec::new(), None);
        assert!(
            mirror_chain("raw.githubusercontent.com").is_empty(),
            "前置: 全新安装链应为空"
        );
        // 模拟 UI 添加并启用一个镜像(整表保存走 sync_custom_mirrors)。
        crate::settings::set_worker_mirrors(vec![crate::settings::WorkerMirror {
            url: "https://my-worker.example.com".to_string(),
            on: true,
            trusted: false,
        }])
        .unwrap();
        for h in CONTENT_HOSTS {
            let c = mirror_chain(h);
            assert!(
                c.contains(&"https://my-worker.example.com".to_string()),
                "{h} 链必须收到启用中的镜像(全新安装也必须生效): {c:?}"
            );
        }
        // 清场：正规路径删除，注册表与全部链恢复空。
        crate::settings::set_worker_mirrors(Vec::new()).ok();
    }

    #[test]
    fn mirror_chain_load_and_topup() {
        let _guard = TEST_LOCK.lock().unwrap();
        // 隔离：自定义镜像注册表经 settings.json 跨进程持久化（上一轮 serial_load 收养的
        // 自建镜像会留在里面），不清空的话 sync_custom_mirrors 会把它们追加进本测试的链。
        crate::settings::save_worker_mirrors(Vec::new());
        let dir = tmpdir();
        std::fs::write(
            dir.join("plans.json"),
            r#"{
  "core": [{"ip": "140.82.112.3", "sni": "baidu.com"}],
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org", "https://my-self.example.com"],
    "not-a-content.host": ["https://v4.gh-proxy.org"]
  }
}"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Vec::new(), Some(log));
        // 镜像链数据权威：用户写什么用什么（含自部署镜像），不白名单、不自动补缺
        let raw_chain = mirror_chain("raw.githubusercontent.com");
        assert_eq!(
            raw_chain,
            vec![
                "https://v4.gh-proxy.org".to_string(),
                "https://my-self.example.com".to_string()
            ],
            "用户链原样保留(含自部署镜像): {raw_chain:?}"
        );
        // 缺链 host：注册表有启用镜像时按 CONTENT_HOSTS 铺键并对齐全量
        // (自建镜像进所有链是既有设计)；无启用镜像时该 host 真正无链。
        let media = mirror_chain("media.githubusercontent.com");
        assert_eq!(
            media,
            vec![
                "https://v4.gh-proxy.org".to_string(),
                "https://my-self.example.com".to_string()
            ],
            "media 无自带链, 应被注册表对齐填成启用镜像全量: {media:?}"
        );
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(!b.contains("not-a-content.host"), "未知 host 应丢弃: {b}");
        assert!(b.contains("\"mirrors_small\""), "镜像链应落盘(raw 为小文件域): {b}");
        let mut new_chain = raw_chain.clone();
        new_chain.reverse();
        assert!(
            set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
            "新链应写入"
        );
        assert!(
            !set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
            "同链应 no-op"
        );
        assert!(
            !set_mirror_chain("github.githubassets.com", &new_chain, "测试"),
            "非内容域 host 应拒收"
        );
    }

    #[test]
    fn cursor_advance_on_failure_then_park_on_success() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        serial_load(&dir, Vec::new(), None);
        let base = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        assert!(base.len() >= 6, "初始表过小: {}", base.len());
        let head = base[0].ip.clone();
        let next = base[1].ip.clone();

        // 失败:记号前移到圈中下一候选
        cursor_note("core", "github.com", &head, false, false, 1);
        {
            let g = SERIAL.lock().unwrap();
            assert_eq!(
                g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
                Some(next.as_str()),
                "失败后记号应前移到下一候选"
            );
        }

        // 成功:记号驻留;表序全程未变
        cursor_note("core", "github.com", &next, true, false, 1);
        {
            let g = SERIAL.lock().unwrap();
            assert_eq!(
                g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
                Some(next.as_str())
            );
            let ps = g.as_ref().unwrap().pools.get("core").unwrap();
            let order_unchanged = ps.iter().zip(base.iter()).all(|(a, b)| a.ip == b.ip);
            assert!(order_unchanged, "表序应冻结(游标不重排)");
        }
    }

    /// 串发重试引擎实机圈：TCP 拒 → 沿圈到活条 → 驻留 + 死亡退避。
    // 串行锁有意全程持有: 测试期间独占全局表, 跨 await 是本意。
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn serial_dial_rotates_on_failure_and_parks_on_success() {
        let _guard = TEST_LOCK.lock().unwrap();
        // 只有 127.0.0.2 在监听；127.0.0.1 的同端口连接会被立刻拒绝。
        let Ok(ln) = tokio::net::TcpListener::bind("127.0.0.2:0").await else {
            eprintln!("跳过: 本机绑不了 127.0.0.2(回环 /8 行为不同), 串发实测留给真机");
            return;
        };
        let port = ln.local_addr().unwrap().port();
        dial::set_dial_port(port);
        let dir = tmpdir();
        std::fs::write(
            dir.join("plans.json"),
            r#"{"core":[{"ip":"127.0.0.1","sni":"a.example"},{"ip":"127.0.0.2","sni":"a.example"}]}"#,
        )
        .unwrap();
        serial_load(&dir, Vec::new(), None);

        let (conn, ip, _) = serial_dial_skip(
            DialSkip {
                pool_name: "core",
                host: "github.com",
                tls_handshake: false,
                skip_ips: &[],
                passthrough: false,
                slot: 1,
                crew: None,
            },
            CancellationToken::new(),
            None,
        )
        .await
        .expect("第二个候选能拨通");
        drop(conn);
        assert_eq!(ip, "127.0.0.2", "被拒的候选应垫底, 活着的那条胜出");
        {
            let g = SERIAL.lock().unwrap();
            let t = g.as_ref().unwrap();
            assert_eq!(
                t.cursor.get("core/all").map(String::as_str),
                Some("127.0.0.2"),
                "成功必须驻留记号(下次从它起步)"
            );
            assert!(
                t.dead.contains_key("127.0.0.1"),
                "TCP 层失败应进死亡退避表"
            );
        }

        // 第二次：从驻留记号起步，直接拿 127.0.0.2（不再先撞被拒的那条）。
        let (conn, ip, _) = serial_dial_skip(
            DialSkip {
                pool_name: "core",
                host: "github.com",
                tls_handshake: false,
                skip_ips: &[],
                passthrough: false,
                slot: 1,
                crew: None,
            },
            CancellationToken::new(),
            None,
        )
        .await
        .expect("驻留后应直接命中");
        drop(conn);
        assert_eq!(ip, "127.0.0.2");
        dial::set_dial_port(0); // 复位，别影响别的测试
    }
}
