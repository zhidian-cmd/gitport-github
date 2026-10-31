//! 串发拨号：plans.json 唯一权威。成功驻留游标、失败前移；SNI 文件权威、与校验名解耦。
pub mod dial;
pub mod route;
pub(crate) mod mirror_stats;

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


/// 按清单对齐镜像链（幂等）：链内已有成员位置不动，缺的追加链尾，该摘的摘除。
/// 大文件 host(is_big_file_host) 用 enabled/disabled——启动/关闭开关只在这里
/// 生效；其余 host 用 small_enabled/small_disabled——开关无关, 注册表全量
/// 按序保留, 仅摘除已删除地址。
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

/// 按注册表对齐全部镜像链（幂等）；removed = 本次删除的地址。
/// 开关只管大文件链：off 的镜从 is_big_file_host 的链摘除；小文件链按链序
/// 全量保留（启停价值低），仅摘除已删除的地址。
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
    // 链全空时(全新安装)先按 CONTENT_HOSTS 建键：values_mut() 对空表遍历不到
    // 任何东西，没有这步镜像永远落不进链(校准/大文件全哑)。
    if !all.is_empty() {
        for h in CONTENT_HOSTS {
            tab.mirrors.entry(h.to_string()).or_default();
        }
    }
    let changed = align_custom_mirrors(&mut tab.mirrors, &enabled, &disabled, &all, removed);
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
#[path = "../tests/pool/dial_crew_tests.rs"]
mod dial_crew_tests;

#[cfg(test)]
#[path = "../tests/pool/mod.rs"]
mod tests;
