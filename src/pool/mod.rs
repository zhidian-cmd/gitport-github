//! 串发拨号：plans.json 唯一权威。ok 置顶 / 失败垫底，同 IP 重复置顶 no-op 不写盘。
//! SNI 形态按 IP 族定（shape_for_ip），SNI 与校验名解耦；全灭冷却 30s。
//! 仅顺序真变更才写盘（2s 原子写回）；edge 混合池按 host 族对口选择（见 route.rs）。

pub mod dial;
pub mod route;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialPlan {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
}

pub const SERIAL_POOLS: &[&str] = &["core", "api", "edge"];

const SEEDS_JSON: &str = include_str!("seeds.json");

pub const MIRRORS: &[&str] = &[
    "https://mirror.ghproxy.com",
    "https://gh-proxy.com",
    "https://gh-proxy.org",
    "https://v4.gh-proxy.org",
    "https://v6.gh-proxy.org",
    "https://cdn.gh-proxy.org",
    "https://axisnow.gh-proxy.org",
    "https://ghproxy.net",
    "https://ghfast.top",
    "https://github.moeyy.xyz",
    "https://cf.ghproxy.cn",
];

pub const CONTENT_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "avatars.githubusercontent.com",
    "user-images.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "media.githubusercontent.com",
];

/// 各链只存实测调优的头部 3 家；尾部由 serial_load 补缺按 MIRRORS 序填满，
/// 校准（Throughput/Ttfb）会重写全序——不手写 11 家全量。
pub const DEFAULT_CHAINS: &[(&str, &[&str])] = &[
    (
        "github.com",
        &["https://gh-proxy.org", "https://v6.gh-proxy.org", "https://cf.ghproxy.cn"],
    ),
    (
        "raw.githubusercontent.com",
        &["https://axisnow.gh-proxy.org", "https://v4.gh-proxy.org", "https://cdn.gh-proxy.org"],
    ),
    (
        "gist.githubusercontent.com",
        &["https://v4.gh-proxy.org", "https://axisnow.gh-proxy.org", "https://gh-proxy.com"],
    ),
    (
        "avatars.githubusercontent.com",
        &["https://axisnow.gh-proxy.org", "https://gh-proxy.com", "https://v4.gh-proxy.org"],
    ),
    (
        "user-images.githubusercontent.com",
        &["https://cf.ghproxy.cn", "https://mirror.ghproxy.com", "https://gh-proxy.com"],
    ),
    (
        "codeload.github.com",
        &["https://gh-proxy.org", "https://v6.gh-proxy.org", "https://cf.ghproxy.cn"],
    ),
    (
        "objects.githubusercontent.com",
        &["https://axisnow.gh-proxy.org", "https://gh-proxy.org", "https://cdn.gh-proxy.org"],
    ),
    (
        "release-assets.githubusercontent.com",
        &["https://gh-proxy.org", "https://v4.gh-proxy.org", "https://gh-proxy.com"],
    ),
    (
        "media.githubusercontent.com",
        &["https://cf.ghproxy.cn", "https://mirror.ghproxy.com", "https://gh-proxy.com"],
    ),
];

pub fn serial_pool(name: &str) -> bool {
    SERIAL_POOLS.contains(&name)
}

/// IP → 默认 SNI 形态（Fastly 边缘对任意 SNI 返本边缘主证书）。
/// .133 伪装被挂起只能真名；.153/.154/.215 伪装抗 SNI 阻断；主站/auth 伪装。Fastly 段强制按族归一。
fn shape_for_ip(ip: &str) -> &'static str {
    if route::fastly_last_octet(ip) == Some("133") {
        dial::MODE_SNI
    } else {
        "baidu.com"
    }
}

fn seed_db() -> HashMap<String, Vec<String>> {
    serde_json::from_str(SEEDS_JSON).unwrap_or_default()
}

const SERIAL_MAX_PLANS: usize = 512; // 防表无限膨胀

struct SerialTab {
    pools: HashMap<String, Vec<SerialPlan>>,
    /// 全灭冷却按 host 记账（池级会让一个域全灭毒倒同池其他族），30s。
    /// 有镜像兜底的 host 不冷却（内容域熔断已覆盖）。
    cool: HashMap<String, Instant>,
    /// per-IP 死亡冷却：TCP 层失败 = IP 对谁都不通，直接跳过。
    /// 指数退避 60s → 5min → 30min 封顶；成功拨号清除。
    dead: HashMap<String, (Instant, u32)>,
    mirrors: HashMap<String, Vec<String>>,
    dirty: bool,
}

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

#[derive(serde::Deserialize)]
struct PlansFile {
    #[serde(default)]
    mirrors: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    pools: HashMap<String, Vec<SerialPlan>>,
}

pub fn plans_snapshot() -> HashMap<String, Vec<SerialPlan>> {
    let g = SERIAL.lock().unwrap();
    let tab = g.as_ref().unwrap();
    let mut out = HashMap::new();
    for name in SERIAL_POOLS {
        if let Some(plans) = tab.pools.get(*name) {
            out.insert(name.to_string(), plans.clone());
        }
    }
    out
}

fn encode_plans(
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) -> String {
    let mut b = String::from("{\n");
    for (i, name) in SERIAL_POOLS.iter().enumerate() {
        if i > 0 {
            b.push_str(",\n");
        }
        b.push_str(&format!("  \"{name}\": ["));
        let ps = tab.get(*name).cloned().unwrap_or_default();
        if !ps.is_empty() {
            b.push('\n');
            for (j, p) in ps.iter().enumerate() {
                if j > 0 {
                    b.push_str(",\n");
                }
                if p.sni.is_empty() {
                    b.push_str(&format!("    {{\"ip\": {}}}", esc(&p.ip)));
                } else {
                    b.push_str(&format!(
                        "    {{\"ip\": {}, \"sni\": {}}}",
                        esc(&p.ip),
                        esc(&p.sni)
                    ));
                }
            }
            b.push_str("\n  ]");
        } else {
            b.push(']');
        }
    }
    let chains: Vec<(&str, &Vec<String>)> = CONTENT_HOSTS
        .iter()
        .filter_map(|h| mirrors.get(*h).map(|c| (*h, c)))
        .collect();
    if !chains.is_empty() {
        b.push_str(",\n  \"mirrors\": {");
        for (i, (host, chain)) in chains.iter().enumerate() {
            if i > 0 {
                b.push(',');
            }
            let items: Vec<String> = chain.iter().map(|m| esc(m)).collect();
            b.push_str(&format!("\n    {}: [{}]", esc(host), items.join(", ")));
        }
        b.push_str("\n  }");
    }
    b.push_str("\n}\n");
    b
}

/// serde 全量转义（手写版漏控制字符会写出非法 plans.json）。
fn esc(s: &str) -> String {
    serde_json::to_string(s).expect("字符串序列化不会失败")
}

fn write_plans_file(
    path: &Path,
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) {
    let data = encode_plans(tab, mirrors);
    let tmp = path.with_extension("json.tmp");
    if let Ok(mut f) = std::fs::File::create(&tmp) {
        if f.write_all(data.as_bytes()).is_ok() {
            let _ = f.flush();
            drop(f);
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn plans_path() -> PathBuf {
    let dir = SERIAL_DIR
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("plans.json")
}

pub fn serial_load(data_dir: &Path, log: Option<LogFn>) {
    *SERIAL_DIR.lock().unwrap() = Some(data_dir.to_path_buf());
    *SERIAL_LOG.lock().unwrap() = log.clone();
    let path = plans_path();
    let raw = std::fs::read_to_string(&path).ok();
    let parsed = raw.as_deref().and_then(|b| serde_json::from_str::<PlansFile>(b).ok());
    if let (Some(_raw), None) = (&raw, &parsed) {
        // 解析失败：先备份原文件再按种子重建，不静默覆丢用户手排表。
        let bak = path.with_extension("json.bak");
        if std::fs::copy(&path, &bak).is_ok() {
            if let Some(l) = log.as_ref() {
                l("[串发] plans.json 解析失败, 原文件已备份为 plans.json.bak, 本次按种子重建");
            }
        }
    }
    let loaded: PlansFile = parsed.unwrap_or_else(|| PlansFile {
        pools: HashMap::new(),
        mirrors: HashMap::new(),
    });
    let plans_map = loaded.pools;
    let loaded_chains = loaded.mirrors;

    let mut tab = SerialTab {
        pools: HashMap::new(),
        cool: HashMap::new(),
        dead: HashMap::new(),
        mirrors: HashMap::new(),
        dirty: false,
    };
    for name in SERIAL_POOLS {
        let ps = plans_map.get(*name).cloned().unwrap_or_default();
        let mut plans = Vec::new();
        for p in ps {
            // 已下线 IP（route::RETIRED_IPS）实表里也不再保留——死 IP 打扰拖慢冷请求。
            if p.ip.parse::<std::net::IpAddr>().is_err()
                || p.sni == "ech"
                || route::is_retired(&p.ip)
            {
                continue;
            }
            // ech 恒失败清除旧遗留；Fastly 段强制按 IP 族归一，其余显式写法保留。
            let sni = if route::fastly_last_octet(&p.ip).is_some() {
                shape_for_ip(&p.ip).to_string()
            } else {
                match p.sni.trim() {
                    "" | "real" | "nosni" => shape_for_ip(&p.ip).to_string(),
                    dial::MODE_SNI => dial::MODE_SNI.to_string(),
                    s => {
                        // sni 会进 WebUI 与 ClientHello，只认域名形态字符（防注入）。
                        let bare = s.trim_start_matches(dial::MODE_FAKE_PFX);
                        if !bare.is_empty()
                            && bare
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                        {
                            bare.to_string()
                        } else {
                            shape_for_ip(&p.ip).to_string()
                        }
                    }
                }
            };
            plans.push(SerialPlan { ip: p.ip, sni });
        }
        if let Some(ips) = seed_db().get(*name) {
            let mut added = 0usize;
            for ip in ips {
                if ip.parse::<std::net::IpAddr>().is_err()
                    || route::is_retired(ip)
                    || plans.iter().any(|p| p.ip == *ip)
                    || plans.len() >= SERIAL_MAX_PLANS
                {
                    continue;
                }
                plans.push(SerialPlan {
                    ip: ip.clone(),
                    sni: shape_for_ip(&ip).to_string(),
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
            continue;
        }
        let vc: Vec<String> = chain
            .into_iter()
            .filter(|m| MIRRORS.contains(&m.as_str()))
            .collect();
        if !vc.is_empty() {
            tab.mirrors.insert(host, vc);
        }
    }
    for (host, def) in DEFAULT_CHAINS {
        let e = tab
            .mirrors
            .entry(host.to_string())
            .or_insert_with(|| def.iter().map(|m| m.to_string()).collect());
        let mut added = 0usize;
        for m in MIRRORS {
            if !e.iter().any(|x| x == m) {
                e.push(m.to_string());
                added += 1;
            }
        }
        if added > 0 {
            if let Some(log) = log.as_ref() {
                log(&format!("[镜像] {host} 链补缺 {added} 条(新镜像上线)"));
            }
        }
    }
    *SERIAL.lock().unwrap_or_else(|p| p.into_inner()) = Some(tab);
    let snap = plans_snapshot();
    let chains = mirror_chains_snapshot();
    write_plans_file(&path, &snap, &chains);
}

/// 顺序变更 2s 内写回（事件驱动 + 去抖，须在 runtime 构建后调用）；无变更零唤醒。
static PERSIST_KICK: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn kick_persist() {
    PERSIST_KICK.notify_one();
}

pub fn start_persist(rt: &tokio::runtime::Runtime) {
    rt.spawn(async move {
        loop {
            PERSIST_KICK.notified().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let dirty = {
                let mut g = SERIAL.lock().unwrap();
                let dirty = g.as_ref().map(|t| t.dirty).unwrap_or(false);
                if dirty {
                    g.as_mut().unwrap().dirty = false;
                }
                dirty
            };
            if dirty {
                let snap = plans_snapshot();
                let chains = mirror_chains_snapshot();
                write_plans_file(&plans_path(), &snap, &chains);
            }
        }
    });
}

/// sni 形态 → dial 模式：裸域名 = 伪装（兼容旧表带 fake: 前缀）；MODE_SNI = 真名。
pub fn plan_mode(sni: &str) -> String {
    match sni {
        dial::MODE_SNI => dial::MODE_SNI.to_string(),
        _ => format!(
            "{}{}",
            dial::MODE_FAKE_PFX,
            sni.trim_start_matches(dial::MODE_FAKE_PFX)
        ),
    }
}

/// 命中条目整体移位：置顶/垫底；顺序没变 no-op，表头真变才打日志。
fn serial_move(pool_name: &str, match_fn: impl Fn(&SerialPlan) -> bool, to_front: bool, why: &str) {
    let mut g = SERIAL.lock().unwrap();
    let tab = g.as_mut().unwrap();
    let Some(pool_plans) = tab.pools.get_mut(pool_name) else {
        return;
    };
    let mut hit = Vec::new();
    let mut rest = Vec::new();
    for p in &*pool_plans {
        if match_fn(p) {
            hit.push(p.clone());
        } else {
            rest.push(p.clone());
        }
    }
    if hit.is_empty() {
        return;
    }
    let new_plans = if to_front {
        let mut v = hit;
        v.extend(rest);
        v
    } else {
        let mut v = rest;
        v.extend(hit);
        v
    };
    if new_plans == *pool_plans {
        return; // 顺序没变：不写盘不打日志
    }
    let old_head = pool_plans.first().map(|p| p.ip.clone());
    let new_head = new_plans.first().map(|p| p.ip.clone());
    *pool_plans = new_plans;
    tab.dirty = true;
    drop(g); // 先放锁再踢醒: 被唤醒的落盘任务要抢同一把锁
    kick_persist();
    if old_head != new_head {
        if let Some(log) = SERIAL_LOG.lock().unwrap().as_ref() {
            log(&format!(
                "[串发] {pool_name} 表头 {} -> {} ({why})",
                old_head.as_deref().unwrap_or("(空)"),
                new_head.as_deref().unwrap_or("(空)")
            ));
        }
    }
}

/// 单串发：按表逐个试，失败垫底换下一个，绕表全灭 → 冷却 30s。
/// 置顶只由数据层 ok 认证；ctx 到期只掐当前那条；混合池只试对口条目。
pub async fn serial_dial(
    pool_name: &str,
    host: &str,
    ctx: CancellationToken,
    tls_handshake: bool,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    {
        let g = SERIAL.lock().unwrap();
        let tab = g.as_ref().unwrap();
        if let Some(cool) = tab.cool.get(host) {
            if Instant::now() < *cool {
                let remain = cool.duration_since(Instant::now()).as_secs();
                return Err(format!("串发冷却中(全灭后约 {remain}s), 快速失败"));
            }
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
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get(pool_name).unwrap().clone()
    };

    // 族筛选：只试对口条目（不试不垫底防池序乒乓）；兜底语义与 family_for 一致（单测钉住）。
    let family = route::serial_family(pool_name, host);
    let serves = family.map(|f| f.serves);
    let family_name = route::family_for(pool_name, host);

    let mut last_err: Option<String> = None;
    let mut tried = 0usize;
    let mut eligible = 0usize; // 对口候选总数（含死亡冷却跳过的）
    for p in &snapshot {
        if let Some(s) = serves {
            if !s(host, p) {
                continue;
            }
        }
        eligible += 1;
        {
            let g = SERIAL.lock().unwrap();
            if let Some((until, _)) = g.as_ref().and_then(|t| t.dead.get(&p.ip)) {
                if Instant::now() < *until {
                    continue;
                }
            }
        }
        tried += 1;
        let mode = plan_mode(
            p.sni
                .trim()
                .is_empty()
                .then_some("baidu.com")
                .unwrap_or(p.sni.trim()),
        );
        let attempt = dial::dial_one(host, &p.ip, &mode, tls_handshake);
        let result = tokio::select! {
            _ = ctx.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "请求预算到期")),
            r = attempt => r,
        };
        match result {
            Ok(conn) => return Ok((conn, p.ip.clone(), p.sni.clone())),
            Err(e) => {
                last_err = Some(e.to_string());
                if ctx.is_cancelled() {
                    break; // 请求预算到期：这条没试完，不算失败；没试完 ≠ 全灭，不冷却
                }
                // 失败分层沉底：TCP 层失败 = IP 对谁都达不通，与域无关，内容域也必须沉底
                // （实测 108/109/111.133 TCP 全超时，豁免导致每轮先撞 9s 死 IP）。
                // TLS 层失败（raw 真名被 RST）是按域干扰，保留内容域豁免——沉底会连坐健康的 .133。
                let msg = e.to_string();
                let tcp_level = msg.starts_with("TCP")
                    || matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    );
                if !route::is_content_host(host) || tcp_level {
                    let target = p.clone();
                    let why = if tcp_level { "IP 不可达" } else { "拨号失败" };
                    serial_move(pool_name, |q| *q == target, false, why);
                }
                if tcp_level {
                    // 指数退避 60s → 5min → 30min 封顶；死 IP 不值得每分钟打扰。
                    if let Ok(mut g) = SERIAL.lock() {
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
    if tried == 0 {
        if eligible > 0 {
            return Err(format!(
                "全部 {eligible} 个对口候选处于死亡冷却({pool_name}, {host})"
            ));
        }
        return Err(format!("无对口 SNI 形态的候选({pool_name}, {host})"));
    }
    // 绕表全灭：按 host 冷却 30s，只有确有镜像兜底的 host 豁免
    // （camo 无链，豁免会让每张徽章重烧整表；池级冷却曾毒倒同池其他族）。
    let has_mirror = !mirror_chain(host).is_empty();
    if !has_mirror {
        let mut g = SERIAL.lock().unwrap();
        g.as_mut().unwrap().cool.insert(
            host.to_string(),
            Instant::now() + Duration::from_secs(30),
        );
    }
    if let Some(log) = log {
        let tail = if has_mirror {
            "不冷却(有镜像兜底)".to_string()
        } else {
            "无镜像兜底, 冷却 30s 快速失败".to_string()
        };
        log(&format!(
            "[串发] {host} {pool_name}/{family_name} 全灭({tried}/{eligible} 候选, 累计 {:?}), {tail}",
            last_err.as_deref().unwrap_or("未知")
        ));
    }
    Err(last_err.unwrap_or_else(|| "串发全灭".to_string()))
}

pub fn serial_note(pool_name: &str, ip: &str, kind: &str) {
    if kind == "ok" {
        if let Ok(mut g) = SERIAL.lock() {
            if let Some(t) = g.as_mut() {
                t.dead.remove(ip);
            }
        }
    }
    serial_move(pool_name, |p| p.ip == ip, kind == "ok", kind);
}

pub fn mirror_chain(host: &str) -> Vec<String> {
    let g = SERIAL.lock().unwrap();
    g.as_ref()
        .unwrap()
        .mirrors
        .get(host)
        .cloned()
        .unwrap_or_default()
}

pub fn set_mirror_chain(host: &str, chain: &[String], why: &str) -> bool {
    if !CONTENT_HOSTS.contains(&host) {
        return false;
    }
    let vc: Vec<String> = chain
        .iter()
        .filter(|m| MIRRORS.contains(&m.as_str()))
        .cloned()
        .collect();
    if vc.is_empty() {
        return false;
    }
    let mut g = SERIAL.lock().unwrap();
    let tab = g.as_mut().unwrap();
    if tab.mirrors.get(host).map(|c| c == &vc).unwrap_or(false) {
        return false;
    }
    tab.mirrors.insert(host.to_string(), vc);
    tab.dirty = true;
    drop(g); // 先放锁再踢醒: 被唤醒的落盘任务要抢同一把锁
    kick_persist();
    if let Some(log) = SERIAL_LOG.lock().unwrap().as_ref() {
        log(&format!("[镜像] {host} 链序更新({why})"));
    }
    true
}

pub fn mirror_chains_snapshot() -> HashMap<String, Vec<String>> {
    let g = SERIAL.lock().unwrap();
    g.as_ref().unwrap().mirrors.clone()
}


/// 全灭熔断：set 后 ttl 内 open=true 快速失败，clear 解除；必须按 host 记账——
/// 全局单值会让"别的域成功"反复清掉 raw 的熔断（内容域直连）/同类 host 快速失败。
struct Breaker {
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
            .unwrap()
    }
    fn open(&self, host: &str) -> bool {
        self.lock()
            .get(host)
            .map(|until| Instant::now() < *until)
            .unwrap_or(false)
    }
    fn set(&self, host: &str) {
        self.lock()
            .insert(host.to_string(), Instant::now() + Duration::from_secs(self.ttl_secs));
    }
    fn clear(&self, host: &str) {
        self.lock().remove(host);
    }
}

/// 内容域直连熔断：被按域黑洞时每请求烧满预算，失败一次熔断 120s 走镜像，成功清除。
static CONTENT_BREAKER: Breaker = Breaker::new(120);
/// 镜像链全灭熔断：全灭一次 60s 内同 host 快速失败（多图仓库否则每张图烧完整条链）。
static MIRROR_BREAKER: Breaker = Breaker::new(60);

pub fn content_direct_open(host: &str) -> bool {
    CONTENT_BREAKER.open(host)
}

pub fn content_direct_ok(host: &str) {
    CONTENT_BREAKER.clear(host);
}

pub fn content_direct_fail(host: &str) {
    CONTENT_BREAKER.set(host);
}

pub fn mirror_breaker_open(host: &str) -> bool {
    MIRROR_BREAKER.open(host)
}

pub fn mirror_breaker_set(host: &str) {
    MIRROR_BREAKER.set(host);
}

pub fn mirror_breaker_clear(host: &str) {
    MIRROR_BREAKER.clear(host);
}

pub use crate::config::pool_for;

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
        serial_load(dir, None);
    }

    #[test]
    fn plan_mode_semantics() {
        assert_eq!(plan_mode(""), "fake:", "空串须由调用方兜底");
        assert_eq!(
            plan_mode("baidu.com"),
            format!("{}baidu.com", dial::MODE_FAKE_PFX)
        );
        assert_eq!(
            plan_mode("fake:baidu.com"),
            plan_mode("baidu.com"),
            "旧表带前缀写法行为一致"
        );
        assert_eq!(plan_mode(dial::MODE_SNI), dial::MODE_SNI);
    }

    #[test]
    fn edge_shape_by_ip_family() {
        assert_eq!(shape_for_ip("185.199.108.133"), dial::MODE_SNI);
        assert_eq!(shape_for_ip("185.199.111.133"), dial::MODE_SNI);
        for ip in ["185.199.108.154", "185.199.111.153"] {
            assert_eq!(shape_for_ip(ip), "baidu.com", "{ip} 应取伪装");
        }
        for ip in ["140.82.112.29", "20.205.243.167"] {
            assert_eq!(shape_for_ip(ip), "baidu.com", "{ip} 应取伪装");
        }
        assert_eq!(shape_for_ip("185.199.108.215"), "baidu.com");
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
        assert!(!serial_pool("fastly"));
        assert!(!serial_pool("codeload"));
        for p in ["core", "api", "edge"] {
            assert!(serial_pool(p), "{p} 应为串发池");
        }
        assert!(!serial_pool("uploads"));
    }

    #[test]
    fn migrate_drops_stats_and_normalizes_shapes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        std::fs::write(
            &dir.join("plans.json"),
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
        assert_eq!(
            ps[0],
            SerialPlan {
                ip: "5.6.7.8".into(),
                sni: "baidu.com".into()
            },
            "用户条目保留在前且归一"
        );
        let core_seed_n = seed_db().get("core").map(|v| v.len()).unwrap_or(0);
        assert_eq!(
            ps.len(),
            1 + core_seed_n,
            "补缺后 = 用户条目 + 全部种子: {ps:?}"
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
                sni: "baidu.com".into()
            }),
            "ghapp 伪装条目保留: {edge_ps:?}"
        );
        assert!(
            edge_ps.contains(&SerialPlan {
                ip: "185.199.108.154".into(),
                sni: "baidu.com".into()
            }) && edge_ps.contains(&SerialPlan {
                ip: "185.199.109.153".into(),
                sni: "baidu.com".into()
            }),
            "Fastly .153/.154 旧表真名强制归一为伪装: {edge_ps:?}"
        );
        assert!(
            edge_ps
                .iter()
                .any(|p| route::fastly_last_octet(&p.ip) == Some("133") && p.sni == dial::MODE_SNI),
            "种子补缺应追加 .133 真名内容域条目: {edge_ps:?}"
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
            &dir.join("plans.json"),
            r#"{ "edge": [{"ip": "140.82.112.29", "sni": "baidu.com"}] }"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        let ps = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("edge").unwrap().clone()
        };
        assert_eq!(
            ps[0].ip, "140.82.112.29",
            "用户手排顺序保留, 补缺只追加尾部"
        );
        let seeds = seed_db();
        let seed = seeds.get("edge").unwrap();
        assert_eq!(ps.len(), seed.len(), "补缺后应覆盖全部种子: {ps:?}");
        assert!(
            seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
            "补缺应打一行日志"
        );
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(b.contains("185.199.110.133"), "补缺应落盘: {b}");
        assert!(
            !b.contains("185.199.108.133")
                && !b.contains("185.199.109.133")
                && !b.contains("185.199.111.133"),
            "退役死 IP 不应补缺落盘: {b}"
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
                    sni: dial::MODE_SNI.into(),
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
        assert!(b.contains("\"mirrors\""), "镜像链板块应落盘: {b}");
        assert!(b.contains("raw.githubusercontent.com"));
        let back_file: PlansFile = serde_json::from_str(&b).unwrap();
        assert_eq!(
            back_file
                .mirrors
                .get("raw.githubusercontent.com")
                .map(|c| c.len()),
            Some(2),
            "镜像链应可读回: {:?}",
            back_file.mirrors
        );
        let back: HashMap<String, Vec<SerialPlan>> = back_file.pools;
        assert_eq!(back["core"].len(), 2);
        assert_eq!(back["core"][0].sni, "baidu.com");
        assert_eq!(back["edge"].len(), 2);
        assert_eq!(back["edge"][0].sni, dial::MODE_SNI);
        assert!(!b.contains("fastly") && !b.contains("codeload"));
    }

    #[test]
    fn notify_persist_writes_on_change_and_skips_noop() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        serial_load(&dir, None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        start_persist(&rt);
        let head_before = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[0].ip.clone()
        };
        let target = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[2].ip.clone()
        };
        assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
        serial_note("core", &target, "ok");
        rt.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
        assert_eq!(
            SERIAL.lock().unwrap().as_ref().unwrap().pools.get("core").unwrap()[0].ip,
            target,
            "置顶应已生效"
        );
        let file1 = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(file1.contains(&target), "变更应落盘");
        let snap_before = plans_snapshot();
        serial_note("core", &target, "ok");
        rt.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
        assert_eq!(plans_snapshot(), snap_before, "no-op 不应触发写盘");
    }

    #[test]
    fn mirror_chain_load_and_topup() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        std::fs::write(
            &dir.join("plans.json"),
            r#"{
  "core": [{"ip": "140.82.112.3", "sni": "baidu.com"}],
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org", "https://evil.example.com"],
    "not-a-content.host": ["https://v4.gh-proxy.org"]
  }
}"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        let raw_chain = mirror_chain("raw.githubusercontent.com");
        assert_eq!(raw_chain[0], "https://v4.gh-proxy.org", "用户手改链头保留");
        assert!(
            !raw_chain.iter().any(|m| m.contains("evil")),
            "池外镜像应被丢弃: {raw_chain:?}"
        );
        assert_eq!(raw_chain.len(), MIRRORS.len(), "补缺后应覆盖全池");
        let media_chain = mirror_chain("media.githubusercontent.com");
        let def: Vec<String> = DEFAULT_CHAINS
            .iter()
            .find(|(h, _)| *h == "media.githubusercontent.com")
            .unwrap()
            .1
            .iter()
            .map(|m| m.to_string())
            .collect();
        for (i, m) in def.iter().enumerate() {
            assert_eq!(media_chain[i], *m, "默认链头应原序保留");
        }
        assert_eq!(media_chain.len(), MIRRORS.len(), "补缺后应覆盖全池");
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(!b.contains("not-a-content.host"), "未知 host 应丢弃: {b}");
        assert!(b.contains("\"mirrors\""), "镜像链应落盘");
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
    fn noop_move_no_write_and_head_rotation_logs() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        let base_len = seen.lock().unwrap().len(); // 初始表日志条数
        let base = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        let head = base[0].ip.clone();
        serial_note("core", &head, "ok");
        {
            let g = SERIAL.lock().unwrap();
            assert!(!g.as_ref().unwrap().dirty, "顺序没变不该置 dirty");
        }
        assert_eq!(seen.lock().unwrap().len(), base_len, "顺序没变不该打日志");
        let other = base[4].ip.clone();
        serial_note("core", &other, "ok");
        {
            let g = SERIAL.lock().unwrap();
            assert!(g.as_ref().unwrap().dirty, "表头轮换该置 dirty");
            let ps = g.as_ref().unwrap().pools.get("core").unwrap();
            assert_eq!(ps[0].ip, other, "新表头应是置顶 IP");
        }
        let lines = seen.lock().unwrap();
        assert!(
            lines[base_len..].iter().any(|l| l.contains("表头")
                && l.contains(&head)
                && l.contains(&other)
                && l.contains("ok")),
            "应打一行带原因的表头轮换日志: {:?}",
            &lines[base_len..]
        );
    }

    #[test]
    fn serial_moves() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        reset_state(&dir);
        let base = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        assert!(base.len() >= 6, "初始表过小: {}", base.len());
        let key = base[3].clone();
        serial_move("core", |p| *p == key, false, "test");
        let last = {
            let g = SERIAL.lock().unwrap();
            g.as_ref()
                .unwrap()
                .pools
                .get("core")
                .unwrap()
                .last()
                .unwrap()
                .clone()
        };
        assert_eq!(last, key, "失败条目应在表尾");
        let ip0 = base[0].ip.clone();
        serial_move("core", |p| p.ip == ip0, true, "ok");
        let head = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[0].clone()
        };
        assert_eq!(head.ip, ip0);
    }
}
