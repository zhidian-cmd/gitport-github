//! 串发拨号：二部图（`ips` 节点 × `hosts` 行）唯一权威。成功驻留游标、失败前移；SNI 骗墙、证书按锚点校验。
pub mod dial;
pub mod edges;
pub mod latency;
pub mod route;

use crate::util::{lock, LogFn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 路由表文件名：`ips` 节点 + `hosts` 行 + 镜像链，手改入口。
const ROUTES_FILE: &str = "routes.json";
/// 0.5.3 及以前的文件名，首启一次性迁走（迁完原表留 .bak）。
const LEGACY_ROUTES_FILE: &str = "plans.json";

/// 游标键：每条路由两把（主键 / `_vice` 副键），双通道各记各的。
pub fn circle_keys() -> Vec<String> {
    route::cursor_keys()
}

/// 串发全灭冷却是否生效中（30s 快速失败窗）。调用方应直接走兜底，不再空转重试。
pub fn dial_cool_open(host: &str) -> bool {
    SERIAL_COOL.open(host)
}

const SEEDS_JSON: &str = include_str!("seeds.json");

pub const CONTENT_HOSTS: &[&str] = &[
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "avatars.githubusercontent.com",
    "user-images.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "media.githubusercontent.com",
];

/// 种子只剩两个用途：全新安装引导、给已有表补节点/边（不新建 hosts 行）。
fn seed_db() -> TopoDoc {
    let Some((doc, _)) = parse_routes_tolerant(SEEDS_JSON, None) else {
        return TopoDoc::default();
    };
    doc
}

const SERIAL_MAX_IPS: usize = 512;

struct SerialTab {
    /// TCP 层死亡退避 60s→5min→30min，成功拨号清除。
    dead: HashMap<String, (Instant, u32)>,
    mirrors: HashMap<String, Vec<String>>,
    /// 每路由（`key` / `key_vice`）一个游标记号；表序冻结，不随游标重排。
    cursor: HashMap<String, String>,
}

static SERIAL_COOL: Breaker = Breaker::new(30);

/// 测试专用：路由表/串发表都是进程级全局态，跨模块的用例靠它串行。
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

/// 路由表文档：v2 给 ips+hosts，旧 routes 字典与旧三池在迁移期兼容；latency = 测速键值。
#[derive(Default)]
struct TopoDoc {
    hosts: Vec<route::HostSpec>,
    ips: Vec<route::IpSpec>,
    chains: HashMap<String, Vec<String>>,
    latency: HashMap<String, u64>,
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
fn parse_routes_tolerant(raw: &str, log: Option<&LogFn>) -> Option<(TopoDoc, bool)> {
    let root: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = root.as_object()?;
    let mut doc = TopoDoc::default();
    let mut big = HashMap::new();
    let mut small = HashMap::new();
    let mut legacy = HashMap::new();
    let mut salvaged = false;

    // v2 格式：ips + hosts。
    if let Some(ips) = obj.get("ips") {
        match serde_json::from_value::<Vec<route::IpSpec>>(ips.clone()) {
            Ok(v) => doc.ips = v,
            Err(e) => {
                salvaged = true;
                if let Some(l) = log {
                    l(&format!("[串发] routes.json ips 段写坏({e}), 该段丢弃"));
                }
            }
        }
    }
    if let Some(serde_json::Value::Object(map)) = obj.get("hosts") {
        for (key, body) in map {
            let mut v = body.clone();
            match v.as_object_mut() {
                Some(o) => {
                    o.insert(
                        "key".to_string(),
                        serde_json::Value::String(key.to_string()),
                    );
                }
                None => {
                    salvaged = true;
                    if let Some(l) = log {
                        l(&format!("[串发] routes.json hosts[{key}] 写坏, 该行丢弃"));
                    }
                    continue;
                }
            }
            match serde_json::from_value::<route::HostSpec>(v) {
                Ok(s) => doc.hosts.push(s),
                Err(e) => {
                    salvaged = true;
                    if let Some(l) = log {
                        l(&format!(
                            "[串发] routes.json hosts[{key}] 写坏({e}), 该行丢弃"
                        ));
                    }
                }
            }
        }
    }

    // 兼容层：v1 的 routes 字典（含 plans）与 0.5.3 的正则数组折算成 v2；旧三池同理。
    let has_v2 = doc.ips.len() + doc.hosts.len() > 0;
    if !has_v2 {
        if let Some(routes) = obj.get("routes") {
            match routes {
                serde_json::Value::Object(map) => {
                    for (key, body) in map {
                        match v1_route_spec(key, body) {
                            Ok(Some(spec)) => {
                                doc.hosts.push(spec.0);
                                doc.ips.extend(spec.1);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                salvaged = true;
                                if let Some(l) = log {
                                    l(&format!(
                                        "[串发] routes.json routes[{key}] 写坏({e}), 该行丢弃"
                                    ));
                                }
                            }
                        }
                    }
                }
                // 0.5.3 及以前：数组 + `match` 正则，读进来一次性转成域名键。
                serde_json::Value::Array(list) => {
                    for (i, v) in list.iter().enumerate() {
                        match legacy_spec_from_row(v) {
                            Ok(Some(spec)) => {
                                doc.hosts.push(spec.0);
                                doc.ips.extend(spec.1);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                salvaged = true;
                                if let Some(l) = log {
                                    l(&format!(
                                        "[串发] routes.json routes[{i}] 写坏({e}), 该行丢弃"
                                    ));
                                }
                            }
                        }
                    }
                }
                _ => {
                    if let Some(l) = log {
                        l("[串发] routes.json routes 既不是对象也不是数组, 本次按种子重建");
                    }
                    return None;
                }
            }
        } else {
            // 最老的旧三池。
            let mut pools: HashMap<String, Vec<V1Plan>> = HashMap::new();
            for (k, v) in obj {
                if k.starts_with("mirrors") {
                    continue;
                }
                if let Ok(p) = serde_json::from_value::<Vec<V1Plan>>(v.clone()) {
                    pools.insert(k.clone(), p);
                }
            }
            if !pools.is_empty() {
                let (hs, is) = legacy_pools_to_v2(&pools);
                doc.hosts = hs;
                doc.ips = is;
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
                    "[串发] routes.json {k} 段不是对象, 该段丢弃(镜像链按注册表重建)"
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
                        l(&format!(
                            "[串发] routes.json 镜像链 {host} 写坏({e}), 该链丢弃"
                        ));
                    }
                }
            }
        }
    }
    doc.chains = merged_chains(&big, &small, &legacy);
    // 测速键：顶层旧布局（{ip: ms}）先读，节点条目内的同键覆盖（新布局）。
    if let Some(v) = obj.get("latency") {
        if let Ok(m) = serde_json::from_value::<HashMap<String, u64>>(v.clone()) {
            doc.latency = m;
        }
    }
    for spec in &doc.ips {
        for (ip, ms) in &spec.latency {
            doc.latency.insert(ip.clone(), *ms);
        }
    }
    Some((doc, salvaged))
}

/// v1 plan 形态（仅迁移解析用）。
#[derive(Clone, Debug, Deserialize)]
struct V1Plan {
    ip: String,
    #[serde(default)]
    sni: String,
}

/// 旧格式一条（0.5.3 及以前）：`match` 是整串正则，转成等价的域名键再折算。
fn legacy_spec_from_row(
    v: &serde_json::Value,
) -> Result<Option<(route::HostSpec, Vec<route::IpSpec>)>, String> {
    let mut v = v.clone();
    let Some(obj) = v.as_object_mut() else {
        return Err("值不是对象".to_string());
    };
    let pat = obj
        .remove("match")
        .and_then(|m| m.as_str().map(str::to_string))
        .ok_or_else(|| "缺 match".to_string())?;
    let key = legacy_match_to_key(&pat);
    obj.insert("key".to_string(), serde_json::Value::String(key.clone()));
    v1_route_spec(&key, &v)
}

/// 把老表的正则收敛成域名键。只认当年真用过的三种形态，其余按字面去转义：
/// - `(.*\.)?x` → `x`     自己和所有子域
/// - `.*\.x`    → `*.x`   仅子域
/// - `x`        → `x`     精确
fn legacy_match_to_key(pat: &str) -> String {
    let p = pat.trim();
    if let Some(rest) = p.strip_prefix("(.*\\.)?") {
        return rest.replace("\\.", ".");
    }
    if let Some(rest) = p.strip_prefix(".*\\.") {
        return format!("*.{}", rest.replace("\\.", "."));
    }
    p.replace("\\.", ".")
}

/// 旧 routes 字典一条 → (hosts 行, 折算出的单 IP 节点)。direct/real/donor 标志按 v2 语义处置：
/// direct 行保留直连（用户显式配置不进代理）；real/donor 标志丢弃（v2 无此概念）。
fn v1_route_spec(
    key: &str,
    body: &serde_json::Value,
) -> Result<Option<(route::HostSpec, Vec<route::IpSpec>)>, String> {
    let mut v = body.clone();
    let Some(obj) = v.as_object_mut() else {
        return Err("值不是对象".to_string());
    };
    obj.insert(
        "key".to_string(),
        serde_json::Value::String(key.to_string()),
    );
    let spec: V1RouteBody = serde_json::from_value(v).map_err(|e| e.to_string())?;
    let direct = spec.action.as_deref() == Some("direct");
    let host = route::HostSpec {
        key: key.to_string(),
        // v2 实测后 direct 4 域进池；迁移时旧 direct 标志一并解除，IP 边由种子补。
        action: None,
        content: spec.content,
        // v1 格式没有会话概念：迁移时按主站族补上风控面标记。
        session: matches!(key, "github.com" | "api.github.com"),
        fallback: spec.fallback.clone(),
        ..Default::default()
    };
    let mut ips = Vec::new();
    for p in spec.plans.iter().chain(spec.real_plans.iter()) {
        ips.push(route::IpSpec {
            ip: p.ip.clone(),
            sni: if p.sni.is_empty() {
                key.to_string()
            } else {
                p.sni.clone()
            },
            verify: verify_for(&p.ip),
            hosts: vec![key.to_string()],
            latency: HashMap::new(),
        });
    }
    let _ = direct;
    Ok(Some((host, ips)))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct V1RouteBody {
    action: Option<String>,
    real: bool,
    content: bool,
    donor: bool,
    fallback: Option<String>,
    plans: Vec<V1Plan>,
    #[serde(rename = "realPlans")]
    real_plans: Vec<V1Plan>,
}

/// Fastly 四段的末段；迁移时用来把旧 edge 池拆回各族。
fn fastly_seg(ip: &str) -> Option<&str> {
    let mut o = ip.split('.');
    match (o.next(), o.next(), o.next(), o.next()) {
        (Some("185"), Some("199"), Some("108" | "109" | "110" | "111"), Some(last)) => Some(last),
        _ => None,
    }
}

/// 旧三池 → v2：完整行集（v1 legacy_routes 同款）+ IP 摊成节点；direct 4 域按实测进池。
fn legacy_pools_to_v2(
    pools: &HashMap<String, Vec<V1Plan>>,
) -> (Vec<route::HostSpec>, Vec<route::IpSpec>) {
    let empty: Vec<V1Plan> = Vec::new();
    let core = pools.get("core").unwrap_or(&empty);
    let api = pools.get("api").unwrap_or(&empty);
    let edge = pools.get("edge").unwrap_or(&empty);
    let seg = |want: &str| -> Vec<&V1Plan> {
        edge.iter()
            .filter(|p| fastly_seg(&p.ip) == Some(want))
            .collect()
    };
    let mut ips: Vec<route::IpSpec> = Vec::new();
    let mut push_all = |list: Vec<&V1Plan>, hosts: &[&str]| {
        for p in list {
            ips.push(route::IpSpec {
                ip: p.ip.clone(),
                sni: if p.sni.is_empty() {
                    "baidu.com".to_string()
                } else {
                    p.sni.clone()
                },
                verify: verify_for(&p.ip),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                latency: HashMap::new(),
            });
        }
    };
    let i133 = seg("133");
    let i153 = seg("153");
    let i154 = seg("154");
    let i215 = seg("215");
    push_all(core.iter().collect(), &["github.com"]);
    push_all(api.iter().collect(), &["api.github.com"]);
    push_all(
        i133,
        &[
            "*.githubusercontent.com",
            "raw.github.com",
            "support.github.com",
            "resources.github.com",
        ],
    );
    push_all(
        i153,
        &[
            "github.io",
            "desktop.github.com",
            "pages.github.com",
            "skills.github.com",
            "archiveprogram.github.com",
            "socialimpact.github.com",
        ],
    );
    push_all(i154, &["githubassets.com", "docs.github.com"]);
    push_all(i215, &["githubassets.com"]);
    let azure: Vec<&V1Plan> = edge.iter().filter(|p| p.ip.starts_with("4.249.")).collect();
    push_all(azure, &["copilot-proxy.githubusercontent.com"]);
    let other: Vec<&V1Plan> = edge
        .iter()
        .filter(|p| fastly_seg(&p.ip).is_none() && !p.ip.starts_with("4.249."))
        .collect();
    push_all(other, &["githubapp.com"]);

    let mut hosts = vec![
        route::HostSpec {
            key: "github.com".into(),
            action: None,
            content: false,
            session: true,
            fallback: None,
            ..Default::default()
        },
        route::HostSpec {
            key: "api.github.com".into(),
            action: None,
            content: false,
            session: true,
            fallback: None,
            ..Default::default()
        },
        route::HostSpec {
            key: "*.githubusercontent.com".into(),
            action: None,
            content: true,
            session: false,
            fallback: Some("mirror".into()),
            ..Default::default()
        },
        route::HostSpec {
            key: "githubassets.com".into(),
            action: None,
            content: false,
            session: false,
            fallback: None,
            ..Default::default()
        },
        route::HostSpec {
            key: "github.io".into(),
            action: None,
            content: false,
            session: false,
            fallback: None,
            ..Default::default()
        },
        route::HostSpec {
            key: "githubapp.com".into(),
            action: None,
            content: false,
            session: false,
            fallback: None,
            ..Default::default()
        },
    ];
    for h in LEGACY_HOST_ROWS {
        hosts.push(route::HostSpec {
            key: (*h).to_string(),
            action: None,
            content: false,
            session: false,
            fallback: None,
            ..Default::default()
        });
    }
    (hosts, ips)
}

/// v1 白名单行（real 标志丢弃）。
const LEGACY_HOST_ROWS: &[&str] = &[
    "docs.github.com",
    "support.github.com",
    "resources.github.com",
    "desktop.github.com",
    "pages.github.com",
    "skills.github.com",
    "archiveprogram.github.com",
    "socialimpact.github.com",
    "raw.github.com",
    "copilot-proxy.githubusercontent.com",
];

/// 迁移期锚点推断：Fastly 段与 Azure 段按实测证书形态给 verify；未知段留空 = 按目标 host 校验。
fn verify_for(ip: &str) -> String {
    let segs: Vec<&str> = ip.split('.').collect();
    if segs.len() != 4 {
        return String::new();
    }
    match (segs[0], segs[1], segs[3]) {
        ("185", "199", "153" | "133") => "github.com".to_string(),
        ("185", "199", "154" | "215") => "githubassets.com".to_string(),
        ("4", "249", _) => "actions.githubusercontent.com".to_string(),
        _ => String::new(),
    }
}

/// 落盘：ips 在前、hosts 只写特殊行，镜像链按 CONTENT_HOSTS 序。
fn encode_routes(mirrors: &HashMap<String, Vec<String>>) -> String {
    let mut parts: Vec<String> = Vec::new();

    // 测速值跟着节点走：只写该节点展开出的 IP，range 节点各 IP 各记各的。
    let lat = latency::snapshot_all();
    let snapshot = route::nodes_snapshot();
    let nodes: Vec<String> = snapshot
        .iter()
        .map(|n| {
            let hosts: Vec<String> = n.hosts.iter().map(json_of).collect();
            let mut fields: Vec<String> = vec![
                format!("\"ip\": {}", json_of(&n.raw)),
                format!("\"sni\": {}", json_of(&n.sni)),
                format!("\"verify\": {}", json_of(&n.verify)),
                format!("\"hosts\": [{}]", hosts.join(", ")),
            ];
            let lat_rows: Vec<String> = n
                .ips
                .iter()
                .filter_map(|ip| lat.get(ip).map(|ms| format!("{}: {}", json_of(ip), ms)))
                .collect();
            if !lat_rows.is_empty() {
                fields.push(format!("\"latency\": {{{}}}", lat_rows.join(", ")));
            }
            format!("    {{\n      {}\n    }}", fields.join(",\n      "))
        })
        .collect();
    parts.push(format!("  \"ips\": [\n{}\n  ]", nodes.join(",\n")));

    // hosts：有节点服务且全默认的键不落盘（域名由节点一行声明），只留特殊属性/无节点的。
    let served: std::collections::HashSet<&str> = snapshot
        .iter()
        .flat_map(|n| n.hosts.iter().map(|s| s.as_str()))
        .collect();
    let rows: Vec<String> = route::hosts_snapshot()
        .iter()
        .filter(|r| {
            let plain = !r.flags.direct && !r.flags.content && r.fallback == route::Fallback::Dns;
            !(plain && served.contains(r.key.as_str()))
        })
        .map(|r| {
            let mut fields: Vec<String> = Vec::new();
            if r.flags.direct {
                fields.push("\"action\": \"direct\"".to_string());
            }
            if r.flags.content {
                fields.push("\"content\": true".to_string());
            }
            if r.flags.session {
                fields.push("\"session\": true".to_string());
            }
            if r.flags.big {
                fields.push("\"big\": true".to_string());
            }
            if r.fallback == route::Fallback::MirrorDns {
                fields.push("\"fallback\": \"mirror\"".to_string());
            }
            if fields.is_empty() {
                format!("    {}: {{}}", json_of(&r.key))
            } else {
                format!("    {}: {{{}}}", json_of(&r.key), fields.join(", "))
            }
        })
        .collect();
    parts.push(format!("  \"hosts\": {{\n{}\n  }}", rows.join(",\n")));

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
        parts.push(format!(
            "  \"mirrors_big\": {{\n{}\n  }}",
            big_rows.join(",\n")
        ));
    }
    if !small_rows.is_empty() {
        parts.push(format!(
            "  \"mirrors_small\": {{\n{}\n  }}",
            small_rows.join(",\n")
        ));
    }
    format!("{{\n{}\n}}\n", parts.join(",\n"))
}

fn json_of<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("JSON 序列化不会失败")
}

fn write_routes_file(path: &Path, mirrors: &HashMap<String, Vec<String>>) {
    let data = encode_routes(mirrors);
    if let Err(e) = crate::fsx::write_atomic(path, data.as_bytes()) {
        // 写盘失败无声 = 镜像链/表变更重启即丢且查无痕迹，必须留一行。
        if let Some(l) = lock(&SERIAL_LOG).as_ref() {
            l(&format!("[串发] routes.json 写盘失败: {e}"));
        }
    }
}

fn routes_path() -> PathBuf {
    let dir = lock(&SERIAL_DIR)
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join(ROUTES_FILE)
}

/// 立即把内存表（含 latency 运行时回流键）落盘：退出时由 main 调用，
/// 让下次冷启动仍有一份拨号延迟基线（运行时回流是内存态，重启即清）。
pub fn save_routes_now() {
    write_routes_file(&routes_path(), &mirror_chains_snapshot());
}

/// 旧名 plans.json → routes.json：只搬一次，搬前留 .bak，rename 失败退化为复制。
fn migrate_legacy_name(path: &Path, log: Option<&LogFn>) {
    let Some(dir) = path.parent() else { return };
    let old = dir.join(LEGACY_ROUTES_FILE);
    if path.exists() {
        // 新表已在：旧名一律不读。否则用户手改旧文件会"看起来改了但没生效"。
        if old.exists() {
            if let Some(l) = log {
                l("[串发] routes.json 已存在, 旧 plans.json 忽略(可自行删除)");
            }
        }
        return;
    }
    if !old.exists() {
        return;
    }
    let bak = path.with_extension("json.bak");
    if std::fs::rename(&old, path).is_err() {
        // rename 失败（被占用/跨卷）：退化成复制，旧名留下让用户自己删。
        if std::fs::copy(&old, path).is_err() {
            if let Some(l) = log {
                l("[串发] plans.json 更名为 routes.json 失败, 本次按种子重建");
            }
            return;
        }
    }
    // 旧 .bak 更值钱就留着，只在新备份缺席时补一份。
    if !bak.exists() {
        let _ = std::fs::copy(path, &bak);
    }
    if let Some(l) = log {
        l("[串发] plans.json 已更名为 routes.json, 原表备份在 routes.json.bak");
    }
}

pub fn serial_load(data_dir: &Path, last_ip: Vec<(String, String)>, log: Option<LogFn>) {
    *lock(&SERIAL_DIR) = Some(data_dir.to_path_buf());
    *lock(&SERIAL_LOG) = log.clone();
    let path = routes_path();
    migrate_legacy_name(&path, log.as_ref());
    let raw = std::fs::read_to_string(&path).ok();
    let parsed = raw
        .as_deref()
        .and_then(|b| parse_routes_tolerant(b, log.as_ref()));
    // 有段落坏/整份读不了：先备份原文件再重建，用户手排表可从 .bak 捡回。
    let bak_why = match (&raw, &parsed) {
        (Some(_), None) => Some("解析失败, 本次按种子重建"),
        (Some(_), Some((_, true))) => Some("有段落坏已按种子重建"),
        _ => None,
    };
    if let Some(why) = bak_why {
        if std::fs::copy(&path, path.with_extension("json.bak")).is_ok() {
            if let Some(l) = log.as_ref() {
                l(&format!(
                    "[串发] routes.json {why}, 原文件已备份为 routes.json.bak"
                ));
            }
        }
    }

    let seeds = seed_db();
    let mut doc = parsed.map(|(d, _)| d).unwrap_or_else(|| TopoDoc {
        hosts: seeds.hosts.clone(),
        ips: seeds.ips.clone(),
        chains: seeds.chains.clone(),
        latency: HashMap::new(),
    });
    latency::install(std::mem::take(&mut doc.latency));
    topup_from_seeds(&mut doc, &seeds, log.as_ref());
    fill_hosts_from_nodes(&mut doc);

    let mut dropped = 0usize;
    let mut rows = Vec::with_capacity(doc.hosts.len());
    for spec in doc.hosts.into_iter() {
        let key = spec.key.clone();
        match route::RouteRow::new(spec) {
            Ok(row) => rows.push(row),
            Err(e) => {
                dropped += 1;
                if let Some(l) = log.as_ref() {
                    l(&format!("[串发] hosts[{key}] 丢弃: {e}"));
                }
            }
        }
    }
    let mut nodes = Vec::with_capacity(doc.ips.len());
    for spec in doc.ips.into_iter() {
        let ip = spec.ip.clone();
        match build_node(spec) {
            Ok(n) => nodes.push(n),
            Err(e) => {
                dropped += 1;
                if let Some(l) = log.as_ref() {
                    l(&format!("[串发] ips[{ip}] 丢弃: {e}"));
                }
            }
        }
    }
    // 只有真有行被丢弃才留底（用户手写的标记还能从 .bak 捡回）；健康表启动不留任何备份。
    if dropped > 0 && !path.with_extension("json.bak").exists() {
        let _ = std::fs::copy(&path, path.with_extension("json.bak"));
    }
    route::install(rows, nodes);

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
                    "[串发] routes.json 镜像链 {host} 不在支持列表, 已丢弃(其余链保留)"
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
    // 注册表对齐只动内存：启动不写盘（routes.json 是手改入口，写盘只发生在运行时改链）。
    sync_custom_mirrors(&[], false);
    // 只有文件不存在（全新安装）才生成一次；之后的启动一律不重写，手改原样生效。
    if raw.is_none() {
        write_routes_file(&path, &mirror_chains_snapshot());
    }
}

/// IpSpec → 运行时节点：末段范围展开 + 边界校验。
fn build_node(spec: route::IpSpec) -> Result<route::IpNode, String> {
    let ips = route::expand_ip(&spec.ip)?;
    if ips.is_empty() {
        return Err("ip 展开为空".to_string());
    }
    let mut hosts = spec.hosts;
    hosts.retain(|k| !k.trim().is_empty());
    hosts
        .iter_mut()
        .for_each(|k| *k = k.trim().trim_end_matches('.').to_ascii_lowercase());
    hosts.dedup();
    if hosts.is_empty() {
        return Err("hosts 为空(节点不服务任何路由键)".to_string());
    }
    Ok(route::IpNode {
        raw: spec.ip,
        ips,
        sni: spec.sni.trim().to_string(),
        verify: spec.verify.trim().to_string(),
        hosts,
    })
}

/// 测试专用：装一份种子路由表，供 certgen/settings 这类不经过 routes.json 的用例。
#[cfg(test)]
pub(crate) fn install_seed_routes() {
    let seeds = seed_db();
    let rows: Vec<route::RouteRow> = seeds
        .hosts
        .iter()
        .filter_map(|s| route::RouteRow::new(s.clone()).ok())
        .collect();
    let nodes: Vec<route::IpNode> = seeds
        .ips
        .iter()
        .filter_map(|s| build_node(s.clone()).ok())
        .collect();
    route::install(rows, nodes);
}

/// 种子只补已有表的节点/边，不新建 hosts 行：用户删掉的行不该被程序加回来。
/// 域名清单可由 ips 节点推出：节点 hosts 里出现、hosts 块没写的键，按默认配置补一行。
/// 落盘时这些行会被省略（见 encode_routes），文件里只剩有特殊属性的域名。
fn fill_hosts_from_nodes(doc: &mut TopoDoc) {
    for spec in &doc.ips {
        for h in &spec.hosts {
            let key = h.trim();
            if key.is_empty() || doc.hosts.iter().any(|x| x.key == key) {
                continue;
            }
            // 通配键继承父域的标志：`*.github.com` 从 `github.com` 拿 session 等，
            // 别让派生行把主站族的会话语义丢了（www.github.com 也带主站会话）。
            let inherited = key
                .strip_prefix("*.")
                .and_then(|bare| doc.hosts.iter().find(|x| x.key == bare));
            let (session, content, fallback) = match inherited {
                Some(p) => (p.session, p.content, p.fallback.clone()),
                None => Default::default(),
            };
            doc.hosts.push(route::HostSpec {
                key: key.to_string(),
                session,
                content,
                fallback,
                ..Default::default()
            });
        }
    }
}

fn topup_from_seeds(doc: &mut TopoDoc, seeds: &TopoDoc, log: Option<&LogFn>) {
    let mut added = 0usize;
    for seed_node in &seeds.ips {
        if doc.ips.len() >= SERIAL_MAX_IPS {
            break;
        }
        let seed_ips = match route::expand_ip(&seed_node.ip) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // 按"展开 IP 集合有交集"找现有节点；找不到且 hosts 行存在 → 新建节点。
        let hit = doc.ips.iter_mut().find(|n| {
            route::expand_ip(&n.ip)
                .map(|v| v.iter().any(|ip| seed_ips.contains(ip)))
                .unwrap_or(false)
        });
        match hit {
            Some(n) => {
                // 同节点：补缺 IP 与缺边。
                for k in &seed_node.hosts {
                    if !n.hosts.iter().any(|x| x == k) {
                        n.hosts.push(k.clone());
                        added += 1;
                    }
                }
            }
            None => {
                if seed_node
                    .hosts
                    .iter()
                    .any(|k| doc.hosts.iter().any(|h| &h.key == k))
                {
                    doc.ips.push(seed_node.clone());
                    added += 1;
                }
            }
        }
    }
    if added > 0 {
        if let Some(l) = log {
            l(&format!("[串发] 路由种子补缺 {added} 处(新边缘 IP 上线)"));
        }
    }
}

/// 数据层结果回写游标：成功驻留、失败前移，零写盘。
pub fn cursor_note(host: &str, ip: &str, ok: bool, slot: u8) {
    let Some(row) = route::route_for(host) else {
        return;
    };
    if row.flags.direct {
        return;
    }
    let key = cursor_key(&row.key, slot);
    let Some(circle) = route::dial_targets(host) else {
        return;
    };
    if circle.is_empty() {
        return;
    }
    let mut g = lock(&SERIAL);
    let Some(t) = g.as_mut() else { return };
    if ok {
        t.dead.remove(ip);
        t.cursor.insert(key, ip.to_string());
        edges::clear(ip, &row.key); // 成功只清短冷却(超时/421)；风控冷却不可清，只随时间过期
        return;
    }
    // 失败：前移到下一候选(整圈后自然复测)。
    if let Some(pos) = circle.iter().position(|p| p.ip == ip) {
        let next = &circle[(pos + 1) % circle.len()];
        t.cursor.insert(key, next.ip.clone());
    }
}

fn cursor_key(key: &str, slot: u8) -> String {
    if slot > 1 {
        format!("{key}_vice")
    } else {
        key.to_string()
    }
}

/// 尝试顺序：游标上的 IP（上次驻留）优先；其余按实测建连延迟升序，未测的垫底并保持表序。
/// 指定档位（prefer_shared）时独占/共享分档：优先档整档在前、另一档垫后，
/// 档内同样游标优先 + 延迟升序——主/副通道的"独占优先/共享优先"在这里落成顺序。
fn dial_order(
    circle: &[route::NodeIp],
    start_ip: Option<&str>,
    prefer_shared: Option<bool>,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..circle.len()).collect();
    order.sort_by_key(|&i| (latency::get(&circle[i].ip).unwrap_or(u64::MAX), i));
    // 游标置顶（在它所属的档内置顶）。
    let bump = |part: &mut Vec<usize>| {
        if let Some(ip) = start_ip {
            if let Some(pos) = circle.iter().position(|p| p.ip == ip) {
                if let Some(at) = part.iter().position(|&j| j == pos) {
                    part.remove(at);
                    part.insert(0, pos);
                }
            }
        }
    };
    match prefer_shared {
        Some(prefer) => {
            let (mut pref, mut rest): (Vec<usize>, Vec<usize>) = order
                .into_iter()
                .partition(|&i| circle[i].shared == prefer);
            bump(&mut pref);
            bump(&mut rest);
            pref.extend(rest);
            pref
        }
        None => {
            bump(&mut order);
            order
        }
    }
}

/// 冷启动双通道的互斥圈：同 IP 只认领一次，Arc 归零整组消亡。
pub struct DialCrew {
    claimed: Mutex<HashSet<String>>,
}
impl DialCrew {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            claimed: Mutex::new(HashSet::new()),
        })
    }
    pub fn claim(&self, ip: &str) -> bool {
        self.claimed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(ip.to_string())
    }
}

/// 串发请求描述：拨哪个 host、怎么拨。
pub struct DialSkip<'a> {
    pub host: &'a str,
    pub tls_handshake: bool,
    pub skip_ips: &'a [String],
    pub slot: u8,
    pub crew: Option<&'a DialCrew>,
    /// Some = 独占/共享分档排序（主副通道分家用）；None = 不分档，维持纯游标+延迟序。
    pub prefer_shared: Option<bool>,
}

/// 证书校验失败？错误串随 BoringSSL 版本变化（`CERTIFICATE_VERIFY_FAILED` / `certificate verify failed` /
/// `hostname mismatch`），统一按小写子串认。只认"校验不过"，不认「系统根证书缺失」那类（`unable to get
/// local issuer certificate`），后者跟锚点无关，别把人往错方向带。
fn cert_miss(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    [
        "certificate_verify",
        "certificate verify",
        "verify failed",
        "hostname mismatch",
    ]
    .iter()
    .any(|k| m.contains(*k))
}

/// 锚点选错的提示：同一 (IP, 锚点) 只打一次——坏锚点会在换 IP 时反复撞上，刷屏没有信息量。
/// 留空时拿目标域名当锚点（[`route::dial_targets`]），所以空锚点失败 = 默认证书没覆盖这个域名。
fn log_cert_miss(ip: &str, sni: &str, verify: &str, host: &str, log: Option<&LogFn>) {
    let Some(log) = log else { return };
    static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
    {
        let mut g = lock(&SEEN);
        let seen = g.get_or_insert_with(HashSet::new);
        let key = format!("{ip}|{verify}");
        if seen.contains(&key) {
            return;
        }
        if seen.len() >= 512 {
            seen.clear();
        }
        seen.insert(key);
    }
    // 空锚点在 route::dial_targets 里已被换成了目标域名，所以"等于 host"就是"这行没填 verify"。
    let blank = verify.is_empty() || verify.eq_ignore_ascii_case(host);
    let what = if blank {
        format!("默认证书没覆盖 {host}(verify 留空 = 拿目标域名当锚点)")
    } else {
        format!("锚点 {verify} 没印在这张证书上")
    };
    log(&format!("[串发] {ip} 证书校验失败: {what}, SNI={sni}"));
    log(&format!(
        "[串发]   这行 verify 填证书 SAN 里任意一个域名即可(不必等于目标域名)。查法: openssl s_client -connect {ip}:443 -servername {sni} </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName"
    ));
}

/// IP 级死亡退避（全局共享，所有 host 的串发都跳过）：TCP 连不上 / h2 谈不成 = 这个 IP
/// 现在建不成通道，跟 SNI 无关。60s 起步，重复失败逐级加重（60/300/1800s），自动过期。
pub fn note_dead(ip: &str) {
    let mut g = lock(&SERIAL);
    if let Some(t) = g.as_mut() {
        let n = t.dead.get(ip).map(|(_, n)| *n).unwrap_or(0) + 1;
        let secs = match n {
            1 => 60,
            2 => 300,
            _ => 1800,
        };
        t.dead.insert(ip.to_string(), (Instant::now() + Duration::from_secs(secs), n));
    }
}

/// 节点级死亡退避（键 = `ip|sni`）：TLS 握手超时。ClientHello 的 SNI 由节点配置决定，
/// 与触发请求的 host 无关——同节点（同 IP 同 SNI）对所有 host 一并跳过，不冤枉任何 host。
pub fn note_dead_node(ip: &str, sni: &str) {
    note_dead(&format!("{ip}|{sni}"));
}

/// 圈式串发：从游标起步逐个试，成功驻留、失败前移、整圈全灭冷却 30s；skip_ips 是双通道硬排除。
/// 同 IP 并发拨不设仲裁：两条都建成，入库时 store_h2 按每 IP 一条去重，输家的握手是接受的代价。
pub async fn serial_dial_skip(
    req: DialSkip<'_>,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    let DialSkip {
        host,
        tls_handshake,
        skip_ips,
        slot,
        crew,
        prefer_shared,
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
    let key = row.key.clone();
    let mut circle = route::dial_targets(host).unwrap_or_default();
    let total_candidates = circle.len();
    if !skip_ips.is_empty() {
        let filtered: Vec<route::NodeIp> = circle
            .iter()
            .filter(|p| !skip_ips.iter().any(|s| s == &p.ip))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            circle = filtered;
        }
    }
    // 已有通道被 skip 掉的数量（过滤全部滤空时保留原表走入库去重，不计）。
    let occupied_n = total_candidates - circle.len();
    if circle.is_empty() {
        return Err(format!("路由 [{key}] 没有可用候选 IP({host})"));
    }
    let cursor_key = cursor_key(&key, slot);

    // 尝试顺序：游标上的 IP（上次驻留）优先；其余按实测建连延迟升序，未测的垫底保持表序。
    let start_ip = {
        let g = lock(&SERIAL);
        g.as_ref().unwrap().cursor.get(&cursor_key).cloned()
    };
    let order = dial_order(&circle, start_ip.as_deref(), prefer_shared);

    let mut last_err: Option<String> = None;
    let mut tried = 0usize;
    let mut dead_skipped = 0usize;
    let mut crew_skipped = 0usize;
    // 预算只由"慢失败"（超时/黑洞，真在等）消耗；拒连/RST 毫秒级，不占——保证快速候选永远试得完。
    let budget_cap = Duration::from_secs(crate::config::SERIAL_DIAL_BUDGET_SECS);
    let mut budget_used = Duration::ZERO;
    let mut budget_hit = false;
    let mut slow_n = 0usize;
    for (oi, &ci) in order.iter().enumerate() {
        let p = &circle[ci];
        // 死亡退避双键：TCP/h2 失败记 IP 粒度（TCP 在 SNI 之前、h2 在 TLS 之后，与 SNI 无关）；
        // TLS 握手超时记节点粒度 ip|sni（ClientHello 由节点配置决定，与触发请求的 host 无关）。
        let node_dead_key = format!("{}|{}", p.ip, p.sni);
        {
            let mut g = lock(&SERIAL);
            if let Some(t) = g.as_mut() {
                let cooling = |k: &str| t.dead.get(k).is_some_and(|(until, _)| Instant::now() < *until);
                if cooling(&p.ip) || cooling(&node_dead_key) {
                    dead_skipped += 1;
                    continue;
                }
            }
        }
        // 同组互斥：对方试过/在试的 IP 绕行。
        if let Some(crew) = crew {
            if !crew.claim(&p.ip) {
                crew_skipped += 1;
                continue;
            }
        }
        tried += 1;
        let t0 = Instant::now();
        let result = dial::dial_one(&p.ip, &p.sni, &p.verify, tls_handshake).await;
        let dt = t0.elapsed();
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
                    let n = order.len();
                    let next = &circle[order[(oi + 1) % n]];
                    if let Some(t) = g.as_mut() {
                        t.cursor.insert(cursor_key.clone(), next.ip.clone());
                    }
                }
                // TCP 失败 = IP 对谁都死，进死亡退避；TLS 失败是按域干扰，只前移。
                let msg = e.to_string();
                // 证书校验失败 = 锚点没印在这张证书上，不是 IP 坏：留一行能照做的提示。
                let cert_bad = msg.contains("TLS") && cert_miss(&msg);
                if cert_bad {
                    log_cert_miss(&p.ip, &p.sni, &p.verify, host, log);
                }
                let tcp_level = msg.starts_with("TCP")
                    || matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    );
                if tcp_level {
                    note_dead(&p.ip);
                }
                // TLS 握手超时（TCP 过了、对端对 ClientHello 装死）= 节点级死亡退避：
                // ClientHello 的 SNI 由节点配置决定，与触发请求的 host 无关，全局共享不冤枉。
                let timed_out = e.kind() == std::io::ErrorKind::TimedOut
                    || msg.contains("超时")
                    || msg.to_lowercase().contains("timed out");
                if tls_handshake && !tcp_level && !cert_bad && timed_out {
                    note_dead_node(&p.ip, &p.sni);
                }
                // 慢失败烧预算；快速失败不烧——连续拒连也拦不住把圈走完。
                if timed_out {
                    budget_used += dt;
                    slow_n += 1;
                    if budget_used >= budget_cap {
                        budget_hit = true;
                        break;
                    }
                }
                continue;
            }
        }
    }

    if budget_hit {
        // 慢失败预算烧满 = 同等退避，防重试每次再烧一遍；有镜像兜底的 host 豁免。
        if mirror_chain(host).is_empty() {
            SERIAL_COOL.set(host);
        }
        if let Some(log) = log {
            log(&format!(
                "[串发] {host} [{key}] 慢失败预算({}s)耗尽(试 {tried} 个, 其中慢 {slow_n} 个), 冷却退避, 剩余候选稍后复测",
                crate::config::SERIAL_DIAL_BUDGET_SECS
            ));
        }
        return Err(format!(
            "串发慢失败预算耗尽({}s)",
            crate::config::SERIAL_DIAL_BUDGET_SECS
        ));
    }
    if tried == 0 {
        return Err(format!(
            "[{key}] {host} 无可拨候选: 共 {total_candidates} 个, {occupied_n} 个已有通道被跳过, \
             {dead_skipped} 个死亡冷却, {crew_skipped} 个同组在建"
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
            "[串发] {host} [{key}] 全灭({tried} 试 / {dead_skipped} 冷却中, 累计 {:?}), {tail}",
            last_err.as_deref().unwrap_or("未知")
        ));
    }
    Err(format!(
        "直连串发全灭: {}",
        last_err.as_deref().unwrap_or("未知")
    ))
}

/* ---------- 通道池统一入口 ---------- */

/// per-host 建造锁：同 host 的取通道未命中只放一个进拨号（雷群去重），
/// 等锁的人重查池子，建造落地就骑现成的，绝不一波请求各拨一条。
static BUILD_LOCKS: std::sync::OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    std::sync::OnceLock::new();

fn build_lock(host: &str) -> Arc<tokio::sync::Mutex<()>> {
    BUILD_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(host.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// 通道获取统一入口。骑池 → 没有 → 建造（内容域主副双腿）；全部通道顶满 →
/// 会话域骑现有连接排队（恒单通道），内容域/其他同 IP 溢出补一条。
/// 请求路径只调这一个函数，不管通道怎么来的。
/// 返回 (通道, 是否本轮新拨)：新拨的通道失败要罚边冷却，骑来的只摘不罚（见 report_failure）。
pub async fn get_or_build(
    host: &str,
    want_slot: Option<u8>,
    log: &LogFn,
) -> Result<(crate::server::upstream::H2Upstream, bool), String> {
    use crate::server::upstream as chan;
    let Some(targets) = route::dial_targets(host) else {
        return Err(format!("域名不在路由表({host})"));
    };
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    let session = chan::host_class(host) == chan::HostClass::Session;

    // 1) 骑池：会话域只认自己建的通道；内容域/其他谁闲用谁。
    if let Some(up) = pick_channel(host, &ips, want_slot, session) {
        let saturated =
            up.inflight.load(std::sync::atomic::Ordering::Relaxed) >= up.max_streams.max(1);
        if !saturated || session {
            return Ok((up, false));
        }
        // 2) 溢出：全部通道顶满 → 同 IP 另开（上限内）；到顶/建不成骑现有连接排队。
        return overflow(host, &targets, &up, want_slot, log).await;
    }

    // 3) 池空 → 建造。等在途建造最多 3s（30ms 步进重查池），超时交 Err 走兜底。
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(up) = pick_channel(host, &ips, want_slot, session) {
            return Ok((up, false)); // 等锁期间别人可能刚建好
        }
        if Instant::now() >= deadline {
            return Err(format!("{host} 建造在途等待超时(3s), 走兜底"));
        }
        let gate = build_lock(host);
        let Ok(_guard) = gate.try_lock() else {
            tokio::time::sleep(Duration::from_millis(30)).await;
            continue;
        };
        // 双检：拿锁前一刻可能刚有人建成。
        if let Some(up) = pick_channel(host, &ips, want_slot, session) {
            return Ok((up, false));
        }
        // 建造：内容域主副双腿、其他单通道、会话域自建单条，全在 dial_upstream 内。
        let up = chan::dial_upstream(host, log).await?;
        return Ok((up, true));
    }
}

/// 池内挑一条：会话域只认自己的通道（自建优先，不蹭公共通道），内容域/其他任意。
fn pick_channel(
    host: &str,
    ips: &[String],
    want_slot: Option<u8>,
    session: bool,
) -> Option<crate::server::upstream::H2Upstream> {
    if session {
        crate::server::upstream::cached_h2_own(host, ips, want_slot)
    } else {
        crate::server::upstream::cached_h2_in(ips, want_slot)
    }
}

/// 全忙溢出：在饱和通道所在的 IP 上再开一条（同 IP 上限内）。持建造锁防并发溢出雷群；
/// 锁被占说明溢出已在途，直接骑现有连接排队（新通道马上就有）。
/// 同 IP 直接拨不走串发：溢出失败不该牵动游标/冷却，那是建造路径的记账。
async fn overflow(
    host: &str,
    targets: &[route::NodeIp],
    saturated: &crate::server::upstream::H2Upstream,
    want_slot: Option<u8>,
    log: &LogFn,
) -> Result<(crate::server::upstream::H2Upstream, bool), String> {
    use crate::server::upstream as chan;
    let ride = Ok((saturated.clone(), false));
    if chan::conn_count_on_ip(&saturated.ip)
        >= chan::max_conns_per_ip(chan::host_class(host))
    {
        return ride; // 同 IP 到顶：骑现有连接排队等释放
    }
    let gate = build_lock(host);
    let Ok(_guard) = gate.try_lock() else {
        return ride;
    };
    // 拿到锁再查一次：别的请求可能刚溢出建成一条闲的。
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    if let Some(up) = pick_channel(host, &ips, want_slot, false) {
        let free =
            up.inflight.load(std::sync::atomic::Ordering::Relaxed) < up.max_streams.max(1);
        if free {
            return Ok((up, false));
        }
    }
    let Some(node) = targets.iter().find(|t| t.ip == saturated.ip) else {
        return ride; // 通道不在候选表里（DNS 兜底来的）：没法按表拨，骑现有连接
    };
    let t0 = Instant::now();
    let conn = match dial::dial_one(&node.ip, &node.sni, &node.verify, true).await {
        Ok(c) => c,
        Err(_) => return ride, // 该 IP 眼下建不成新通道：骑现有连接
    };
    match chan::h2_from_dialed(host, conn, &node.ip, saturated.slot, log).await {
        Ok(up) => {
            latency::note(&node.ip, t0.elapsed().as_millis() as u64);
            let up = chan::store_h2(&node.ip, up);
            Ok((up, true))
        }
        Err(_) => {
            // h2 谈不成 = 这个 IP 现在建不成通道，进死亡退避，别家串发直接跳过。
            note_dead(&node.ip);
            ride
        }
    }
}

/// 通道失败上报：摘通道 + 记账。fresh=本轮新拨（IP 真试过了，罚边冷却 + 游标前移）；
/// false=池里骑来的旧通道（只说明这条连接死了，IP 一点没试过，不罚——
/// 实测复用超时后 1 秒同 IP 新建 334ms 就回 200，冤枉好 IP 会把直连逼进镜像链）。
pub fn report_failure(up: &crate::server::upstream::H2Upstream, host: &str, fresh: bool) {
    use crate::server::upstream as chan;
    chan::drop_h2_id(&up.ip, up.id);
    if !fresh {
        return;
    }
    if let Some(row) = route::route_for(host) {
        edges::mark_stall(&up.ip, &row.key);
    }
    if !route::is_content(host) {
        cursor_note(host, &up.ip, false, up.slot);
    }
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
    seed_db().chains.into_values().flatten().collect()
}

/// 按注册表对齐全部镜像链（幂等）；开关只管大文件链，小文件链全量保留、仅摘已删除地址。
/// persist=false：只对齐内存，不落盘（启动路径用，避免把手改的 routes.json 规范化重写）。
pub fn sync_custom_mirrors(removed: &[String], persist: bool) {
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
    if changed && persist {
        write_routes_file(&routes_path(), &mirror_chains_snapshot());
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
    write_routes_file(&routes_path(), &mirror_chains_snapshot());
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
        m.insert(
            host.to_string(),
            Instant::now() + Duration::from_secs(self.ttl_secs),
        );
    }
    pub fn clear(&self, host: &str) {
        self.lock().remove(host);
    }
}

/// 镜像链全灭熔断 60s。
pub static MIRROR_BREAKER: Breaker = Breaker::new(60);

#[cfg(test)]
#[path = "../tests/pool/dial_crew_tests.rs"]
mod dial_crew_tests;

#[cfg(test)]
#[path = "../tests/pool/mod.rs"]
mod tests;
