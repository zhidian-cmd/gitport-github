//! 拨号与连接池：二部图（ips × hosts）唯一权威；内容域竞速取最速一条，会话/低频域串发（游标驻留、失败前移），取用统一走 get_or_build。
pub mod dial;
pub mod edges;
pub mod route;
pub mod speed;

use crate::util::{lock, LogFn};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// 路由表文件名：`ips` 节点 + `hosts` 行 + 镜像链，手改入口。
const ROUTES_FILE: &str = "routes.json";

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

/// 媒体救援链（直连切片 5s 未完的段换镜像续传）：保留键、加载/落盘专门伺候；图片段走图片链、视频段走视频链。
pub const MEDIA_IMAGE_CHAIN: &str = "图片";
pub const MEDIA_VIDEO_CHAIN: &str = "视频";
pub const MEDIA_CHAINS: &[&str] = &[MEDIA_IMAGE_CHAIN, MEDIA_VIDEO_CHAIN];

/// routes.json 镜像链键的白名单口径：内容域 host + 媒体救援保留键。
fn is_chain_key(key: &str) -> bool {
    CONTENT_HOSTS.contains(&key) || MEDIA_CHAINS.contains(&key)
}

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
    /// 小文件/媒体救援链：1 host 1 条（含保留键）。
    mirrors: HashMap<String, Vec<String>>,
    /// 大文件域单链：所有 big host 共用一条（成员本就相同，per-host 是冗余）。
    big_mirrors: Vec<String>,
    /// 每条串发路由（会话域+其他低频域）一个游标记号；内容域竞速不记；表序冻结，不随游标重排。
    cursor: HashMap<String, String>,
}

/// 串发全灭冷却（30s 快速失败窗）：全灭后调用方直接走兜底，不再空转重试。
pub static SERIAL_COOL: Breaker = Breaker::new(30);

/// 测试专用：路由表/串发表都是进程级全局态，跨模块的用例靠它串行。
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

/// 路由表文档：v2 给 ips+hosts（测速值在 ips 节点条目内）。
#[derive(Default)]
struct TopoDoc {
    hosts: Vec<route::HostSpec>,
    ips: Vec<route::IpSpec>,
    chains: HashMap<String, Vec<String>>,
    /// 大文件域单链（所有 big host 共用一条，不再每 host 一条）。
    big: Vec<String>,
}

/// 容错解析：坏段只丢那一段；salvaged = 有段被丢弃，调用方备份原文件。
fn parse_routes_tolerant(raw: &str, log: Option<&LogFn>) -> Option<(TopoDoc, bool)> {
    let root: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = root.as_object()?;
    let mut doc = TopoDoc::default();
    let mut small = HashMap::new();
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

    for (k, v) in obj {
        if !k.starts_with("mirrors") {
            continue;
        }
        // 大文件域单链：新格式是列表；旧 per-host map 原地合并（各 host 链本就相同）。
        if k == "mirrors_big" {
            match v {
                serde_json::Value::Array(list) => {
                    for u in list {
                        if let Ok(s) = serde_json::from_value::<String>(u.clone()) {
                            if s.starts_with("https://")
                                && !s.contains(' ')
                                && !doc.big.contains(&s)
                            {
                                doc.big.push(s);
                            }
                        }
                    }
                }
                serde_json::Value::Object(m) => {
                    // 旧 per-host map：按域名序把所有 host 的链去重合并成一条；排序只为确定性，是升级迁移路径。
                    let mut keys: Vec<String> = m.keys().cloned().collect();
                    keys.sort();
                    for h in keys {
                        let Some(chain) = m.get(&h) else { continue };
                        if let Ok(c) = serde_json::from_value::<Vec<String>>(chain.clone()) {
                            for s in c {
                                if s.starts_with("https://")
                                    && !s.contains(' ')
                                    && !doc.big.contains(&s)
                                {
                                    doc.big.push(s);
                                }
                            }
                        }
                    }
                    if !m.is_empty() {
                        if let Some(l) = log {
                            l("[串发] routes.json mirrors_big 是旧 per-host 字典, 已按域名序合并为单链");
                        }
                    }
                }
                _ => {
                    salvaged = true;
                    if let Some(l) = log {
                        l("[串发] routes.json mirrors_big 写坏, 该段丢弃");
                    }
                }
            }
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
            "mirrors_small" => &mut small,
            // 0.5.2 前的裸 mirrors 旧字典（及未知 mirrors* 键）：随两代迁移层一并停读
            other => {
                if let Some(l) = log {
                    l(&format!("[串发] routes.json {other} 段已停读(旧格式), 该段忽略"));
                }
                continue;
            }
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
    doc.chains = small;
    // 测速值兼容：旧布局顶层 {ip: ms} 与节点条目内映射都已收编为节点标量（IpSpec.latency 反序列化处理），
    // 这里只补顶层旧键 → 对应节点标量的一次迁移；新布局直接带节点标量。
    if let Some(serde_json::Value::Object(map)) = obj.get("latency") {
        for spec in &mut doc.ips {
            let ip = spec.ip.trim().to_string();
            if let Some(v) = map.get(&ip).and_then(|x| x.as_u64()) {
                spec.latency = Some(v);
            }
        }
    }
    Some((doc, salvaged))
}

/// 落盘：ips 在前、hosts 只写特殊行，镜像链按 CONTENT_HOSTS 序。
fn encode_routes(mirrors: &HashMap<String, Vec<String>>, big: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // 测速值跟着节点走：单 IP 节点一个标量，未测(0)不写。
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
            let ms = n.latency.load(Ordering::Relaxed);
            if ms > 0 {
                fields.push(format!("\"latency\": {}", ms));
            }
            format!("    {{\n      {}\n    }}", fields.join(",\n      "))
        })
        .collect();
    parts.push(format!("  \"ips\": [\n{}\n  ]", nodes.join(",\n")));

    // hosts 只落特殊属性/无节点的键：全默认判定必须把 session/big 算进去，否则第一次存盘就丢标志。
    let served: std::collections::HashSet<&str> = snapshot
        .iter()
        .flat_map(|n| n.hosts.iter().map(|s| s.as_str()))
        .collect();
    let rows: Vec<String> = route::hosts_snapshot()
        .iter()
        .filter(|r| {
            let plain = !r.flags.direct
                && !r.flags.content
                && !r.flags.session
                && !r.flags.big
                && r.fallback == route::Fallback::Dns;
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
    // hosts 表压成一行：纯路由声明，逐行展开徒增文件高度。
    parts.push(format!("  \"hosts\": {{{}}}", rows.join(", ")));

    let mut small_rows: Vec<String> = Vec::new();
    for h in CONTENT_HOSTS {
        // 大文件域已单链化，不占 per-host 键位。
        if route::is_big_file_host(h) {
            continue;
        }
        let Some(c) = mirrors.get(*h) else { continue };
        let items: Vec<String> = c.iter().map(json_of).collect();
        small_rows.push(format!("    {}: [{}]", json_of(h), items.join(", ")));
    }
    // 媒体救援链是保留键：原样回写进 mirrors_small，手改的内容不因落盘丢失。
    for h in MEDIA_CHAINS {
        let Some(c) = mirrors.get(*h) else { continue };
        let items: Vec<String> = c.iter().map(json_of).collect();
        small_rows.push(format!("    {}: [{}]", json_of(h), items.join(", ")));
    }
    // 大文件域单链：列表落盘（旧 per-host map 由解析端原地合并迁移）。
    if !big.is_empty() {
        let items: Vec<String> = big.iter().map(json_of).collect();
        parts.push(format!("  \"mirrors_big\": [{}]", items.join(", ")));
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

/// routes.json 写盘互斥：退出落盘与后台改镜像链可能同时写，撞在一起会把两份配置搅成一份。
static ROUTES_SAVE_LOCK: Mutex<()> = Mutex::new(());

fn write_routes_file(path: &Path, mirrors: &HashMap<String, Vec<String>>) {
    let _guard = ROUTES_SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let data = encode_routes(mirrors, &big_chain());
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

/// 立即把内存表（含 latency 回流）落盘，下次冷启动仍有拨号延迟基线。
pub fn save_routes_now() {
    write_routes_file(&routes_path(), &mirror_chains_snapshot());
}

pub fn serial_load(data_dir: &Path, last_ip: Vec<(String, String)>, log: Option<LogFn>) {
    *lock(&SERIAL_DIR) = Some(data_dir.to_path_buf());
    *lock(&SERIAL_LOG) = log.clone();
    let path = routes_path();
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
    let mut doc = match parsed {
        Some((mut d, _)) => {
            // v1/0.5.3 旧格式（routes 字典/旧三池）不再被读懂：文件在却拆不出任何路由行 = 旧格式或残缺，
            // 路由行按种子重建（用户镜像链/测速值保留），绝不静默半重建——只有镜像链没有路由的表跑不起来。
            if d.hosts.is_empty() && d.ips.is_empty() {
                if let Some(l) = log.as_ref() {
                    l("[串发] routes.json 无 ips/hosts 路由行(旧格式或残缺), 路由行按种子重建");
                }
                if std::fs::copy(&path, path.with_extension("json.bak")).is_ok() {
                    if let Some(l) = log.as_ref() {
                        l("[串发] routes.json 原文件已备份为 routes.json.bak");
                    }
                }
                d.hosts = seeds.hosts.clone();
                d.ips = seeds.ips.clone();
            }
            d
        }
        None => TopoDoc {
            hosts: seeds.hosts.clone(),
            ips: seeds.ips.clone(),
            chains: seeds.chains.clone(),
            big: Vec::new(),
        },
    };
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
        big_mirrors: doc.big,
        cursor: HashMap::new(),
    };
    // 游标圈预写空记号；settings.last_ip 非空值覆盖（表外旧键直接丢）。
        for key in route::cursor_keys() {
        tab.cursor.insert(key, String::new());
    }
    for (key, ip) in &last_ip {
        if !ip.is_empty() && tab.cursor.contains_key(key) {
            tab.cursor.insert(key.clone(), ip.clone());
        }
    }
    for (host, chain) in doc.chains {
        if !is_chain_key(&host) {
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
        if vc.is_empty() {
            continue;
        }
        if route::is_big_file_host(&host) {
            // 用户把 big host 的链放错字典：归位合并进大文件单链，不静默丢。
            for u in vc {
                if !tab.big_mirrors.contains(&u) {
                    tab.big_mirrors.push(u);
                }
            }
        } else {
            tab.mirrors.insert(host, vc);
        }
    }
    // 手改/收编的镜像进注册表(幂等)：工作台看得到、开关管得到、删得掉。
    {
        let mut registry = crate::settings::worker_mirrors();
        let mut adopted = false;
        // host 排序仅为确定性。
        let mut hosts: Vec<&String> = tab.mirrors.keys().collect();
        hosts.sort();
        for h in hosts {
            for u in &tab.mirrors[h] {
                if registry.iter().any(|w| w.url == *u) {
                    continue;
                }
                registry.push(crate::settings::WorkerMirror {
                    url: u.clone(),
                    on: true,
                    template: String::new(),
                    invalid: false,
                });
                adopted = true;
            }
        }
        // 手改的 big 镜像必须收编注册表：否则工作台看不到、开关管不到、删不掉。
        for u in &tab.big_mirrors {
            if registry.iter().any(|w| w.url == *u) {
                continue;
            }
            registry.push(crate::settings::WorkerMirror {
                url: u.clone(),
                on: true,
                template: String::new(),
                invalid: false,
            });
            adopted = true;
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

/// IpSpec → 运行时节点：单 IP 节点（范围写法已下线），latency 跟节点走。
fn build_node(spec: route::IpSpec) -> Result<route::IpNode, String> {
    let ip = spec.ip.trim().to_string();
    let segs: Vec<&str> = ip.split('.').collect();
    let ok = segs.len() == 4
        && segs
            .iter()
            .all(|s| s.parse::<u32>().map(|v| v <= 255).unwrap_or(false));
    if !ok {
        return Err(format!(
            "ip {ip:?} 应为单个点分地址(每段 0~255, 范围写法已下线)"
        ));
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
        raw: ip.clone(),
        ips: vec![ip],
        sni: spec.sni.trim().to_string(),
        verify: spec.verify.trim().to_string(),
        hosts,
        latency: AtomicU64::new(spec.latency.unwrap_or(0)),
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

/// 种子只补已有表的节点/边，不新建 hosts 行（用户删的不该被加回）；节点 hosts 里出现但 hosts 块没写的键按默认补行，落盘时省略。
fn fill_hosts_from_nodes(doc: &mut TopoDoc) {
    for spec in &doc.ips {
        for h in &spec.hosts {
            let key = h.trim();
            if key.is_empty() || doc.hosts.iter().any(|x| x.key == key) {
                continue;
            }
            // 通配键继承父域标志：*.github.com 从 github.com 拿 session，别让派生行丢主站会话语义。
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
        let seed_ip = seed_node.ip.trim().to_string();
        // 按"同地址"找现有节点；找不到且 hosts 行存在 → 新建节点。
        let hit = doc
            .ips
            .iter_mut()
            .find(|n| n.ip.trim() == seed_ip);
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

/// 数据层结果回写游标：成功驻留、失败前移、零写盘；内容域竞速不记游标但仍清死亡退避与 421/超时短冷却。
pub fn cursor_note(host: &str, ip: &str, ok: bool) {
    let Some(row) = route::route_for(host) else {
        return;
    };
    if row.flags.direct {
        return;
    }
    let key = row.key.clone();
    let track = !row.flags.content;
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
        if track {
            t.cursor.insert(key, ip.to_string());
        }
        edges::clear(ip, &row.key); // 成功只清短冷却(超时/421)；风控冷却不可清，只随时间过期
        return;
    }
    // 失败：前移到下一候选(整圈后自然复测)；内容域竞速选路，游标无人读，不挪。
    if track {
        if let Some(pos) = circle.iter().position(|p| p.ip == ip) {
            let next = &circle[(pos + 1) % circle.len()];
            t.cursor.insert(key, next.ip.clone());
        }
    }
}

/// 尝试顺序：游标 IP 优先，其余按实测延迟升序、未测垫底保持表序；内容域竞速不看此序。
fn dial_order(circle: &[route::NodeIp], start_ip: Option<&str>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..circle.len()).collect();
    order.sort_by_key(|&i| {
        let l = circle[i].latency;
        (if l == 0 { u64::MAX } else { l }, i)
    });
    // 游标置顶。
    if let Some(ip) = start_ip {
        if let Some(pos) = circle.iter().position(|p| p.ip == ip) {
            if let Some(at) = order.iter().position(|&j| j == pos) {
                order.remove(at);
                order.insert(0, pos);
            }
        }
    }
    order
}

/// 全局拨号认领集：同一 IP 全进程至多一条腿在拨（跨 host 去重），窗口 = 起拨到入库/失败；TCP 隧道腿 1:1 不认领。
static DIAL_CLAIMS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// 认领拨号：返回 false = 已有别的腿在拨这个 IP，本腿不出场。
pub(crate) fn claim_dial(ip: &str) -> bool {
    lock(&DIAL_CLAIMS).insert(ip.to_string())
}

/// 释放认领：入库/失败后必调——漏放 = 该 IP 本进程永久哑火。
pub(crate) fn release_dial(ip: &str) {
    lock(&DIAL_CLAIMS).remove(ip);
}

/// 串发请求描述：拨哪个 host、怎么拨。
pub struct DialSkip<'a> {
    pub host: &'a str,
    pub tls_handshake: bool,
    pub skip_ips: &'a [String],
}

/// 证书校验失败按小写子串认（错误串随 BoringSSL 版本变）；只认校验不过，不认系统根证书缺失那类。
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

/// 锚点选错提示：同一 (IP, 锚点) 只打一次；空锚点失败 = 默认证书没覆盖该域名。
fn log_cert_miss(ip: &str, sni: &str, verify: &str, host: &str, log: Option<&LogFn>) {
    let Some(log) = log else { return };
    static SEEN: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
    {
        let mut seen = lock(&SEEN);
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

/// IP 级死亡退避（全局共享）：TCP 连不上 / h2 谈不成 = 该 IP 建不成通道，60/300/1800s 递增、自动过期。
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

/// 该 IP 或该节点（ip|sni）是否在死亡冷却中：竞速取候选与外部预检共用这一个口径。
pub fn dial_cooling(ip: &str, sni: &str) -> bool {
    let g = lock(&SERIAL);
    let Some(t) = g.as_ref() else { return false };
    let now = Instant::now();
    let cooling = |k: &str| t.dead.get(k).is_some_and(|(until, _)| now < *until);
    cooling(ip) || cooling(&format!("{ip}|{sni}"))
}

/// 串发日志限速：每 host 每 60s 最多 12 行，留证又不刷屏。
fn serial_try_allowed(host: &str) -> bool {
    static Q: LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let mut map = lock(&Q);
    if map.len() >= 256 {
        map.clear();
    }
    let now = Instant::now();
    let e = map.entry(host.to_string()).or_insert((0, now));
    if e.1.elapsed() >= Duration::from_secs(60) {
        *e = (0, now);
    }
    if e.0 >= 12 {
        return false;
    }
    e.0 += 1;
    true
}

/// 错误文案截断：串发日志一行一个，长错误会把整行撑爆。
fn brief_err(msg: &str) -> String {
    let s = msg.trim();
    if s.chars().count() <= 60 {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(60).collect::<String>())
    }
}

/// 圈式串发：游标起步逐个试，成功驻留、失败前移、全灭冷却 30s；skip_ips 硬排除已占用 IP，同 IP 不仲裁。
pub async fn serial_dial_skip(
    req: DialSkip<'_>,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    let DialSkip {
        host,
        tls_handshake,
        skip_ips,
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
    // 与 cursor_note 同一道闸：内容域竞速不记游标，候选剩 1 条退回串发时也不写孤儿游标。
    let track = !row.flags.content;
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
    // 慢 IP 软排除：全慢时 usable 原样返回，一圈候选不会打空。会话域固定单 IP，不参与。
    let mut slow_skipped = 0usize;
    if crate::server::upstream::host_class(host) != crate::server::upstream::HostClass::Session {
        let ips: Vec<String> = circle.iter().map(|p| p.ip.clone()).collect();
        let keep = speed::usable(&ips);
        if keep.len() < ips.len() {
            slow_skipped = ips.len() - keep.len();
            circle.retain(|p| keep.iter().any(|k| k == &p.ip));
        }
    }
    if circle.is_empty() {
        return Err(format!("路由 [{key}] 没有可用候选 IP({host})"));
    }
    // 尝试顺序：游标上的 IP（上次驻留）优先；其余按实测建连延迟升序，未测的垫底保持表序。
    let start_ip = {
        let g = lock(&SERIAL);
        g.as_ref().unwrap().cursor.get(&key).cloned()
    };
    let order = dial_order(&circle, start_ip.as_deref());

    let mut last_err: Option<String> = None;
    let mut tried = 0usize;
    let mut dead_skipped = 0usize;
    let mut claimed_skipped = 0usize;
    for (oi, &ci) in order.iter().enumerate() {
        let p = &circle[ci];
        // 死亡退避双键：TCP/h2 失败记 IP 粒度（与 SNI 无关）；TLS 握手超时记 ip|sni 节点粒度。
        if dial_cooling(&p.ip, &p.sni) {
            dead_skipped += 1;
            continue;
        }
        // TLS 拨号走全局认领：同一 IP 全进程至多一条腿（跨 host 去重）；TCP 隧道腿不认领。
        if tls_handshake && !claim_dial(&p.ip) {
            claimed_skipped += 1;
            continue;
        }
        tried += 1;
        let t0 = Instant::now();
        let result = dial::dial_one(&p.ip, &p.sni, &p.verify, tls_handshake).await;
        if tls_handshake {
            release_dial(&p.ip);
        }
        let dt = t0.elapsed();
        // 每次尝试都留一行（限速）：换 IP 的全过程以前完全无日志，出问题查不到。
        if let Some(log) = log {
            if serial_try_allowed(host) {
                let verdict = match &result {
                    Ok(_) => "成功".to_string(),
                    Err(e) => format!("失败({})", brief_err(&e.to_string())),
                };
                log(&format!(
                    "[串发] {host} 试 {}({}) {verdict} {}ms [{tried}/{}]",
                    p.ip,
                    p.sni,
                    dt.as_millis(),
                    order.len()
                ));
            }
        }
        match result {
            Ok(conn) => {
                // 成功驻留；变更落盘 settings.last_ip（set_last_ips 未变化时 no-op）。
                if track {
                    let snap = {
                        let mut g = lock(&SERIAL);
                        let t = g.as_mut().unwrap();
                        t.cursor.insert(key.clone(), p.ip.clone());
                        t.cursor
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    };
                    crate::settings::set_last_ips(snap);
                }
                return Ok((conn, p.ip.clone(), p.sni.clone()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
                // 前移到下一候选；物理顺序不动，零写盘（内容域不记游标）。
                if track {
                    let mut g = lock(&SERIAL);
                    let n = order.len();
                    let next = &circle[order[(oi + 1) % n]];
                    if let Some(t) = g.as_mut() {
                        t.cursor.insert(key.clone(), next.ip.clone());
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
                // TLS 握手超时 = 节点级死亡退避：SNI 由节点配置决定，与请求 host 无关。
                let timed_out = e.kind() == std::io::ErrorKind::TimedOut
                    || msg.contains("超时")
                    || msg.to_lowercase().contains("timed out");
                if tls_handshake && !tcp_level && !cert_bad && timed_out {
                    // 节点级死亡退避（键 = ip|sni）：握手超时；SNI 由节点配置决定，全局共享不冤枉。
                    note_dead(&format!("{}|{}", p.ip, p.sni));
                }
                continue;
            }
        }
    }

    if tried == 0 {
        // 一条腿都没轮到拨 = 候选全被别的 host 认领：哨兵让调用方稍候重查池。
        if claimed_skipped > 0 {
            return Err(crate::server::upstream::ERR_ALL_CLAIMED.to_string());
        }
        return Err(format!(
            "[{key}] {host} 无可拨候选: 共 {total_candidates} 个, {occupied_n} 个已有通道被跳过, \
             {dead_skipped} 个死亡冷却, {slow_skipped} 个慢冷却"
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

/// per-host 建造锁：未命中只放一个进拨号，等锁者重查池子骑现成的。
static BUILD_LOCKS: std::sync::OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    std::sync::OnceLock::new();

/// 建造等待上界 15s：必须盖过竞速全程（RACE_WINDOW 8s + h2 握手 5s）+ 余量，否则冷启动一页并发请求集体超时摔给兜底；同一把尺也量建造本身。
pub(crate) const BUILD_WAIT_SECS: u64 = 15;

/// 测试专用：读游标驻留（游标本身内存态、零写盘，没有别的读出口）。
#[cfg(test)]
pub(crate) fn cursor_of(route_key: &str) -> Option<String> {
    lock(&SERIAL).as_ref()?.cursor.get(route_key).cloned()
}

/// 建造锁表容量：按 host 建键，常驻进程访问过上千子域后不能只涨不降。
const BUILD_LOCK_CAP: usize = 1024;

fn build_lock(host: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut g = BUILD_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if g.len() >= BUILD_LOCK_CAP {
        // 只留还有调用方持有的锁：Arc 计数 > 1 说明有人正在等/在建，删了会拆掉雷群去重。
        g.retain(|_, l| Arc::strong_count(l) > 1);
    }
    g.entry(host.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// 通道获取统一入口：从池取可用通道（取→建→溢出），来源对调用方不可见；fresh 只用于失败归因（新拨罚边，沿用只摘）。
pub async fn get_or_build(
    host: &str,
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
    // 慢 IP 软排除：usable 在全慢时原样返回，候选不会被打空。会话域固定单 IP，换 IP 是风控特征，不参与。
    let ips = if session { ips } else { speed::usable(&ips) };

    // 1) 选：会话域只认自己建的通道；内容域/其他谁闲用谁。
    if let Some(up) = pick_channel(host, &ips, session) {
        let saturated =
            up.inflight.load(std::sync::atomic::Ordering::Relaxed) >= up.max_streams.max(1);
        if !saturated || session {
            return Ok((up, false));
        }
        // 2) 溢出：全部通道顶满 → 补一条临时通道；补不出骑现有连接排队等释放。
        return match overflow_build(host, &targets, log).await {
            Some(new) => Ok((new, true)),
            None => Ok((up, false)),
        };
    }

    // 池空 → 排队等在途建造：锁队列即正在建造的登记簿，唤醒后双检、前一位失败则自己顶上；每人自己的 15s 上界盖过竞速全程。
    let gate = build_lock(host);
    let deadline = Instant::now() + Duration::from_secs(BUILD_WAIT_SECS);
    loop {
        if let Some(up) = pick_channel(host, &ips, session) {
            return Ok((up, false)); // 排队期间被喂饱了
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Err(format!("{host} 建造在途等待超时({BUILD_WAIT_SECS}s), 走兜底"));
        }
        let _guard = match tokio::time::timeout(wait, gate.lock()).await {
            Ok(g) => g,
            Err(_) => return Err(format!("{host} 建造在途等待超时({BUILD_WAIT_SECS}s), 走兜底")),
        };
        // 双检：轮到我时前一位可能刚建成。
        if let Some(up) = pick_channel(host, &ips, session) {
            return Ok((up, false));
        }
        // 建造（内容域竞速/其余串发）也受同一硬窗：否则抢到锁的人挂几十秒不返回也不兜底；串发是旁路，超窗只影响这条请求。
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return Err(format!("{host} 建造在途等待超时({BUILD_WAIT_SECS}s), 走兜底"));
        }
        match tokio::time::timeout(remain, chan::dial_upstream(host, log)).await {
            Ok(Err(e)) if e == chan::ERR_ALL_CLAIMED => {
                // 候选全被别的 host 在拨：松锁等它落池，50ms 后重查（界照旧）。
                drop(_guard);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            Ok(r) => return Ok((r?, true)),
            Err(_) => {
                return Err(format!(
                    "{host} 建造总窗超时({BUILD_WAIT_SECS}s), 走兜底(串发后台继续)"
                ));
            }
        }
    }
}

/* ---------- 黑洞触发链：池子摘出 → 通知建连机器人换血 ---------- */

/// 黑洞按域处置：会话域摘黑+游标前移+预建；内容域软禁黑 IP 60s（不杀在途）+换血补缺；其他域暂缓即可。
pub fn on_channel_blackhole(host: &str, ip: &str, log: &LogFn) {
    use crate::server::upstream as chan;
    match chan::host_class(host) {
        chan::HostClass::Session => {
            chan::cull_channel(ip);
            cursor_note(host, ip, false); // 游标挪到下一候选，别死磕黑 IP
            route::sink_latency(ip); // 拨号排序同步降权，不然游标挪了排序还把它排第一
            (log)(&format!(
                "[黑洞] {host} 会话通道 {ip} 弃用, 游标挪动并预建替代通道"
            ));
            let host = host.to_string();
            let log = log.clone();
            tokio::spawn(async move {
                // 预建：池空即拨，游标已指向下一候选 IP
                let _ = get_or_build(&host, &log).await;
            });
        }
        chan::HostClass::Content => {
            // 软禁 60s 不杀在途：一条 h2 驮几十条流，个别流黑洞≠连接死，cull 会连坐全部在途流。
            speed::bench(ip);
            (log)(&format!(
                "[黑洞] {host} {ip} 暂缓(数据窗零字节), 触发全量换血"
            ));
            if speed::try_begin_rebuild(host) {
                ensure_coverage(host, log.clone());
            }
        }
        _ => {
            speed::bench(ip);
        }
    }
}

/// 建连机器人：把 host 缺通道的 IP 都建出来（一 IP 一条），直接入池，去留交给真实流量。
fn ensure_coverage(host: &str, log: LogFn) {
    let host = host.to_string();
    tokio::spawn(async move {
        use crate::server::upstream as chan;
        let targets = route::dial_targets(&host).unwrap_or_default();
        let mut built = 0usize;
        for t in targets {
            // 只补没通道且不在冷却的 IP；有通道的不动。
            if chan::conn_count_on_ip(&t.ip) > 0 || dial_cooling(&t.ip, &t.sni) {
                continue;
            }
            let host2 = host.clone();
            let log2 = log.clone();
            let dial_job = async move {
                // 拨号/握手失败各落一行：吞掉的话坏 IP 每 60 秒白付一次完整握手还查无痕迹。
                let conn = match dial::dial_one(&t.ip, &t.sni, &t.verify, true).await {
                    Ok(c) => c,
                    Err(e) => {
                        (log2)(&format!("[池] {host2} {} 拨号失败({e}), 本轮跳过", t.ip));
                        return;
                    }
                };
                let up = match chan::h2_from_dialed(&host2, conn, &t.ip, &log2).await {
                    Ok(u) => u,
                    Err(e) => {
                        (log2)(&format!("[池] {host2} {} h2 握手失败({e}), 本轮跳过", t.ip));
                        return;
                    }
                };
                let _ = chan::store_h2(&t.ip, up);
                (log2)(&format!("[池] {host2} 新通道 {} 入池", t.ip));
            };
            tokio::spawn(dial_job);
            built += 1;
        }
        // 派发数不是建成数——成没成由各腿自己的回执行说话，这里只报派了几条。
        (log)(&format!("[池] {host} 换血: 派发 {built} 腿"));
    });
}

/// 竞速候选准备：路由候选→滤死亡冷却→滤暂缓（全滤空回退全表）；调用方须非会话域（会话域恒串发）。
pub(crate) fn dial_candidates(host: &str) -> Vec<route::NodeIp> {
    let targets = route::dial_targets(host).unwrap_or_default();
    let alive: Vec<route::NodeIp> = targets
        .iter()
        .filter(|t| !dial_cooling(&t.ip, &t.sni))
        .cloned()
        .collect();
    let alive = if alive.is_empty() { targets } else { alive };
    let ips: Vec<String> = alive.iter().map(|t| t.ip.clone()).collect();
    let keep = speed::usable(&ips);
    alive
        .into_iter()
        .filter(|t| keep.iter().any(|ip| ip == &t.ip))
        .collect()
}

/// 内容域 TCP 竞速（仅 MITM 关的隧道用）：并发拨 TCP，第一个通的开管；不进认领（1:1 消费）、不错峰、不建池；会话域不进来（跨 IP SYN 是风控画像）。
pub async fn tcp_race_connect(host: &str) -> Result<(dial::Dialed, String), String> {
    if SERIAL_COOL.open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let cands = dial_candidates(host);
    if cands.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走兜底"));
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<(dial::Dialed, String), String>>(cands.len());
    for node in cands {
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let t0 = Instant::now();
            match dial::dial_one(&node.ip, &node.sni, &node.verify, false).await {
                Ok(conn) => {
                    route::note_latency(&node.ip, t0.elapsed().as_millis() as u64);
                    let _ = tx2.send(Ok((conn, node.ip.clone()))).await;
                }
                Err(e) => {
                    // TCP 失败 = IP 对谁都死，进死亡退避（与串发同款判据）。
                    if msg_is_tcp_dead(&e) {
                        note_dead(&node.ip);
                    }
                    let _ = tx2.send(Err(format!("{} 拨号失败({e})", node.ip))).await;
                }
            }
        });
    }
    drop(tx);
    // 第一个通的即胜，其余随 rx drop 自灭：未握手的 SYN 自消，已握手的 drop 即关。
    let mut last: Option<String> = None;
    loop {
        match rx.recv().await {
            Some(Ok((conn, ip))) => return Ok((conn, ip)),
            Some(Err(e)) => last = Some(e),
            None => {
                // 全灭冷却：MITM 关模式下镜像腿不营业，无豁免，30s 内直落系统 DNS。
                SERIAL_COOL.set(host);
                return Err(last.unwrap_or_else(|| format!("{host} TCP 竞速全败")));
            }
        }
    }
}

/// TCP 层失败判据（与串发同款）：IP 对谁都死才进死亡退避。
fn msg_is_tcp_dead(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
        || e.kind() == std::io::ErrorKind::ConnectionReset
        || e.kind() == std::io::ErrorKind::ConnectionAborted
        || e.to_string().starts_with("TCP")
}

/// 池内挑一条：会话域只认自己的通道（自建优先，不蹭公共通道），内容域/其他任意。
fn pick_channel(
    host: &str,
    ips: &[String],
    session: bool,
) -> Option<crate::server::upstream::H2Upstream> {
    if session {
        crate::server::upstream::cached_h2_own(host, ips)
    } else {
        crate::server::upstream::cached_h2_in(ips)
    }
}

/// 溢出只补零通道 IP 的临时通道（同 IP 溢出已废：多一条 TCP 只摊薄窗口）；满载骑排队；溢出句柄 pick 不外发、闲置即焚；会话域不溢出。
async fn overflow_build(
    host: &str,
    targets: &[route::NodeIp],
    log: &LogFn,
) -> Option<crate::server::upstream::H2Upstream> {
    use crate::server::upstream as chan;
    if chan::host_class(host) == chan::HostClass::Session {
        return None;
    }
    // 首选且唯一：零通道 IP。
    let Some(node) = targets
        .iter()
        .filter(|t| chan::conn_count_on_ip(&t.ip) == 0 && !dial_cooling(&t.ip, &t.sni))
        .next()
        .cloned()
    else {
        return None;
    };
    let gate = build_lock(host);
    let Ok(_guard) = gate.try_lock() else {
        return None; // 建造/溢出在途：不排队，用现有通道凑合
    };
    let t0 = Instant::now();
    let conn = dial::dial_one(&node.ip, &node.sni, &node.verify, true).await.ok()?;
    match chan::h2_from_dialed(host, conn, &node.ip, log).await {
        Ok(mut up) => {
            route::note_latency(&node.ip, t0.elapsed().as_millis() as u64);
            up.overflow = true;
            (log)(&format!("[溢出] {host} 零通道 IP 补建: {}", node.ip));
            Some(chan::store_h2(&node.ip, up))
        }
        Err(_) => {
            // h2 谈不成 = 这个 IP 现在建不成通道，进死亡退避，别家串发直接跳过。
            note_dead(&node.ip);
            None
        }
    }
}

/// 收齐 host 候选内最多 want 条通道：现成的直接给，不够建腿+溢出补，补不动交现有的；空 = 直连暂不可用。
pub async fn gather_channels(
    host: &str,
    want: usize,
    log: &LogFn,
) -> Vec<crate::server::upstream::H2Upstream> {
    use crate::server::upstream as chan;
    if want == 0 {
        return Vec::new();
    }
    let Some(targets) = route::dial_targets(host) else {
        return Vec::new();
    };
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    let mut got = chan::channels_for(&ips);
    if got.len() >= want {
        got.truncate(want);
        return got;
    }
    // 池空先建，再把池里现成的（可能不止这条）一并收进来。
    if got.is_empty() {
        match get_or_build(host, log).await {
            Ok((up, _)) => got.push(up),
            Err(_) => return Vec::new(),
        }
        for c in chan::channels_for(&ips) {
            if !got.iter().any(|g| g.id == c.id) {
                got.push(c);
            }
        }
    }
    // 还缺就溢出补临时通道；补不出交现有的。
    while got.len() < want {
        match overflow_build(host, &targets, log).await {
            Some(up) => got.push(up),
            None => break,
        }
    }
    got
}

/// 失败上报：摘通道+记账；新拨的游标前移+罚边冷却，骑来的旧通道只摘不罚（IP 没被试过）。
pub fn report_failure(up: &crate::server::upstream::H2Upstream, host: &str, fresh: bool) {
    use crate::server::upstream as chan;
    chan::drop_h2_id(&up.ip, up.id);
    if !fresh {
        return;
    }
    // 先挪游标再拉黑：反了的话候选圈滤掉该 IP，游标永远挪不动。
    cursor_note(host, &up.ip, false);
    if let Some(row) = route::route_for(host) {
        edges::mark_stall(&up.ip, &row.key);
    }
}

/// 单链对齐（幂等）：已有成员位置不动，缺的追加链尾，停用的摘除。
fn align_chain(chain: &mut Vec<String>, en: &[String], dis: &[String]) -> bool {
    let mut changed = false;
    for u in dis {
        if chain.iter().any(|m| m == u) {
            chain.retain(|m| m != u);
            changed = true;
        }
    }
    for u in en {
        if !chain.iter().any(|m| m == u) {
            chain.push(u.clone());
            changed = true;
        }
    }
    changed
}

/// 小文件/媒体链 per-host 对齐：全量保留注册表镜像、仅摘已删除地址（开关只管大文件单链）。
pub fn align_custom_mirrors(
    mirrors: &mut HashMap<String, Vec<String>>,
    enabled: &[String],
    disabled: &[String],
) -> bool {
    let mut changed = false;
    for chain in mirrors.values_mut() {
        if align_chain(chain, enabled, disabled) {
            changed = true;
        }
    }
    changed
}

/// 按注册表对齐全部镜像链（幂等）：开关只管大文件单链，小文件链全留、仅摘已删地址；persist=false 只改内存不落盘。
pub fn sync_custom_mirrors(removed: &[String], persist: bool) {
    let registry = crate::settings::worker_mirrors();
    // 探测标红的条目不进链：用法没验证过的镜像放进去只会白占链位。
    let enabled: Vec<String> = registry
        .iter()
        .filter(|w| w.on && !w.invalid)
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
    // 链全空时先建键，否则镜像落不进链；大文件域已单链化，不占 per-host 键位。
    if !all.is_empty() {
        for h in CONTENT_HOSTS.iter().copied().chain(MEDIA_CHAINS.iter().copied()) {
            if route::is_big_file_host(h) {
                continue;
            }
            tab.mirrors.entry(h.to_string()).or_default();
        }
    }
    let mut changed = align_custom_mirrors(&mut tab.mirrors, &all, removed);
    // 大文件单链：开关只管它（启用者进链、停用者摘除）。
    if align_chain(&mut tab.big_mirrors, &enabled, &disabled) {
        changed = true;
    }
    // 建了键但没启用镜像的 host 留空链无害(无链=回落语义)，不必回收。
    drop(g);
    if changed && persist {
        write_routes_file(&routes_path(), &mirror_chains_snapshot());
    }
}

pub fn mirror_chain(host: &str) -> Vec<String> {
    let g = lock(&SERIAL);
    let Some(t) = g.as_ref() else {
        return Vec::new(); // 池未初始化(单测独立跑 chain_fetch 时)——空链等价"无镜像腿"
    };
    // 大文件域单链：所有 big host 共用一条。
    if route::is_big_file_host(host) {
        return t.big_mirrors.clone();
    }
    t.mirrors.get(host).cloned().unwrap_or_default()
}

/// 大文件域单链快照（落盘用）。
fn big_chain() -> Vec<String> {
    let g = lock(&SERIAL);
    g.as_ref()
        .map(|t| t.big_mirrors.clone())
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
