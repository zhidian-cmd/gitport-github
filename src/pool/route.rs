//! 路由表 v2：二部图，ips 节点 × hosts 行，边 = 节点服务该路由键；routes.json 两块 + 运行时反向索引。

use super::edges;
use crate::util::lock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// host 侧开关位；全部来自 routes.json 的 hosts 块。
#[derive(Debug, Clone, Default)]
pub struct Flags {
    /// 本机直连，不进代理。
    pub direct: bool,
    /// 内容域：短响应头预算（2s）、竞速拨号、游标不记。
    pub content: bool,
    /// 会话域带用户会话、跨 IP 是风控特征，只标实测出拦截页的主站族，own 过滤只认自建通道；内容型子域写进 ips 节点的 hosts 即豁免通配。
    pub session: bool,
    /// 大文件域：单通道（一条长流占满槽位）+ 大镜像链。数据源自 mirrors_big 键集。
    pub big: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fallback {
    #[default]
    Dns,
    MirrorDns,
}

/// `hosts` 块一条；域名键在外层，解析时补进 `key`。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HostSpec {
    #[serde(default)]
    pub key: String,
    /// 目前只有 "direct"。
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub content: bool,
    /// 会话域：带用户会话、跨 IP 是风控特征——own 过滤（只认自建通道）。
    #[serde(default)]
    pub session: bool,
    /// 大文件域：单通道 + 大镜像链。
    #[serde(default)]
    pub big: bool,
    /// "dns"（默认）或 "mirror"。
    #[serde(default)]
    pub fallback: Option<String>,
}

/// `ips` 块一条：伪装身份 + 支持的路由键。`ip` 末段支持 `a-b` 展开。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IpSpec {
    #[serde(default)]
    pub ip: String,
    /// ClientHello SNI：骗墙用，与目标 host 无关。
    #[serde(default)]
    pub sni: String,
    /// 证书校验锚点：空 = 按目标 host 校验；只有目标不在该 IP 默认证书 SAN 上才填，填哪个都行（域名由 :authority 定）。
    #[serde(default)]
    pub verify: String,
    /// 本节点服务的路由键列表。
    #[serde(default)]
    pub hosts: Vec<String>,
    /// 拨号实测毫秒（0 = 未测）。旧文件曾用 `{具体 IP: 毫秒}` 映射，单 IP 节点收编为标量；
    /// 兼容两种读取，写盘统一标量。
    #[serde(default, deserialize_with = "deserialize_latency")]
    pub latency: Option<u64>,
}

/// 旧布局兼容：节点条目里的 latency 曾是 `{具体 IP: 毫秒}` 映射（range 时代每个展开 IP 各记各的）。
/// 单 IP 节点恰有一条 → 收编为标量；多条（旧范围节点）无法对应，放弃让拨号重测。
fn deserialize_latency<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => Ok(n.as_u64()),
        serde_json::Value::Object(map) if map.len() == 1 => {
            Ok(map.values().next().and_then(|x| x.as_u64()))
        }
        _ => Ok(None),
    }
}

/// 运行时节点：单个具体 IP + 伪装身份。
#[derive(Debug)]
pub struct IpNode {
    /// 原始 ip 表达式，落盘回写用。
    pub raw: String,
    pub ips: Vec<String>,
    pub sni: String,
    pub verify: String,
    /// 服务的路由键。
    pub hosts: Vec<String>,
    /// 拨号实测毫秒：拨号事件回流更新（原子量，拓扑在 Arc 下共享）。
    pub latency: AtomicU64,
}

impl Clone for IpNode {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            ips: self.ips.clone(),
            sni: self.sni.clone(),
            verify: self.verify.clone(),
            hosts: self.hosts.clone(),
            latency: AtomicU64::new(self.latency.load(Ordering::Relaxed)),
        }
    }
}

/// 拨号候选：一个具体 IP 的完整伪装身份。
#[derive(Clone, Debug)]
pub struct NodeIp {
    pub ip: String,
    pub sni: String,
    pub verify: String,
    /// 拨号实测毫秒（0 = 未测）：串发排序用。
    pub latency: u64,
}

/// host 侧路由行；裸键含自身+子域，`*.` 仅子域，最长键胜。
pub struct RouteRow {
    pub key: String,
    pub flags: Flags,
    pub fallback: Fallback,
    /// 去掉 `*.` 的裸域名，全小写。
    bare: String,
    /// `*.` 前缀：只认子域，裸域不命中。
    sub_only: bool,
    /// 具体度 = bare 的字符数；多条同时命中时长的胜。
    rank: usize,
}

impl RouteRow {
    pub fn new(spec: HostSpec) -> Result<Self, String> {
        let key = spec.key.trim().trim_end_matches('.').to_string();
        if key.is_empty() {
            return Err("key 为空".to_string());
        }
        let lower = key.to_ascii_lowercase();
        let (sub_only, bare) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest.to_string()),
            None => (false, lower),
        };
        if bare.is_empty() {
            return Err(format!("key {key:?} 缺域名"));
        }
        if bare.contains('*') {
            return Err(format!("key {key:?} 只允许开头一个 `*.`"));
        }
        if !bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(format!(
                "key {key:?} 含非法字符（域名只允许字母数字 . - _）"
            ));
        }
        if !bare.contains('.') || bare.starts_with('.') {
            return Err(format!("key {key:?} 不像域名（至少一个点）"));
        }
        let fallback = match spec.fallback.as_deref().unwrap_or("dns") {
            "dns" => Fallback::Dns,
            "mirror" => Fallback::MirrorDns,
            other => return Err(format!("key {key:?} fallback 未知({other})")),
        };
        let direct = match spec.action.as_deref().unwrap_or("") {
            "" => false,
            "direct" => true,
            other => return Err(format!("key {key:?} action 未知({other})")),
        };
        Ok(Self {
            rank: bare.len(),
            key,
            flags: Flags {
                direct,
                content: spec.content,
                session: spec.session,
                big: spec.big,
            },
            fallback,
            bare,
            sub_only,
        })
    }

    /// host 命中要求点分隔：foo.github.com 命中 github.com，evilgithub.com 不命中。
    #[inline]
    fn hits(&self, host_lower: &str) -> bool {
        if host_lower.len() > self.bare.len() && host_lower.ends_with(&self.bare) {
            // 边界必须是点：github.com 命中，xgithub.com 不命中
            if host_lower.as_bytes()[host_lower.len() - self.bare.len() - 1] == b'.' {
                return true;
            }
        }
        !self.sub_only && host_lower == self.bare
    }
}

/// 表 + 反向索引一体：Arc 持有，脱离锁安全读（不出本模块，pub 字段供同模块方法用）。
struct Topology {
    rows: Vec<RouteRow>,
    nodes: Vec<IpNode>,
    /// 路由键 → 节点下标。
    host_index: HashMap<String, Vec<usize>>,
}

impl Topology {
    fn build(rows: Vec<RouteRow>, nodes: Vec<IpNode>) -> Self {
        let mut host_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            for k in &n.hosts {
                host_index.entry(k.clone()).or_default().push(i);
            }
        }
        Self {
            rows,
            nodes,
            host_index,
        }
    }
}

static TABLE: Mutex<Option<Arc<Topology>>> = Mutex::new(None);

/// host → 命中的下标；路由表装载后不再变化，缓存无需失效。
static MEMO: Mutex<Option<HashMap<String, Option<usize>>>> = Mutex::new(None);

/// 装载路由表（启动一次；测试可反复调用）。
pub fn install(rows: Vec<RouteRow>, nodes: Vec<IpNode>) {
    let topo = Arc::new(Topology::build(rows, nodes));
    *lock(&TABLE) = Some(topo);
    *lock(&MEMO) = Some(HashMap::new());
}

/// 命中的路由行。
pub struct Hit {
    topo: Arc<Topology>,
    idx: usize,
}

impl std::ops::Deref for Hit {
    type Target = RouteRow;
    fn deref(&self) -> &RouteRow {
        &self.topo.rows[self.idx]
    }
}

pub fn route_for(host: &str) -> Option<Hit> {
    let topo = lock(&TABLE).as_ref()?.clone();
    let mut memo = lock(&MEMO);
    let memo = memo.as_mut()?;
    let idx = match memo.get(host) {
        Some(v) => *v,
        None => {
            // 域名不区分大小写；每个 host 只算一次，结果进 memo。
            let lower = host.to_ascii_lowercase();
            let mut best: Option<usize> = None;
            for (i, r) in topo.rows.iter().enumerate() {
                if !r.hits(&lower) {
                    continue;
                }
                // 同 rank 时更具体的声明胜，否则 github.com 与 *.github.com 谁赢靠文件顺序。
                let better = match best {
                    None => true,
                    Some(b) => {
                        let cur = &topo.rows[b];
                        r.rank > cur.rank || (r.rank == cur.rank && r.sub_only && !cur.sub_only)
                    }
                };
                if better {
                    best = Some(i);
                }
            }
            if memo.len() < 4096 {
                memo.insert(host.to_string(), best);
            }
            best
        }
    }?;
    Some(Hit { topo, idx })
}

/// 查询管线：host → 邻接节点展开 IP → 滤黑边 → 去重；verify 空 = 按目标校验；None = 不在表，Some(空) = 全黑。
pub fn dial_targets(host: &str) -> Option<Vec<NodeIp>> {
    let topo = lock(&TABLE).as_ref()?.clone();
    let row_idx = route_for(host)?.idx;
    let key = &topo.rows[row_idx].key;
    let host_lower = host.to_ascii_lowercase();
    let mut out: Vec<NodeIp> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for &ni in topo.host_index.get(key).into_iter().flatten() {
        let node = &topo.nodes[ni];
        for ip in &node.ips {
            if !seen.insert(ip.as_str()) || edges::is_bad(ip, key) {
                continue;
            }
            out.push(NodeIp {
                ip: ip.clone(),
                sni: node.sni.clone(),
                verify: if node.verify.is_empty() {
                    host_lower.clone()
                } else {
                    node.verify.clone()
                },
                latency: node.latency.load(Ordering::Relaxed),
            });
        }
    }
    Some(out)
}

/// 按具体 IP 找节点（单 IP 节点：ips 恰含它）。
fn node_index_by_ip(topo: &Topology, ip: &str) -> Option<usize> {
    topo.nodes
        .iter()
        .position(|n| n.ips.first().is_some_and(|a| a == ip))
}

/// 拨号实测回流：与旧值取均值防 GFW 抖动一刀切；未测直入。
pub fn note_latency(ip: &str, ms: u64) {
    let topo = match lock(&TABLE).as_ref() {
        Some(t) => t.clone(),
        None => return,
    };
    let Some(i) = node_index_by_ip(&topo, ip) else {
        return;
    };
    let node = &topo.nodes[i];
    let old = node.latency.load(Ordering::Relaxed);
    let v = if old == 0 { ms } else { (old + ms) / 2 };
    node.latency.store(v, Ordering::Relaxed);
}

/// 黑洞降权：实测翻倍（3s~10s）沉到已测队尾，不沉过未测候选，60s 内随正常样本稀释恢复。
pub fn sink_latency(ip: &str) {
    let topo = match lock(&TABLE).as_ref() {
        Some(t) => t.clone(),
        None => return,
    };
    let Some(i) = node_index_by_ip(&topo, ip) else {
        return;
    };
    let node = &topo.nodes[i];
    let old = node.latency.load(Ordering::Relaxed);
    let v = match old {
        0 => 3000,
        o => (o * 2).clamp(3000, 10000),
    };
    node.latency.store(v, Ordering::Relaxed);
}

/// 该 IP 的实测拨号毫秒；未测 = 0。
pub(crate) fn latency_of(ip: &str) -> u64 {
    let topo = match lock(&TABLE).as_ref() {
        Some(t) => t.clone(),
        None => return 0,
    };
    node_index_by_ip(&topo, ip)
        .map(|i| topo.nodes[i].latency.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// 受管（会进代理）的域名？direct 行不算。
pub fn is_managed(host: &str) -> bool {
    route_for(host).is_some_and(|r| !r.flags.direct)
}

pub fn is_content(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.content)
}

pub fn fallback_for(host: &str) -> Fallback {
    route_for(host).map_or(Fallback::Dns, |r| r.fallback)
}

/// 游标键只记串发域主键；内容域竞速无人读、直连行不占键；settings.lastIp 键位顺序恒为此表。
pub fn cursor_keys() -> Vec<String> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(t.rows.len());
    for r in t.rows.iter() {
        if r.flags.direct || r.flags.content {
            continue;
        }
        out.push(r.key.clone());
    }
    out
}

/// PAC 用：(走代理的裸域名, 直连的具体 host)。
pub fn pac_lists() -> (Vec<String>, Vec<String>) {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return (Vec::new(), Vec::new());
    };
    let mut proxy = Vec::new();
    let mut direct = Vec::new();
    for r in t.rows.iter() {
        let slot = if r.flags.direct { &mut direct } else { &mut proxy };
        if !slot.contains(&r.bare) {
            slot.push(r.bare.clone());
        }
    }
    (proxy, direct)
}

/// 落盘用 host 侧快照。
pub struct HostMeta {
    pub key: String,
    pub flags: Flags,
    pub fallback: Fallback,
}

pub fn hosts_snapshot() -> Vec<HostMeta> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    t.rows
        .iter()
        .map(|r| HostMeta {
            key: r.key.clone(),
            flags: r.flags.clone(),
            fallback: r.fallback,
        })
        .collect()
}

/// 落盘用节点侧快照。
pub fn nodes_snapshot() -> Vec<IpNode> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    t.nodes.clone()
}

pub fn route_count() -> usize {
    lock(&TABLE).as_ref().map_or(0, |t| t.rows.len())
}

/// 概览数字：节点展开后的具体 IP 总数（去重）。
pub fn ip_count() -> usize {
    lock(&TABLE).as_ref().map_or(0, |t| {
        t.nodes
            .iter()
            .flat_map(|n| n.ips.iter().map(String::as_str))
            .collect::<std::collections::HashSet<_>>()
            .len()
    })
}

// ---- 镜像链归属（与拨号路由正交，仍按 host 形状判定）----

/// 大文件域：objects/release-assets 附件 302 落点，由 hosts 标志 big:true 判定（数据，不硬编码域名）。
pub fn is_big_file_host(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.big)
}

/// github.com 仓库附件下载路径（/releases/download/...）：镜像链归属 release-assets。
fn is_release_asset_path(host: &str, path: &str) -> bool {
    if host != "github.com" {
        return false;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        (segs.get(2), segs.get(3), segs.get(4)),
        (Some(&"releases"), Some(&"download"), _)
            | (Some(&"releases"), Some(&"latest"), Some(&"download"))
    )
}

/// 镜像链归属：请求 host → 实际内容 host 的专属链。（codeload 已迁池，Archive 路径不再走镜像。）
pub fn mirror_chain_host<'a>(host: &'a str, path: &'a str) -> &'a str {
    if is_big_file_host(host) {
        return host;
    }
    if is_release_asset_path(host, path) {
        "release-assets.githubusercontent.com"
    } else {
        host
    }
}

/// 总路由判定：生产只分流镜像（大文件域/附件 GET|HEAD → Mirror），直连行/表外/其余
/// 各走既定管线（System/Tunnel/Pool）——四值枚举里只有 Mirror 被读，坍成布尔。
pub fn is_mirror_route(host: &str, method: &str, path: &str) -> bool {
    let Some(row) = route_for(host) else {
        return false;
    };
    if row.flags.direct {
        return false;
    }
    matches!(method, "GET" | "HEAD")
        && (is_big_file_host(host) || is_release_asset_path(host, path))
}

#[cfg(test)]
#[path = "../tests/pool/route.rs"]
mod tests;
