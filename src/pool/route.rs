//! 路由表 v2：二部图。`ips` 节点（伪装身份与目标 host 无关）× `hosts` 行（开关位），
//! 边 = 节点服务该路由键；`routes.json` 的 `ips`/`hosts` 两块 + 运行时反向索引。

use super::edges;
use crate::util::lock;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    System,
    Mirror,
    Pool,
    Tunnel,
}

/// host 侧开关位；全部来自 routes.json 的 hosts 块。
#[derive(Debug, Clone, Default)]
pub struct Flags {
    /// 本机直连，不进代理。
    pub direct: bool,
    /// 内容域：走熔断与短响应预算。
    pub content: bool,
    /// 会话域：带用户会话、跨 IP 是风控特征——长期通道 + ping 闸 + own 过滤。
    /// 只标实测出拦截页的主站族（github.com / *.github.com / api.github.com）。
    /// 内容型的子域不做通配排除——直接写进 ips 节点的 hosts（写完整即豁免，
    /// 具体键最长匹配天然压过通配）。
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
    /// 会话域：带用户会话、跨 IP 是风控特征——长期通道 + ping 闸 + own 过滤。
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
    /// 证书校验锚点：空 = 拿目标 host 当锚点。只有目标 host 不在该 IP 默认证书的 SAN 上时才需要填，
    /// 填哪个都行（证明"对面持有 GitHub 证书"即可，域名由 h2 的 `:authority` 说了算）。
    #[serde(default)]
    pub verify: String,
    /// 本节点服务的路由键列表。
    #[serde(default)]
    pub hosts: Vec<String>,
    /// 测速值（`{具体 IP: 毫秒}`）：跟着节点条目走，range 节点每个展开 IP 各记各的。
    #[serde(default)]
    pub latency: HashMap<String, u64>,
}

/// 展开后的运行时节点：具体 IP 组 + 伪装身份。
#[derive(Clone, Debug)]
pub struct IpNode {
    /// 原始 ip 表达式（含段展开写法），落盘回写用。
    pub raw: String,
    pub ips: Vec<String>,
    pub sni: String,
    pub verify: String,
    /// 服务的路由键。
    pub hosts: Vec<String>,
}

/// 拨号候选：一个具体 IP 的完整伪装身份。
#[derive(Clone, Debug)]
pub struct NodeIp {
    pub ip: String,
    pub sni: String,
    pub verify: String,
    /// 装表时算好：这个 IP 会被多个 host 用到（prefer_shared 分档排序用）。
    pub shared: bool,
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

    /// 这个 host（已小写）命中本行吗？`foo.github.com` 命中 `github.com`；
    /// `evilgithub.com` 不命中（要求点分隔）。
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

/// 单段 `a-b` 数字范围展开；非范围段原样返回单项。
fn expand_seg(seg: &str, key: &str) -> Result<Vec<String>, String> {
    if let Some((a, b)) = seg.split_once('-') {
        let a: u32 = a
            .parse()
            .map_err(|_| format!("ip {key:?} 段 {seg:?} 起点不是数字"))?;
        let b: u32 = b
            .parse()
            .map_err(|_| format!("ip {key:?} 段 {seg:?} 终点不是数字"))?;
        if a > b || b > 255 {
            return Err(format!("ip {key:?} 段 {seg:?} 越界(要求 0≤a≤b≤255)"));
        }
        return Ok((a..=b).map(|n| n.to_string()).collect());
    }
    Ok(vec![seg.to_string()])
}

/// 末段范围展开：`140.82.112-114.5-6` → 6 个 IP；多段范围做笛卡尔积，上限 64。
pub fn expand_ip(spec: &str) -> Result<Vec<String>, String> {
    let spec = spec.trim();
    // 每段先各自展开成选项，再逐段拼前缀（笛卡尔积）。
    let mut prefixes: Vec<String> = vec![String::new()];
    for seg in spec.split('.') {
        let outs = expand_seg(seg, spec)?;
        let mut next: Vec<String> = Vec::with_capacity(prefixes.len() * outs.len());
        for prefix in &prefixes {
            for o in &outs {
                next.push(if prefix.is_empty() {
                    o.clone()
                } else {
                    format!("{prefix}.{o}")
                });
            }
        }
        prefixes = next;
        if prefixes.len() > 64 {
            return Err(format!("ip {spec:?} 展开超过 64 个"));
        }
    }
    Ok(prefixes)
}

/// 表 + 反向索引一体：Arc 持有，脱离锁安全读。
pub struct Topology {
    pub rows: Vec<RouteRow>,
    pub nodes: Vec<IpNode>,
    /// 路由键 → 节点下标。
    host_index: HashMap<String, Vec<usize>>,
    /// 装表时算好的共享 IP：挂了 2 个以上路由键，或含 `*.` 通配键（一个键背后几十个 host）。
    shared: HashSet<String>,
}

impl Topology {
    fn build(rows: Vec<RouteRow>, nodes: Vec<IpNode>) -> Self {
        let mut host_index: HashMap<String, Vec<usize>> = HashMap::new();
        // 按具体 IP 聚合，不按节点数：一个 IP 被拆到几个节点各挂一键，照样是共享。
        let mut keys_per_ip: HashMap<String, HashSet<String>> = HashMap::new();
        let mut wildcard: HashSet<String> = HashSet::new();
        for (i, n) in nodes.iter().enumerate() {
            for k in &n.hosts {
                host_index.entry(k.clone()).or_default().push(i);
                for ip in &n.ips {
                    keys_per_ip.entry(ip.clone()).or_default().insert(k.clone());
                    if k.starts_with("*.") {
                        wildcard.insert(ip.clone());
                    }
                }
            }
        }
        // 宁可多标（只是多个标记），不能漏标（漏了 prefer_shared 分档就失真）。
        let shared: HashSet<String> = keys_per_ip
            .into_iter()
            .filter(|(ip, keys)| keys.len() >= 2 || wildcard.contains(ip))
            .map(|(ip, _)| ip)
            .collect();
        Self {
            rows,
            nodes,
            host_index,
            shared,
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

impl Hit {
    pub fn row_idx(&self) -> usize {
        self.idx
    }
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
                // 同 rank 时更具体的声明胜：`*.x`（仅子域）压过等长的裸键 `x`（自身+任意级子域）。
                // 没有这条，`github.com` 与 `*.github.com` 就靠文件顺序决定谁赢。
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

/// 查询管线②③：host → 邻接节点展开成具体 IP → 滤黑边 → 去重。
/// 节点 verify 留空 = 按目标 host 校验（迁移期安全默认，等价 v1 行为）。
/// 返回 None = host 不在表（走 Tunnel）；Some(空) = 全黑（走 fallback）。
pub fn dial_targets(host: &str) -> Option<Vec<NodeIp>> {
    let topo = lock(&TABLE).as_ref()?.clone();
    let row_idx = route_for(host)?.row_idx();
    let key = &topo.rows[row_idx].key;
    let host_lower = host.to_ascii_lowercase();
    let mut out: Vec<NodeIp> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for &ni in topo.host_index.get(key).into_iter().flatten() {
        let node = &topo.nodes[ni];
        for ip in &node.ips {
            if seen.contains(&ip.as_str()) || edges::is_bad(ip, key) {
                continue;
            }
            seen.push(ip);
            out.push(NodeIp {
                ip: ip.clone(),
                sni: node.sni.clone(),
                verify: if node.verify.is_empty() {
                    host_lower.clone()
                } else {
                    node.verify.clone()
                },
                shared: topo.shared.contains(ip),
            });
        }
    }
    Some(out)
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

/// 游标键：每条非直连路由至少一把主键；只有内容域才有 `_vice` 副键。
/// 会话域固定单通道，记副键没有意义，还会让 settings.json 里多出一堆永远为空的键。
pub fn cursor_keys() -> Vec<String> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(t.rows.len() * 2);
    for r in t.rows.iter() {
        if r.flags.direct {
            continue;
        }
        out.push(r.key.clone());
        if r.flags.content {
            out.push(format!("{}_vice", r.key));
        }
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
        if r.flags.direct {
            if !direct.contains(&r.bare) {
                direct.push(r.bare.clone());
            }
        } else if !proxy.contains(&r.bare) {
            proxy.push(r.bare.clone());
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
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return 0;
    };
    let mut seen: Vec<&str> = Vec::new();
    for n in &t.nodes {
        for ip in &n.ips {
            if !seen.contains(&ip.as_str()) {
                seen.push(ip);
            }
        }
    }
    seen.len()
}

// ---- 镜像链归属（与拨号路由正交，仍按 host 形状判定）----

/// 大文件下载域（分片竞速）：objects/release-assets=附件 302 落点。
/// 大文件域判定：routes.json/seeds.json 的 hosts 标志 `big: true`（数据，不再硬编码域名）。
pub fn is_big_file_host(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.big)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetKind {
    Release,
}

fn release_asset_kind(host: &str, path: &str) -> Option<AssetKind> {
    if host != "github.com" {
        return None;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (segs.get(2), segs.get(3), segs.get(4)) {
        (Some(&"releases"), Some(&"download"), _) => Some(AssetKind::Release),
        (Some(&"releases"), Some(&"latest"), Some(&"download")) => Some(AssetKind::Release),
        _ => None,
    }
}

fn is_release_asset_path(host: &str, path: &str) -> bool {
    release_asset_kind(host, path).is_some()
}

/// 镜像链归属：请求 host → 实际内容 host 的专属链。（codeload 已迁池，Archive 路径不再走镜像。）
pub fn mirror_chain_host<'a>(host: &'a str, path: &'a str) -> &'a str {
    if is_big_file_host(host) {
        return host;
    }
    match release_asset_kind(host, path) {
        Some(AssetKind::Release) => "release-assets.githubusercontent.com",
        None => host,
    }
}

/// 总路由：命中直连行 → System；未命中 → Tunnel；大文件域/附件路径 → Mirror；其余 Pool。
/// （codeload 已迁池：命中 github.com 裸键走 Pool。）
pub fn master_route(host: &str, method: &str, path: &str) -> Route {
    let Some(row) = route_for(host) else {
        return Route::Tunnel;
    };
    if row.flags.direct {
        return Route::System;
    }
    if matches!(method, "GET" | "HEAD")
        && (is_big_file_host(host) || is_release_asset_path(host, path))
    {
        return Route::Mirror;
    }
    Route::Pool
}

#[cfg(test)]
#[path = "../tests/pool/route.rs"]
mod tests;
