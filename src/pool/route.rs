//! 路由表：plans.json 的 `routes` 数组，整串正则匹配，从上往下先命中先用。
//!
//! 这张表是唯一真相：一个 host 用哪组 IP、握手用真名还是伪装、全灭后走镜像还是 DNS。
//! 代码里不再有"IP 末段是多少"的判断——加 IP 只改 plans.json。

use super::SerialPlan;
use crate::util::lock;
use regex_lite::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    System,
    Mirror,
    Pool,
    Tunnel,
}

/// 一条路由的开关位；全部来自 plans.json，不从 host 形态推断。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// 本机直连，不进代理。
    pub direct: bool,
    /// 真名 SNI + ClientHello 分片：伪装会被上游判非法的域用。
    pub real: bool,
    /// 内容域：走熔断与短响应预算。
    pub content: bool,
    /// 可被借道当 donor。
    pub donor: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fallback {
    #[default]
    Dns,
    MirrorDns,
}

/// plans.json 里一条 routes 的原始形状。
#[derive(Debug, Clone, Deserialize)]
pub struct RouteSpec {
    #[serde(rename = "match")]
    pub matcher: String,
    #[serde(default)]
    pub pac: Option<String>,
    /// 目前只有 "direct"。
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub real: bool,
    #[serde(default)]
    pub content: bool,
    #[serde(default)]
    pub donor: bool,
    /// "dns"（默认）或 "mirror"。
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub plans: Vec<SerialPlan>,
    /// 只在真名腿（隧道 / real 路由）额外可用的 IP。
    #[serde(default, rename = "realPlans")]
    pub real_plans: Vec<SerialPlan>,
}

pub struct RouteRow {
    pub pattern: String,
    pub pac: Option<String>,
    pub flags: Flags,
    pub fallback: Fallback,
    pub plans: Vec<SerialPlan>,
    pub real_plans: Vec<SerialPlan>,
    re: Regex,
}

impl RouteRow {
    pub fn new(spec: RouteSpec) -> Result<Self, String> {
        let pattern = spec.matcher.trim().to_string();
        if pattern.is_empty() {
            return Err("match 为空".to_string());
        }
        // 整串匹配：用户写 github\.com 就只匹配它自己，不用记锚点。
        let re = Regex::new(&format!("^(?:{pattern})$"))
            .map_err(|e| format!("match {pattern:?} 正则无效: {e}"))?;
        let fallback = match spec.fallback.as_deref().unwrap_or("dns") {
            "dns" => Fallback::Dns,
            "mirror" => Fallback::MirrorDns,
            other => return Err(format!("match {pattern:?} fallback 未知({other})")),
        };
        let direct = match spec.action.as_deref().unwrap_or("") {
            "" => false,
            "direct" => true,
            other => return Err(format!("match {pattern:?} action 未知({other})")),
        };
        Ok(Self {
            pattern,
            pac: spec.pac,
            flags: Flags {
                direct,
                real: spec.real,
                content: spec.content,
                donor: spec.donor,
            },
            fallback,
            plans: spec.plans,
            real_plans: spec.real_plans,
            re,
        })
    }

    /// 拨号候选：真名腿（隧道 / real 路由）额外带上 realPlans。
    pub fn dial_plans(&self, real_wire: bool) -> Vec<SerialPlan> {
        let mut out = self.plans.clone();
        if real_wire {
            out.extend(self.real_plans.iter().cloned());
        }
        out
    }
}

/// 落盘用的快照（不含正则）。
pub struct RowMeta {
    pub pattern: String,
    pub pac: Option<String>,
    pub flags: Flags,
    pub fallback: Fallback,
    pub plans: Vec<SerialPlan>,
    pub real_plans: Vec<SerialPlan>,
}

static TABLE: Mutex<Option<Arc<Vec<RouteRow>>>> = Mutex::new(None);

/// host → 命中的下标；路由表装载后不再变化，缓存无需失效。
static MEMO: Mutex<Option<HashMap<String, Option<usize>>>> = Mutex::new(None);

/// 装载路由表（启动一次；测试可反复调用）。
pub fn install(rows: Vec<RouteRow>) {
    *lock(&TABLE) = Some(Arc::new(rows));
    *lock(&MEMO) = Some(HashMap::new());
}

/// 命中的路由行；持有表的 Arc，脱离锁也能安全读。
pub struct Hit {
    table: Arc<Vec<RouteRow>>,
    idx: usize,
}

impl std::ops::Deref for Hit {
    type Target = RouteRow;
    fn deref(&self) -> &RouteRow {
        &self.table[self.idx]
    }
}

pub fn route_for(host: &str) -> Option<Hit> {
    let table = lock(&TABLE).as_ref()?.clone();
    let mut memo = lock(&MEMO);
    let memo = memo.as_mut()?;
    let idx = match memo.get(host) {
        Some(v) => *v,
        None => {
            let i = table.iter().position(|r| r.re.is_match(host));
            if memo.len() < 4096 {
                memo.insert(host.to_string(), i);
            }
            i
        }
    }?;
    Some(Hit { table, idx })
}

/// 受管（会进代理）的域名？direct 行不算。
pub fn is_managed(host: &str) -> bool {
    route_for(host).is_some_and(|r| !r.flags.direct)
}

pub fn is_content(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.content)
}

pub fn is_donor(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.donor)
}

pub fn is_real(host: &str) -> bool {
    route_for(host).is_some_and(|r| r.flags.real)
}

pub fn fallback_for(host: &str) -> Fallback {
    route_for(host).map_or(Fallback::Dns, |r| r.fallback)
}

/// 游标键：每条非直连路由两把（主键 / `~2` 副键），双通道各记各的。
pub fn cursor_keys() -> Vec<String> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(t.len() * 2);
    for r in t.iter() {
        if r.flags.direct {
            continue;
        }
        out.push(r.pattern.clone());
        out.push(format!("{}~2", r.pattern));
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
    for r in t.iter() {
        let Some(pac) = r.pac.as_ref() else { continue };
        if r.flags.direct {
            if !direct.contains(pac) {
                direct.push(pac.clone());
            }
        } else if !proxy.contains(pac) {
            proxy.push(pac.clone());
        }
    }
    (proxy, direct)
}

pub fn snapshot() -> Vec<RowMeta> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return Vec::new();
    };
    t.iter()
        .map(|r| RowMeta {
            pattern: r.pattern.clone(),
            pac: r.pac.clone(),
            flags: r.flags,
            fallback: r.fallback,
            plans: r.plans.clone(),
            real_plans: r.real_plans.clone(),
        })
        .collect()
}

pub fn route_count() -> usize {
    lock(&TABLE).as_ref().map_or(0, |t| t.len())
}

pub fn plan_count() -> usize {
    let g = lock(&TABLE);
    g.as_ref()
        .map(|t| {
            t.iter()
                .map(|r| r.plans.len() + r.real_plans.len())
                .sum()
        })
        .unwrap_or(0)
}

// ---- 镜像链归属（与拨号路由正交，仍按 host 形状判定）----

/// 大文件下载域（分片竞速）：objects/release-assets=附件 302 落点。
pub fn is_big_file_host(host: &str) -> bool {
    matches!(
        host,
        "objects.githubusercontent.com" | "release-assets.githubusercontent.com"
    )
}

/// 整域镜像域：大文件域 + codeload。
pub fn is_whole_domain_mirror(host: &str) -> bool {
    is_big_file_host(host) || host == "codeload.github.com"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetKind {
    Release,
    Archive,
}

fn release_asset_kind(host: &str, path: &str) -> Option<AssetKind> {
    if host != "github.com" {
        return None;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (segs.get(2), segs.get(3), segs.get(4)) {
        (Some(&"archive"), ..) => Some(AssetKind::Archive),
        (Some(&"releases"), Some(&"download"), _) => Some(AssetKind::Release),
        (Some(&"releases"), Some(&"latest"), Some(&"download")) => Some(AssetKind::Release),
        _ => None,
    }
}

fn is_release_asset_path(host: &str, path: &str) -> bool {
    release_asset_kind(host, path).is_some()
}

/// 镜像链归属：请求 host → 实际内容 host 的专属链。
pub fn mirror_chain_host<'a>(host: &'a str, path: &'a str) -> &'a str {
    if is_whole_domain_mirror(host) {
        return host;
    }
    match release_asset_kind(host, path) {
        Some(AssetKind::Archive) => "codeload.github.com",
        Some(AssetKind::Release) => "release-assets.githubusercontent.com",
        None => host,
    }
}

/// 总路由：命中直连行 → System；未命中 → Tunnel；其余按镜像路径分流。
pub fn master_route(host: &str, method: &str, path: &str) -> Route {
    let Some(row) = route_for(host) else {
        return Route::Tunnel;
    };
    if row.flags.direct {
        return Route::System;
    }
    if matches!(method, "GET" | "HEAD")
        && (is_whole_domain_mirror(host) || is_release_asset_path(host, path))
    {
        return Route::Mirror;
    }
    Route::Pool
}

#[cfg(test)]
#[path = "../tests/pool/route.rs"]
mod tests;
