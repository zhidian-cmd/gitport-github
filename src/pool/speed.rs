//! 通道池的暂缓/复测账本：判黑的通道先停车不发（60s 到期由真实流量复验），
//! 换血按 host 限频（60s 冷却）。测速判定已拆除——失败信号（黑洞/超时/拨号失败）全权处置。
use crate::util::lock;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 暂缓时长：判黑的通道先放着不发，到期复测，不重拨。
const BENCH_SECS: u64 = 60;
/// 每 host 两轮重建之间的最短间隔：一页几百个请求同时报黑也只触发一轮。
const REBUILD_COOLDOWN_SECS: u64 = 60;

/// 暂缓表：ip → 到期时刻。
static BENCH: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// 暂缓：判黑的通道先不发（60 秒），到期复测，不重拨。
pub fn bench(ip: &str) {
    let mut g = lock(&BENCH);
    let t = g.get_or_insert_with(HashMap::new);
    let until = Instant::now() + Duration::from_secs(BENCH_SECS);
    if t.get(ip).is_none_or(|u| until > *u) {
        t.insert(ip.to_string(), until);
    }
}

/// 软排除：从候选里摘掉暂缓中的 IP。
/// 全部暂缓时原样返回——「全慢才回来」就落在这里，绝不因为筛选把候选清空。
pub fn usable(ips: &[String]) -> Vec<String> {
    let g = lock(&BENCH);
    let Some(t) = g.as_ref() else {
        return ips.to_vec();
    };
    let now = Instant::now();
    let live: Vec<String> = ips
        .iter()
        .filter(|ip| !t.get(*ip).is_some_and(|u| now < *u))
        .cloned()
        .collect();
    if live.is_empty() {
        ips.to_vec()
    } else {
        live
    }
}

/// 暂缓剩余秒数（状态行用）；未暂缓/已到期 = None。
pub fn bench_remaining_secs(ip: &str) -> Option<u64> {
    let g = lock(&BENCH);
    g.as_ref()?
        .get(ip)
        .map(|u| u.saturating_duration_since(Instant::now()).as_secs())
        .filter(|s| *s > 0)
}

/// 单 host 的重建节奏：60s 一轮限流（探针已摘，无熔断——限流即约束）。
#[derive(Default)]
struct HostRace {
    last: Option<Instant>,
}

static HOSTS: Mutex<Option<HashMap<String, HostRace>>> = Mutex::new(None);

/// 现在能不能为这个 host 触发一轮重建：冷却中不行。
pub fn may_rebuild(host: &str) -> bool {
    let g = lock(&HOSTS);
    match g.as_ref().and_then(|m| m.get(host)) {
        None => true,
        Some(st) => st
            .last
            .is_none_or(|t| Instant::now().duration_since(t).as_secs() >= REBUILD_COOLDOWN_SECS),
    }
}

/// 记一轮重建开始。
pub fn begin_rebuild(host: &str) {
    let mut g = lock(&HOSTS);
    let m = g.get_or_insert_with(HashMap::new);
    m.entry(host.to_string()).or_default().last = Some(Instant::now());
}

/// 测试专用：清空暂缓表与重建节奏表。
#[cfg(test)]
pub(crate) fn clear() {
    *lock(&BENCH) = Some(HashMap::new());
    *lock(&HOSTS) = Some(HashMap::new());
}

#[cfg(test)]
#[path = "../tests/pool/speed.rs"]
mod tests;
