//! 暂缓/复测账本：判黑通道先停车，60s 到期由真实流量复验；换血按 host 限频。测速判定已拆。
use crate::util::lock;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// 暂缓时长：判黑通道不发，到期复测，不重拨。
const BENCH_SECS: u64 = 60;
/// 每 host 重建最短间隔：并发报黑只触发一轮。
const REBUILD_COOLDOWN_SECS: u64 = 60;

/// 暂缓表：ip → 到期时刻。
static BENCH: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 暂缓：判黑通道不发 60s，到期复测，不重拨。
pub fn bench(ip: &str) {
    let mut t = lock(&BENCH);
    // 过期清理放低频写入路径；usable 热路径不全表扫。
    let now = Instant::now();
    t.retain(|_, u| now < *u);
    let until = now + Duration::from_secs(BENCH_SECS);
    if t.get(ip).is_none_or(|u| until > *u) {
        t.insert(ip.to_string(), until);
    }
}

/// 软排除只摘暂缓 IP；全暂缓则原样返回，绝不筛空。
pub fn usable(ips: &[String]) -> Vec<String> {
    let t = lock(&BENCH);
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
    let t = lock(&BENCH);
    t.get(ip)
        .map(|u| u.saturating_duration_since(Instant::now()).as_secs())
        .filter(|s| *s > 0)
}

/// 单 host 重建节奏：60s 限流，无熔断。
#[derive(Default)]
struct HostRace {
    last: Option<Instant>,
}

static HOSTS: LazyLock<Mutex<HashMap<String, HostRace>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 检查+写入必须一次持锁完成（否则并发报黑全触发换血）。
pub fn try_begin_rebuild(host: &str) -> bool {
    let mut m = lock(&HOSTS);
    // 清 24h 无动静的 host 条目。
    let cutoff = Instant::now() - Duration::from_secs(24 * 3600);
    m.retain(|_, st| st.last.is_some_and(|t| t > cutoff));
    if m.len() > 1024 {
        m.clear();
    }
    let st = m.entry(host.to_string()).or_default();
    if st
        .last
        .is_some_and(|t| Instant::now().duration_since(t).as_secs() < REBUILD_COOLDOWN_SECS)
    {
        return false;
    }
    st.last = Some(Instant::now());
    true
}

/// 测试专用：清空暂缓表与重建节奏表。
#[cfg(test)]
pub(crate) fn clear() {
    *lock(&BENCH) = HashMap::new();
    *lock(&HOSTS) = HashMap::new();
}

#[cfg(test)]
#[path = "../tests/pool/speed.rs"]
mod tests;
