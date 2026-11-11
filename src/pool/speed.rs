//! 通道池的速度账本：**被动测速**——每条通道挂 500ms ECT 窗（H2Upstream.ect），
//! 每流速度 = 上一窗实收 ÷ 在途流数，通道闲置窗口自然归零、零门槛零样本。
//! 本文件只管：够用线/触发线判定的分流（暂缓/解锁）与换血节奏（60s 冷却限流）。
use crate::util::lock;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 触发线：比够用线再降一档。只有候选里所有已测通道都低于它（主副全低）才值得
/// 催建连机器人补齐；还有一条在它之上就把请求让给它，将就用不折腾。
pub const TRIGGER_KBPS: f64 = 45.0;
/// 够用线：每流速度达到就认定够快，解暂缓。
pub const TARGET_KBPS: f64 = 50.0;
/// 暂缓时长：不够够用线的通道先放着不发，下一轮触发时复测，不重拨。
const BENCH_SECS: u64 = 60;
/// 每 host 两轮重建之间的最短间隔：一页几百个请求同时报慢也只触发一轮。
const REBUILD_COOLDOWN_SECS: u64 = 60;

/// 暂缓表：ip → 到期时刻。
static BENCH: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// 暂缓：不够够用线的通道先不发（60 秒），下一轮触发时复测，不重拨。
pub fn bench(ip: &str) {
    let mut g = lock(&BENCH);
    let t = g.get_or_insert_with(HashMap::new);
    let until = Instant::now() + Duration::from_secs(BENCH_SECS);
    if t.get(ip).is_none_or(|u| until > *u) {
        t.insert(ip.to_string(), until);
    }
}

/// 达标即解暂缓：这条通道已经够快，立刻恢复发单。
pub fn release(ip: &str) {
    lock(&BENCH).as_mut().and_then(|t| t.remove(ip));
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
