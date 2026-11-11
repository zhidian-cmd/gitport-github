//! 通道池的速度账本：只记实测吞吐，只做两件事——够不够用线、该不该催建连机器人补齐。
//!
//! 分工：建造机器人只管把通道路建出来（握手快慢是它自己的拨号排序）；
//! 池子只认真实传输的吞吐（字节 ÷ 耗时），低于够用线就暂缓这条通道、通知机器人补齐其余 IP。
use crate::util::lock;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 样本下限：小于这个字节数的响应不参与判定（小文件测不准，别让它们投票）。
pub const MIN_SAMPLE_BYTES: u64 = 64 * 1024;
/// 够用线：达到就认定够快，不再为它折腾。
pub const TARGET_KBPS: f64 = 50.0;
/// 触发线：比够用线再降一档。只有候选里所有已测通道都低于它（主副全低）才值得
/// 催建连机器人补齐；还有一条在它之上就把请求让给它，将就用不折腾。
pub const TRIGGER_KBPS: f64 = 45.0;
/// 暂缓时长：不够够用线的通道先放着不发，下一轮触发时复测，不重拨。
const BENCH_SECS: u64 = 60;
/// 每 host 两轮重建之间的最短间隔：一页几百个请求同时报慢也只触发一轮。
const REBUILD_COOLDOWN_SECS: u64 = 60;
/// EWMA 新样本权重。
const ALPHA: f64 = 0.4;

#[derive(Clone, Copy)]
struct Stat {
    /// 吞吐 EWMA（KB/s）；0 = 还没测过。
    ewma: f64,
    /// 暂缓到期时刻；None = 正常发单。
    until: Option<Instant>,
}

static TABLE: Mutex<Option<HashMap<String, Stat>>> = Mutex::new(None);

/// 状态行的样本窗：自上次取走以来各 IP 的（样本数, 吞吐和）。
static SAMPLES: Mutex<Option<HashMap<String, (u32, f64)>>> = Mutex::new(None);

/// 记一次真实传输的吞吐（只记账，不判死活）。样本不足 64KB 返回 None。
pub fn record(ip: &str, bytes: u64, ms: u64) -> Option<f64> {
    if bytes < MIN_SAMPLE_BYTES || ms == 0 {
        return None;
    }
    let kbps = bytes as f64 / 1024.0 / (ms as f64 / 1000.0);
    note_sample(ip, kbps)
}

fn note_sample(ip: &str, kbps: f64) -> Option<f64> {
    let mut g = lock(&TABLE);
    let t = g.get_or_insert_with(HashMap::new);
    let st = t.entry(ip.to_string()).or_insert(Stat {
        ewma: 0.0,
        until: None,
    });
    st.ewma = if st.ewma <= 0.0 {
        kbps
    } else {
        st.ewma * (1.0 - ALPHA) + kbps * ALPHA
    };
    let mut g = lock(&SAMPLES);
    let e = g
        .get_or_insert_with(HashMap::new)
        .entry(ip.to_string())
        .or_insert((0, 0.0));
    e.0 += 1;
    e.1 += kbps;
    Some(st.ewma)
}

/// 该 IP 的实测吞吐（KB/s）；没测过 = None。
pub fn kbps_of(ip: &str) -> Option<f64> {
    let g = lock(&TABLE);
    let st = g.as_ref()?.get(ip)?;
    if st.ewma > 0.0 {
        Some(st.ewma)
    } else {
        None
    }
}

/// 候选里是否还有已测吞吐达到 line 的通道——有 = 慢的那条只是个别现象，
/// 请求让给快的就行（将就用），不值得为它触发一轮重建。
pub fn any_at_or_above(ips: &[String], line: f64) -> bool {
    ips.iter()
        .any(|ip| kbps_of(ip).is_some_and(|k| k >= line))
}

/// 暂缓：不够够用线的通道先不发（60 秒），下一轮触发时复测，不重拨。
pub fn bench(ip: &str) {
    let mut g = lock(&TABLE);
    let t = g.get_or_insert_with(HashMap::new);
    let st = t.entry(ip.to_string()).or_insert(Stat {
        ewma: 0.0,
        until: None,
    });
    let until = Instant::now() + Duration::from_secs(BENCH_SECS);
    if st.until.is_none_or(|u| until > u) {
        st.until = Some(until);
    }
}

/// 达标即解暂缓：这条通道已经够快，立刻恢复发单。
pub fn release(ip: &str) {
    let mut g = lock(&TABLE);
    if let Some(st) = g.as_mut().and_then(|t| t.get_mut(ip)) {
        if st.ewma >= TARGET_KBPS {
            st.until = None;
        }
    }
}

/// 软排除：从候选里摘掉暂缓中的 IP。
/// 全部暂缓时原样返回——「全慢才回来」就落在这里，绝不因为筛选把候选清空。
pub fn usable(ips: &[String]) -> Vec<String> {
    let g = lock(&TABLE);
    let Some(t) = g.as_ref() else {
        return ips.to_vec();
    };
    let now = Instant::now();
    let live: Vec<String> = ips
        .iter()
        .filter(|ip| {
            !t.get(ip.as_str())
                .and_then(|s| s.until)
                .is_some_and(|u| now < u)
        })
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
    let g = lock(&TABLE);
    let st = g.as_ref()?.get(ip)?;
    st.until
        .map(|u| u.saturating_duration_since(Instant::now()).as_secs())
        .filter(|s| *s > 0)
}

/// 取走自上次取走以来累计的（IP, 样本数, 均值 KB/s）——状态行 30s 一取，取走即清。
pub fn drain_samples() -> Vec<(String, u32, f64)> {
    let mut g = lock(&SAMPLES);
    let Some(m) = g.take() else { return Vec::new() };
    m.into_iter()
        .map(|(ip, (c, sum))| {
            let mean = if c > 0 { sum / c as f64 } else { 0.0 };
            (ip, c, mean)
        })
        .collect()
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
    let st = m.entry(host.to_string()).or_default();
    st.last = Some(Instant::now());
}

/// 测试专用：清空速度账本与重建节奏表。
#[cfg(test)]
pub(crate) fn clear() {
    *lock(&TABLE) = Some(HashMap::new());
    *lock(&HOSTS) = Some(HashMap::new());
    *lock(&SAMPLES) = None;
}

#[cfg(test)]
#[path = "../tests/pool/speed.rs"]
mod tests;
