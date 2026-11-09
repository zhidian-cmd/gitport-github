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
/// 暂缓时长：不够够用线的通道先放着不发，下一轮触发时复测，不重拨。
const BENCH_SECS: u64 = 60;
/// 每 host 两轮重建之间的最短间隔：一页几百个请求同时报慢也只触发一轮。
const REBUILD_COOLDOWN_SECS: u64 = 60;
/// 连续几轮重建都达不到够用线就熔断（这条线路就这水平，别烧流量折腾）。
const BREAKER_STRIKES: u32 = 3;
/// 熔断时长。
const BREAKER_SECS: u64 = 600;
/// EWMA 新样本权重。
const ALPHA: f64 = 0.4;

/// 一次实测样本。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub kbps: f64,
    pub target: f64,
}

#[derive(Clone, Copy)]
struct Stat {
    /// 吞吐 EWMA（KB/s）；0 = 还没测过。
    ewma: f64,
    /// 暂缓到期时刻；None = 正常发单。
    until: Option<Instant>,
}

static TABLE: Mutex<Option<HashMap<String, Stat>>> = Mutex::new(None);

/// 记一次真实传输的吞吐（只记账，不判死活）。样本不足 64KB 返回 None。
pub fn record(ip: &str, bytes: u64, ms: u64) -> Option<Sample> {
    if bytes < MIN_SAMPLE_BYTES || ms == 0 {
        return None;
    }
    let kbps = bytes as f64 / 1024.0 / (ms as f64 / 1000.0);
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
    Some(Sample {
        kbps: st.ewma,
        target: TARGET_KBPS,
    })
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

/// 单 IP 是否暂缓中（测试用；运行期筛选走 usable）。
#[cfg(test)]
pub fn is_benched(ip: &str) -> bool {
    let g = lock(&TABLE);
    g.as_ref()
        .and_then(|t| t.get(ip))
        .and_then(|s| s.until)
        .is_some_and(|u| Instant::now() < u)
}

/// 单 host 的重建节奏：60s 一轮，连续 3 轮不达标熔断 10 分钟。
#[derive(Default)]
struct HostRace {
    last: Option<Instant>,
    /// 连续几轮重建后仍没筛出达标通道。
    strikes: u32,
    open_until: Option<Instant>,
}

static HOSTS: Mutex<Option<HashMap<String, HostRace>>> = Mutex::new(None);

/// 现在能不能为这个 host 触发一轮重建：熔断中/冷却中都不行。
pub fn may_rebuild(host: &str) -> bool {
    let mut g = lock(&HOSTS);
    let m = g.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    let Some(st) = m.get(host) else { return true };
    if st.open_until.is_some_and(|u| now < u) {
        return false;
    }
    st.last
        .is_none_or(|t| now.duration_since(t).as_secs() >= REBUILD_COOLDOWN_SECS)
}

/// 记一轮重建开始。
pub fn begin_rebuild(host: &str) {
    let mut g = lock(&HOSTS);
    let m = g.get_or_insert_with(HashMap::new);
    let st = m.entry(host.to_string()).or_default();
    st.last = Some(Instant::now());
}

/// 一轮重建收尾：best = 本轮筛出的最快吞吐（None = 一条都没测成）。
/// 返回 true 表示这一轮把熔断打开了。
pub fn finish_rebuild(host: &str, best: Option<f64>) -> bool {
    let hit = best.is_some_and(|k| k >= TARGET_KBPS);
    let mut g = lock(&HOSTS);
    let m = g.get_or_insert_with(HashMap::new);
    let st = m.entry(host.to_string()).or_default();
    if hit {
        st.strikes = 0;
        st.open_until = None;
        return false;
    }
    st.strikes = st.strikes.saturating_add(1);
    if st.strikes >= BREAKER_STRIKES {
        st.strikes = 0;
        st.open_until = Some(Instant::now() + Duration::from_secs(BREAKER_SECS));
        return true;
    }
    false
}

/// 这个 host 是否处于熔断期（日志/测试用）。
pub fn breaker_open(host: &str) -> bool {
    let g = lock(&HOSTS);
    g.as_ref()
        .and_then(|m| m.get(host))
        .and_then(|st| st.open_until)
        .is_some_and(|u| Instant::now() < u)
}

/// 测试专用：清空速度账本与重建节奏表。
#[cfg(test)]
pub(crate) fn clear() {
    *lock(&TABLE) = Some(HashMap::new());
    *lock(&HOSTS) = Some(HashMap::new());
}

#[cfg(test)]
#[path = "../tests/pool/speed.rs"]
mod tests;
