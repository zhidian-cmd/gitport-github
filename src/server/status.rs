//! 状态行：每 30s 把池内通道的实测吞吐与状态摊开一行，只打最近有活动的 host。
//! 平时页面快慢在日志里看不见——meter_body 静默记账、竞速只在触发时说话，
//! 这里有事没事都把账本亮出来，快慢对得上浏览器的体感。
use crate::pool::speed;
use crate::server::upstream;
use crate::util::LogFn;
use std::time::Duration;

/// 状态行节奏：30s 一拍。
const STATUS_INTERVAL_SECS: u64 = 30;
/// 最近有活动才打：通道空闲或样本窗内出现过，避免给闲置 host 刷屏。
const ACTIVE_WINDOW_SECS: u64 = 90;

pub fn start_ticker(log: LogFn) {
    crate::logger::spawn("status", move || loop {
        std::thread::sleep(Duration::from_secs(STATUS_INTERVAL_SECS));
        emit(&log);
    });
}

fn emit(log: &LogFn) {
    let channels = upstream::channels_snapshot();
    let samples = speed::drain_samples();
    for (host, chans) in channels {
        if chans.is_empty() {
            continue;
        }
        // 活跃 = 有通道最近用过，或样本窗里出现过它的流量。
        let active = chans.iter().any(|(_, _, _, idle)| *idle < ACTIVE_WINDOW_SECS)
            || samples
                .iter()
                .any(|(ip, _, _)| chans.iter().any(|(cip, _, _, _)| cip == ip));
        if !active {
            continue;
        }
        let mut parts: Vec<String> = Vec::with_capacity(chans.len());
        for (ip, inflight, cap, _idle) in &chans {
            let mut p = match speed::kbps_of(ip) {
                Some(k) => format!("{:.0}KB/s", k),
                None => "无样本".to_string(),
            };
            if let Some(r) = speed::bench_remaining_secs(ip) {
                p += &format!(" 暂缓{}s", r);
            }
            if *inflight > 0 {
                p += &format!(" 在途{}/{}", inflight, cap);
            }
            parts.push(format!("{ip} {p}"));
        }
        let breaker = speed::breaker_remaining_secs(&host)
            .map(|r| format!("; 熔断剩余{}s", r))
            .unwrap_or_default();
        // 本窗真实样本：只统计这个 host 名下通道的。
        let (n, sum) = samples
            .iter()
            .filter(|(ip, _, _)| chans.iter().any(|(cip, _, _, _)| cip == ip))
            .fold((0u32, 0.0f64), |(n, s), (_, c, mean)| (n + c, s + mean * *c as f64));
        let samp = if n > 0 {
            format!("; 30s 真实样本 {} 个 均 {:.0}KB/s", n, sum / n as f64)
        } else {
            String::new()
        };
        log(&format!(
            "[状态] {host} {} 通道: {}{}{}",
            chans.len(),
            parts.join(" | "),
            breaker,
            samp
        ));
    }
}
