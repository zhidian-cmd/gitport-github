//! 状态行：每 30s 把池内通道的被动测速（ECT 每流速度）与状态摊开一行，
//! 只打最近有活动的 host。平时页面快慢在日志里看不见——这里有事没事都亮账本。
use crate::server::upstream;
use crate::util::LogFn;
use std::time::Duration;

/// 状态行节奏：30s 一拍。
const STATUS_INTERVAL_SECS: u64 = 30;
/// 最近有活动才打：通道空闲，避免给闲置 host 刷屏。
const ACTIVE_WINDOW_SECS: u64 = 90;

pub fn start_ticker(log: LogFn) {
    crate::logger::spawn("status", move || loop {
        std::thread::sleep(Duration::from_secs(STATUS_INTERVAL_SECS));
        emit(&log);
    });
}

fn emit(log: &LogFn) {
    let channels = upstream::channels_snapshot();
    for (host, chans) in channels {
        if chans.is_empty() {
            continue;
        }
        // 活跃 = 有通道最近用过。
        let active = chans.iter().any(|(_, _, _, idle)| *idle < ACTIVE_WINDOW_SECS);
        if !active {
            continue;
        }
        let mut parts: Vec<String> = Vec::with_capacity(chans.len());
        for (ip, inflight, cap, _idle) in &chans {
            // 每流速度 = 上一 ECT 窗实收 ÷ 在途流数（被动测速，无样本概念）。
            let mut p = match upstream::ect_flow_kbps(ip) {
                Some(k) => format!("{:.0}KB/s", k),
                None => "无数据".to_string(),
            };
            if let Some(r) = upstream::bench_remaining_secs(ip) {
                p += &format!(" 暂缓{}s", r);
            }
            if *inflight > 0 {
                p += &format!(" 在途{}/{}", inflight, cap);
            }
            parts.push(format!("{ip} {p}"));
        }
        log(&format!(
            "[状态] {host} {} 通道: {}",
            chans.len(),
            parts.join(" | ")
        ));
    }
}
