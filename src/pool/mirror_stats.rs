//! 镜像价值评估缓存：探测交分按时间戳落盘到 .cache/mirror_stats.json,
//! 唯一用途是回答"这个镜像还配留在大文件链里吗"(镜像不是越多越好)。
//! 真实下载派发路径不读这里——ECT 只用当次实测冻结分, 缓存与派发完全隔离。

use crate::settings;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

/// 每镜保留条数(环形截断)。
const CAP: usize = 30;
/// 每 EVAL_EVERY 条触发一次评估。
const EVAL_EVERY: usize = 10;
/// 参评最少记录数(不足者既不当基准也不被评)。
const MIN_RECORDS: usize = 3;
/// 停用判据: 中位速率 × RATIO < 最快中位 → 停用(仅大文件语义, 可手动恢复)。
const CULL_RATIO: u64 = 5;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
struct Rec {
    /// 时间戳(ms)。
    t: u64,
    /// 速率(bytes/s)。
    v: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Stats {
    #[serde(default)]
    mirrors: HashMap<String, Vec<Rec>>,
}

/// 本会话已记过的镜像(每会话每镜 1 条, 首落分为准)。
static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn path() -> PathBuf {
    settings::exe_dir().join(".cache").join("mirror_stats.json")
}

fn load() -> Stats {
    std::fs::read(path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(s: &Stats) {
    if let Some(dir) = path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(b) = serde_json::to_vec_pretty(s) {
        let _ = std::fs::write(path(), b);
    }
}

/// 追加一条并环形截断; 返回是否到了评估里程碑。
fn append(st: &mut Stats, mirror: &str, speed: u64, now: u64) -> bool {
    let e = st.mirrors.entry(mirror.to_string()).or_default();
    e.push(Rec { t: now, v: speed });
    if e.len() > CAP {
        let n = e.len();
        *e = e.split_off(n - CAP);
    }
    e.len().is_multiple_of(EVAL_EVERY)
}

/// 评估(纯函数): 各镜(≥MIN_RECORDS 条)取中位, 中位 × RATIO < 最快中位 → 停用。
/// 相对判据自保护: 全员都慢时最快者即基准, 同质慢链不互杀。
fn evaluate(all: &HashMap<String, Vec<Rec>>) -> Vec<String> {
    let medians: Vec<(&String, u64)> = all
        .iter()
        .filter(|(_, rs)| rs.len() >= MIN_RECORDS)
        .map(|(m, rs)| (m, median(rs)))
        .collect();
    if medians.len() < 2 {
        return Vec::new();
    }
    let best = medians.iter().map(|(_, v)| *v).max().unwrap_or(0);
    if best == 0 {
        return Vec::new();
    }
    medians
        .into_iter()
        .filter(|(_, v)| *v * CULL_RATIO < best)
        .map(|(m, _)| (*m).clone())
        .collect()
}

fn median(rs: &[Rec]) -> u64 {
    if rs.is_empty() {
        return 0;
    }
    let mut v: Vec<u64> = rs.iter().map(|r| r.v).collect();
    v.sort_unstable();
    v[v.len() / 2]
}

/// 探测落账: 每会话每镜 1 条(流结束时的终值, 不是首帧的慢启动读数)。
/// 到里程碑时评估——只产建议(日志一条), 绝不改动 settings/镜像链。
/// `direct/` 是直连腿的记账键, 不是镜像: 不参评, 否则直连会当"最快基准"
/// 把真实镜像全比下去。
pub(crate) fn record(mirror: &str, speed: u64) {
    if mirror.is_empty() || speed == 0 || mirror.starts_with("direct/") {
        return;
    }
    {
        let mut g = SEEN.lock().unwrap_or_else(|p| p.into_inner());
        let seen = g.get_or_insert_with(HashSet::new);
        if !seen.insert(mirror.to_string()) {
            return; // 本会话已记
        }
    }
    let mut st = load();
    let milestone = append(&mut st, mirror, speed, super::now_ms());
    save(&st);
    if milestone {
        let to_off = evaluate(&st.mirrors);
        for u in to_off {
            if let Some(log) = super::lock(&super::SERIAL_LOG).as_ref() {
                log(&format!(
                    "[评估] {u} 历史中位速率垫底(近 {EVAL_EVERY} 次), 建议停用(手动处理)"
                ));
            }
        }
    }
}

/// UI 快照: (镜像, 是否建议停用)。只给建议——不显示速度/次数。
pub(crate) fn snapshot() -> Vec<(String, bool)> {
    let st = load();
    let off = evaluate(&st.mirrors);
    let mut out: Vec<(String, bool)> = st
        .mirrors
        .keys()
        .map(|m| (m.clone(), off.iter().any(|u| u == m)))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests;
