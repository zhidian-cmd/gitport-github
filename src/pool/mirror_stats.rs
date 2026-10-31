//! 镜像价值评估缓存：探测交分按时间戳落盘到 .cache/mirror_stats.json,
//! 唯一用途是回答"这个镜像还配留在大文件链里吗"(镜像不是越多越好)。
//! 真实下载派发路径不读这里——ECT 只用当次实测冻结分, 缓存与派发完全隔离。

use crate::settings::{self, WorkerMirror};
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

/// 探测交分落账: 每会话每镜 1 条(首落分)。到里程碑时评估并自动停用垫底镜。
pub(crate) fn record(mirror: &str, speed: u64) {
    if mirror.is_empty() || speed == 0 {
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
        if !to_off.is_empty() {
            apply_off(&to_off);
        }
    }
}

fn apply_off(to_off: &[String]) {
    let mut reg: Vec<WorkerMirror> = settings::worker_mirrors();
    let mut changed = false;
    for w in reg.iter_mut() {
        if w.on && to_off.iter().any(|m| m == &w.url) {
            w.on = false;
            changed = true;
            if let Some(log) = super::lock(&super::SERIAL_LOG).as_ref() {
                log(&format!(
                    "[评估] {} 历史中位速率垫底(近 {EVAL_EVERY} 次), 大文件自动停用(可手动恢复)",
                    w.url
                ));
            }
        }
    }
    if changed {
        settings::save_worker_mirrors(reg);
        super::sync_custom_mirrors(&[]); // 大文件链摘除 + plans 落盘
    }
}

/// UI 快照: (镜像, 记录数, 近期中位速率 bytes/s)。
pub(crate) fn snapshot() -> Vec<(String, usize, u64)> {
    let st = load();
    let mut out: Vec<(String, usize, u64)> = st
        .mirrors
        .iter()
        .map(|(m, rs)| (m.clone(), rs.len(), median(rs)))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(v: u64) -> Rec {
        Rec { t: 0, v }
    }

    #[test]
    fn append_rings_and_milestones() {
        let mut st = Stats::default();
        for i in 1u64..10 {
            assert!(!append(&mut st, "m", 1000, i));
        }
        assert!(append(&mut st, "m", 1000, 10), "第 10 条触发评估");
        for i in 11u64..20 {
            assert!(!append(&mut st, "m", 1000, i));
        }
        assert!(append(&mut st, "m", 1000, 20), "第 20 条再触发");
        assert_eq!(st.mirrors["m"].len(), 20);
        for i in 21u64..30 {
            assert!(!append(&mut st, "m", 1000, i));
        }
        assert!(append(&mut st, "m", 1000, 30), "第 30 条里程碑");
        assert_eq!(st.mirrors["m"].len(), CAP);
        assert!(append(&mut st, "m", 1000, 999), "环形截断后 len=30, 仍处里程碑");
        assert_eq!(st.mirrors["m"].len(), CAP, "环形截断");
    }

    #[test]
    fn evaluate_disables_only_distant_loser() {
        let mut all = HashMap::new();
        all.insert("fast".to_string(), vec![rec(12 * 1024 * 1024); 10]);
        all.insert("mid".to_string(), vec![rec(7 * 1024 * 1024); 10]);
        all.insert("slow".to_string(), vec![rec(400 * 1024); 10]);
        all.insert("newbie".to_string(), vec![rec(1024); 2]); // 不足 3 条不参评
        let off = evaluate(&all);
        assert_eq!(off, vec!["slow".to_string()], "仅 1/5 之外者停用: {off:?}");
    }

    #[test]
    fn evaluate_spares_homogeneous_slow_chain() {
        let mut all = HashMap::new();
        all.insert("a".to_string(), vec![rec(300 * 1024); 10]);
        all.insert("b".to_string(), vec![rec(280 * 1024); 10]);
        assert!(evaluate(&all).is_empty(), "全员都慢时相对判据自保护");
    }

    #[test]
    fn evaluate_needs_two_qualified() {
        let mut all = HashMap::new();
        all.insert("only".to_string(), vec![rec(1024); 10]);
        assert!(evaluate(&all).is_empty(), "只有一个参评者无从比较");
    }
}
