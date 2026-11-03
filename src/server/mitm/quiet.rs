//! 样板日志降噪：隧道/归属链/首包 Range 等每请求重复的行同 host 只留首条；镜像只在换链或头过慢时出声；复用按分钟聚合成一行。

use crate::util::LogFn;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn seen() -> &'static Mutex<HashSet<String>> {
    static S: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn rotated() -> &'static Mutex<HashMap<String, String>> {
    static M: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 单 host 的复用窗口：(次数, 累计毫秒, 窗口起点)。
type ReuseStat = (u64, u64, Instant);

fn reuse() -> &'static Mutex<HashMap<String, ReuseStat>> {
    static R: OnceLock<Mutex<HashMap<String, ReuseStat>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 该 host 的这类样板首次出现？表满整盘清空——纯日志用途，丢历史无副作用。
pub(super) fn first_time(tag: &str, host: &str) -> bool {
    let mut g = seen().lock().unwrap();
    if g.len() >= 512 {
        g.clear();
    }
    g.insert(format!("{tag}\u{1}{host}"))
}

/// 该链上次成功的镜像换了没有；true = 换家，值得记一笔。
pub(super) fn mirror_rotated(chain_host: &str, mirror: &str) -> bool {
    let mut g = rotated().lock().unwrap();
    if g.len() >= 256 {
        g.clear();
    }
    match g.get(chain_host) {
        Some(prev) if prev == mirror => false,
        _ => {
            g.insert(chain_host.to_string(), mirror.to_string());
            true
        }
    }
}

/// 复用连接记账：每个 host 满一分钟落一行汇总，免得每请求一条。
pub(super) fn note_reuse(log: &LogFn, host: &str, ms: u64) {
    let mut g = reuse().lock().unwrap();
    if g.len() >= 128 {
        g.clear();
    }
    let e = g.entry(host.to_string()).or_insert((0, 0, Instant::now()));
    e.0 += 1;
    e.1 += ms;
    if e.2.elapsed() >= Duration::from_secs(60) {
        (log)(&format!(
            "[上游] {host} 复用连接 {} 次, 均 {}ms",
            e.0,
            e.1 / e.0
        ));
        *e = (0, 0, Instant::now());
    }
}
