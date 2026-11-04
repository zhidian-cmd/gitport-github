//! 全局"这个 IP 正在拨"登记：拨之前抢，拨完立刻放；别的 host 看到就跳过这个 IP、试下一个。
//!
//! 语义只有一条：**同一 IP 同一时刻只允许一个拨号者**。
//! 抢不到不等（等会把首屏拖住），直接换候选；候选全被占才由上层决定等还是自建。

use crate::util::lock;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static TABLE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn table() -> &'static Mutex<HashMap<String, Instant>> {
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 这个 IP 此刻有没有人在拨。
pub fn busy(ip: &str) -> bool {
    lock(table()).contains_key(ip)
}

/// 拨号权：抢到才算数，Drop 时自动释放（成功、失败、panic 都释放）。
pub struct Guard {
    ip: String,
}

/// 抢占单个 IP 的拨号权；已被占用返回 None。原子操作：检查和写入在同一把锁里。
pub fn try_claim(ip: &str) -> Option<Guard> {
    let mut g = lock(table());
    if g.contains_key(ip) {
        return None;
    }
    g.insert(ip.to_string(), Instant::now());
    Some(Guard { ip: ip.to_string() })
}

impl Drop for Guard {
    fn drop(&mut self) {
        lock(table()).remove(&self.ip);
    }
}

#[cfg(test)]
pub(crate) fn clear() {
    lock(table()).clear();
}
