//! 边状态机：(IP, 路由键) 的实测坏态。表是预判，边是实测——421 拉黑、超时降权、成功清黑。
use crate::util::lock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 421 / 证书不匹配：静态属性不会自愈，长冷却。
const REJECT_SECS: u64 = 4 * 3600;
/// 请求超时 / 断连：网络波动，短冷却。
const STALL_SECS: u64 = 120;
/// 容量硬顶：超限惰性清过期，再超就整表清（极端场景宁可重新试探）。
const CAP: usize = 8192;

static EDGES: std::sync::Mutex<Option<HashMap<(String, String), Instant>>> =
    std::sync::Mutex::new(None);

fn map() -> &'static std::sync::Mutex<Option<HashMap<(String, String), Instant>>> {
    &EDGES
}

fn set(ip: &str, key: &str, secs: u64) {
    let mut g = lock(map());
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= CAP {
        let now = Instant::now();
        m.retain(|_, until| now < *until);
        if m.len() >= CAP {
            m.clear();
        }
    }
    m.insert(
        (ip.to_string(), key.to_string()),
        Instant::now() + Duration::from_secs(secs),
    );
}

/// 边被服务端拒绝（421 等）：这个 IP 服务不了这个键，长冷却。
pub fn mark_reject(ip: &str, key: &str) {
    set(ip, key, REJECT_SECS);
}

/// 边请求超时/断连：短冷却，稍后复测。
pub fn mark_stall(ip: &str, key: &str) {
    set(ip, key, STALL_SECS);
}

/// 边在冷却期？查询管线第③步据此滤黑。
pub fn is_bad(ip: &str, key: &str) -> bool {
    let mut g = lock(map());
    let Some(m) = g.as_mut() else { return false };
    match m.get(&(ip.to_string(), key.to_string())) {
        Some(until) if Instant::now() < *until => true,
        Some(_) => {
            m.remove(&(ip.to_string(), key.to_string()));
            false
        }
        None => false,
    }
}

/// 成功即清黑：坏边自愈的唯一通道。
pub fn clear(ip: &str, key: &str) {
    if let Some(m) = lock(map()).as_mut() {
        m.remove(&(ip.to_string(), key.to_string()));
    }
}

#[cfg(test)]
pub(crate) fn clear_all() {
    *lock(map()) = Some(HashMap::new());
}
