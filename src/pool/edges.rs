//! 边状态机：(IP, 路由键) 的实测坏态。表是预判，边是实测——421 拉黑、超时降权、成功清短冷却；
//! 风控冷却只随时间过期：风控页本身就是一次"成功"的 HTTP 交换，可清就会当场被并发回写洗掉
//! （实测：风暴里 26 家候选 3 轮就回头，根因即此）。
use crate::util::lock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 421 / 证书不匹配：静态属性不会自愈，长冷却。
const REJECT_SECS: u64 = 4 * 3600;
/// 请求超时 / 断连：网络波动，短冷却。
const STALL_SECS: u64 = 120;
/// 风控拦截页：IP 对该域暂时不干净，冷却到窗口过期（GitHub 的限流窗通常几分钟）。
const RISK_SECS: u64 = 600;
/// 容量硬顶：超限惰性清过期，再超就整表清（极端场景宁可重新试探）。
const CAP: usize = 8192;

/// 值 = (到期时刻, 是否风控冷却)。风控项免疫 clear()，只能到期自愈。
type EdgeMap = HashMap<(String, String), (Instant, bool)>;
type EdgeTable = std::sync::Mutex<Option<EdgeMap>>;

static EDGES: EdgeTable = std::sync::Mutex::new(None);

fn set(ip: &str, key: &str, secs: u64, risk: bool) {
    let mut g = lock(&EDGES);
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= CAP {
        let now = Instant::now();
        m.retain(|_, v| now < v.0);
        if m.len() >= CAP {
            m.clear();
        }
    }
    let now = Instant::now();
    // 活着的风控冷却只接受风控改写：短冷却不得把它降级成"可清"。
    if !risk {
        if let Some((until, true)) = m.get(&(ip.to_string(), key.to_string())) {
            if now < *until {
                return;
            }
        }
    }
    m.insert(
        (ip.to_string(), key.to_string()),
        (now + Duration::from_secs(secs), risk),
    );
}

/// 边被服务端拒绝（421 等）：这个 IP 服务不了这个键，长冷却。
pub fn mark_reject(ip: &str, key: &str) {
    set(ip, key, REJECT_SECS, false);
}

/// 边请求超时/断连：短冷却，稍后复测。
pub fn mark_stall(ip: &str, key: &str) {
    set(ip, key, STALL_SECS, false);
}

/// 边返回风控拦截页：10 分钟冷却，免疫"成功清黑"（只能到期自愈）。
pub fn mark_risk(ip: &str, key: &str) {
    set(ip, key, RISK_SECS, true);
}

/// 边在冷却期？查询管线第③步据此滤黑。
pub fn is_bad(ip: &str, key: &str) -> bool {
    let mut g = lock(&EDGES);
    let Some(m) = g.as_mut() else { return false };
    match m.get(&(ip.to_string(), key.to_string())) {
        Some((until, _)) if Instant::now() < *until => true,
        Some(_) => {
            m.remove(&(ip.to_string(), key.to_string()));
            false
        }
        None => false,
    }
}

/// 成功只清短冷却（超时/421 的自愈通道）；风控冷却不可清，只随时间过期。
pub fn clear(ip: &str, key: &str) {
    let k = (ip.to_string(), key.to_string());
    if let Some(m) = lock(&EDGES).as_mut() {
        if m.get(&k).is_some_and(|(_, risk)| !*risk) {
            m.remove(&k);
        }
    }
}

#[cfg(test)]
pub(crate) fn clear_all() {
    *lock(&EDGES) = Some(HashMap::new());
}
