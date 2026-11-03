//! IP 建连测速：TCP+TLS 实测用时，作为 `latency` 键存进 routes.json；拨号失败时按延迟升序挑候选。
use crate::util::lock;
use std::collections::HashMap;
use std::sync::Mutex;

static TABLE: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// 装载（routes.json 的 `latency` 键）；缺失 = 全未测（排序回落表序）。
pub fn install(map: HashMap<String, u64>) {
    *lock(&TABLE) = Some(map);
}

/// 该 IP 的实测建连用时（毫秒）；未测 = None（排序垫底）。
pub fn get(ip: &str) -> Option<u64> {
    let g = lock(&TABLE);
    g.as_ref()?.get(ip).copied()
}

/// 本轮结果覆盖：成功记用时，失败删除旧值（下次排序按未测垫底）。
pub fn replace(rows: &[(String, Option<u64>)]) {
    let mut g = lock(&TABLE);
    let m = g.get_or_insert_with(HashMap::new);
    for (ip, ms) in rows {
        match ms {
            Some(ms) => {
                m.insert(ip.clone(), *ms);
            }
            None => {
                m.remove(ip);
            }
        }
    }
}

/// 落盘用全量快照（编码 routes.json 时写入 `latency` 键）。
pub fn snapshot_all() -> HashMap<String, u64> {
    lock(&TABLE).clone().unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn seed(ip: &str, ms: u64) {
    lock(&TABLE)
        .get_or_insert_with(HashMap::new)
        .insert(ip.to_string(), ms);
}
