//! IP 建连延迟：真实拨号的实测用时（事件驱动回流——每次建连成功记一笔，无定时器、
//! 无主动探测），退出时经 pool::save_routes_now 落进 routes.json 的 `latency` 键；
//! 拨号候选按延迟升序挑。
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

/// 运行时拨号延迟回流：每次真实建连都把实测用时写进排序表（内存态，重启回落
/// routes.json 的测速基线）。有旧值时取均值——单次 GFW 抖动（4 秒抽签）不会把
/// 一个 IP 一棍子打死，连续慢才会让它沉底。
pub fn note(ip: &str, ms: u64) {
    let mut g = lock(&TABLE);
    let m = g.get_or_insert_with(HashMap::new);
    let merged = match m.get(ip) {
        Some(old) => (*old + ms) / 2,
        None => ms,
    };
    m.insert(ip.to_string(), merged);
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
