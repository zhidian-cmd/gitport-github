//! 建连延迟：真实拨号用时（事件回流、无主动探测），退出落 routes.json 的 latency 键，拨号按延迟升序。
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

/// 每次真实建连写实测用时（内存态，重启回落盘基线）；有旧值取均值，单次 GFW 抖动不会一棍子打死。
pub fn note(ip: &str, ms: u64) {
    let mut g = lock(&TABLE);
    let m = g.get_or_insert_with(HashMap::new);
    let merged = match m.get(ip) {
        Some(old) => (*old + ms) / 2,
        None => ms,
    };
    m.insert(ip.to_string(), merged);
}

/// 黑洞降权：实测翻倍（3s~10s）沉到已测队尾，不沉过未测候选，60s 内随正常样本稀释恢复。
pub fn sink(ip: &str) {
    let mut g = lock(&TABLE);
    let m = g.get_or_insert_with(HashMap::new);
    let merged = match m.get(ip) {
        Some(old) => (*old * 2).max(3000).min(10000),
        None => 3000,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        crate::pool::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// note 合并取均值：单次 GFW 抖动（4 秒抽签）不会一棍子打死，连续慢才沉底。
    #[test]
    fn note_merges_as_average() {
        let _g = guard();
        install(HashMap::new());
        note("1.1.1.1", 500);
        note("1.1.1.1", 900);
        assert_eq!(get("1.1.1.1"), Some(700), "(500+900)/2");
        note("1.1.1.1", 100);
        assert_eq!(get("1.1.1.1"), Some(400), "(700+100)/2");
    }

    /// sink 降权钳在 [3s, 10s]：一次误判不把 IP 沉到未测候选之下（未测恒垫底）。
    #[test]
    fn sink_clamps_between_3s_and_10s() {
        let _g = guard();
        install(HashMap::new());
        sink("2.2.2.2");
        assert_eq!(get("2.2.2.2"), Some(3000), "未测 IP 一刀进 3s 档");
        seed("3.3.3.3", 100);
        sink("3.3.3.3");
        assert_eq!(get("3.3.3.3"), Some(3000), "100ms 翻倍也只到下限");
        seed("4.4.4.4", 9000);
        sink("4.4.4.4");
        assert_eq!(get("4.4.4.4"), Some(10000), "封顶 10s");
    }
}
