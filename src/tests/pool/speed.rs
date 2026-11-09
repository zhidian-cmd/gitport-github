use super::*;

/// 速度账本/重建节奏都是进程级全局态：跨用例必须串行。
fn guard() -> std::sync::MutexGuard<'static, ()> {
    crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn s(ips: &[&str]) -> Vec<String> {
    ips.iter().map(|s| s.to_string()).collect()
}

/// 小样本不投票：低于 64KB 的响应测不准，一律不记。
#[test]
fn tiny_sample_is_ignored() {
    let _g = guard();
    clear();
    assert_eq!(record("1.1.1.1", MIN_SAMPLE_BYTES - 1, 30_000), None);
    assert_eq!(kbps_of("1.1.1.1"), None);
}

/// 够用线：达到 70KB/s 就解暂缓；没到就保持暂缓（不发单）。
#[test]
fn bench_until_reaches_target() {
    let _g = guard();
    clear();
    let ips = s(&["1.1.1.1", "2.2.2.2"]);
    // 9KB/s：低于够用线，暂缓
    record("1.1.1.1", 273_758, 30_000);
    bench("1.1.1.1");
    assert!(is_benched("1.1.1.1"));
    assert_eq!(usable(&ips), s(&["2.2.2.2"]), "暂缓的通道先不发");
    // 同一条后来跑出 150KB/s：EWMA 平滑，9→65.4 一次就过 60 的够用线
    record("1.1.1.1", 307_200, 2_000);
    release("1.1.1.1");
    assert!(!is_benched("1.1.1.1"), "单次好样本足以越过 60KB/s 够用线");
    assert_eq!(usable(&ips), ips);
}

/// 全暂缓才回来：所有候选都暂缓时原样放行，不把候选打空。
#[test]
fn all_benched_falls_back_to_full_list() {
    let _g = guard();
    clear();
    let ips = s(&["1.1.1.1", "2.2.2.2"]);
    bench("1.1.1.1");
    bench("2.2.2.2");
    assert!(is_benched("1.1.1.1") && is_benched("2.2.2.2"));
    assert_eq!(usable(&ips), ips, "全暂缓必须原样返回，否则无处可拨");
}

/// 每 host 60 秒最多触发一轮；冷却内再来慢样本不重复催建。
#[test]
fn rebuild_is_cooldown_limited() {
    let _g = guard();
    clear();
    assert!(may_rebuild("h1"));
    begin_rebuild("h1");
    assert!(!may_rebuild("h1"), "60 秒内不许再赛");
    assert!(may_rebuild("h2"), "不同 host 各算各的");
}

/// 连续 3 轮都达不到够用线 → 熔断 10 分钟；有一轮达标就从零计数。
#[test]
fn three_fruitless_rounds_open_breaker() {
    let _g = guard();
    clear();
    let host = "h1";
    assert!(!finish_rebuild(host, Some(20.0)), "第 1 轮不熔断");
    assert!(!finish_rebuild(host, Some(30.0)), "第 2 轮不熔断");
    assert!(finish_rebuild(host, Some(40.0)), "第 3 轮开熔断");
    assert!(breaker_open(host));
    assert!(!may_rebuild(host), "熔断期不许再赛");
    // 熔断后重新计数：先模拟过期
    clear();
    finish_rebuild(host, Some(20.0));
    finish_rebuild(host, Some(20.0));
    assert!(!finish_rebuild(host, Some(150.0)), "达标那轮清零，不熔断");
    assert!(!breaker_open(host));
    assert!(!finish_rebuild(host, Some(20.0)), "清零后重新从 1 数");
}
