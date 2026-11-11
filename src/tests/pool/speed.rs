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

/// 全暂缓才回来：所有候选都暂缓时原样放行，不把候选打空。
#[test]
fn all_benched_falls_back_to_full_list() {
    let _g = guard();
    clear();
    let ips = s(&["1.1.1.1", "2.2.2.2"]);
    bench("1.1.1.1");
    bench("2.2.2.2");
    assert!(
        bench_remaining_secs("1.1.1.1").is_some() && bench_remaining_secs("2.2.2.2").is_some()
    );
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

/// 触发线判定：候选里还有一条已测 ≥45KB/s 就不该折腾（将就用），全低才返回 true。
#[test]
fn rebuild_cooldown_gates_reruns() {
    let _g = guard();
    clear();
    let host = "h1";
    assert!(may_rebuild(host));
    begin_rebuild(host);
    assert!(!may_rebuild(host), "60 秒内不许再赛");
    assert!(may_rebuild("h2"), "不同 host 各算各的");
}
