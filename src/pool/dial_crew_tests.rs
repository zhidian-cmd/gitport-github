use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 互斥语义:同一 IP 首次认领成功,重复认领被拒;不同 IP 不受影响。
#[test]
fn dial_crew_claim_excludes_peer() {
    let crew = DialCrew::new();
    assert!(crew.claim("1.2.3.4"), "首次认领应成功");
    assert!(!crew.claim("1.2.3.4"), "重复认领应被拒");
    assert!(crew.claim("5.6.7.8"), "不同 IP 不受同组互避影响");
}

/// 并发竞争:两个线程对同一 IP 各认领 5000 次,成功总数恰为 1。
/// 这是冷启动双任务"不同 IP"保证的根基——互斥坏了会静默退化成同 IP 双连。
#[test]
fn dial_crew_claim_race_yields_exactly_one_winner() {
    let crew = DialCrew::new();
    let ok = std::sync::Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let crew = crew.clone();
        let ok = ok.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..5000 {
                if crew.claim("10.0.0.1") {
                    ok.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        ok.load(Ordering::Relaxed),
        1,
        "并发认领同一 IP 必须恰有一个胜者"
    );
}
