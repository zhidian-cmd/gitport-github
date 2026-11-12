use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 全局认领互斥:同一 IP 首次认领成功,重复认领被拒;不同 IP 不受影响。
#[test]
fn claim_dial_excludes_peer() {
    assert!(claim_dial("1.2.3.4"), "首次认领应成功");
    assert!(!claim_dial("1.2.3.4"), "重复认领应被拒");
    assert!(claim_dial("5.6.7.8"), "不同 IP 不受影响");
    release_dial("1.2.3.4");
    release_dial("5.6.7.8");
}

/// 并发竞争：两线程对同一 IP 各认领 5000 次，成功总数恰为 1——跨 host 拨号去重的根基，互斥坏了会静默退化成同 IP 双连。
#[test]
fn claim_dial_race_yields_exactly_one_winner() {
    let ok = std::sync::Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let ok = ok.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..5000 {
                if claim_dial("10.0.0.1") {
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
    release_dial("10.0.0.1");
}
