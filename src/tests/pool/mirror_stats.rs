use super::*;

fn rec(v: u64) -> Rec {
    Rec { t: 0, v }
}

#[test]
fn append_rings_and_milestones() {
    let mut st = Stats::default();
    for i in 1u64..10 {
        assert!(!append(&mut st, "m", 1000, i));
    }
    assert!(append(&mut st, "m", 1000, 10), "第 10 条触发评估");
    for i in 11u64..20 {
        assert!(!append(&mut st, "m", 1000, i));
    }
    assert!(append(&mut st, "m", 1000, 20), "第 20 条再触发");
    assert_eq!(st.mirrors["m"].len(), 20);
    for i in 21u64..30 {
        assert!(!append(&mut st, "m", 1000, i));
    }
    assert!(append(&mut st, "m", 1000, 30), "第 30 条里程碑");
    assert_eq!(st.mirrors["m"].len(), CAP);
    assert!(append(&mut st, "m", 1000, 999), "环形截断后 len=30, 仍处里程碑");
    assert_eq!(st.mirrors["m"].len(), CAP, "环形截断");
}

#[test]
fn evaluate_disables_only_distant_loser() {
    let mut all = HashMap::new();
    all.insert("fast".to_string(), vec![rec(12 * 1024 * 1024); 10]);
    all.insert("mid".to_string(), vec![rec(7 * 1024 * 1024); 10]);
    all.insert("slow".to_string(), vec![rec(400 * 1024); 10]);
    all.insert("newbie".to_string(), vec![rec(1024); 2]); // 不足 3 条不参评
    let off = evaluate(&all);
    assert_eq!(off, vec!["slow".to_string()], "仅 1/5 之外者停用: {off:?}");
}

#[test]
fn evaluate_spares_homogeneous_slow_chain() {
    let mut all = HashMap::new();
    all.insert("a".to_string(), vec![rec(300 * 1024); 10]);
    all.insert("b".to_string(), vec![rec(280 * 1024); 10]);
    assert!(evaluate(&all).is_empty(), "全员都慢时相对判据自保护");
}

#[test]
fn evaluate_needs_two_qualified() {
    let mut all = HashMap::new();
    all.insert("only".to_string(), vec![rec(1024); 10]);
    assert!(evaluate(&all).is_empty(), "只有一个参评者无从比较");
}
