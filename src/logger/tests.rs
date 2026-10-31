use super::*;

#[test]
fn ring_evicts_oldest_keeps_window() {
    let lg = Logger::new(false);
    for i in 0..(LOG_BUFFER_SIZE + 5) {
        lg.log(&format!("line{i}"));
    }
    let (entries, latest) = lg.since(0);
    assert_eq!(entries.len(), LOG_BUFFER_SIZE);
    assert!(
        entries[0].1.ends_with("line5"),
        "最旧 5 条应被挤出: {}",
        entries[0].1
    );
    assert!(entries
        .last()
        .unwrap()
        .1
        .ends_with(&format!("line{}", LOG_BUFFER_SIZE + 4)));
    assert_eq!(latest, (LOG_BUFFER_SIZE + 5) as u64);
    let (tail, _) = lg.since(entries[0].0);
    assert_eq!(tail.len(), LOG_BUFFER_SIZE - 1);
}
