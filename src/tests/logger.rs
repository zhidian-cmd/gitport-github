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

/// 启动打点一律不进 WebUI 日志流：界面不该出现，也不该留开关。
#[test]
fn boot_lines_never_reach_webui() {
    let lg = Logger::new(false);
    lg.log("[启动] 核心 49ms（配置 0 / 路由表 1 / CA 17 / 代理 29）");
    lg.log("[启动] 托盘就绪 +208ms");
    lg.log("[MITM] github.com 隧道已解密");
    let (entries, latest) = lg.since(0);
    assert_eq!(entries.len(), 1, "只有普通日志进环形缓冲");
    assert!(entries[0].1.contains("[MITM]"));
    assert!(entries.iter().all(|e| !e.1.contains("[启动]")));
    // 序号不因被丢弃的行产生空洞：拉取游标仍连续可判。
    assert_eq!(latest, 1);
}
