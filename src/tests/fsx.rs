use super::*;

fn no_tmp_left(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect()
}

/// 成功写盘：内容正确、零 tmp 残留。
#[test]
fn atomic_write_success_leaves_no_tmp() {
    let dir = std::env::temp_dir().join("gitport_fsx_ok");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("settings.json");
    write_atomic(&target, b"hello").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    assert!(
        no_tmp_left(&dir).is_empty(),
        "成功写盘不许留 tmp: {:?}",
        no_tmp_left(&dir)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// rename 失败（目标是个目录）：守卫必须清掉 tmp，不留垃圾。
#[test]
fn failed_rename_cleans_tmp() {
    let dir = std::env::temp_dir().join("gitport_fsx_fail");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target_is_dir = dir.join("target");
    std::fs::create_dir(&target_is_dir).unwrap();
    let r = write_atomic(&target_is_dir, b"data");
    assert!(r.is_err(), "rename 到目录路径必须失败");
    assert!(
        no_tmp_left(&dir).is_empty(),
        "失败路径不许留 tmp: {:?}",
        no_tmp_left(&dir)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
