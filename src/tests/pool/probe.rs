use super::*;
use crate::pool::{dial_cooling, serial_load};
use crate::pool::TEST_LOCK;
use std::sync::Arc;

// 路由表未装载：测速目标为空 → 立即返回且防重入标志复位（不拨号、无网络）。
#[tokio::test]
async fn probe_resets_running_flag_when_table_empty() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // 清场：显式装空表（TABLE 是进程级全局，其他用例可能装过数据）
    route::install(vec![], vec![]);
    assert!(route::probe_targets().is_empty(), "空表时无测速目标");
    let log: LogFn = Arc::new(|_| {});
    let report = probe_serial_domains(&log).await;
    assert!(report.contains("路由表未装载"), "{report}");
    assert!(
        !PROBE_RUNNING.load(std::sync::atomic::Ordering::SeqCst),
        "提前返回也必须复位防重入标志"
    );
    route::install(vec![], vec![]); // 清场
}

// 获得执行权/释放：swap 语义与守卫复位。
#[test]
fn probe_begin_guard_roundtrip() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    assert!(probe_begin(), "首次应获得执行权");
    assert!(!probe_begin(), "进行中再取应失败（防重入）");
    drop(crate::pool::probe::ProbeGuard);
    assert!(probe_begin(), "释放后应可再次获得");
    drop(crate::pool::probe::ProbeGuard);
}

// 死亡退避清除：note_dead 进表后 clear_dead 移除，dial_cooling 由 true 翻 false。
#[test]
fn clear_dead_releases_cooling() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join(format!("gitport_probe_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    serial_load(&dir, Vec::new(), None); // SERIAL 装载（routes.json 缺失也置 Some，dead 表可用）
    note_dead("198.51.100.7");
    assert!(dial_cooling("198.51.100.7", "github.com"), "退避期内应被拦");
    clear_dead("198.51.100.7");
    assert!(!dial_cooling("198.51.100.7", "github.com"), "清除后应放行");
    std::fs::remove_dir_all(&dir).ok();
    route::install(vec![], vec![]); // 清场
}

// 真实拨号：对 routes.json 全部 IP 串发建通道（约 65 个，1~2 分钟）。验证延迟落盘与游标清空。
#[test]
#[ignore = "真实网络：串发拨号全部节点 IP"]
fn probe_serial_domains_real_network() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let log: LogFn = Arc::new(|m| println!("{m}"));
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let report = probe_serial_domains(&log).await;
        println!("{report}");
        assert!(report.contains("完成："));
    });
}
