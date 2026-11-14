//! 原子写盘：先写唯一名 .tmp 再改名，避免断电留下半截 JSON。

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // tmp 名带进程号+序号：固定名的话两个并发写者会往同一个 tmp 交错写，
    // rename 出来是两份 JSON 的混合体，下次启动按种子重建、用户手改全丢还报"成功"。
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(
        "{}.{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id(),
        n
    ));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?; // 断电也不留空/半截文件（flush 只到 OS 页缓存，不够）
    drop(f);
    std::fs::rename(&tmp, path)
}
