//! 原子写盘：先写唯一名 .tmp 再改名，避免断电留下半截 JSON。

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// tmp 文件 RAII 守卫：任何失败路径都删 tmp，成功 rename 后删除落空无害。
struct TmpGuard<'a>(&'a Path);

impl Drop for TmpGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // tmp 名带进程号+序号：固定名会让并发写者交错写同一个 tmp，rename 出混合 JSON。
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(
        "{}.{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id(),
        n
    ));
    let mut f = std::fs::File::create(&tmp)?;
    let _guard = TmpGuard(&tmp); // create 成功即接管：此后任何 ? 早退都清 tmp
    f.write_all(data)?;
    f.sync_all()?; // 断电也不留空/半截文件（flush 只到 OS 页缓存，不够）
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
#[path = "tests/fsx.rs"]
mod tests;
