//! 原子写盘：先写 .json.tmp 再改名，避免断电留下半截 JSON。

use std::io::Write;
use std::path::Path;

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?; // 断电也不留空/半截文件（flush 只到 OS 页缓存，不够）
    drop(f);
    std::fs::rename(&tmp, path)
}
