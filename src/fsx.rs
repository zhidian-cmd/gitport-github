//! 原子写盘：先写 "<名>.json.tmp" 再改名，避免断电/被杀留下半截 JSON。
//! 只用于 *.json 数据文件（临时名按 `.json.tmp` 派生）。

use std::io::Write;
use std::path::Path;

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.flush()?;
    drop(f);
    std::fs::rename(&tmp, path)
}
