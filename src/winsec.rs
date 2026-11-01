//! Windows 文件 ACL 收紧：ca.key 与 settings.json 只授当前用户与 SYSTEM——根私钥可读即可伪造叶子证书。

use std::os::windows::process::CommandExt;
use std::process::Command;

/// 子进程不弹控制台窗口（本程序是 GUI 子系统）。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 受保护 DACL（文件版）：仅 SYSTEM 与当前用户；文件上带 (OI)(CI) 会被 icacls 静默忽略，必须用裸 (F)。
pub fn restrict_to_current_user(path: &str) -> Result<(), String> {
    restrict(path, "(F)")
}

/// 受保护 DACL（目录版）：授权带 (OI)(CI)，否则 /inheritance:r 后旧子目录被剥成空 DACL，缓存全写不进去。
pub fn restrict_dir_to_current_user(path: &str) -> Result<(), String> {
    restrict(path, "(OI)(CI)F")
}

fn restrict(path: &str, rights: &str) -> Result<(), String> {
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.trim().is_empty() {
        // 拿不到用户名时宁可不改：只授 SYSTEM 会把用户自己锁在外面。
        return Err("取不到当前用户名，跳过 ACL 收紧".to_string());
    }
    // rights 由调用方定：文件=裸 (F)，目录=(OI)(CI)F（可继承，见上）
    let grant_user = format!("{user}:{rights}");
    let out = Command::new("icacls")
        .args([
            path,
            "/inheritance:r",
            "/grant:r",
            grant_user.as_str(),
            "/grant:r",
            format!("*S-1-5-18:{rights}").as_str(),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("icacls 执行失败: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(format!(
        "icacls 退出码 {:?}: {detail}",
        out.status.code().unwrap_or(-1)
    ))
}

#[cfg(test)]
#[path = "tests/winsec.rs"]
mod tests;
