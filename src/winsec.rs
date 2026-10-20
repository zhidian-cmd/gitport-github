//! Windows 文件 ACL 收紧：Rust 0600 在 Windows 只映射只读属性，文件缺省继承目录 ACL。
//! ca.key（MITM 根私钥）/settings.json 收紧为仅当前用户与 SYSTEM——根私钥可读即可伪造用户已信任的叶子证书。
//!
//! 走系统自带 icacls：一条命令 = 断开继承 + 只授当前用户与 SYSTEM，等价于受保护 DACL。
//! 失败按 best-effort 返回错误，调用方只记日志，不阻断主流程。

use std::os::windows::process::CommandExt;
use std::process::Command;

/// 子进程不弹控制台窗口（本程序是 GUI 子系统）。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 受保护 DACL：仅 SYSTEM 与当前用户完全控制，其余（含继承来的 Administrators）剥离。
pub fn restrict_to_current_user(path: &str) -> Result<(), String> {
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.trim().is_empty() {
        // 拿不到用户名时宁可不改：只授 SYSTEM 会把用户自己锁在外面。
        return Err("取不到当前用户名，跳过 ACL 收紧".to_string());
    }
    let grant_user = format!("{user}:(F)");
    let out = Command::new("icacls")
        .args([
            path,
            "/inheritance:r",
            "/grant:r",
            grant_user.as_str(),
            "/grant:r",
            "*S-1-5-18:(F)",
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
mod tests {
    use super::*;

    /// 契约：收紧后只剩「当前用户 + SYSTEM」两条 ACE，且继承标记 (I) 全部消失。
    #[test]
    fn acl_keeps_only_user_and_system() {
        let dir = std::env::temp_dir().join(format!("gitport_acl_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("ca.key");
        std::fs::write(&f, b"x").unwrap();
        let p = f.to_string_lossy().to_string();
        restrict_to_current_user(&p).unwrap();

        let out = Command::new("icacls").arg(&p).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(text.matches(":(").count(), 2, "应只剩两条 ACE: {text}");
        assert!(!text.contains("(I)"), "继承 ACE 应已断开: {text}");
        assert!(
            text.contains("SYSTEM") || text.contains("S-1-5-18"),
            "SYSTEM 应保留: {text}"
        );
    }
}
