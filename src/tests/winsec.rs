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
    // 完整性标签(Mandatory Label)不是权限 ACE：低 IL 环境（沙箱、下载目录）会给文件挂一条，既不算"两条 ACE"也不算继承未断。
    let aces: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(":(") && !l.contains("Mandatory Label"))
        .collect();
    assert_eq!(aces.len(), 2, "应只剩两条权限 ACE: {text}");
    assert!(
        aces.iter().all(|l| !l.contains("(I)")),
        "继承 ACE 应已断开: {text}"
    );
    assert!(
        text.contains("SYSTEM") || text.contains("S-1-5-18"),
        "SYSTEM 应保留: {text}"
    );
}

/// 契约（目录版）：授权带 (OI)(CI) 继承标志——曾因目录授权无继承 + 断继承，子目录被剥成空 DACL，cacache 临时文件全部创建失败。
#[test]
fn acl_dir_grants_inheritable_access() {
    let dir = std::env::temp_dir().join(format!("gitport_acl_dir_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    restrict_dir_to_current_user(&dir.to_string_lossy()).unwrap();
    let child = dir.join("writable.txt");
    std::fs::write(&child, b"x").expect("目录收紧后子文件必须可写");
    std::fs::remove_dir_all(&dir).unwrap();
}
