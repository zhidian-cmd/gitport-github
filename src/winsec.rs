//! Windows 文件 ACL 收紧：ca.key 与 settings.json 只授当前用户与 SYSTEM——根私钥可读即可伪造叶子证书。
//! 原生 ACL API（SetNamedSecurityInfoW）实现。以前靠 spawn icacls 子进程，关机时序中子进程
//! 启动失败会弹 0xc0000142 错误窗（git.exe 弹窗的同源第二来源），原生调用零子进程，任何时序都安全。

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, LocalFree, ERROR_SUCCESS, HLOCAL, HANDLE,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, PSID,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
    Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SetEntriesInAclW,
        SetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_TYPE, TRUSTEE_W,
    },
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 受保护 DACL（文件版）：仅 SYSTEM 与当前用户，完全控制——icacls 的裸 (F)。
pub fn restrict_to_current_user(path: &str) -> Result<(), String> {
    restrict(path, GENERIC_ALL.0, ACE_FLAGS(0))
}

/// 受保护 DACL（目录版）：完全控制 + 对象/容器继承，否则断继承后旧子目录被剥成空 DACL，缓存全写不进去。
/// 继承标志必须放 grfInheritance 字段——混进权限掩码会让子目录继承出空 DACL，缓存写盘全部拒绝访问。
pub fn restrict_dir_to_current_user(path: &str) -> Result<(), String> {
    restrict(
        path,
        GENERIC_ALL.0,
        ACE_FLAGS(OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0),
    )
}

fn restrict(path: &str, rights: u32, inheritance: ACE_FLAGS) -> Result<(), String> {
    unsafe {
        // 1) 当前用户 SID：从进程令牌直取（比按用户名解析精确，无同名歧义）。
        //    SID 指向 _sid_buf 内部，_sid_buf 必须活到 SetEntriesInAclW 之后。
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| format!("打开进程令牌失败: {e}"))?;
        let (user_sid, _sid_buf) = get_token_user_sid(token)?;
        let _ = CloseHandle(token);

        // 2) SYSTEM 的 SID（S-1-5-18）：ConvertStringSidToSidW 分配，用完 LocalFree。
        let mut system_sid = PSID::default();
        ConvertStringSidToSidW(&HSTRING::from("S-1-5-18"), &mut system_sid)
            .map_err(|e| format!("构造 SYSTEM SID 失败: {e}"))?;

        // 3) 两条授权条目：当前用户 + SYSTEM。SetEntriesInAclW 的基线传 None =
        //    从零构建新 DACL（等价 icacls /grant:r 的替换语义），继承由 PROTECTED 标志断开。
        let entries = [
            explicit_access(&user_sid, rights, inheritance, TRUSTEE_IS_USER),
            explicit_access(&system_sid, rights, inheritance, TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let ret = SetEntriesInAclW(Some(&entries), None, &mut new_dacl);
        if ret != ERROR_SUCCESS {
            return Err(format!("构建新 DACL 失败: {}", ret.0));
        }

        // 4) 落盘：PROTECTED_DACL_SECURITY_INFORMATION = icacls 的 /inheritance:r（断继承）。
        let ret = SetNamedSecurityInfoW(
            &HSTRING::from(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new_dacl.cast())));
        let _ = LocalFree(Some(HLOCAL(system_sid.0.cast())));
        if ret != ERROR_SUCCESS {
            return Err(format!("写入 ACL 失败: {}", ret.0));
        }
        Ok(())
    }
}

fn explicit_access(
    sid: &PSID,
    rights: u32,
    inheritance: ACE_FLAGS,
    trustee_type: TRUSTEE_TYPE,
) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            ptstrName: PWSTR(sid.0.cast()),
        },
    }
}

/// 从进程令牌取当前用户的 SID。SID 指向返回的 buf 内部，buf 必须与 SID 同生命周期。
unsafe fn get_token_user_sid(token: HANDLE) -> Result<(PSID, Vec<u8>), String> {
    let mut len = 0u32;
    let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
    if len == 0 {
        return Err("查不到令牌信息长度".into());
    }
    let mut buf = vec![0u8; len as usize];
    GetTokenInformation(
        token,
        TokenUser,
        Some(buf.as_mut_ptr().cast()),
        len,
        &mut len,
    )
    .map_err(|e| format!("读取令牌用户失败: {e}"))?;
    let user = buf.as_ptr().cast::<TOKEN_USER>().read();
    Ok((user.User.Sid, buf))
}
