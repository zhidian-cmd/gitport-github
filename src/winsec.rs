//! Windows 文件 ACL 收紧。Rust 的 0600 权限位在 Windows 上只映射到只读属性，
//! 不生成 ACL —— 文件缺省继承所在目录 ACL，同机其他账户/进程可读。
//! ca.key（MITM 根私钥）/settings.json 属敏感本地数据，落盘后收紧为
//! 仅当前用户与 SYSTEM：根私钥一旦可读，同机进程即可伪造用户已信任的
//! "GitPort Root" 叶子证书对用户实施中间人。

use windows::core::{BOOL, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 用受保护 DACL 覆盖继承权限：仅 SYSTEM 与当前用户保留完全控制，
/// 其他账户（含同机普通用户）一律剥离。失败返回错误（文件本身已写入成功，
/// 调用方按 best-effort 处理，不影响主流程）。
pub fn restrict_to_current_user(path: &str) -> Result<(), String> {
    // 打开当前进程令牌并取用户 SID
    let mut token = Default::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| format!("OpenProcessToken 失败: {e}"))?;
    }
    // TOKEN_USER 缓冲（SID 大小可变，用固定缓冲 + GetTokenInformation 查询）
    let mut buf = vec![0u8; 512];
    let mut size = 0u32;
    let first_ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut size,
        )
        .is_ok()
    };
    if !first_ok {
        // 缓冲不足：按返回大小重试一次
        if size > buf.len() as u32 {
            buf.resize(size as usize, 0);
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    Some(buf.as_mut_ptr().cast()),
                    buf.len() as u32,
                    &mut size,
                )
            }
            .map_err(|e| format!("GetTokenInformation(重试) 失败: {e}"))?;
        } else {
            return Err("GetTokenInformation 失败".to_string());
        }
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = user.User.Sid;

    // SID → 字符串（advapi32 分配，用完 LocalFree）
    let mut sid_str = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut sid_str)
            .map_err(|e| format!("ConvertSidToStringSidW 失败: {e}"))?;
    }
    let sid_text = unsafe { sid_str.to_string() }.unwrap_or_default();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_str.0 as *mut core::ffi::c_void)));
    }

    // 构造保护 DACL：SYSTEM 与当前用户完全控制，其余一律剥离
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text})");
    let sd_h = HSTRING::from(sddl.as_str());
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sd_h.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
        )
        .map_err(|e| format!("SDDL 解析失败: {e}"))?;
    }
    let mut present = BOOL(0);
    let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| format!("取 DACL 失败: {e}"))?;
    }
    if !present.as_bool() || dacl.is_null() {
        return Err("SDDL 未产出 DACL".to_string());
    }

    let path_u16: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_u16.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    // dacl 指向 ConvertString... 分配的安全描述符内的 ACL —— 必须等
    // SetNamedSecurityInfoW 完成后再释放 sd；此前先 LocalFree(sd) 会让 dacl
    // 变悬垂指针，SetNamedSecurityInfoW 可能写出空 DACL(实测 D:PAI)，
    // 把文件锁死成谁都打不开(2026-10-13 实测 settings.json 变空 ACL)。
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    if err.0 != 0 {
        return Err(format!("SetNamedSecurityInfoW 失败: {}", err.0));
    }
    unsafe {
        let _ = CloseHandle(token);
    }
    Ok(())
}
