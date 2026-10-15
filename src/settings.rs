//! 开机自启动（注册表 Run 键）+ 关闭窗口到系统托盘 + 分流接管开关
//! （settings.json 持久化）+ 系统代理接管（PAC）。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Viaduct";
/// 更名前的旧自启动键：写/删新键时顺手清掉，防双自启残留。
const RUN_VALUE_LEGACY: &str = "ProxyWorkbench";
const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

struct SettingsState {
    close_to_tray: std::sync::atomic::AtomicBool,
    mitm: std::sync::atomic::AtomicBool,
    github_pac: std::sync::atomic::AtomicBool,
    win_rect: Mutex<[i32; 4]>,
    proxy_backup: Mutex<String>,
    // our_pac 本程序当前写入的 PAC 地址(持久化到 settings.json)：清理/自愈时
    // 用来精确判定"AutoConfigURL 是不是我们设的"，避免把用户自己的配置或我们的
    // 旧残留误判。端口无关兜底见 is_our_pac 的 localhost 正则。
    // 对照 Go 0f02257「代理接管(PAC)清理强化」。
    our_pac: Mutex<String>,
}

static SETTINGS: OnceLock<SettingsState> = OnceLock::new();
static EXE_DIR: OnceLock<PathBuf> = OnceLock::new();

fn state() -> &'static SettingsState {
    SETTINGS.get_or_init(|| SettingsState {
        close_to_tray: std::sync::atomic::AtomicBool::new(false),
        mitm: std::sync::atomic::AtomicBool::new(false),
        github_pac: std::sync::atomic::AtomicBool::new(true), // 缺省开：开箱即用免插件
        win_rect: Mutex::new([0; 4]),
        proxy_backup: Mutex::new(String::new()),
        our_pac: Mutex::new(String::new()),
    })
}

/// 初始化 exe 目录（settings.json / ca.crt 读写基准），启动时调用一次。
pub fn init_exe_dir(dir: &Path) {
    let _ = EXE_DIR.set(dir.to_path_buf());
}

fn exe_dir() -> PathBuf {
    EXE_DIR.get().cloned().unwrap_or_else(|| PathBuf::from("."))
}

// ---------- 分流接管开关 ----------

pub fn github_pac() -> bool {
    state()
        .github_pac
        .load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_github_pac(on: bool) -> Result<(), String> {
    state()
        .github_pac
        .store(on, std::sync::atomic::Ordering::Relaxed);
    save()
}

// ---------- 系统代理接管（PAC） ----------
// 只动 WinINET 的 AutoConfigURL（PAC 脚本位）：接管前备份原值，还原时恢复 ——
// 用户自己配的代理/脚本不被破坏。ProxyServer/ProxyEnable 永不触碰。

/// 分流 PAC 脚本地址（WebUI 提供，按开关动态生成域名表）。
pub fn pac_url() -> String {
    format!("http://127.0.0.1:{}/proxy.pac", crate::config::webui_port())
}

fn internet_settings_key() -> Result<RegKey, String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_READ | KEY_SET_VALUE)
        .map_err(|e| format!("打开 Internet Settings 失败: {e}"))
}

fn get_auto_config_url(key: &RegKey) -> String {
    key.get_value::<String, _>("AutoConfigURL")
        .unwrap_or_default()
}

/// 本程序设置的 PAC 兜底形态：仅本程序在 127.0.0.1 提供 /proxy.pac，端口无关
/// —— 覆盖端口曾变化/旧版残留等场景，让清理与自愈不依赖精确端口匹配。
/// 严格等价 Go 0f02257 的 localhostPACRE：`^https?://127\.0\.0\.1:\d+/proxy\.pac$`。
fn is_our_pac_like(cur: &str) -> bool {
    let cur = cur.trim();
    let Some(rest) = cur
        .strip_prefix("http://")
        .or_else(|| cur.strip_prefix("https://"))
    else {
        return false;
    };
    let Some(idx) = rest.find('/') else {
        return false;
    };
    let hostport = &rest[..idx];
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return false; // 必须带端口（Go regex :\d+）
    };
    if host != "127.0.0.1" {
        return false;
    }
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    &rest[idx..] == "/proxy.pac"
}

/// 给定 AutoConfigURL 是否本程序设置：精确匹配持久化的 our_pac，或兜底匹配
/// 127.0.0.1 的 /proxy.pac 形态。空串返回 false。对照 Go 0f02257 isOurPAC。
pub fn is_our_pac(cur: &str) -> bool {
    if cur.trim().is_empty() {
        return false;
    }
    let op = state().our_pac.lock().unwrap().clone();
    if !op.is_empty() && cur == op {
        return true;
    }
    is_our_pac_like(cur)
}

/// 广播代理设置变更，让 Edge/Chrome 等立即生效（免重启浏览器）。
/// 与 Go 版一致：LazyDLL 动态加载 wininet.dll（不依赖静态链接）。
fn refresh_wininet() {
    use windows::core::{s, w};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    unsafe {
        let Ok(dll) = LoadLibraryW(w!("wininet.dll")) else {
            return;
        };
        let Some(proc) = GetProcAddress(dll, s!("InternetSetOptionW")) else {
            return;
        };
        let f: extern "system" fn(
            *const core::ffi::c_void,
            u32,
            *const core::ffi::c_void,
            u32,
        ) -> i32 = std::mem::transmute(proc);
        let _ = f(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = f(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}

/// 按开关状态接管/还原系统代理（幂等，代理运行中调用）。
/// 对照 Go 0f02257：只备份用户自己的配置（旧残留若也是我们设的，不当成
/// "用户原配置"备份 —— 否则污染 proxyBackup 导致自愈时把死端口 PAC 当原
/// 配置还原而非删除，直观表现为"pac 越积越多 / 退出还生效"）。
pub fn ensure_system_proxy() {
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    let pac = pac_url();
    if github_pac() {
        if cur == pac {
            *state().our_pac.lock().unwrap() = pac.clone();
            return;
        }
        if !cur.is_empty() && !is_our_pac(&cur) {
            *state().proxy_backup.lock().unwrap() = cur.clone(); // 备份用户自己的设置
        }
        if key.set_value("AutoConfigURL", &pac).is_ok() {
            *state().our_pac.lock().unwrap() = pac;
            refresh_wininet();
            let _ = save();
        }
        return;
    }
    clear_if_ours(&key, &cur);
}

/// RAII 兜底（对照 Go 0f02257 的 `defer settings.RemoveSystemProxy()`）：
/// main 正常返回路径（窗口循环 return / headless）都经过本 guard 的 drop 再
/// 还原一次系统代理；幂等无害。panic/abort 不走 drop，崩溃后由下次启动的
/// heal_stale_proxy 兜底。
pub struct ProxyGuard;
impl ProxyGuard {
    pub fn new() -> Self {
        ProxyGuard
    }
}
impl Drop for ProxyGuard {
    fn drop(&mut self) {
        remove_system_proxy();
    }
}

/// 还原系统代理（代理停止时调用 —— PAC 指向已停端口只会拖垮目标站点）。
/// 端口无关：任何 127.0.0.1 的 /proxy.pac 残留(含旧端口)都视为我们的并清理。
pub fn remove_system_proxy() {
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    clear_if_ours(&key, &cur);
}

/// 恢复备份或直接删除（调用前已判定当前 PAC 是我们设的）：回填用户原配置，
/// 否则清掉；随后清备份落盘 + 广播刷新 + 存盘。
fn restore_or_clear(key: &RegKey) {
    let backup = state().proxy_backup.lock().unwrap().clone();
    if !backup.is_empty() && !is_our_pac(&backup) {
        let _ = key.set_value("AutoConfigURL", &backup);
    } else {
        let _ = key.delete_value("AutoConfigURL");
    }
    *state().proxy_backup.lock().unwrap() = String::new();
    *state().our_pac.lock().unwrap() = String::new();
    refresh_wininet();
    let _ = save();
}

/// 当前 PAC 是我们设置的才还原（备份回填或删除）。
/// 还原用户原配置时也要排除"我们的旧 PAC"，避免把死端口 PAC 当原配置写回。
fn clear_if_ours(key: &RegKey, cur: &str) {
    if !is_our_pac(cur) {
        return;
    }
    restore_or_clear(key);
}

// ---------- 窗口/托盘/开关状态 ----------

pub fn close_to_tray() -> bool {
    state()
        .close_to_tray
        .load(std::sync::atomic::Ordering::Relaxed)
}

pub fn mitm() -> bool {
    state().mitm.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn window_rect() -> Option<(i32, i32, i32, i32)> {
    let v = *state().win_rect.lock().unwrap();
    if v[2] < 400 || v[3] < 300 {
        return None;
    }
    Some((v[0], v[1], v[2], v[3]))
}

pub fn set_window_rect(l: i32, t: i32, w: i32, h: i32) -> Result<(), String> {
    *state().win_rect.lock().unwrap() = [l, t, w, h];
    save()
}

pub fn set_close_to_tray(on: bool) -> Result<(), String> {
    state()
        .close_to_tray
        .store(on, std::sync::atomic::Ordering::Relaxed);
    save()
}

pub fn set_mitm(on: bool) -> Result<(), String> {
    state().mitm.store(on, std::sync::atomic::Ordering::Relaxed);
    save()
}

// ---------- settings.json ----------

#[derive(Serialize, Deserialize)]
// 字段名与 Go 版 settings.json 完全一致(camelCase)：用户机器上可能留有
// Go 版写出的 settings.json(closeToTray/mitm/winRect/githubPAC/proxyBackup/ourPAC)，
// 移植版必须能读——之前漏 rename 导致 Go 遗留文件 serde 反序列化失败、
// 静默回退全部默认值(MITM 开关失效, 2026-10-13 实测)。
#[serde(rename_all = "camelCase")]
struct SettingsFile {
    close_to_tray: bool,
    mitm: bool,
    win_rect: [i32; 4],
    #[serde(rename = "githubPAC", skip_serializing_if = "Option::is_none")]
    github_pac: Option<bool>,
    #[serde(default)]
    groups: std::collections::HashMap<String, bool>, // 旧版键（多开关时代），读出后并入，写盘不再产出
    #[serde(default)]
    proxy_backup: String,
    // 键名与 Go 版一致：Go save 显式写 "ourPAC"(PAC 全大写, 非 camelCase 的 ourPac)，
    // 缺 rename 会写出 ourPac → Go 版读不到(双向兼容破坏)
    #[serde(default, rename = "ourPAC")]
    our_pac: String, // 对照 Go 0f02257：持久化"我们当前写入的 PAC"用于端口无关自识别
}

/// 从 exe 同目录 settings.json 恢复设置，程序启动时调用一次。
pub fn load() {
    let path = exe_dir().join("settings.json");
    let Ok(data) = std::fs::read_to_string(&path) else {
        return;
    };
    // 记事本等编辑器可能写入 UTF-8 BOM，serde_json 不认，会静默回退全部默认值
    let data = data.strip_prefix('\u{feff}').unwrap_or(&data);
    let Ok(v) = serde_json::from_str::<SettingsFile>(data) else {
        return;
    };
    state()
        .close_to_tray
        .store(v.close_to_tray, std::sync::atomic::Ordering::Relaxed);
    state()
        .mitm
        .store(v.mitm, std::sync::atomic::Ordering::Relaxed);
    *state().win_rect.lock().unwrap() = v.win_rect;
    *state().proxy_backup.lock().unwrap() = v.proxy_backup;
    *state().our_pac.lock().unwrap() = v.our_pac;
    if let Some(on) = v.github_pac {
        state()
            .github_pac
            .store(on, std::sync::atomic::Ordering::Relaxed);
    } else if let Some(on) = v.groups.get("github") {
        // 旧 settings.json 的一次性迁移
        state()
            .github_pac
            .store(*on, std::sync::atomic::Ordering::Relaxed);
    }
    heal_stale_proxy();
}

fn save() -> Result<(), String> {
    let s = state();
    let data = SettingsFile {
        close_to_tray: s.close_to_tray.load(std::sync::atomic::Ordering::Relaxed),
        mitm: s.mitm.load(std::sync::atomic::Ordering::Relaxed),
        win_rect: *s.win_rect.lock().unwrap(),
        github_pac: Some(s.github_pac.load(std::sync::atomic::Ordering::Relaxed)),
        groups: std::collections::HashMap::new(),
        proxy_backup: s.proxy_backup.lock().unwrap().clone(),
        our_pac: s.our_pac.lock().unwrap().clone(),
    };
    let json = serde_json::to_string(&data).map_err(|e| e.to_string())?;
    let p = exe_dir().join("settings.json");
    std::fs::write(&p, json).map_err(|e| e.to_string())?;
    // settings.json 含本机配置：ACL 收紧为仅当前用户（best-effort）
    let _ = crate::winsec::restrict_to_current_user(&p.to_string_lossy());
    Ok(())
}

/// 陈旧接管自愈（启动时一次）：上次进程异常退出时，注册表里可能残留指向
/// 本程序 PAC 的 AutoConfigURL。依据 settings.json 留存的备份回填或直接删除。
/// 端口无关：任何 127.0.0.1 的 /proxy.pac 残留(含旧端口)都视为我们的并清理。
fn heal_stale_proxy() {
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    if cur.is_empty() || !is_our_pac(&cur) {
        return; // 本来就干净，或是用户自己的配置：绝不触碰
    }
    restore_or_clear(&key);
}

// ---------- 开机自启 ----------

pub fn autostart_enabled() -> bool {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_READ)
    else {
        return false;
    };
    let Ok(v) = key.get_value::<String, _>(RUN_VALUE) else {
        return false;
    };
    // 值存在还要 exe 仍在 —— exe 被移动/删除后设置页如实显示未开启
    autostart_exe_exists(&v)
}

/// 解析 Run 键命令行（`"exe" args` 或裸 exe）并检查 exe 存在。
/// 从自启命令中解析 exe 路径（首段，带引号则取引号内内容）。
fn parse_exe_path(cmdline: &str) -> Option<&str> {
    if let Some(rest) = cmdline.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            Some(&rest[..end])
        } else {
            Some(rest)
        }
    } else {
        cmdline.split([' ', '\t']).next().filter(|p| !p.is_empty())
    }
}

fn autostart_exe_exists(cmdline: &str) -> bool {
    match parse_exe_path(cmdline) {
        Some(p) if !p.is_empty() => Path::new(p).exists(),
        _ => false,
    }
}

pub fn set_autostart(on: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(RUN_KEY)
        .map_err(|e| format!("打开 Run 键失败: {e}"))?;
    if on {
        // -tray: 开机自启直接驻留托盘，不弹工作台窗口
        key.set_value(RUN_VALUE, &format!("\"{}\" -tray", exe.to_string_lossy()))
            .map_err(|e| format!("写入 Run 键失败: {e}"))?;
    } else {
        let _ = key.delete_value(RUN_VALUE);
    }
    let _ = key.delete_value(RUN_VALUE_LEGACY); // 旧键名残留清理(更名前版本)
    Ok(())
}

// ---------- 启动参数辅助 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_cmd_parse() {
        // 纯解析（不依赖文件系统存在性）
        assert_eq!(
            parse_exe_path(r#""C:\x\a.exe" -tray"#),
            Some("C:\\x\\a.exe")
        );
        assert_eq!(
            parse_exe_path(r#""C:\no\such.exe" -tray"#),
            Some("C:\\no\\such.exe")
        );
        assert_eq!(parse_exe_path("C:\\x\\a.exe"), Some("C:\\x\\a.exe"));
        assert_eq!(parse_exe_path(""), None);
        assert_eq!(parse_exe_path("   "), None);
    }

    // 对照 Go 0f02257 settings_windows_test.go TestIsOurPAC：端口无关自识别。
    // 本程序写出的 PAC 形态（任意端口）都算"我们的"；用户自己的配置不算。
    #[test]
    fn is_our_pac_port_agnostic() {
        // 精确匹配持久化的 ourPAC 形态
        assert!(is_our_pac_like("http://127.0.0.1:7811/proxy.pac"));
        assert!(is_our_pac_like("https://127.0.0.1:9999/proxy.pac"));
        assert!(is_our_pac_like("http://127.0.0.1:65535/proxy.pac"));
        // 非本程序形态：绝对不算
        assert!(!is_our_pac_like("http://127.0.0.2:7811/proxy.pac"));
        assert!(!is_our_pac_like("http://127.0.0.1/proxy.pac")); // 无端口
        assert!(!is_our_pac_like("http://localhost:7811/proxy.pac")); // 非 127.0.0.1
        assert!(!is_our_pac_like("http://127.0.0.1:7811/other.pac"));
        assert!(!is_our_pac_like("http://example.com:7811/proxy.pac"));
        assert!(!is_our_pac_like(""));
        assert!(!is_our_pac_like("socks5://127.0.0.1:7811/proxy.pac"));
        assert!(!is_our_pac_like("http://127.0.0.1:78a1/proxy.pac")); // 端口非数字
        assert!(!is_our_pac_like("http://127.0.0.1:7811/proxy.pac?x=1")); // 严格等 Go regex
    }
}
