//! 自启注册表 / 关窗到托盘 / 分流开关（settings.json 持久化）/ 系统代理 PAC 接管。
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "gitport-github";
const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

struct SettingsState {
    close_to_tray: std::sync::atomic::AtomicBool,
    mitm: std::sync::atomic::AtomicBool,
    github_pac: std::sync::atomic::AtomicBool,
    win_rect: Mutex<[i32; 4]>,
    proxy_backup: Mutex<String>,
    // 本程序当前写入的 PAC 地址（持久化）：自愈时精确判定"是不是我们设的"。
    our_pac: Mutex<String>,
    // 串发游标（每池/族记号 = 上次驻留的 IP）：故障转移时更新并落盘。
    last_ip: Mutex<LastIpTable>,
}

static SETTINGS: OnceLock<SettingsState> = OnceLock::new();
static EXE_DIR: OnceLock<PathBuf> = OnceLock::new();

fn state() -> &'static SettingsState {
    SETTINGS.get_or_init(|| SettingsState {
        close_to_tray: std::sync::atomic::AtomicBool::new(false),
        mitm: std::sync::atomic::AtomicBool::new(false),
        github_pac: std::sync::atomic::AtomicBool::new(false),
        win_rect: Mutex::new([0; 4]),
        proxy_backup: Mutex::new(String::new()),
        our_pac: Mutex::new(String::new()),
        last_ip: Mutex::new(LastIpTable::default()),
    })
}

pub fn init_exe_dir(dir: &Path) {
    let _ = EXE_DIR.set(dir.to_path_buf());
}

fn exe_dir() -> PathBuf {
    EXE_DIR.get().cloned().unwrap_or_else(|| PathBuf::from("."))
}


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

// 只动 WinINET 的 AutoConfigURL：接管前备份，还原时恢复；ProxyServer/ProxyEnable 永不触碰。

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

/// 端口无关：任何 127.0.0.1 的 /proxy.pac 形态都算本程序设置的。
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
        return false; // 必须带端口
    };
    if host != "127.0.0.1" {
        return false;
    }
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    &rest[idx..] == "/proxy.pac"
}

/// 是否本程序设置的 PAC：精确匹配 our_pac 或兜底形态。
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

/// 广播代理设置变更（动态加载 wininet.dll）。
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

/// 按开关接管/还原系统代理（幂等）。只备份用户自己的配置——把我们的旧残留当原配置会让自愈还原死 PAC。
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

/// RAII 兜底：正常退出路径 drop 时再还原一次；panic 由下次启动 heal_stale_proxy 兜底。
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

/// 还原系统代理：端口无关，任何 /proxy.pac 残留都视为我们的并清理。
pub fn remove_system_proxy() {
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    clear_if_ours(&key, &cur);
}

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

/// 当前 PAC 是我们设置的才还原（还原用户原配置时也排除我们的旧 PAC）。
fn clear_if_ours(key: &RegKey, cur: &str) {
    if !is_our_pac(cur) {
        return;
    }
    restore_or_clear(key);
}


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


/// 串发游标表：`{"core/all": "1.2.3.4", ...}`。
/// 不变量（settings.json 的契约）：
///   1. 键位恒为 `pool::circle_keys()` 全量——core/all、api/all、edge/{content,assets,io,auth}；
///   2. 顺序恒为表序，从上到下，不随 HashMap 抖动；
///   3. 值 `""` = 该族未驻留（与"键缺失"等价，但写出来让人能看全 schema）。
/// 读兼容对象、`[[k,v],…]` 数组、整段缺失；写只写对象。
#[derive(Clone, Debug, PartialEq, Eq)]
struct LastIpTable(Vec<(String, String)>);

impl LastIpTable {
    /// 按规范键序成表：全量键位预写空值，再以给定记号覆盖；表外键（族改名/手写残留）按字典序
    /// 追加尾部——不丢数据，也不打乱规范序。
    fn from_marks(marks: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut pending: HashMap<String, String> = marks.into_iter().collect();
        let mut rows = Vec::with_capacity(pending.len() + 8);
        for key in crate::pool::circle_keys() {
            let ip = pending.remove(&key).unwrap_or_default();
            rows.push((key, ip));
        }
        let mut strays: Vec<(String, String)> = pending.into_iter().collect();
        strays.sort_by(|a, b| a.0.cmp(&b.0));
        rows.extend(strays);
        LastIpTable(rows)
    }

    fn marks(&self) -> &[(String, String)] {
        &self.0
    }
}

// 全新安装/整段缺失也铺满键位：落盘同样是 6 个空串，而不是空对象。
impl Default for LastIpTable {
    fn default() -> Self {
        Self::from_marks(std::iter::empty::<(String, String)>())
    }
}

impl Serialize for LastIpTable {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        // 逐项按现有顺序写入（serde_json 的 serializer 按调用序落盘）；
        // 不能借 Map 容器中转：未开 preserve_order 时它会被 BTreeMap 重排成字典序。
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (key, ip) in &self.0 {
            map.serialize_entry(key, ip)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for LastIpTable {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Shape {
            Map(HashMap<String, String>),
            List(Vec<(String, String)>),
        }
        Ok(match Shape::deserialize(d)? {
            Shape::Map(map) => Self::from_marks(map),
            Shape::List(list) => Self::from_marks(list),
        })
    }
}

/// 单字段容错：值写坏（类型不符）只回退该字段，不连坐整份配置。
/// settings.json 允许手改，任何一处笔误都不该让开关、窗口位置、游标一起归零。
fn lenient<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + Default,
{
    let raw = serde_json::Value::deserialize(d)?;
    Ok(T::deserialize(raw).unwrap_or_default())
}

#[derive(Serialize, Deserialize, Default)]
// 字段名(camelCase)即既有落盘格式，不可改——漏 rename 会让旧文件反序列化失败静默回默认。
// 容器级 default：漏键只回退该键；字段级 lenient：值写坏也只回退该键。
#[serde(rename_all = "camelCase", default)]
struct SettingsFile {
    #[serde(deserialize_with = "lenient")]
    close_to_tray: bool,
    #[serde(deserialize_with = "lenient")]
    mitm: bool,
    #[serde(deserialize_with = "lenient")]
    win_rect: [i32; 4],
    #[serde(
        rename = "githubPAC",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    github_pac: Option<bool>,
    #[serde(deserialize_with = "lenient")]
    proxy_backup: String,
    // 键名显式写 "ourPAC"（非 camelCase）：既有落盘即此形。
    #[serde(rename = "ourPAC", deserialize_with = "lenient")]
    our_pac: String, // 持久化"我们当前写入的 PAC"用于端口无关自识别
    #[serde(deserialize_with = "lenient")]
    last_ip: LastIpTable, // 串发游标(每池/族上次驻留的 IP),恒全量键位、恒规范序
}

fn settings_path() -> PathBuf {
    exe_dir().join("settings.json")
}

pub fn load() {
    match std::fs::read_to_string(settings_path()) {
        Ok(raw) => apply(parse(&raw)),
        // 全新安装：首启落一份全键位空模板，"固定位置 + 固定 schema"从第一次运行起成立。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = save();
        }
        Err(_) => {}
    }
    heal_stale_proxy();
}

fn parse(raw: &str) -> SettingsFile {
    // 记事本可能写入 UTF-8 BOM，serde_json 不认
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    serde_json::from_str(raw).unwrap_or_default()
}

fn apply(v: SettingsFile) {
    state()
        .close_to_tray
        .store(v.close_to_tray, std::sync::atomic::Ordering::Relaxed);
    state()
        .mitm
        .store(v.mitm, std::sync::atomic::Ordering::Relaxed);
    *state().win_rect.lock().unwrap() = v.win_rect;
    *state().proxy_backup.lock().unwrap() = v.proxy_backup;
    *state().our_pac.lock().unwrap() = v.our_pac;
    *state().last_ip.lock().unwrap() = v.last_ip;
    if let Some(on) = v.github_pac {
        state()
            .github_pac
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }
}

fn save() -> Result<(), String> {
    let s = state();
    let data = SettingsFile {
        close_to_tray: s.close_to_tray.load(std::sync::atomic::Ordering::Relaxed),
        mitm: s.mitm.load(std::sync::atomic::Ordering::Relaxed),
        win_rect: *s.win_rect.lock().unwrap(),
        github_pac: Some(s.github_pac.load(std::sync::atomic::Ordering::Relaxed)),
        proxy_backup: s.proxy_backup.lock().unwrap().clone(),
        our_pac: s.our_pac.lock().unwrap().clone(),
        last_ip: s.last_ip.lock().unwrap().clone(),
    };
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    let p = settings_path();
    std::fs::write(&p, json).map_err(|e| e.to_string())?;
    let _ = crate::winsec::restrict_to_current_user(&p.to_string_lossy());
    Ok(())
}

/// 陈旧接管自愈（启动时一次）：异常退出残留的 AutoConfigURL 按备份回填或删除；端口无关。
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

pub fn last_ips() -> Vec<(String, String)> {
    state().last_ip.lock().unwrap().marks().to_vec()
}

/// 故障转移时记录驻留 IP(每池/族一个游标记号),并落盘 settings.json。
/// 游标变化是窗口级罕见事件,直接同步写;崩溃最多丢最后一跳。
pub fn set_last_ips(marks: Vec<(String, String)>) {
    let next = LastIpTable::from_marks(marks);
    {
        let mut st = state().last_ip.lock().unwrap();
        if *st == next {
            return;
        }
        *st = next;
    }
    let _ = save();
}


pub fn autostart_enabled() -> bool {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_READ)
    else {
        return false;
    };
    let Ok(v) = key.get_value::<String, _>(RUN_VALUE) else {
        return false;
    };
    autostart_exe_exists(&v)
}

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
        key.set_value(RUN_VALUE, &format!("\"{}\" -tray", exe.to_string_lossy()))
            .map_err(|e| format!("写入 Run 键失败: {e}"))?;
    } else {
        let _ = key.delete_value(RUN_VALUE);
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_cmd_parse() {
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

    #[test]
    fn is_our_pac_port_agnostic() {
        assert!(is_our_pac_like("http://127.0.0.1:7811/proxy.pac"));
        assert!(is_our_pac_like("https://127.0.0.1:9999/proxy.pac"));
        assert!(is_our_pac_like("http://127.0.0.1:65535/proxy.pac"));
        assert!(!is_our_pac_like("http://127.0.0.2:7811/proxy.pac"));
        assert!(!is_our_pac_like("http://127.0.0.1/proxy.pac")); // 无端口
        assert!(!is_our_pac_like("http://localhost:7811/proxy.pac")); // 非 127.0.0.1
        assert!(!is_our_pac_like("http://127.0.0.1:7811/other.pac"));
        assert!(!is_our_pac_like("http://example.com:7811/proxy.pac"));
        assert!(!is_our_pac_like(""));
        assert!(!is_our_pac_like("socks5://127.0.0.1:7811/proxy.pac"));
        assert!(!is_our_pac_like("http://127.0.0.1:78a1/proxy.pac")); // 端口非数字
        assert!(!is_our_pac_like("http://127.0.0.1:7811/proxy.pac?x=1"));
    }

    fn keys(pairs: &[(String, String)]) -> Vec<&str> {
        pairs.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn last_ip_object_form_expands_to_full_schema() {
        // 旧落盘形态：对象、只有 4 个键、乱序。
        let v = parse(
            r#"{"closeToTray":true,"mitm":true,"winRect":[0,0,800,600],"githubPAC":true,
                "lastIp":{"edge/assets":"185.199.108.154","core/all":"20.27.177.114",
                          "edge/content":"185.199.110.133","api/all":"140.82.114.6"}}"#,
        );
        assert!(v.close_to_tray && v.mitm && v.github_pac == Some(true), "其他字段被连坐");
        assert_eq!(
            v.last_ip.marks().to_vec(),
            vec![
                ("core/all".to_string(), "20.27.177.114".to_string()),
                ("api/all".to_string(), "140.82.114.6".to_string()),
                ("edge/content".to_string(), "185.199.110.133".to_string()),
                ("edge/assets".to_string(), "185.199.108.154".to_string()),
                ("edge/io".to_string(), String::new()),
                ("edge/auth".to_string(), String::new()),
            ],
            "对象形态必须归一到规范键序，缺位补空串"
        );
    }

    #[test]
    fn last_ip_array_and_missing_forms_accepted() {
        let arr = parse(r#"{"lastIp":[["edge/io","1.2.3.4"],["core/all",""]]}"#);
        assert_eq!(
            keys(arr.last_ip.marks()),
            ["core/all", "api/all", "edge/content", "edge/assets", "edge/io", "edge/auth"]
        );
        assert_eq!(arr.last_ip.marks()[4].1, "1.2.3.4");

        let none = parse(r#"{"mitm":true}"#);
        assert!(none.mitm);
        assert_eq!(none.last_ip.marks().len(), 6, "整段缺失也要铺满键位");
        assert!(none.last_ip.marks().iter().all(|(_, v)| v.is_empty()));
    }

    #[test]
    fn save_emits_full_schema_in_canonical_order() {
        let f = SettingsFile {
            close_to_tray: true,
            mitm: false,
            win_rect: [1, 2, 3, 4],
            github_pac: Some(false),
            proxy_backup: String::new(),
            our_pac: String::new(),
            last_ip: LastIpTable::from_marks(vec![(
                "api/all".to_string(),
                "140.82.114.6".to_string(),
            )]),
        };
        let json = serde_json::to_string_pretty(&f).unwrap();
        let expect = r#"  "lastIp": {
    "core/all": "",
    "api/all": "140.82.114.6",
    "edge/content": "",
    "edge/assets": "",
    "edge/io": "",
    "edge/auth": ""
  }"#;
        assert!(json.contains(expect), "落盘 schema 漂移:\n{json}");
        // 落盘 → 再读必须回同值（写读闭环）
        let back = parse(&json);
        assert_eq!(back.last_ip.marks(), f.last_ip.marks());
        assert_eq!(back.win_rect, [1, 2, 3, 4]);
    }

    #[test]
    fn single_bad_field_does_not_wipe_file() {
        // winRect 写坏：只回退该字段，开关与游标照读。
        let v = parse(
            r#"{"closeToTray":true,"mitm":true,"winRect":"oops","lastIp":{"api/all":"1.1.1.1"}}"#,
        );
        assert!(v.close_to_tray && v.mitm, "一个字段笔误不得连坐整份配置");
        assert_eq!(v.win_rect, [0; 4]);
        assert_eq!(v.last_ip.marks()[1], ("api/all".to_string(), "1.1.1.1".to_string()));
        // 非 JSON 垃圾才整体回默认
        assert_eq!(parse("not json").close_to_tray, false);
    }
}
