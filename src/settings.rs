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
    // 串发游标（每池/族记号 = 上次驻留的 IP）：故障转移时更新并落盘。
    last_ip: Mutex<LastIpTable>,
    // 自定义镜像注册表：settings.json 永久记录（删除 = 彻底消失）；
    // 启停状态只增删 plans.json 镜像链成员，不动注册表。
    worker_mirrors: Mutex<Vec<WorkerMirror>>,
}

/// 一条自定义镜像：url = Worker 反代地址（拼接格式），on = 是否已启用进镜像链。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(default)]
pub struct WorkerMirror {
    pub url: String,
    pub on: bool,
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
        last_ip: Mutex::new(LastIpTable::default()),
        worker_mirrors: Mutex::new(Vec::new()),
    })
}

pub fn init_exe_dir(dir: &Path) {
    let _ = EXE_DIR.set(dir.to_path_buf());
}

/// exe 所在目录（缓存/配置落盘基准）。供页面缓存等模块取 .cache 基准路径。
pub fn exe_dir() -> PathBuf {
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

/// 是否本程序设置的 PAC：端口无关，任何 `127.0.0.1:端口/proxy.pac` 形态都算
/// （我们写进去的必然是这个形态，不必再逐字记住自己写过什么）。
pub fn is_our_pac(cur: &str) -> bool {
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

/// 广播代理设置变更（WinINET 已装即链上 wininet.dll，无需动态解析）。
fn refresh_wininet() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
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
            return; // 已是我们设的（幂等）
        }
        if !cur.is_empty() && !is_our_pac(&cur) {
            *state().proxy_backup.lock().unwrap() = cur.clone(); // 备份用户自己的设置
        }
        if key.set_value("AutoConfigURL", &pac).is_ok() {
            refresh_wininet();
            let _ = save();
        }
        return;
    }
    clear_if_ours(&key, &cur);
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
    /// 按规范键序成表：全量键位预写空值，再以给定记号覆盖；表外键（族改名/手写残留）直接丢弃，
    /// 键位由 `circle_keys()` 单一决定。
    fn from_marks(marks: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut pending: HashMap<String, String> = marks.into_iter().collect();
        let rows = crate::pool::circle_keys()
            .into_iter()
            .map(|key| {
                let ip = pending.remove(&key).unwrap_or_default();
                (key, ip)
            })
            .collect();
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
    #[serde(rename = "githubPAC", deserialize_with = "lenient")]
    github_pac: bool,
    #[serde(deserialize_with = "lenient")]
    proxy_backup: String,
    #[serde(deserialize_with = "lenient")]
    last_ip: LastIpTable, // 串发游标(每池/族上次驻留的 IP),恒全量键位、恒规范序
    /// 自定义镜像注册表：settings.json 永久记录；启停只增删 plans.json 链成员。
    #[serde(deserialize_with = "lenient")]
    worker_mirrors: Vec<WorkerMirror>,
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
    *state().last_ip.lock().unwrap() = v.last_ip;
    state()
        .github_pac
        .store(v.github_pac, std::sync::atomic::Ordering::Relaxed);
    *state().worker_mirrors.lock().unwrap() = v.worker_mirrors;
}

/// settings.json 保存互斥：快照 + 写盘必须整段原子完成。
/// WebUI 改设置与拨号路径写游标（set_last_ips）是两条并发路径，无锁时互相拿
/// 快照+写盘全程持锁，防旧快照覆写丢更新（保存是罕见事件，临界区短）。
static SAVE_LOCK: Mutex<()> = Mutex::new(());

fn save() -> Result<(), String> {
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let s = state();
    let data = SettingsFile {
        close_to_tray: s.close_to_tray.load(std::sync::atomic::Ordering::Relaxed),
        mitm: s.mitm.load(std::sync::atomic::Ordering::Relaxed),
        win_rect: *s.win_rect.lock().unwrap(),
        github_pac: s.github_pac.load(std::sync::atomic::Ordering::Relaxed),
        proxy_backup: s.proxy_backup.lock().unwrap().clone(),
        last_ip: s.last_ip.lock().unwrap().clone(),
        worker_mirrors: s.worker_mirrors.lock().unwrap().clone(),
    };
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    let p = settings_path();
    crate::fsx::write_atomic(&p, json.as_bytes()).map_err(|e| e.to_string())?;
    // 每次都要重收紧：rename 换进来的是新文件，继承的是目录 ACL，不是旧文件的受保护 DACL。
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

/// 自定义镜像注册表（settings.json 永久记录；启停只增删 plans.json 链成员）。
pub fn worker_mirrors() -> Vec<WorkerMirror> {
    state().worker_mirrors.lock().unwrap().clone()
}

/// 收编保存（启动迁移用）：仅落盘注册表，不动镜像链——链中本来就有，
/// 位置交给测速校准。顺序保持调用方给的原序（先写哪个就是哪个）。
pub fn save_worker_mirrors(list: Vec<WorkerMirror>) {
    *state().worker_mirrors.lock().unwrap() = list;
    let _ = save();
}

/// 整表保存自定义镜像注册表：校验（https:// 开头、无空格、去尾斜杠、去重去空）、
/// 与旧表做差集（新增/停用/删除），交由镜像链对齐后落盘。返回启用中的地址列表。
/// 删除条目由"新旧差集"自动从链中移除——删除即彻底消失。
pub fn set_worker_mirrors(list: Vec<WorkerMirror>) -> Result<Vec<String>, String> {
    let mut norm: Vec<WorkerMirror> = Vec::new();
    for w in list {
        let u = w.url.trim().trim_end_matches('/').to_string();
        if u.is_empty() {
            continue; // 未填完的空行直接忽略
        }
        if !u.starts_with("https://") || u.contains(' ') {
            return Err(format!("镜像地址须以 https:// 开头且不含空格: {u}"));
        }
        if norm.iter().any(|x| x.url == u) {
            continue; // 去重
        }
        norm.push(WorkerMirror { url: u, on: w.on });
    }
    let old = worker_mirrors();
    let removed: Vec<String> = old
        .iter()
        .map(|w| w.url.clone())
        .filter(|u| !norm.iter().any(|n| n.url == *u))
        .collect();
    let enabled: Vec<String> = norm.iter().filter(|w| w.on).map(|w| w.url.clone()).collect();
    *state().worker_mirrors.lock().unwrap() = norm;
    save()?;
    crate::pool::sync_custom_mirrors(&removed);
    Ok(enabled)
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
        assert!(is_our_pac("http://127.0.0.1:7811/proxy.pac"));
        assert!(is_our_pac("https://127.0.0.1:9999/proxy.pac"));
        assert!(is_our_pac("http://127.0.0.1:65535/proxy.pac"));
        assert!(!is_our_pac("http://127.0.0.2:7811/proxy.pac"));
        assert!(!is_our_pac("http://127.0.0.1/proxy.pac")); // 无端口
        assert!(!is_our_pac("http://localhost:7811/proxy.pac")); // 非 127.0.0.1
        assert!(!is_our_pac("http://127.0.0.1:7811/other.pac"));
        assert!(!is_our_pac("http://example.com:7811/proxy.pac"));
        assert!(!is_our_pac(""));
        assert!(!is_our_pac("socks5://127.0.0.1:7811/proxy.pac"));
        assert!(!is_our_pac("http://127.0.0.1:78a1/proxy.pac")); // 端口非数字
        assert!(!is_our_pac("http://127.0.0.1:7811/proxy.pac?x=1"));
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
        assert!(v.close_to_tray && v.mitm && v.github_pac, "其他字段被连坐");
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
            github_pac: false,
            proxy_backup: String::new(),
            last_ip: LastIpTable::from_marks(vec![(
                "api/all".to_string(),
                "140.82.114.6".to_string(),
            )]),
            worker_mirrors: vec![WorkerMirror {
                url: "https://my.worker".to_string(),
                on: true,
            }],
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

    #[test]
    fn worker_mirrors_roundtrip() {
        // 正常清单：url + 启停状态原样回读
        let v = parse(
            r#"{"workerMirrors":[{"url":"https://my.worker","on":true},{"url":"https://b.worker","on":false}]}"#,
        );
        assert_eq!(v.worker_mirrors.len(), 2);
        assert_eq!(v.worker_mirrors[0].url, "https://my.worker");
        assert!(v.worker_mirrors[0].on);
        assert!(!v.worker_mirrors[1].on);
        // 缺键 = 空注册表
        let v2 = parse("{}");
        assert!(v2.worker_mirrors.is_empty());
        // 整段写坏 = 回空表（不连坐其他字段）
        let v3 = parse(r#"{"workerMirrors":"oops","mitm":true}"#);
        assert!(v3.worker_mirrors.is_empty());
        assert!(v3.mitm);
    }
}
