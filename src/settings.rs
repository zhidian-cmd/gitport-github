//! 自启注册表 / 关窗到托盘 / 分流开关（settings.json 持久化）/ 系统代理 PAC 接管。
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;
use windows::Win32::Networking::WinInet::{
    PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "gitport-github";
const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
/// WinINET 把"每条连接"的代理配置存在这个二进制值里（AutoConfigURL 只是给人和旧程序看的镜像）。
const CONNECTIONS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const CONN_SETTINGS_VALUE: &str = "DefaultConnectionSettings";

struct SettingsState {
    close_to_tray: std::sync::atomic::AtomicBool,
    mitm: std::sync::atomic::AtomicBool,
    github_pac: std::sync::atomic::AtomicBool,
    win_rect: Mutex<[i32; 4]>,
    proxy_backup: Mutex<String>,
    // 我们最后一次成功写进系统的 PAC URL：接管时区分"自己的残留"与别家同形态
    last_pac: Mutex<String>,
    // 串发游标（每池/族记号 = 上次驻留的 IP）：故障转移时更新并落盘。
    last_ip: Mutex<LastIpTable>,
    // 自定义镜像注册表：settings.json 永久记录；启停只改镜像链成员，不动注册表。
    worker_mirrors: Mutex<Vec<WorkerMirror>>,
}

/// 一条自定义镜像：url 为反代地址，on 为是否进链，trusted 表示用户授权把签名 URL 交给它。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(default)]
pub struct WorkerMirror {
    pub url: String,
    pub on: bool,
    pub trusted: bool,
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
        last_pac: Mutex::new(String::new()),
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
    // 只要求读权限：改代理必须走 InternetSetOption。这台机器上该键对普通进程是只读的，
    // 拿 KEY_SET_VALUE 会直接"拒绝访问"——PAC 一直不生效就是卡在这一步。
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_READ)
        .map_err(|e| format!("打开 Internet Settings 失败: {e}"))
}

/// AutoConfigURL 只是给人看的镜像值，写不进去不算错误（真实配置由 InternetSetOption 落）。
fn mirror_auto_config_url(value: Option<&str>) {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_READ | KEY_SET_VALUE)
    else {
        return;
    };
    match value {
        Some(v) => {
            let _ = key.set_value("AutoConfigURL", &v);
        }
        None => {
            mirror_auto_config_url(None);
        }
    }
}

fn get_auto_config_url(key: &RegKey) -> String {
    key.get_value::<String, _>("AutoConfigURL")
        .unwrap_or_default()
}

/// 是否本程序设置的 PAC：任何 `127.0.0.1:端口/proxy.pac` 形态都算，端口无关。
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

/// 接管时该备份的：非空、不是正要写的、也不是上次自己写的，其余都算用户配置。
fn should_backup_foreign(cur: &str, pac: &str, last_pac: &str) -> bool {
    let cur = cur.trim();
    !cur.is_empty() && cur != pac.trim() && cur != last_pac.trim()
}

/// 系统里的 PAC 是不是自己写的：last_pac 非空按确切字符串比，为空（升级前）退回形状判定一次。
fn is_our_current_pac(cur: &str, last_pac: &str) -> bool {
    let last = last_pac.trim();
    if last.is_empty() {
        return is_our_pac(cur);
    }
    cur.trim() == last
}

/// 备份值是不是自己写过的残留；是则不还原，免得把死 PAC 写回系统。
fn backup_is_ours(backup: &str, last_pac: &str) -> bool {
    let last = last_pac.trim();
    if last.is_empty() {
        return is_our_pac(backup);
    }
    backup.trim() == last
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

/// 连接级代理配置：必须置 `PROXY_TYPE_AUTO_PROXY_URL` 位，只写 AutoConfigURL 会被系统刷新抹掉。
/// 失败返回 Win32 错误码——调用方要原样报出来，别再吞成"什么都没发生"。
fn apply_conn_options(flags: u32, pac: Option<&str>) -> Result<(), u32> {
    use windows::core::PWSTR;
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW,
        INTERNET_OPTION_PER_CONNECTION_OPTION,
    };

    // 字符串在调用期间必须保持有效且可写
    let mut pac_buf: Vec<u16> = pac
        .map(|s| s.encode_utf16().chain(std::iter::once(0)).collect())
        .unwrap_or_default();

    let mut opts: [INTERNET_PER_CONN_OPTIONW; 2] = unsafe { std::mem::zeroed() };
    opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
    opts[0].Value.dwValue = flags;
    let mut n = 1u32;
    if !pac_buf.is_empty() {
        opts[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        opts[1].Value.pszValue = PWSTR(pac_buf.as_mut_ptr());
        n = 2;
    }

    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: PWSTR::null(),
        dwOptionCount: n,
        dwOptionError: 0,
        pOptions: opts.as_mut_ptr(),
    };
    unsafe {
        match InternetSetOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some(&mut list as *mut _ as *const std::ffi::c_void),
            std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.code().0 as u32),
        }
    }
}

/// 兜底：WinINET 已经存着我们的 PAC URL、只是标志位没置上时，直接补这一位。
/// 只改 flags 这 4 个字节，不碰 blob 里的字符串，写坏了也不会。
fn force_pac_flag() -> Result<(), String> {
    let conn = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(CONNECTIONS_KEY, KEY_READ | KEY_SET_VALUE)
        .map_err(|e| format!("打开 Connections 失败: {e}"))?;
    let raw: winreg::RegValue = conn
        .get_raw_value(CONN_SETTINGS_VALUE)
        .map_err(|e| format!("读 {CONN_SETTINGS_VALUE} 失败: {e}"))?;
    if raw.bytes.len() < 12 {
        return Err(format!("{CONN_SETTINGS_VALUE} 长度异常"));
    }
    let mut bytes: Vec<u8> = raw.bytes.to_vec();
    let flags = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if flags & (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT)
        == (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT)
    {
        return Ok(()); // 已经是 直连+PAC
    }
    let fixed = flags | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT;
    bytes[8..12].copy_from_slice(&fixed.to_le_bytes());
    conn.set_raw_value(
        CONN_SETTINGS_VALUE,
        &winreg::RegValue {
            bytes: bytes.into(),
            vtype: raw.vtype,
        },
    )
    .map_err(|e| format!("写 {CONN_SETTINGS_VALUE} 失败: {e}"))?;
    Ok(())
}

/// 按开关接管/还原系统代理（幂等）。只备份用户自己的配置——把我们的旧残留当原配置会让自愈还原死 PAC。
/// 返回一句可读的结果（供启动日志与界面日志原样打印），失败带 Win32 错误码。
pub fn ensure_system_proxy() -> Result<String, String> {
    let key = internet_settings_key()?;
    let cur = get_auto_config_url(&key);
    let pac = pac_url();
    if github_pac() {
        // 备份判定不看 is_our_pac：它端口无关，别家同形态会被吞；以 last_pac 认自己的残留。
        let last = state().last_pac.lock().unwrap().clone();
        if should_backup_foreign(&cur, &pac, &last) {
            *state().proxy_backup.lock().unwrap() = cur.clone(); // 备份用户自己的设置
        }
        // 不走 cur == pac 早退：字符串在、标志位没开正是要修的状态，重复设一遍无副作用。
        let note = match apply_conn_options(
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL,
            Some(&pac),
        ) {
            Ok(()) => "已接管".to_string(),
            Err(code) => {
                // 系统不认这次调用时，退一步直接补连接配置里的 PAC 位。
                force_pac_flag().map_err(|e| {
                    format!("InternetSetOption 失败(Win32 {code})，补 PAC 位也失败: {e}")
                })?;
                format!("已接管(InternetSetOption 返回 Win32 {code}，用注册表补的 PAC 位)")
            }
        };
        // 顺带留一份镜像值：自愈与"是不是我们的"判断都靠它
        mirror_auto_config_url(Some(&pac));
        *state().last_pac.lock().unwrap() = pac.clone(); // 记下我们写的
        refresh_wininet();
        let _ = save();
        return Ok(note);
    }
    clear_if_ours(&key, &cur);
    Ok("未开启分流, 已还原".to_string())
}

/// 还原系统代理：只动我们上次写进去的那条 PAC（last_pac 精确比较），别家的不碰。
pub fn remove_system_proxy() {
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    clear_if_ours(&key, &cur);
}

fn restore_or_clear(key: &RegKey) {
    let backup = state().proxy_backup.lock().unwrap().clone();
    let last = state().last_pac.lock().unwrap().clone();
    let keep_manual = manual_proxy_active(key);
    // 只排除 last_pac（自己写过），其余备份一律还原；按形状丢等于备份白做。
    if !backup.is_empty() && !backup_is_ours(&backup, &last) {
        // 用户原本就用自动配置脚本：连标志位一起还原，别只留个字符串
        let _ = apply_conn_options(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL, Some(&backup));
        mirror_auto_config_url(Some(&backup));
    } else {
        // 没有备份就关掉「启用自动配置脚本」，只删字符串会留下半截状态。
        let flags = if keep_manual {
            PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        } else {
            PROXY_TYPE_DIRECT
        };
        let _ = apply_conn_options(flags, None);
        let _ = key.delete_value("AutoConfigURL");
    }
    *state().proxy_backup.lock().unwrap() = String::new();
    *state().last_pac.lock().unwrap() = String::new();
    refresh_wininet();
    let _ = save();
}

/// 系统当前是否有生效的手动代理（ProxyEnable=1 且 ProxyServer 非空），还原时决定要不要保留。
fn manual_proxy_active(key: &RegKey) -> bool {
    let enabled = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) != 0;
    let server = key.get_value::<String, _>("ProxyServer").unwrap_or_default();
    enabled && !server.trim().is_empty()
}

/// 确实是上次我们写进去的那条 PAC 才还原（别的工具中途接管了就不碰）。
fn clear_if_ours(key: &RegKey, cur: &str) {
    let last = state().last_pac.lock().unwrap().clone();
    if !is_our_current_pac(cur, &last) {
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


/// 串发游标表：键位恒为全量族键、顺序恒为表序、空值表示该族未驻留；读兼容数组与对象，写只写对象。
#[derive(Clone, Debug, PartialEq, Eq)]
struct LastIpTable(Vec<(String, String)>);

impl LastIpTable {
    /// 按规范键序成表：全量键位预写空值再覆盖，表外键直接丢弃。
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
        // 按现有顺序逐项写；不能借 Map 中转，未开 preserve_order 会被重排成字典序。
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

/// 单字段容错：值写坏只回退该字段，不连坐整份配置。
fn lenient<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + Default,
{
    let raw = serde_json::Value::deserialize(d)?;
    Ok(T::deserialize(raw).unwrap_or_default())
}

#[derive(Serialize, Deserialize, Default)]
// 字段名(camelCase)即落盘格式，不能改；容器 default 管漏键，字段 lenient 管坏值。
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
    last_pac: String, // 我们最后一次写进系统的 PAC URL——识别自己的残留
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
    *state().last_pac.lock().unwrap() = v.last_pac;
    *state().last_ip.lock().unwrap() = v.last_ip;
    state()
        .github_pac
        .store(v.github_pac, std::sync::atomic::Ordering::Relaxed);
    *state().worker_mirrors.lock().unwrap() = v.worker_mirrors;
}

/// 保存互斥：快照与写盘全程持锁，防旧快照覆写丢更新（保存罕见，临界区短）。
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
        last_pac: s.last_pac.lock().unwrap().clone(),
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

/// 自愈是否该动手：开关开着或曾接管过（有备份）才碰注册表，否则 AutoConfigURL 再像也不碰。
fn heal_should_touch(managed: bool, backup: &str) -> bool {
    managed || !backup.trim().is_empty()
}

fn heal_stale_proxy() {
    if !heal_should_touch(github_pac(), &state().proxy_backup.lock().unwrap()) {
        return;
    }
    let Ok(key) = internet_settings_key() else {
        return;
    };
    let cur = get_auto_config_url(&key);
    let last = state().last_pac.lock().unwrap().clone();
    if cur.is_empty() || !is_our_current_pac(&cur, &last) {
        // 本来就干净，或已是别人的 PAC：不碰，留给 ensure_system_proxy 走先备份后接管。
        return;
    }
    restore_or_clear(&key);
}

pub fn last_ips() -> Vec<(String, String)> {
    state().last_ip.lock().unwrap().marks().to_vec()
}

/// 记录驻留 IP 并落盘；游标变化罕见，直接同步写，崩溃最多丢最后一跳。
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

/// 读回开机自启登记的命令行（启动日志用）：空串 = 没登记。
pub fn autostart_state() -> Result<String, String> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, KEY_READ)
        .map_err(|e| format!("打开 Run 键失败: {e}"))?;
    Ok(key.get_value::<String, _>(RUN_VALUE).unwrap_or_default())
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

/// 收编保存：只落盘注册表不动镜像链，顺序按调用方给的。
pub fn save_worker_mirrors(list: Vec<WorkerMirror>) {
    *state().worker_mirrors.lock().unwrap() = list;
    let _ = save();
}

/// 整表保存：规范化校验后与旧表做差集，删除即彻底消失；前端提交前必须先 GET 合并。
/// 返回 (启用清单, 被删除的地址)——链对齐由调用方用 removed 触发，本模块只管存。
pub fn set_worker_mirrors(list: Vec<WorkerMirror>) -> Result<(Vec<String>, Vec<String>), String> {
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
        norm.push(WorkerMirror { url: u, on: w.on, trusted: w.trusted });
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
    Ok((enabled, removed))
}

/// 凭据串放行名单：用户标记为可信的已启用镜像 URL 集合。
pub fn trusted_mirrors() -> std::collections::HashSet<String> {
    state()
        .worker_mirrors
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.on && w.trusted)
        .map(|w| w.url.clone())
        .collect()
}


#[cfg(test)]
#[path = "tests/settings.rs"]
mod tests;
