//! 桌面框架：tao 窗口 + wry(WebView2) + 托盘；✕ 收托盘即释放 WebView2，单实例 mutex。

use crate::settings;
use crate::util::LogFn;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tao::window::{Window, WindowBuilder};

/// 写系统剪贴板（WebView2 拒 JS 剪贴板 API 时的兜底）；失败时句柄仍归调用方，须自行释放。
#[cfg(target_os = "windows")]
fn write_clipboard(text: &str) -> bool {
    use windows::Win32::Foundation::{GlobalFree, HANDLE};
    use windows::Win32::System::DataExchange::{CloseClipboard, OpenClipboard, SetClipboardData};
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let ok = (|| {
            let mut wide: Vec<u16> = text.encode_utf16().collect();
            wide.push(0); // NUL 结尾
            let hglobal = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2).ok()?;
            let dst = GlobalLock(hglobal);
            if dst.is_null() {
                // 锁失败: 句柄没交出去, 还回去, 否则泄漏一个全局堆块
                let _ = GlobalFree(Some(hglobal));
                return None;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst as *mut u16, wide.len());
            let _ = GlobalUnlock(hglobal);
            let set = SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hglobal.0))).is_ok();
            if !set {
                // 系统没接管: 句柄仍归我们, 必须释放
                let _ = GlobalFree(Some(hglobal));
            }
            Some(set)
        })();
        let _ = CloseClipboard();
        ok.unwrap_or(false)
    }
}

pub enum AppEvent {
    ShowWindow,
    RequestQuit,
}

const WIN_W: f64 = 1250.0;
const WIN_H: f64 = 795.0;
const WIN_DY: f64 = 60.0;

// ---- 托盘 ----
// 不用 tray-icon（它丢掉 Shell_NotifyIcon 返回值，注册失败也报"成功"）：自做窗口+消息泵，每步记真实结果。

const TRAY_CLASS: windows::core::PCWSTR = windows::core::w!("GitPortTrayWnd");
const TRAY_UID: u32 = 1;
/// 托盘注册失败后的重试定时器（开机自启时 Explorer 未必就绪）。
const TRAY_RETRY_TIMER: usize = 1;
const WM_TRAY_NOTIFY: u32 = windows::Win32::UI::WindowsAndMessaging::WM_USER + 1;
const ID_TRAY_SHOW: usize = 1;
const ID_TRAY_QUIT: usize = 2;

static TRAY_PROXY: Mutex<Option<tao::event_loop::EventLoopProxy<AppEvent>>> = Mutex::new(None);
static TRAY_MENU: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static TRAY_ICON: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
/// WebView2 建失败过一次就别再自愈重建：窗口建出来立刻销毁会变成无限循环，
/// 每圈刷两行日志，页面跟着一起抽（实测踩到）。
static WV_FAILED: AtomicBool = AtomicBool::new(false);
/// 窗口对象是否存在（含 WebView2 失败后保留的提示窗）。
static WIN_ALIVE: AtomicBool = AtomicBool::new(false);
/// 托盘注册连续失败次数：超过上限就停，别每 2 秒写一行盘。
static TRAY_RETRIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static TASKBAR_CREATED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn tray_send(ev: AppEvent) {
    if let Some(p) = TRAY_PROXY.lock().unwrap().as_ref() {
        let _ = p.send_event(ev);
    }
}

/// 当前进程完整性级别；低于 shell 时 Shell_NotifyIcon 会被 UIPI 拒（err=5）。
unsafe fn current_il() -> u32 {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetSidSubAuthority, GetTokenInformation, TokenIntegrityLevel, SID_AND_ATTRIBUTES,
        TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return 0;
        }
        let mut need = 0u32;
        let _ = GetTokenInformation(tok, TokenIntegrityLevel, None, 0, &mut need);
        if need == 0 {
            return 0;
        }
        let mut buf = vec![0u8; need as usize];
        if GetTokenInformation(
            tok,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut _),
            need,
            &mut need,
        )
        .is_err()
        {
            return 0;
        }
        let sa = &*(buf.as_ptr() as *const SID_AND_ATTRIBUTES);
        *GetSidSubAuthority(sa.Sid, 0)
    }
}

/// 挂图标，返回 (成功, GetLastError)。
unsafe fn tray_add(
    hwnd: windows::Win32::Foundation::HWND,
    hicon: windows::Win32::UI::WindowsAndMessaging::HICON,
) -> (bool, u32) {
    use windows::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NOTIFYICONDATAW,
    };
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY_NOTIFY,
        hIcon: hicon,
        ..Default::default()
    };
    for (i, c) in "GitPort GitHub".encode_utf16().enumerate() {
        nid.szTip[i] = c;
    }
    let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
    let err = unsafe { windows::Win32::Foundation::GetLastError() }.0;
    (ok.as_bool(), err)
}

/// 删掉已注册的托盘图标（重挂前清残留记录）。
fn tray_delete(hwnd: windows::Win32::Foundation::HWND) {
    use windows::Win32::UI::Shell::{Shell_NotifyIconW, NIM_DELETE, NOTIFYICONDATAW};
    let nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        ..Default::default()
    };
    let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
}

/// 自检：NIM_ADD 返回 TRUE 不代表图标真进了通知区（Explorer 未就绪时会"假成功"）。
/// 反查 GetRect 才作数；查不到就删残留重挂，仍不行转后台定时重试。
fn tray_self_check(
    hwnd: windows::Win32::Foundation::HWND,
    hicon: windows::Win32::UI::WindowsAndMessaging::HICON,
) -> Option<String> {
    let probe = tray_rect(hwnd);
    if !probe.starts_with("GetRect 失败") {
        return None;
    }
    tray_delete(hwnd);
    let (ok, err) = unsafe { tray_add(hwnd, hicon) };
    if ok {
        let again = tray_rect(hwnd);
        if !again.starts_with("GetRect 失败") {
            return None;
        }
        return Some(format!("重加后仍查不到: {again}"));
    }
    use windows::Win32::UI::WindowsAndMessaging::SetTimer;
    let _ = unsafe { SetTimer(Some(hwnd), TRAY_RETRY_TIMER, 2000, None) };
    Some(format!("重加失败 err={err}, 已转后台重试"))
}

/// 问系统要图标矩形：拿到才算真进了通知区。
fn tray_rect(hwnd: windows::Win32::Foundation::HWND) -> String {
    use windows::Win32::UI::Shell::{Shell_NotifyIconGetRect, NOTIFYICONIDENTIFIER};
    let id = NOTIFYICONIDENTIFIER {
        cbSize: std::mem::size_of::<NOTIFYICONIDENTIFIER>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        guidItem: Default::default(),
    };
    match unsafe { Shell_NotifyIconGetRect(&id) } {
        Ok(r) => format!("已入通知区 ({}, {})", r.left, r.top),
        Err(e) => format!("GetRect 失败 {e}"),
    }
}

/// 右键菜单：先置前再弹，弹完补一条空消息，否则点空白处关不掉。
unsafe fn tray_popup(hwnd: windows::Win32::Foundation::HWND) {
    use windows::Win32::Foundation::{LPARAM, POINT, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, GetCursorPos, PostMessageW, SetForegroundWindow,
        TrackPopupMenu, HMENU, MF_STRING, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_NULL,
    };
    unsafe {
        let mut menu = HMENU(TRAY_MENU.load(Ordering::Relaxed) as *mut _);
        if TRAY_MENU.load(Ordering::Relaxed) == 0 {
            let Ok(m) = CreatePopupMenu() else { return };
            let _ = AppendMenuW(m, MF_STRING, ID_TRAY_SHOW, windows::core::w!("显示工作台"));
            let _ = AppendMenuW(m, MF_STRING, ID_TRAY_QUIT, windows::core::w!("退出"));
            TRAY_MENU.store(m.0 as isize, Ordering::Relaxed);
            menu = m;
        }
        let _ = SetForegroundWindow(hwnd);
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            None,
            hwnd,
            None,
        );
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
        match cmd.0 as usize {
            ID_TRAY_SHOW => tray_send(AppEvent::ShowWindow),
            ID_TRAY_QUIT => tray_send(AppEvent::RequestQuit),
            _ => {}
        }
    }
}

unsafe extern "system" fn tray_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wp: windows::Win32::Foundation::WPARAM,
    lp: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::LRESULT;
    use windows::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, KillTimer, WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER,
    };
    unsafe {
        // 开机自启时 Explorer 往往还没就绪，第一次 NIM_ADD 会失败；定时器每 2s 重挂直到成功。
        if msg == WM_TIMER && wp.0 == TRAY_RETRY_TIMER {
            let n = TRAY_RETRIES.fetch_add(1, Ordering::Relaxed) + 1;
            let (ok, err) = tray_add(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::HICON(
                    TRAY_ICON.load(Ordering::Relaxed) as *mut _,
                ),
            );
            if ok {
                TRAY_RETRIES.store(0, Ordering::Relaxed);
                let _ = KillTimer(Some(hwnd), TRAY_RETRY_TIMER);
                tray_log("[托盘] 重试成功, 已入通知区");
            } else if n >= 10 {
                // 失败原因多半是 WebView2 已经起来、系统拒绝 Shell_NotifyIcon(err=5)。
                // 再重试也是徒劳，停掉定时器，别把日志和磁盘刷爆。
                let _ = KillTimer(Some(hwnd), TRAY_RETRY_TIMER);
                tray_log(&format!(
                    "[托盘] 重试 {n} 次仍失败(err={err}), 停止重试; 重启程序或资源管理器可恢复"
                ));
            } else if n <= 3 {
                tray_log(&format!("[托盘] 注册重试 {n}: err={err}"));
            }
            return LRESULT(0);
        }
        if msg == WM_TRAY_NOTIFY {
            match lp.0 as u32 {
                WM_LBUTTONUP => tray_send(AppEvent::ShowWindow),
                WM_RBUTTONUP => tray_popup(hwnd),
                _ => {}
            }
            return LRESULT(0);
        }
        let restart = TASKBAR_CREATED.load(Ordering::Relaxed);
        if restart != 0 && msg == restart {
            // 资源管理器重启：旧图标已被清空，重新挂一次。
            let (ok, err) = tray_add(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::HICON(
                    TRAY_ICON.load(Ordering::Relaxed) as *mut _
                ),
            );
            tray_log(&format!("[托盘] explorer 重启后重挂: {ok} err={err}"));
        }
        DefWindowProcW(hwnd, msg, wp, lp)
    }
}

/// 托盘独立线程：建窗、挂图标、泵消息；注册结果经回执通道立即发回，调用方据此决定是否继续建窗口。
fn spawn_tray(
    proxy: tao::event_loop::EventLoopProxy<AppEvent>,
    log: LogFn,
) -> std::sync::mpsc::Receiver<(bool, u32)> {
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_log = log.clone();
    let spawned = std::thread::Builder::new()
        .name("gitport-tray".to_string())
        .spawn(move || {
            use windows::Win32::Foundation::{HINSTANCE, HWND};
            use windows::Win32::System::LibraryLoader::GetModuleHandleW;
            use windows::Win32::UI::WindowsAndMessaging::{
                CreateWindowExW, DispatchMessageW, GetMessageW, LoadImageW, RegisterClassW,
                RegisterWindowMessageW, SetTimer, TranslateMessage, HICON, IDI_APPLICATION,
                IMAGE_ICON, LR_DEFAULTCOLOR, LR_SHARED, MSG, WNDCLASSW, WS_EX_TOOLWINDOW,
                WS_OVERLAPPED,
            };
            let note = |s: String| {
                thread_log(&s);
                // [启动] 行由 logger 统一落 .cache/tray.log，这里别再写一遍。
                if !s.starts_with("[启动]") {
                    tray_log(&s);
                }
            };
            *TRAY_PROXY.lock().unwrap() = Some(proxy);
            unsafe {
                let Ok(hmod) = GetModuleHandleW(None) else {
                    note("[启动] 托盘: 取模块句柄失败".to_string());
                    return;
                };
                let hinst = HINSTANCE(hmod.0);
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(tray_proc),
                    hInstance: hinst,
                    lpszClassName: TRAY_CLASS,
                    ..std::mem::zeroed()
                };
                if RegisterClassW(&wc) == 0 {
                    note(format!(
                        "[启动] 托盘: 注册窗口类失败 err={}",
                        windows::Win32::Foundation::GetLastError().0
                    ));
                    return;
                }
                let hwnd: HWND = match CreateWindowExW(
                    WS_EX_TOOLWINDOW,
                    TRAY_CLASS,
                    windows::core::w!("GitPort GitHub"),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    Some(hinst),
                    None,
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        note(format!("[启动] 托盘: 建窗失败 {e}"));
                        return;
                    }
                };
                // 图标取 exe 内嵌资源 1（assets/app.rc）；取不到退系统默认，绝不留空。
                let hicon: HICON = match LoadImageW(
                    Some(hinst),
                    windows::core::PCWSTR(std::ptr::without_provenance(1)),
                    IMAGE_ICON,
                    32,
                    32,
                    LR_DEFAULTCOLOR,
                ) {
                    Ok(h) => HICON(h.0),
                    Err(_) => {
                        LoadImageW(None, IDI_APPLICATION, IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR)
                            .map(|h| HICON(h.0))
                            .unwrap_or_default()
                    }
                };
                TRAY_ICON.store(hicon.0 as isize, Ordering::Relaxed);
                let (mut ok, mut err) = tray_add(hwnd, hicon);
                if !ok {
                    // 图标句柄有问题时换系统默认图标再试：能分开"图标坏"和"进程被拒"。
                    let sys_icon = LoadImageW(None, IDI_APPLICATION, IMAGE_ICON, 32, 32, LR_SHARED)
                        .map(|h| HICON(h.0))
                        .unwrap_or_default();
                    let (ok2, err2) = tray_add(hwnd, sys_icon);
                    if ok2 {
                        TRAY_ICON.store(sys_icon.0 as isize, Ordering::Relaxed);
                        ok = true;
                        err = 0;
                    } else {
                        err = err2; // 两次都失败时报后一次，才是当前真实原因
                    }
                }
                // 回执立即发：NIM_ADD 已有结果，主线程等的是"注册动作完成"好建窗；
                // 落图标自检只影响日志与重试，放后台做，别让启动干等 200ms。
                let _ = tx.send((ok, err));
                if ok {
                    // NIM_ADD 的 TRUE 不可信：给 shell 200ms 落图标，再反查真实位置。
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    match tray_self_check(hwnd, hicon) {
                        None => note(format!("[启动] 托盘: {}", tray_rect(hwnd))),
                        Some(why) => {
                            note(format!("[启动] 托盘: 自检未通过 —— {why}, 后台重试中"));
                            SetTimer(Some(hwnd), TRAY_RETRY_TIMER, 2000, None);
                        }
                    }
                } else {
                    note(format!(
                        "[启动] 托盘: 注册失败 err={err} (进程完整性 {}), 后台重试中{}",
                        current_il(),
                        // err=5 实测根因：exe 所在目录被设了完整性标签（icacls 可见 Mandatory Label），
                        // 托盘注册与 WebView2 孵化都会被拒。剥掉标签即恢复。
                        if err == 5 { "；若 WebView2 也报拒绝访问, 检查 exe 目录是否被设了完整性标签(icacls 看 Mandatory Label)" } else { "" }
                    ));
                    // 开机时 shell 未就绪是常态：交给消息循环里的定时器每 2s 重挂，
                    // 不再 sleep 干等，也不依赖 Explorer 恰好广播 TaskbarCreated。
                    SetTimer(Some(hwnd), TRAY_RETRY_TIMER, 2000, None);
                }
                TASKBAR_CREATED.store(
                    RegisterWindowMessageW(windows::core::w!("TaskbarCreated")),
                    Ordering::Relaxed,
                );
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        });
    if let Err(e) = spawned {
        let line = format!("[启动] 托盘: 线程起不来 {e}");
        log(&line); // logger 统一落盘，不再单独写 tray.log
    }
    rx
}

// 托盘/窗口失败落盘统一走 logger::tray_log（GUI 版没有 stdout，留一行到 .cache/tray.log 备查）。
use crate::logger::tray_log;

/// 单实例守卫：已有实例在跑则弹提示并返回 true；mutex 句柄须活到进程退出，用 static 锚住。
struct SingleMutexHandle {
    _handle: windows::Win32::Foundation::HANDLE,
}
unsafe impl Send for SingleMutexHandle {}
unsafe impl Sync for SingleMutexHandle {}

static SINGLE_MUTEX: Mutex<Option<SingleMutexHandle>> = Mutex::new(None);

static EVENT_PROXY: std::sync::OnceLock<tao::event_loop::EventLoopProxy<AppEvent>> =
    std::sync::OnceLock::new();

pub fn show_via_proxy() -> bool {
    EVENT_PROXY
        .get()
        .map(|p| p.send_event(AppEvent::ShowWindow).is_ok())
        .unwrap_or(false)
}

/// 界面已死（WebView2 失败且窗口也没了）：这种实例必须让位，不能占着单实例锁挡新启动。
pub fn ui_dead() -> bool {
    WV_FAILED.load(Ordering::SeqCst) && !WIN_ALIVE.load(Ordering::SeqCst)
}

pub fn quit_via_proxy() {
    if let Some(p) = EVENT_PROXY.get() {
        let _ = p.send_event(AppEvent::RequestQuit);
    }
}

pub fn already_running() -> bool {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    // CreateMutexW 在"互斥量已存在"时返回成功句柄，只在 LastError 报 ALREADY_EXISTS —— 必须查 LastError。
    let r = unsafe { CreateMutexW(None, false, windows::core::w!("Local\\gitport-github")) };
    match r {
        Ok(h) => {
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe {
                    let _ = CloseHandle(h);
                }
                true
            } else {
                *SINGLE_MUTEX.lock().unwrap() = Some(SingleMutexHandle { _handle: h });
                false
            }
        }
        Err(_) => false, // mutex 创建失败: 放行, 靠端口绑定报错兜底
    }
}

pub fn notify_already_running() {
    use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
    let text = windows::core::w!("GitPort GitHub 已在运行(请看系统托盘)。");
    let title = windows::core::w!("GitPort GitHub");
    unsafe {
        let _ = MessageBoxW(
            None,
            text,
            title,
            windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(0x30),
        );
    }
}

pub fn signal_show(port: u16) -> bool {
    use std::io::{Read, Write};
    let addr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut s =
        match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1200)) {
            Ok(s) => s,
            Err(_) => return false,
        };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
    let req = "POST /api/show HTTP/1.1\r\nHost: 127.0.0.1\r\nX-GitPort-Request: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    resp.contains("\"ok\":true")
}

struct WinSlot {
    win: Option<Window>,
    wv: Option<wry::WebView>,
}

fn create_window(
    slot: &Mutex<WinSlot>,
    elwt: &tao::event_loop::EventLoopWindowTarget<AppEvent>,
    url: &str,
    log: &LogFn,
) -> bool {
    if WV_FAILED.load(Ordering::SeqCst) {
        return false; // 本进程已确认 WebView2 起不来，别再反复建窗销毁
    }
    {
        let g = slot.lock().unwrap();
        if g.win.is_some() {
            return true;
        }
    }
    let mut g = slot.lock().unwrap();
    // 窗口按 winRect 出生即在位（避免闪跳），无记录则居中偏下并写回。
    let (sw, sh) = elwt
        .primary_monitor()
        .map(|m| {
            let s = m.size();
            (s.width as i32, s.height as i32)
        })
        .unwrap_or((1920, 1080));
    let default_rect = || {
        let x = ((sw as f64 - WIN_W) / 2.0).max(0.0) as i32;
        let y = ((sh as f64 - WIN_H) / 2.0 + WIN_DY).max(0.0) as i32;
        (x, y, WIN_W as i32, WIN_H as i32)
    };
    let (l, t, w, h) = match settings::window_rect() {
        Some((l, t, w, h)) if l < sw && t < sh && l + w > 0 && t + h > 0 => (l, t, w, h),
        _ => default_rect(),
    };
    if settings::window_rect() != Some((l, t, w, h)) {
        let _ = settings::set_window_rect(l, t, w, h);
    }
    let window = match WindowBuilder::new()
        .with_title("GitPort GitHub")
        .with_inner_size(tao::dpi::PhysicalSize::new(w, h))
        .with_position(tao::dpi::PhysicalPosition::new(l, t))
        .build(elwt)
    {
        Ok(w) => w,
        Err(_) => return false,
    };
    // 数据目录放 %LOCALAPPDATA%：exe 同目录可能带 ACL/策略限制，WebView2 的渲染进程
    // （AppContainer）写不进去就报 0x80070005「拒绝访问」。
    let data_dir = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("GitPort")
        .join("WebView2");
    if let Some(parent) = data_dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let build_wv = |dir: &std::path::Path| -> Result<wry::WebView, wry::Error> {
        let mut ctx = wry::WebContext::new(Some(dir.to_path_buf()));
        wry::WebViewBuilder::new_with_web_context(&mut ctx)
            .with_ipc_handler(move |req: http::Request<String>| {
                // 复制是高频操作且用户常复制日志本身，打日志会把复制内容污染成递归，静默直写。
                if let Some(text) = req.body().strip_prefix("copy:") {
                    write_clipboard(text);
                }
            })
            .with_url(url)
            .build(&window)
    };
    let mut built = build_wv(&data_dir);
    if built.is_err() {
        // 收托盘时刚释放的浏览器进程退出有延迟、profile 也可能被崩坏锁住：
        // 先等一拍重试；仍失败且 profile 在，就挪走换新目录，最后才认输。
        std::thread::sleep(std::time::Duration::from_millis(300));
        built = build_wv(&data_dir);
        if built.is_err() && data_dir.join("EBWebView").exists() {
            let aside = data_dir.with_extension(format!("broken-{}", std::process::id()));
            // 刚失败的浏览器进程句柄还没放干净，rename 会短暂 err=5：300ms×3 重试。
            let mut renamed = Err(std::io::Error::other("未尝试"));
            for _ in 0..3 {
                renamed = std::fs::rename(&data_dir, &aside);
                if renamed.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            match renamed {
                Ok(()) => {
                    let _ = std::fs::create_dir_all(&data_dir);
                    tray_log(&format!(
                        "[窗口] WebView2 profile 疑似损坏, 已轮换 -> {}",
                        aside.display()
                    ));
                    built = build_wv(&data_dir);
                }
                Err(e) => tray_log(&format!("[窗口] WebView2 profile 轮换失败: {e}")),
            }
        }
    }
    match built {
        Ok(wv) => {
            g.win = Some(window);
            g.wv = Some(wv);
            WIN_ALIVE.store(true, Ordering::SeqCst);
            drop(g);
            save_window_rect(slot);
            true
        }
        Err(e) => {
            // 留住窗口并写明原因：窗口对象在这里被 drop 会触发 Destroyed，
            // 不记标志就会「销毁→自愈重建→再失败」的死循环。
            WV_FAILED.store(true, Ordering::SeqCst);
            window.set_title("GitPort — WebView2 不可用，请安装或修复 WebView2 Runtime");
            g.win = Some(window);
            WIN_ALIVE.store(true, Ordering::SeqCst);
            // 这条必须落到 tray.log：GUI 版没有 stdout，不写盘就永远不知道失败原因。
            tray_log(&format!("[窗口] WebView2 建失败: {e}"));
            (log)(&format!(
                "WebView2 不可用({e}), 已保留提示窗口, 未打开浏览器"
            ));
            false
        }
    }
}

fn save_window_rect(slot: &Mutex<WinSlot>) {
    let g = slot.lock().unwrap();
    let Some(w) = &g.win else { return };
    let Ok(pos) = w.outer_position() else { return };
    // 尺寸存 inner_size（客户区）：存 outer_size 会每轮重开叠加装饰，窗口越变越大。
    let size = w.inner_size();
    let (wpx, hpx) = (size.width as i32, size.height as i32);
    if wpx < 400 || hpx < 300 {
        return; // 异常矩形(窗口已销毁等)不保存
    }
    let _ = settings::set_window_rect(pos.x, pos.y, wpx, hpx);
}

fn show_window(slot: &Mutex<WinSlot>) -> bool {
    let g = slot.lock().unwrap();
    let Some(w) = &g.win else { return false };
    w.set_visible(true);
    w.set_focus();
    true
}

/// 没有窗口就建；WebView2 不可用则退回系统浏览器。
fn show_or_open(
    slot: &Mutex<WinSlot>,
    elwt: &tao::event_loop::EventLoopWindowTarget<AppEvent>,
    url: &str,
    log: &LogFn,
) {
    // 建窗失败不再拉系统浏览器：用户明确不要这个行为，只在窗口标题上写清原因。
    if !create_window(slot, elwt, url, log) {
        (log)("WebView2 不可用, 未自动打开浏览器(原因见上一行)");
    }
}

pub struct DesktopArgs {
    pub url: String,
    pub log: LogFn,
    pub open_window: bool, // false = -tray: 等托盘点击再开
    pub on_quit: Arc<dyn Fn() + Send + Sync>,
}

pub fn run(args: DesktopArgs) -> ! {
    let url = args.url;
    let log = args.log;
    let on_quit = args.on_quit;
    let open_window = args.open_window;

    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let _ = EVENT_PROXY.set(proxy.clone());
    let slot = Rc::new(Mutex::new(WinSlot {
        win: None,
        wv: None,
    }));

    // 托盘留到窗口建好后注册：WebView2 初始化会动 shell，先挂上去的图标会被吞掉。
    let quitting = Arc::new(AtomicBool::new(false));
    // 主动收起到托盘的标记: 供 Destroyed 事件区分"自己收的"与"外部销毁"。
    let tray_hidden = Arc::new(AtomicBool::new(false));
    let slot2 = slot.clone();
    let quitting2 = quitting.clone();
    let on_quit2 = on_quit.clone();
    let do_quit = move |cf: &mut ControlFlow| {
        if !quitting2.swap(true, Ordering::SeqCst) {
            save_window_rect(&slot2);
            // 先释放 WebView2(与托盘收起同路径):浏览器进程退出后用户数据目录才解锁。
            {
                let mut g = slot2.lock().unwrap();
                g.wv = None;
                g.win = None;
                WIN_ALIVE.store(false, Ordering::SeqCst);
            }
            (on_quit2)(); // 撤系统代理 + 停代理核心
            *cf = ControlFlow::Exit;
        }
    };

    let mut created_once = false;
    // 不再删 WebView2 数据目录：删到一半（几百个小文件、句柄未释放）就让 WebView2
    // 在残缺 profile 上初始化，直接 0x80070005「拒绝访问」。留着让运行时自己管。
    // 托盘先挂、拿到回执再往下走：WebView2 起来后 Shell_NotifyIcon 会被系统拒（err=5），必须先托盘后窗口且等它真的注册上。
    let t_desktop = std::time::Instant::now();
    let tray_rx = spawn_tray(proxy.clone(), log.clone());
    // 成功与否托盘线程已经记了，这里只兜"线程根本没回话"。
    match tray_rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok((ok, _)) => (log)(&format!(
            "[启动] 托盘{} +{}ms",
            if ok { "就绪" } else { "未就绪(后台重试)" },
            t_desktop.elapsed().as_millis()
        )),
        Err(_) => (log)("[启动] 托盘: 回执超时"),
    }
    event_loop.run(move |event, elwt, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(AppEvent::ShowWindow) => {
                if !show_window(&slot) {
                    show_or_open(&slot, elwt, &url, &log);
                }
            }
            Event::UserEvent(AppEvent::RequestQuit) => do_quit(control_flow),
            Event::LoopDestroyed => {
                // 系统关机/注销：还原系统代理防残留（tao 只在 wParam=TRUE 时发本事件）。
                if !quitting.swap(true, Ordering::SeqCst) {
                    save_window_rect(&slot);
                    (on_quit)();
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if settings::close_to_tray() {
                    // 托盘化 = 彻底释放 WebView2：先存矩形再放窗口，随后 Destroyed 由 tray_hidden 拦截不自愈。
                    save_window_rect(&slot);
                    tray_hidden.store(true, Ordering::SeqCst);
                    let mut g = slot.lock().unwrap();
                    g.wv = None;
                    g.win = None;
                    WIN_ALIVE.store(false, Ordering::SeqCst);
                    drop(g);
                } else {
                    do_quit(control_flow);
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(size),
                window_id,
                ..
            } => {
                let g = slot.lock().unwrap();
                if let (Some(wv), Some(w)) = (&g.wv, &g.win) {
                    if w.id() == window_id {
                        let _ = wv.set_bounds(wry::Rect {
                            position: tao::dpi::LogicalPosition::new(0.0, 0.0).into(),
                            size: size.into(),
                        });
                    }
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Destroyed,
                ..
            } => {
                {
                    let mut g = slot.lock().unwrap();
                    g.win = None;
                    g.wv = None;
                    WIN_ALIVE.store(false, Ordering::SeqCst);
                }
                if !WV_FAILED.load(Ordering::SeqCst)
                    && !quitting.load(Ordering::SeqCst)
                    && !tray_hidden.swap(false, Ordering::SeqCst)
                {
                    (log)("工作台窗口被外部销毁, 自愈重建(代理保持运行)");
                    if create_window(&slot, elwt, &url, &log) {
                        (log)("工作台窗口重建成功");
                    }
                }
            }
            _ => {}
        }
        if open_window && !created_once {
            created_once = true;
            show_or_open(&slot, elwt, &url, &log);
        }
    });
}
