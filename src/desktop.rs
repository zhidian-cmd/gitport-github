//! 桌面框架：tao 窗口 + wry(WebView2) + 托盘。
//! ✕ 收托盘 = 释放整个 WebView2（占用 ≈ headless）；外部销毁自愈重建；单实例 mutex；窗口矩形记忆。

use crate::pool::LogFn;
use crate::settings;
use std::sync::atomic::{AtomicBool, Ordering};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// 写系统剪贴板（WebView2 拒 JS 剪贴板 API 时的兜底）。
/// 句柄所有权：SetClipboardData 失败仍归调用方（须 GlobalFree），成功则系统接管（禁释放）。
#[cfg(target_os = "windows")]
fn write_clipboard(text: &str) -> bool {
    use windows::Win32::Foundation::{GlobalFree, HANDLE};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, OpenClipboard, SetClipboardData,
    };
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

fn build_tray(show_id: MenuItem, quit_id: MenuItem) -> Result<TrayIcon, String> {
    let menu = Menu::new();
    menu.append_items(&[&show_id, &quit_id])
        .map_err(|e| e.to_string())?;
    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("GitPort GitHub");
    // 图标取 exe 内嵌资源（assets/app.rc 的 `1 ICON`），无需解码 ico；取不到也不阻断托盘。
    if let Ok(icon) = Icon::from_resource(1, None) {
        builder = builder.with_icon(icon);
    }
    builder.build().map_err(|e| e.to_string())
}

/// 单实例守卫：已有实例在跑则弹提示并返回 true。
/// mutex HANDLE 必须活到进程退出，故存 static 锚住（字段永不读）。
#[allow(dead_code)]
struct SingleMutexHandle(windows::Win32::Foundation::HANDLE);
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
                *SINGLE_MUTEX.lock().unwrap() = Some(SingleMutexHandle(h));
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
    let mut s = match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1200)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
    let req = "POST /api/show HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
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
    {
        let g = slot.lock().unwrap();
        if g.win.is_some() {
            return true;
        }
    }
    join_udf_cleanup(); // 上次收托盘的删除还没收尾：等它删完再建新 profile
    let mut g = slot.lock().unwrap();
    // 窗口按 winRect 出生即在位（builder 直接定位，避免闪跳）；
    // 无记录则居中偏下现算并立刻写回——settings.json 是窗口状态唯一来源。
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
        Some((l, t, w, h))
            if l < sw && t < sh && l + w > 0 && t + h > 0 =>
        {
            (l, t, w, h)
        }
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
    let ipc_log = log.clone();
    match wry::WebViewBuilder::new()
        .with_ipc_handler(move |req: http::Request<String>| {
            if let Some(text) = req.body().strip_prefix("copy:") {
                let ok = write_clipboard(text);
                let n = text.chars().count();
                (ipc_log)(&format!(
                    "[剪贴板] IPC 收到 {n} 字符, 写入{}",
                    if ok { "成功" } else { "失败" }
                ));
            }
        })
        .with_url(url).build(&window) {
        Ok(wv) => {
            g.win = Some(window);
            g.wv = Some(wv);
            drop(g);
            save_window_rect(slot);
            true
        }
        Err(_) => {
            (log)("WebView2 不可用, 工作台暂由系统浏览器提供");
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
    if create_window(slot, elwt, url, log) {
        (log)("工作台窗口已创建");
    } else {
        open_browser(url);
    }
}

/// 删除 WebView2 用户数据目录(退出/收托盘清场)。浏览器进程刚被释放,
/// 交还文件锁有延迟,300ms×10 重试兜底;超时留给下次启动的启动清理。
fn remove_webview_udf() {
    for _ in 0..10 {
        if std::fs::remove_dir_all("gitport-github.exe.WebView2").is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

/// 收托盘时的清场线程：不在界面线程上等，但重开窗口前必须等它结束——
/// 否则新 WebView2 刚建的数据目录会被后台重试删掉。
static UDF_CLEANUP: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

fn join_udf_cleanup() {
    if let Some(h) = UDF_CLEANUP.lock().unwrap().take() {
        let _ = h.join();
    }
}

pub fn open_browser(url: &str) {
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
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

    let show_item = MenuItem::new("显示工作台", true, None);
    let quit_item = MenuItem::new("退出", true, None);
    let show_id = show_item.id().clone();
    let quit_id = quit_item.id().clone();
    let mut _tray = build_tray(show_item, quit_item).ok();
    // 托盘事件 → 全事件驱动（crossbeam recv 无事件即内核级睡眠，零周期唤醒）。
    {
        let proxy = proxy.clone();
        std::thread::spawn(move || {
            let tray_rx = TrayIconEvent::receiver();
            while let Ok(ev) = tray_rx.recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    ..
                } = ev
                {
                    if proxy.send_event(AppEvent::ShowWindow).is_err() {
                        break; // 事件循环已退出：进程行将结束
                    }
                }
            }
        });
    }
    {
        let proxy = proxy.clone();
        std::thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            while let Ok(ev) = menu_rx.recv() {
                let ev = if *ev.id() == show_id {
                    AppEvent::ShowWindow
                } else if *ev.id() == quit_id {
                    AppEvent::RequestQuit
                } else {
                    continue;
                };
                if proxy.send_event(ev).is_err() {
                    break;
                }
            }
        });
    }

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
            }
            (on_quit2)(); // 撤系统代理 + 停代理核心
            remove_webview_udf(); // 退出清场：留净土, 超时留待下次启动兜底
            *cf = ControlFlow::Exit;
        }
    };

    let mut created_once = false;
    // 上次会话若退出未及清理，启动即删 WebView2 用户数据目录残留
    // （此刻 WebView2 尚未创建，无锁；单实例已由 mutex 保证）。
    let _ = std::fs::remove_dir_all("gitport-github.exe.WebView2");
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
                    // 托盘化 = 彻底释放 WebView2（~286MB commit 全退，只剩代理核心 ~12MB）；
                    // 先存矩形再放 WebView/窗口；随后 Destroyed 由 tray_hidden 拦截不自愈。
                    save_window_rect(&slot);
                    tray_hidden.store(true, Ordering::SeqCst);
                    let mut g = slot.lock().unwrap();
                    g.wv = None;
                    g.win = None;
                    drop(g);
                    // 清场放后台：这里重试删除最多等 3s，不能卡住界面线程；重开窗口前 join。
                    *UDF_CLEANUP.lock().unwrap() = Some(std::thread::spawn(remove_webview_udf));
                    (log)("工作台已收起到托盘, WebView2 及其数据目录已清理(点击托盘重开)");
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
                }
                if !quitting.load(Ordering::SeqCst) && !tray_hidden.swap(false, Ordering::SeqCst) {
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
