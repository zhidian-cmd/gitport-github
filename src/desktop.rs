//! 桌面框架 —— tao 原生窗口 + wry(WebView2 渲染 WebUI) + tray-icon 系统托盘。
//! - ✕ 且开"关闭到托盘" → 释放整个 WebView2 收进托盘（点击托盘重建；
//!   托盘态无 Chromium 进程，占用 ≈ headless）
//! - 窗口被外部销毁（WebView2 运行时事件） → 自愈重建（代理保持运行）
//! - 托盘左键/菜单「显示工作台」→ 有窗则显示聚焦，无窗则按需创建
//! - 窗口矩形退出时记忆、启动时恢复；无记录则居中偏下
//! - 单实例 mutex + 二次启动弹提示

use crate::pool::LogFn;
use crate::settings;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// 写系统剪贴板(CF_UNICODETEXT)。WebView2 默认拒 JS 剪贴板 API，这里是复制的最终兜底。
#[cfg(target_os = "windows")]
fn write_clipboard(text: &str) -> bool {
    use windows::Win32::Foundation::HANDLE;
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
                return None;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst as *mut u16, wide.len());
            let _ = GlobalUnlock(hglobal);
            Some(SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hglobal.0))).is_ok())
        })();
        let _ = CloseClipboard();
        ok.unwrap_or(false)
    }
}

#[cfg(not(target_os = "windows"))]
fn write_clipboard(_text: &str) -> bool {
    false
}

pub enum AppEvent {
    ShowWindow,
    RequestQuit,
}

const WIN_W: f64 = 1250.0;
const WIN_H: f64 = 795.0;
const WIN_DY: f64 = 60.0;

/// 托盘图标（exe 同目录 asset 内嵌）。
fn load_icon() -> Icon {
    let bytes = include_bytes!("../assets/icon.ico");
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Ico)
        .expect("内置 icon.ico 解码失败");
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    Icon::from_rgba(rgba.into_raw(), w, h).expect("托盘图标初始化失败")
}

/// 构建托盘。
fn build_tray(show_id: MenuItem, quit_id: MenuItem) -> Result<TrayIcon, String> {
    let menu = Menu::new();
    menu.append_items(&[&show_id, &quit_id])
        .map_err(|e| e.to_string())?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("GitPort GitHub")
        .with_icon(load_icon())
        .build()
        .map_err(|e| e.to_string())?;
    Ok(tray)
}

/// 单实例守卫：已有实例在跑则弹提示并返回 true。
/// mutex HANDLE 必须活到进程退出，故存 static 锚住（字段永不读）。
#[allow(dead_code)]
struct SingleMutexHandle(windows::Win32::Foundation::HANDLE);
unsafe impl Send for SingleMutexHandle {}
unsafe impl Sync for SingleMutexHandle {}

static SINGLE_MUTEX: Mutex<Option<SingleMutexHandle>> = Mutex::new(None);

/// 事件循环代理（WebUI 的 /api/show 用它唤起窗口）。
static EVENT_PROXY: std::sync::OnceLock<tao::event_loop::EventLoopProxy<AppEvent>> =
    std::sync::OnceLock::new();

/// 触发"显示工作台"（二次启动经 /api/show 调用）。headless 无事件循环 → false。
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

/// 二次启动的兜底提示（唤起失败时用）。
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

/// 请求已运行实例唤起工作台（POST /api/show）；false = 没唤起，调用方走提示兜底。
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
    let req = format!(
        "POST /api/show HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    resp.contains("\"ok\":true")
}

/// 窗口与 WebView 的联合句柄（事件循环闭包内共享）。
struct WinSlot {
    win: Option<Window>,
    wv: Option<wry::WebView>,
}

/// 在事件循环线程创建窗口并导航；WebView2 不可用返回 None，调用方走浏览器兜底。
fn create_window(
    slot: &Mutex<WinSlot>,
    elwt: &tao::event_loop::EventLoopWindowTarget<AppEvent>,
    url: &str,
    log: &LogFn,
) -> bool {
    let mut g = slot.lock().unwrap();
    if g.win.is_some() {
        return true;
    }
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
        // 记录缺失或矩形落在当前主屏外（拔了显示器等）→ 退回默认居中
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
            // WebView2 剪贴板 API 默认被拒，JS 层复制经 IPC 到本机写系统剪贴板
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
            // OS 可能钳制位置：把实际矩形立刻写回，settings.json 恒等于窗口现状
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

/// 读取主窗口当前矩形并持久化(退出时调用)。
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

/// 显示并聚焦工作台窗口(托盘「显示工作台」)。
fn show_window(slot: &Mutex<WinSlot>) -> bool {
    let g = slot.lock().unwrap();
    let Some(w) = &g.win else { return false };
    w.set_visible(true);
    let _ = w.set_focus();
    true
}

/// 打开系统默认浏览器。
pub fn open_browser(url: &str) {
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
}

/// 桌面运行参数（main 装配）。
pub struct DesktopArgs {
    pub url: String,
    pub log: LogFn,
    pub open_window: bool, // false = -tray: 等托盘点击再开
    pub on_quit: Arc<dyn Fn() + Send + Sync>,
}

/// 桌面主循环(阻塞)。on_quit = 善后函数，由 main 注入；事件循环线程 = 主线程。
pub fn run(args: DesktopArgs) -> ! {
    let url = args.url;
    let log = args.log;
    let on_quit = args.on_quit;
    let open_window = args.open_window;

    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let _ = EVENT_PROXY.set(proxy.clone());
    let slot = Arc::new(Mutex::new(WinSlot {
        win: None,
        wv: None,
    }));

    // 托盘
    let show_item = MenuItem::new("显示工作台", true, None);
    let quit_item = MenuItem::new("退出", true, None);
    let show_id = show_item.id().clone();
    let quit_id = quit_item.id().clone();
    let mut _tray = build_tray(show_item, quit_item).ok();
    // 托盘事件 → 全事件驱动（crossbeam recv 无事件即内核级睡眠，零周期唤醒）。
    {
        let proxy = proxy.clone();
        std::thread::spawn(move || {
            // 左键单击 = 显示工作台
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
            // 菜单：显示工作台 / 退出
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
            (on_quit2)();
            *cf = ControlFlow::Exit;
        }
    };

    let mut created_once = false;
    event_loop.run(move |event, elwt, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(AppEvent::ShowWindow) => {
                if !show_window(&slot) {
                    if create_window(&slot, elwt, &url, &log) {
                        (log)("工作台窗口已创建");
                    } else {
                        open_browser(&url);
                    }
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
                    (log)("工作台已收起到托盘, WebView2 已释放(点击托盘重开)");
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
                if quitting.load(Ordering::SeqCst) {
                } else if tray_hidden.swap(false, Ordering::SeqCst) {
                } else {
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
            if create_window(&slot, elwt, &url, &log) {
                (log)("工作台窗口已创建");
            } else {
                open_browser(&url);
            }
        }
    });
}
