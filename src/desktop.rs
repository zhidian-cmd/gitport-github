//! 桌面框架 —— tao 原生窗口 + wry(WebView2 渲染 WebUI) + tray-icon 系统托盘。
//! 对应 Go 版 webview_go + energye/systray 的语义：
//! - ✕ 且开"关闭到托盘" → 隐藏窗口(吞掉关闭)；未开 → 退出
//! - 窗口被外部销毁(WebView2 运行时事件) → 自愈重建(代理保持运行)
//! - 托盘左键/菜单「显示工作台」→ 有窗则显示聚焦，无窗则按需创建
//! - 窗口矩形退出时记忆、启动时恢复；无记录则居中偏下
//! - 单实例 mutex + 二次启动弹提示

use crate::pool::LogFn;
use crate::settings;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// 写系统剪贴板(CF_UNICODETEXT)。桌面壳与代理同会话, 必成 —— JS 层
/// clipboard API 在 WebView2 默认被拒, 这里是复制的最终兜底。
/// (失败路径不 GlobalFree: 分配块极小且极罕见, 交由进程退出回收)
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
        .with_tooltip("Viaduct")
        .with_icon(load_icon())
        .build()
        .map_err(|e| e.to_string())?;
    Ok(tray)
}

/// 单实例守卫：已有实例在跑则弹提示并返回 true(调用方直接退出)。
/// 单实例 mutex 的 handle 必须持有到进程退出：Windows 在最后一个 handle
/// 关闭时销毁 mutex。windows crate 的 HANDLE 带 Drop(自动 CloseHandle)，
/// 若随函数返回即被关闭，mutex 会立刻消失 —— 二次启动照样放行，多实例
/// 竞争端口（2026-10-13 实测：双击二次启动导致 7810 绑定失败）。Go 版
/// runtime.KeepAlive(mu) 是同一目的。持有在 static，进程退出由 OS 清理。
/// 该 handle 仅作"mutex 存活的锚"：只写一次、绝不被其它线程使用或关闭，
/// 进程退出由 OS 统一清理 —— 跨线程持有是安全的。字段故意永不读。
#[allow(dead_code)]
struct SingleMutexHandle(windows::Win32::Foundation::HANDLE);
// 该 handle 仅作"mutex 存活的锚"：只写一次、绝不被其它线程使用或关闭，
// 进程退出由 OS 统一清理 —— 跨线程持有是安全的。
unsafe impl Send for SingleMutexHandle {}
unsafe impl Sync for SingleMutexHandle {}

static SINGLE_MUTEX: Mutex<Option<SingleMutexHandle>> = Mutex::new(None);

pub fn already_running() -> bool {
    use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
    let r = unsafe { CreateMutexW(None, false, windows::core::w!("Local\\viaduct")) };
    match r {
        Ok(h) => {
            *SINGLE_MUTEX.lock().unwrap() = Some(SingleMutexHandle(h));
            false
        }
        Err(err) => {
            if err.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) {
                let text = windows::core::w!("Viaduct 已在运行(请看系统托盘)。");
                let title = windows::core::w!("Viaduct");
                unsafe {
                    let _ = MessageBoxW(
                        None,
                        text,
                        title,
                        windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(0x30),
                    ); // MB_ICONWARNING
                }
                true
            } else {
                false // mutex 创建失败: 放行, 后面靠端口绑定报错兜底
            }
        }
    }
}

/// 窗口与 WebView 的联合句柄（事件循环闭包内共享）。
struct WinSlot {
    win: Option<Window>,
    wv: Option<wry::WebView>,
}

/// 在事件循环线程创建窗口并导航。WebView2 运行时不可用/创建失败返回 None
/// （wry 的 build 会直接报错），调用方走浏览器兜底 + 周期重试。
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
    let window = match WindowBuilder::new()
        .with_title("Viaduct")
        .with_inner_size(tao::dpi::LogicalSize::new(WIN_W, WIN_H))
        .build(elwt)
    {
        Ok(w) => w,
        Err(_) => return false,
    };
    let ipc_log = log.clone();
    match wry::WebViewBuilder::new()
        .with_ipc_handler(move |req: http::Request<String>| {
            // WebView2 的剪贴板 API(navigator.clipboard/execCommand)默认被拒,
            // JS 层复制优先经 IPC 到本机写系统剪贴板(同会话, 必成)
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
            // 恢复上次退出时的窗口状态，无记录则居中偏下
            if let Some((l, t, w, h)) = settings::window_rect() {
                set_window_rect(&g.win.as_ref().unwrap(), l, t, w, h);
            } else {
                place_window(&g.win.as_ref().unwrap(), WIN_W, WIN_H, WIN_DY);
            }
            true
        }
        Err(_) => {
            log("WebView2 不可用, 工作台暂由系统浏览器提供");
            false
        }
    }
}

/// 移动窗口到指定位置与尺寸。
fn set_window_rect(window: &Window, l: i32, t: i32, w: i32, h: i32) {
    let _ = window.set_outer_position(tao::dpi::PhysicalPosition::new(l, t));
    let _ = window.set_inner_size(tao::dpi::PhysicalSize::new(w, h));
}

/// 把窗口摆到屏幕 (水平居中, 垂直居中+dy)。
fn place_window(window: &Window, w: f64, h: f64, dy: f64) {
    if let Some(m) = window.current_monitor() {
        let area = m.size();
        let sw = area.width as f64;
        let sh = area.height as f64;
        let x = ((sw - w) / 2.0).max(0.0) as i32;
        let y = ((sh - h) / 2.0 + dy).max(0.0) as i32;
        let _ = window.set_outer_position(tao::dpi::PhysicalPosition::new(x, y));
    }
}

/// 读取主窗口当前矩形并持久化(退出时调用, 下次启动恢复)。
fn save_window_rect(slot: &Mutex<WinSlot>) {
    let g = slot.lock().unwrap();
    let Some(w) = &g.win else { return };
    let Ok(pos) = w.outer_position() else { return };
    let size = w.outer_size();
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

/// 桌面主循环(阻塞)。on_quit = 善后函数(还原系统代理/停代理), 由 main 注入。
/// 事件循环线程 = 主线程（tao 要求）。
pub fn run(args: DesktopArgs) -> ! {
    let url = args.url;
    let log = args.log;
    let on_quit = args.on_quit;
    let open_window = args.open_window;

    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
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
    {
        let proxy = proxy.clone();
        std::thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            let tray_rx = TrayIconEvent::receiver();
            loop {
                match tray_rx.recv_timeout(Duration::from_millis(80)) {
                    Ok(ev) => {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            ..
                        } = ev
                        {
                            let _ = proxy.send_event(AppEvent::ShowWindow);
                        }
                    }
                    Err(_) => {}
                }
                if let Ok(ev) = menu_rx.try_recv() {
                    if *ev.id() == show_id {
                        let _ = proxy.send_event(AppEvent::ShowWindow);
                    } else if *ev.id() == quit_id {
                        let _ = proxy.send_event(AppEvent::RequestQuit);
                    }
                }
            }
        });
    }

    let quitting = Arc::new(AtomicBool::new(false));
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
                // 系统关机/注销(WM_ENDSESSION wParam!=0)或退出流程结束: 还原系统
                // 代理(避免关机残留指向死端口的 PAC 断用户网)。tao 0.34.8
                // event_loop.rs:2384 只有 wParam=TRUE 才发 LoopDestroyed, 取消关机
                // (wParam=0)到不了这儿 —— 不误清(代理仍在跑)。等价 Go 0f02257
                // desktop_windows.go 的 WM_ENDSESSION 分支; 与 do_quit 幂等合并
                // (quitting 防重入, save_window_rect 收尾一次)。
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
                    let g = slot.lock().unwrap();
                    if let Some(w) = &g.win {
                        w.set_visible(false);
                    }
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
                if !quitting.load(Ordering::SeqCst) {
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
