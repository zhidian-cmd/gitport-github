// GitPort GitHub —— 多站点加速代理工作台。
// 桌面框架: tao 原生窗口 + wry(WebView2 渲染 WebUI) + tray-icon 系统托盘。
// 代理 127.0.0.1:7810 + WebUI http://127.0.0.1:7811(窗口加载该地址, 无 WebView2 时回退浏览器)。
// 启动参数: -tray 直接驻留托盘不开窗(开机自启用), -headless 只跑代理+WebUI,
// -port N 覆盖代理端口, -webui N 覆盖 WebUI 端口(与其他实例共存时避开 7810/7811)。
// Windows 子系统: release 双击运行无控制台黑框(日志走文件+WebUI 环形缓冲,
// 崩溃取证走 crash.log); headless 仍可用命令行重定向观察 stdout。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod certgen;
mod config;
mod desktop;
mod logger;
mod pool;
mod server;
mod settings;
mod webui;
mod winsec;

use std::sync::Arc;

/// 解析 `-name value` 型启动参数。
fn arg_value(args: &[String], name: &str) -> Option<u16> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u16>().ok())
}

fn main() {
    // 顶层护栏：主线程(窗口线程)的 panic 取证后退出
    logger::install_panic_hook();
    logger::guard("main", || run());
}

fn run() {
    if desktop::already_running() {
        return; // 单实例: 二次启动只弹提示
    }
    // 工作目录切到 exe 目录：开机自启/快捷方式的 cwd 不可靠，
    // 而 ca.crt / settings.json / plans.json 都按相对路径读写
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let _ = std::env::set_current_dir(&exe_dir);
    logger::set_crash_path(&exe_dir);
    settings::init_exe_dir(&exe_dir);
    settings::load();
    // 兜底：run 任何正常返回路径（含窗口循环 return / headless
    // 信号）都再还原一次系统代理。on_quit 已先清，此处幂等无害；端口无关：任何
    // 127.0.0.1 的 /proxy.pac 残留（含崩溃/被杀遗留）都会被清掉。
    // 注意：panic/abort 不走本 defer，但崩溃后下次启动 heal_stale_proxy 兜底。
    let _proxy_guard = settings::ProxyGuard::new();

    let args: Vec<String> = std::env::args().collect();
    let headless = args.iter().any(|a| a == "-headless");
    let tray_mode = args.iter().any(|a| a == "-tray");
    // 端口覆盖：仅命令行显式给才改默认（避开其他实例占用的默认端口）
    if let Some(p) = arg_value(&args, "-port") {
        config::set_proxy_port(p);
    }
    if let Some(p) = arg_value(&args, "-webui") {
        config::set_webui_port(p);
    }
    let web_url = format!("http://127.0.0.1:{}", config::webui_port());

    // 日志 stdout 回显仅 headless: GUI 构建的 stdout 重定向会把访问域名等浏览痕迹落盘
    let logs = Arc::new(logger::Logger::new(headless));
    let log_fn: pool::LogFn = {
        let l = logs.clone();
        Arc::new(move |msg: &str| l.log(msg))
    };
    // 串发核心: plans.json 唯一权威, 随使用演化(首次运行由内嵌种子初始化)
    pool::serial_load(&exe_dir, Some(log_fn.clone()));
    let ca = certgen::load_or_generate(&exe_dir).ok();
    if ca.is_none() {
        log_fn("CA 初始化失败, MITM 不可用");
    }

    // tokio runtime: 代理 + WebUI 常驻
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime 创建失败"),
    );

    // 串发表顺序变更 2s 内落盘（需 runtime 就绪）
    pool::start_persist(&rt);

    // 启动代理
    let srv = Arc::new(server::ProxyServer {
        log: log_fn.clone(),
        authority: ca.clone(),
    });
    if let Err(e) = server::start_proxy_with(&rt, srv, config::proxy_port()) {
        log_fn(&format!("代理启动失败: {e}"));
    } else {
        settings::ensure_system_proxy(); // 分流开关接管系统代理(全关 = no-op)
    }

    // WebUI 服务(护栏: panic 只断 webui 并取证, 进程活着)
    let app = Arc::new(webui::App {
        logs: logs.clone(),
        ca,
        dir: exe_dir.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION"),
    });
    {
        let app = app.clone();
        let rt = rt.clone();
        logger::spawn("webui", move || {
            let _ = rt.block_on(webui::serve(app));
        });
    }

    // headless: 只跑代理+WebUI, 不开窗口/托盘(调试/服务器用)
    if headless {
        loop {
            std::thread::park();
        }
    }

    // ---------- 桌面框架 ----------
    let on_quit: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        // 退出第一步: 先还原系统代理(在任何退出机器武装之前)
        settings::remove_system_proxy();
        // 停代理(异步收尾, 端口随 serve 退出释放)
        let rt = rt.clone();
        std::thread::spawn(move || {
            server::stop_proxy(&rt);
        });
    });
    desktop::run(desktop::DesktopArgs {
        url: web_url.to_string(),
        log: log_fn,
        open_window: !tray_mode,
        on_quit,
    });
}
