// 代理 7810 + WebUI 7811；-tray 驻留托盘 / -headless 无窗 / -port / -webui 换端口。
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

fn arg_value(args: &[String], name: &str) -> Option<u16> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u16>().ok())
}

fn main() {
    logger::install_panic_hook();
    logger::guard("main", || run());
}

fn run() {
    if desktop::already_running() {
        if !desktop::signal_show(config::webui_port()) {
            desktop::notify_already_running();
        }
        return;
    }
    // 工作目录切到 exe 目录：自启/快捷方式的 cwd 不可靠，数据文件按相对路径读写。
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let _ = std::env::set_current_dir(&exe_dir);
    logger::set_crash_path(&exe_dir);
    settings::init_exe_dir(&exe_dir);
    settings::load();
    // 兜底：正常返回路径再还原一次系统代理（幂等）；panic 由下次启动自愈。
    let _proxy_guard = settings::ProxyGuard::new();

    let args: Vec<String> = std::env::args().collect();
    let headless = args.iter().any(|a| a == "-headless");
    let tray_mode = args.iter().any(|a| a == "-tray");
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
    pool::serial_load(&exe_dir, Some(log_fn.clone()));
    let ca = certgen::load_or_generate(&exe_dir, Some(&log_fn)).ok();
    if ca.is_none() {
        log_fn("CA 初始化失败, MITM 不可用");
    }

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime 创建失败"),
    );

    pool::start_persist(&rt);
    server::upstream::start_keepalive(&rt);

    let srv = Arc::new(server::ProxyServer {
        log: log_fn.clone(),
        authority: ca.clone(),
    });
    if let Err(e) = server::start_proxy_with(&rt, srv, config::proxy_port()) {
        log_fn(&format!("代理启动失败: {e}"));
    } else {
        settings::ensure_system_proxy(); // 分流开关接管系统代理(全关 = no-op)
    }

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

    if headless {
        loop {
            std::thread::park();
        }
    }

    let on_quit: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        settings::remove_system_proxy();
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
