// 代理 7810 + WebUI 7811；-tray 驻留托盘 / -headless 无窗 / -port / -webui 换端口。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod certgen;
mod config;
mod desktop;
mod fsx;
mod logger;
mod pool;
mod server;
mod settings;
mod util;
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
    // 主线程护栏：panic 时补一次系统代理还原（PAC 死端口会整机断网）。
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
    if crashed.is_err() {
        let note = settings::remove_system_proxy();
        logger::tray_log(&format!(
            "[panic] 主线程护栏捕获, 系统代理还原{}",
            if note.contains("失败") {
                format!("失败: {note}")
            } else {
                "完成".to_string()
            }
        ));
    }
}

fn run() {
    let t0 = std::time::Instant::now();
    if desktop::already_running() {
        if desktop::signal_show(config::webui_port()) {
            return;
        }
        // ok:false = 旧实例界面已死；等其让出单实例锁后接管。
        for _ in 0..20 {
            if !desktop::already_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        if desktop::already_running() {
            desktop::notify_already_running();
            return;
        }
    }
    // 工作目录切到 exe 目录（自启/快捷方式 cwd 不可靠）。
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let _ = std::env::set_current_dir(&exe_dir);
    let cache_dir = exe_dir.join(".cache");
    let _ = std::fs::create_dir_all(&cache_dir);
    logger::set_crash_path(&cache_dir);
    settings::init_exe_dir(&exe_dir);
    settings::load();
    let t_settings = t0.elapsed();

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

    // 日志 stdout 回显仅 headless（GUI 重定向会落浏览痕迹）。
    let logs = Arc::new(logger::Logger::new(headless));
    let log_fn: util::LogFn = {
        let l = logs.clone();
        Arc::new(move |msg: &str| l.log(msg))
    };
    pool::serial_load(&exe_dir, settings::last_ips(), Some(log_fn.clone()));
    let t_routes = t0.elapsed();
    let ca = match certgen::load_or_generate(&exe_dir) {
        Ok(c) => Some(c),
        Err(e) => {
            log_fn(&format!("CA 初始化失败, MITM 不可用: {e}"));
            None
        }
    };
    let t_ca = t0.elapsed();

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime 创建失败"),
    );

    server::status::start_ticker(log_fn.clone());

    let srv = Arc::new(server::ProxyServer {
        log: log_fn.clone(),
        authority: ca.clone(),
    });
    if let Err(e) = server::start_proxy_with(&rt, srv, config::proxy_port()) {
        log_fn(&format!("代理启动失败: {e}"));
    } else {
        // 系统代理接管失败才留痕。
        if let Err(e) = settings::ensure_system_proxy() {
            log_fn(&format!("[启动] 系统代理: 未接管 —— {e}"));
        }
    }
    let t_proxy = t0.elapsed();
    // 启动打点：区分卡在路由表/CA/系统代理。
    log_fn(&format!(
        "[启动] 核心 {}ms（配置 {} / 路由表 {} / CA {} / 代理 {}）",
        t_proxy.as_millis(),
        t_settings.as_millis(),
        t_routes.saturating_sub(t_settings).as_millis(),
        t_ca.saturating_sub(t_routes).as_millis(),
        t_proxy.saturating_sub(t_ca).as_millis(),
    ));
    let me = settings::exe_name();
    match settings::autostart_state() {
        // 开机自启指向别处才留痕。
        Ok(v) if !v.is_empty() && (me.is_empty() || !v.contains(me.as_str())) => {
            log_fn(&format!("[启动] 开机自启: 指向别处 —— {v}"))
        }
        Ok(_) => {}
        Err(e) => log_fn(&format!("[启动] 开机自启: 读不到 —— {e}")),
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
        let logs = logs.clone();
        logger::spawn("webui", move || {
            // 绑定失败必须留痕（否则页面打不开却不知原因）。
            if let Err(e) = rt.block_on(webui::serve(app)) {
                logs.log(&format!("管理界面未启动: {e}"));
            }
        });
    }

    if headless {
        loop {
            std::thread::park();
        }
    }

    let on_quit: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        // 退出时落盘延迟回流（内存态，无定时器）。
        pool::save_routes_now();
        // 系统代理还原失败必须留痕（PAC 死端口会整机断网）。
        let note = settings::remove_system_proxy();
        if note.contains("失败") {
            logger::tray_log(&format!("[退出] {note}"));
        }
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
