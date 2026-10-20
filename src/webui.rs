//! 管理界面：axum + 内嵌前端，REST API 驱动；本地管理面防护见 localGuard。
use crate::certgen::Authority;
use crate::config::{self, pooled_domains};
use crate::logger::Logger;
use crate::{pool, settings};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("web/index.html");
const STYLE_CSS: &str = include_str!("web/style.css");
const APP_JS: &str = include_str!("web/app.js");

#[derive(Clone)]
pub struct App {
    pub logs: Arc<Logger>,
    pub ca: Option<Arc<Authority>>,
    pub dir: String, // exe 目录(CA 证书所在)
    pub version: &'static str,
}


fn local_host(h: &str) -> bool {
    matches!(
        crate::server::host_only(&h.to_lowercase()),
        "127.0.0.1" | "localhost"
    )
}

fn local_origin(o: &str) -> bool {
    let lower = o.to_lowercase();
    let o = lower.trim_end_matches('/');
    let port = config::webui_port();
    for base in [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ] {
        if o == base || o.starts_with(&format!("{base}/")) {
            return true;
        }
    }
    false
}

/// 写操作来源校验：Origin 为准，缺失回退 Referer，两者皆无 = curl/git 等本机工具放行。
fn same_site_write(headers: &HeaderMap) -> bool {
    if let Some(o) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        return local_origin(o);
    }
    if let Some(ref_uri) = headers.get("referer").and_then(|v| v.to_str().ok()) {
        return local_origin(ref_uri);
    }
    true
}

async fn local_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !local_host(&host) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let m = req.method().clone();
    if m != Method::GET && m != Method::HEAD && !same_site_write(req.headers()) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}


pub async fn serve(app: Arc<App>) -> Result<(), String> {
    let router = axum::Router::new()
        .route("/", axum::routing::get(index))
        .route("/style.css", axum::routing::get(style))
        .route("/app.js", axum::routing::get(app_js))
        .route("/proxy.pac", axum::routing::get(proxy_pac))
        .route("/api/status", axum::routing::get(api_status))
        .route("/api/pools", axum::routing::get(api_pools))
        .route("/api/logs", axum::routing::get(api_logs))
        .route("/api/mitm", axum::routing::post(api_mitm))
        .route("/api/settings", axum::routing::get(api_settings))
        .route(
            "/api/settings/autostart",
            axum::routing::post(api_autostart),
        )
        .route(
            "/api/settings/closeToTray",
            axum::routing::post(api_close_to_tray),
        )
        .route(
            "/api/settings/githubPAC",
            axum::routing::post(api_github_pac),
        )
        .route("/api/show", axum::routing::post(api_show))
        .route(
            "/api/calibrate",
            axum::routing::get(api_calib_status).post(api_calibrate),
        )
        .with_state(app.clone())
        .layer(axum::middleware::from_fn(local_guard));
    let port = config::webui_port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("管理界面端口 {port} 绑定失败: {e}"))?;
    app.logs.log(&format!("管理界面: http://127.0.0.1:{port}"));
    axum::serve(listener, router)
        .await
        .map_err(|e| format!("webui 服务退出: {e}"))
}

fn no_store(headers: &mut axum::http::HeaderMap) {
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
}

fn write_json<T: Serialize>(v: &T) -> Response {
    let mut resp = axum::Json(v).into_response();
    no_store(resp.headers_mut());
    resp
}

async fn index() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // CSP 锁 self 断外传数据；unsafe-inline 供内联脚本（注入源已在 pool 层收口，此处第二道）。
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    (headers, INDEX_HTML).into_response()
}

async fn style() -> Response {
    (
        [
            ("cache-control", "no-cache"),
            ("content-type", "text/css; charset=utf-8"),
        ],
        STYLE_CSS,
    )
        .into_response()
}

async fn app_js() -> Response {
    (
        [
            ("cache-control", "no-cache"),
            ("content-type", "application/javascript; charset=utf-8"),
        ],
        APP_JS,
    )
        .into_response()
}

/// 分流 PAC：白名单 DIRECT 短路必须在通配符匹配之前（否则被 *.githubusercontent.com 吞掉）。
fn pac_script() -> String {
    let mut domains: Vec<&str> = Vec::new();
    if settings::github_pac() {
        for d in pooled_domains() {
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
    }
    let proxy = format!("PROXY 127.0.0.1:{}", config::proxy_port());
    let list = domains
        .iter()
        .map(|d| format!("'{d}'"))
        .collect::<Vec<_>>()
        .join(",");
    let direct_list = config::DIRECT_HOSTS
        .iter()
        .map(|d| format!("'{d}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "// GitPort GitHub 分流 PAC —— 由工作台按开关动态生成, 勿手改\n\
function FindProxyForURL(url, host) {{\n\
  var h = (host + '').toLowerCase();\n\
  var dl = [{direct_list}];\n\
  for (var i = 0; i < dl.length; i++) {{ if (h === dl[i]) return 'DIRECT'; }}\n\
  if (fpMatch(h)) return '{proxy}; DIRECT';\n\
  return 'DIRECT';\n\
}}\n\
function fpMatch(h) {{\n\
  var l = [{list}];\n\
  for (var i = 0; i < l.length; i++) {{\n\
    var d = l[i];\n\
    if (h === d) return true;\n\
    if (h.length > d.length && h.lastIndexOf('.' + d) === h.length - d.length - 1) return true;\n\
  }}\n\
  return false;\n\
}}\n"
    )
}

async fn proxy_pac() -> Response {
    (
        [
            ("content-type", "application/x-ns-proxy-autoconfig"),
            ("cache-control", "no-cache"),
        ],
        pac_script(),
    )
        .into_response()
}

#[derive(Serialize)]
// 键名 camelCase：曾输出 snake_case 导致前端读不到。
#[serde(rename_all = "camelCase")]
struct StatusResp {
    version: String,
    running: bool,
    port: u16,
    mitm: bool,
    domain_count: usize,
}

async fn api_status(State(st): State<Arc<App>>) -> Response {
    let domain_count = config::GROUPS.iter().map(|g| g.patterns.len()).sum();
    write_json(&StatusResp {
        version: st.version.to_string(),
        running: crate::server::running(),
        port: config::proxy_port(),
        mitm: settings::mitm(),
        domain_count,
    })
}

async fn api_pools() -> Response {
    let snap = pool::plans_snapshot();
    let obj: serde_json::Map<String, serde_json::Value> = pool::SERIAL_POOLS
        .iter()
        .map(|name| {
            (
                name.to_string(),
                serde_json::json!(snap.get(*name).cloned().unwrap_or_default()),
            )
        })
        .collect();
    write_json(&serde_json::Value::Object(obj))
}

async fn api_calibrate(
    State(st): State<Arc<App>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let logs = st.logs.clone();
    let log: pool::LogFn = Arc::new(move |m: &str| logs.log(m));
    if crate::server::mitm::CALIB_RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return (
            [
                ("content-type", "text/plain; charset=utf-8"),
                ("cache-control", "no-store"),
            ],
            "校准已在后台进行中，请等当前校准结束（进度见运行日志页）".to_string(),
        )
            .into_response();
    }
    let mode = match q.get("mode").map(|s| s.as_str()) {
        Some("ttfb") => crate::server::mitm::CalibMode::Ttfb,
        _ => crate::server::mitm::CalibMode::Throughput,
    };
    let mode_name = match mode {
        crate::server::mitm::CalibMode::Throughput => "大文件链(下载测速)",
        crate::server::mitm::CalibMode::Ttfb => "图片链(响应头测速)",
    };
    tokio::spawn(async move {
        crate::server::mitm::set_calibrate_report(None);
        let report = crate::server::mitm::calibrate_chains(&log, mode).await;
        (log)(&format!("[校准] 完成\n{report}"));
        crate::server::mitm::set_calibrate_report(Some(report));
        crate::server::mitm::CALIB_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    });
    (
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        format!(
            "{mode_name}校准已在后台开始：进度与结果见「运行日志」页，完成后新链序自动保存。\
             关闭窗口进托盘不影响任务。"
        ),
    )
    .into_response()
}

#[derive(Deserialize)]
struct LogsQuery {
    after: Option<u64>,
}

async fn api_logs(State(st): State<Arc<App>>, Query(q): Query<LogsQuery>) -> Response {
    let after = q.after.unwrap_or(0);
    let (raw, latest) = st.logs.since(after);
    let logs: Vec<[serde_json::Value; 2]> = raw
        .into_iter()
        .map(|(seq, line)| {
            [
                serde_json::Value::from(seq),
                serde_json::Value::String(line),
            ]
        })
        .collect();
    write_json(&serde_json::json!({ "logs": logs, "latest": latest }))
}

#[derive(Deserialize)]
struct OnBody {
    on: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_host_and_origin_gate() {
        assert!(local_host("127.0.0.1:7811"));
        assert!(local_host("LOCALHOST:7811"));
        assert!(!local_host("evil.com"));
        assert!(!local_host("127.0.0.2:7811"));
        let port = config::webui_port();
        assert!(local_origin(&format!("http://127.0.0.1:{port}")));
        assert!(local_origin(&format!("http://localhost:{port}/")));
        assert!(!local_origin(&format!("http://127.0.0.1:{port}@evil.com")));
        assert!(!local_origin("http://evil.com"));
        assert!(!local_origin(""));
    }

    #[test]
    fn same_site_write_rules() {
        let mut h = HeaderMap::new();
        assert!(
            same_site_write(&h),
            "无 Origin/Referer = curl/git 等本机工具放行"
        );
        let base = format!("http://127.0.0.1:{}", config::webui_port());
        h.insert(
            "origin",
            HeaderValue::from_str(&base).unwrap(),
        );
        assert!(same_site_write(&h));
        h.insert("origin", HeaderValue::from_static("http://evil.com"));
        assert!(!same_site_write(&h));
        h.remove("origin");
        h.insert(
            "referer",
            HeaderValue::from_str(&format!("{base}/x")).unwrap(),
        );
        assert!(same_site_write(&h));
        h.insert("referer", HeaderValue::from_static("http://evil.com/x"));
        assert!(!same_site_write(&h));
    }
}

async fn api_mitm(State(st): State<Arc<App>>, axum::Json(body): axum::Json<OnBody>) -> Response {
    if body.on {
        if st.ca.is_none() {
            return write_json(&serde_json::json!({"ok": false, "error": "CA 未初始化"}));
        }
        if let Err(e) = crate::certgen::install_ca(&st.dir) {
            return write_json(&serde_json::json!({"ok": false, "error": e}));
        }
    }
    if let Err(e) = settings::set_mitm(body.on) {
        return write_json(&serde_json::json!({"ok": false, "error": e}));
    }
    st.logs.log(&format!(
        "MITM 解密纠错已{}",
        if body.on {
            "开启(浏览器需重启一次生效)"
        } else {
            "关闭"
        }
    ));
    write_json(&serde_json::json!({"ok": true}))
}

#[derive(Serialize)]
// 键名 camelCase：前端读 s.closeToTray / s.githubPAC。
#[serde(rename_all = "camelCase")]
struct SettingsResp {
    autostart: bool,
    close_to_tray: bool,
    #[serde(rename = "githubPAC")]
    github_pac: bool,
}

async fn api_settings() -> Response {
    write_json(&SettingsResp {
        autostart: settings::autostart_enabled(),
        close_to_tray: settings::close_to_tray(),
        github_pac: settings::github_pac(),
    })
}

async fn api_calib_status() -> Response {
    write_json(&serde_json::json!({
        "running": crate::server::mitm::CALIB_RUNNING.load(std::sync::atomic::Ordering::SeqCst),
        "report": crate::server::mitm::last_calibrate_report(),
    }))
}

async fn api_show() -> Response {
    if crate::desktop::show_via_proxy() {
        write_json(&serde_json::json!({"ok": true}))
    } else {
        write_json(&serde_json::json!({"ok": false, "error": "无窗口(headless 或事件循环未就绪)"}))
    }
}

async fn api_autostart(axum::Json(body): axum::Json<OnBody>) -> Response {
    match settings::set_autostart(body.on) {
        Ok(_) => write_json(&serde_json::json!({"ok": true})),
        Err(e) => write_json(&serde_json::json!({"ok": false, "error": e})),
    }
}

async fn api_close_to_tray(axum::Json(body): axum::Json<OnBody>) -> Response {
    match settings::set_close_to_tray(body.on) {
        Ok(_) => write_json(&serde_json::json!({"ok": true})),
        Err(e) => write_json(&serde_json::json!({"ok": false, "error": e})),
    }
}

async fn api_github_pac(
    State(st): State<Arc<App>>,
    axum::Json(body): axum::Json<OnBody>,
) -> Response {
    if let Err(e) = settings::set_github_pac(body.on) {
        return write_json(&serde_json::json!({"ok": false, "error": e}));
    }
    if crate::server::running() {
        settings::ensure_system_proxy();
    } else {
        settings::remove_system_proxy();
    }
    st.logs.log(&format!(
        "分流接管已{}, {}",
        if body.on { "开启" } else { "关闭" },
        if crate::server::running() {
            "系统代理已同步"
        } else {
            "代理未运行, 未接管"
        }
    ));
    write_json(&serde_json::json!({"ok": true}))
}
