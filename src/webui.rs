//! 管理界面 —— axum + include_str! 内嵌前端，REST API 驱动页面。
//! 本地管理面防护(DNS rebinding / 跨站伪造写操作)见 localGuard。

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

/// 应用运行时状态。
#[derive(Clone)]
pub struct App {
    pub logs: Arc<Logger>,
    pub ca: Option<Arc<Authority>>,
    pub dir: String, // exe 目录(CA 证书所在)
    pub version: &'static str,
}

// ---------- 本地管理面防护 ----------

/// Host 必须是本机(剥端口逻辑与 server::host_only 同源, 大小写不敏感)。
fn local_host(h: &str) -> bool {
    matches!(
        crate::server::host_only(&h.to_lowercase()),
        "127.0.0.1" | "localhost"
    )
}

/// 本机工作台页面源(端口恒为 webui_port)。
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

/// 本地管理面中间件。
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

// ---------- 路由 ----------

/// 启动管理界面(127.0.0.1:7811)。
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
        .route("/api/mirrors", axum::routing::get(api_mirrors))
        .route("/api/calibrate", axum::routing::post(api_calibrate))
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

/// 分流 PAC 脚本(系统代理接管)：开启时池内全部域名 → PROXY 127.0.0.1:port，
/// 其余 DIRECT。JScript 是 ES3：后缀判断手写 lastIndexOf。
fn pac_script() -> String {
    let mut domains: Vec<&str> = Vec::new();
    if settings::github_pac() {
        for d in pooled_domains() {
            if !domains.contains(d) {
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
    format!(
        "// Viaduct 分流 PAC —— 由工作台按开关动态生成, 勿手改\n\
function FindProxyForURL(url, host) {{\n\
  if (fpMatch((host + '').toLowerCase())) return '{proxy}; DIRECT';\n\
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
// 键名与 Go 版 /api/status 一致(camelCase)：前端 index.html/app.js 是 Go 原样
// 复制，读 s.domainCount —— Rust 曾输出 domain_count(snake) 导致前端显示 undefined。
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

/// 镜像链查询（UI 校准面板展示当前链序）。
async fn api_mirrors() -> Response {
    let chains = pool::mirror_chains_snapshot();
    let obj: serde_json::Map<String, serde_json::Value> = pool::CONTENT_HOSTS
        .iter()
        .map(|h| {
            (
                h.to_string(),
                serde_json::json!(chains.get(*h).cloned().unwrap_or_default()),
            )
        })
        .collect();
    write_json(&serde_json::Value::Object(obj))
}

/// 镜像链校准（UI"校准"按钮）：串行实测每链 TTFB 后按成绩重排并写盘。
/// 最坏耗时 ≈ 链长 × 头预算(8s)（host 间已并行），约 30~90s —— 前端显示
/// "校准中"并等待本响应。
async fn api_calibrate(State(st): State<Arc<App>>) -> Response {
    let logs = st.logs.clone();
    let log: pool::LogFn = Arc::new(move |m: &str| logs.log(m));
    let report = crate::server::mitm::calibrate_chains(&log).await;
    (
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        report,
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

async fn api_mitm(State(st): State<Arc<App>>, axum::Json(body): axum::Json<OnBody>) -> Response {
    if body.on {
        let Some(ca) = &st.ca else {
            return write_json(&serde_json::json!({"ok": false, "error": "CA 未初始化"}));
        };
        if let Err(e) = crate::certgen::install_ca(&st.dir) {
            return write_json(&serde_json::json!({"ok": false, "error": e}));
        }
        let _ = ca;
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
// 键名与 Go 版 /api/settings 一致(camelCase)：前端读 s.closeToTray / s.githubPAC。
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
