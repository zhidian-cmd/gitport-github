//! 页面缓存：首页骨架落盘 7 天（keep/，键无会话号）；数据与整页 HTML 走内存 15 分钟（带身份标签）；githubassets 按 URL 落盘回放。
//! 闸门页/限流降级页拒存；仓库页零转换直出（防旧 JS 配新数据白屏）。
use super::{asset_store, BoxBody};
use crate::server::protocol::{self, Incoming};
use crate::server::upstream;
use crate::util::{lock, LogFn};
use bytes::Bytes;
use http::{Method, StatusCode};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{LazyLock, Mutex, OnceLock};

/// 唯一缓存域：github.com。
const CACHE_HOST: &str = "github.com";

/// 骨架缓存上限 5MB，满则整盘重来。
const PAGE_CACHE_MAX_BYTES: u64 = 5 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限，满则丢弃

/// 骨架保质期 7 天，超期交旧 + 后台重拉（SWR）。
const KEEP_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 软导航片段上限 256KB，超限不收。
const HTML_FRAGMENT_MAX_BYTES: usize = 256 * 1024;

/// 文档导航判定：sec-fetch-dest=document；无该头按导航处理。
fn is_document_nav<B>(req: &hyper::Request<B>) -> bool {
    req.headers()
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .map(|d| d.eq_ignore_ascii_case("document"))
        .unwrap_or(true)
}

/// 取侧桶选择：搜索页文档导航→"-p"，非文档导航按 Accept→"-j"/"-h"，其余文档导航→None（首页走 keep，仓库页回源）。
fn xhr_lookup_kind<B>(req: &hyper::Request<B>, accept: Option<&str>) -> Option<&'static str> {
    if is_search_page(req.uri().path()) && is_document_nav(req) {
        Some("-p")
    } else if !is_document_nav(req) {
        Some(xhr_kind_from_accept(accept))
    } else {
        None
    }
}

/// 首页：纯骨架，跨会话长寿命缓存。
fn is_home_path(path: &str) -> bool {
    path == "/" || path.is_empty()
}

/// 搜索页：整页 HTML 内嵌真实结果，按数据走内存 15 分钟 + 身份标签。
fn is_search_page(path: &str) -> bool {
    path == "/search"
}

/// XHR 数据正文：JSON、`+json` 家族、ndjson、纯文本。
fn is_xhr_body(ct_lower: &str) -> bool {
    ct_lower.starts_with("application/json")
        || ct_lower.starts_with("text/plain")
        || ct_lower.contains("+json")
        || ct_lower.contains("ndjson")
}

/// 落盘骨架路由：仅首页 HTML 进 keep（7 天），其余改道内存。
fn keep_route(path: &str, ct_lower: &str) -> bool {
    is_home_path(path) && !is_xhr_body(ct_lower)
}

/// 条目目录：keep/。
fn entry_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("keep")
}

/// 任务自带目录：发送时取一次。
enum CacheMsg {
    Save {
        key: String,
        bytes: Bytes,
        status: u16,
        hdrs: Vec<Vec<String>>,
    },
    /// githubassets 资产入库（管家线程落盘）。
    SaveAsset {
        url: String,
        bytes: Bytes,
        hdrs: Vec<Vec<String>>,
    },
    /// 写操作后标过期 keep 快照（SWR）。
    Invalidate { host: String, path: String },
}

// ---------- 对外唯二入口 ----------

/// 准入：github.com 的 GET 且非 no-cache。
fn cache_eligible<B>(req: &hyper::Request<B>, host: &str) -> bool {
    cache_eligible_rules(
        host,
        req.method(),
        req.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
    )
}

/// 准入规则纯函数形态，便于测试。
fn cache_eligible_rules(host: &str, method: &Method, cache_control: Option<&str>) -> bool {
    host == CACHE_HOST
        && *method == Method::GET
        && !cache_control
            .map(|c| c.contains("no-cache"))
            .unwrap_or(false)
}

/// 取路由：XHR 内存→首页 keep→上游；githubassets 由资产库分支接管。
pub(super) fn cache_take<B>(
    log: &LogFn,
    req: &hyper::Request<B>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    if host != CACHE_HOST || req.method() != Method::GET || !cache_eligible(req, host) {
        return None; // 直通场景走上游
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let enc = upstream::encoding_bucket(req);

    // ① XHR 内存命中（15 分钟，键含身份标签）：搜索页整页 "-p" / JSON "-j" / 片段 "-h" 三键互斥。
    let accept = req.headers().get("accept").and_then(|v| v.to_str().ok());
    if let Some(kind) = xhr_lookup_kind(req, accept) {
        if let Some((status, hdrs, body)) =
            xhr_take(&xhr_cache_key(req.uri(), host, cookies, enc, kind))
        {
            if super::quiet::first_time("xhrhit", &path) {
                (log)(&format!(
                    "[缓存] XHR 回放 {path} ({kind} {})",
                    fmt_size(body.len())
                ));
            }
            let mut hdrmap = hyper::HeaderMap::new();
            for pair in &hdrs {
                if let (Ok(name), Ok(val)) = (
                    hyper::header::HeaderName::from_bytes(pair[0].as_bytes()),
                    hyper::header::HeaderValue::from_str(&pair[1]),
                ) {
                    hdrmap.insert(name, val);
                }
            }
            let mut resp = hyper::Response::builder()
                .status(status)
                .body(protocol::full_body(body))
                .unwrap();
            *resp.headers_mut() = hdrmap;
            resp.headers_mut().insert(
                "x-gitport-cache",
                hyper::header::HeaderValue::from_static("xhr"),
            );
            return Some(resp);
        }
    }

    // ② keep 命中：仅首页纯骨架（键无会话号）；SWR 过期交旧 + 后台重拉。
    if !is_home_path(req.uri().path()) {
        return None; // 首页以外无磁盘骨架
    }
    let variant = keep_lookup_variant(req.uri().path(), accept);
    let key = live_cache_key(req.uri(), host, enc, variant);
    let ((status, hdrs, body), swr_expired) = match load_disk_entry_reason(&key) {
            Ok(v) => v,
            Err(reason) => {
                // 有条目却被读侧拒绝：落日志。
                if reason != "无此条目" {
                    (log)(&format!("[缓存] 命中失败 {path} ({reason})"));
                }
                return None;
            }
        };
    // 命中留痕：写盘静默，小正文按字节显示。
    if super::quiet::first_time("cachehit", &path) {
        (log)(&format!("[缓存] 命中 {path} ({}) 本地", fmt_size(body.len())));
    }
    // SWR：过期快照交旧 + 后台重拉。
    if swr_expired {
        (log)(&format!("[缓存] 页面快照过期, 交旧 + 后台重拉 {path}"));
        spawn_page_refetch(log, host, &key, &path, cookies, upstream::encoding_bucket(req));
    }
    Some(rebuild_cached_response(status, &hdrs, body))
}

/// 大小显示：小正文按字节。
fn fmt_size(len: usize) -> String {
    if len < 1024 {
        format!("{}B", len)
    } else {
        format!("{}KB", len / 1024)
    }
}

// ---------- 内部：XHR 15 分钟内存缓存 ----------

struct XhrEntry {
    expires: std::time::Instant,
    status: u16,
    hdrs: Vec<Vec<String>>,
    body: Bytes,
}

static XHR_CACHE: LazyLock<Mutex<HashMap<String, XhrEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static XHR_BYTES: AtomicU64 = AtomicU64::new(0);
const XHR_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const XHR_CACHE_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// 表示档：按 Accept 选 "-j"/"-h"，存侧按实际 Content-Type、取侧预测，预测不中只 miss。
fn xhr_kind_from_accept(accept: Option<&str>) -> &'static str {
    match accept {
        Some(a) if a.to_ascii_lowercase().contains("html") => "-h",
        _ => "-j",
    }
}

fn xhr_cache_key(
    uri: &http::Uri,
    host: &str,
    cookies: Option<&str>,
    enc: &str,
    kind: &str,
) -> String {
    let path = uri.path();
    let q = uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let cookie_tag = session_fingerprint(cookies);
    let enc_tag = match enc {
        "br" => "-br",
        "gzip" => "-gz",
        _ => "-id",
    };
    format!("GET {host}{path}{q}{cookie_tag}{enc_tag}{kind}")
}

/// XHR 回放：未过期返回 (状态, 头, 体)，过期惰性删除。
fn xhr_take(key: &str) -> Option<(u16, Vec<Vec<String>>, Bytes)> {
    let mut map = lock(&XHR_CACHE);
    let now = std::time::Instant::now();
    match map.get(key) {
        Some(e) if e.expires > now => Some((e.status, e.hdrs.clone(), e.body.clone())),
        Some(_) => {
            let gone = map.remove(key).expect("刚判定存在");
            XHR_BYTES.fetch_sub(gone.body.len() as u64, Ordering::Relaxed);
            None
        }
        None => None,
    }
}

/// XHR 入库：15 分钟 TTL，总量 5MB，按最早过期先淘汰。
fn xhr_store(key: &str, status: u16, hdrs: Vec<Vec<String>>, body: Bytes) {
    let expires = std::time::Instant::now() + XHR_TTL;
    let mut map = lock(&XHR_CACHE);
    xhr_sweep_expired(&mut map); // 顺带清扫过期条目
    if let Some(old) = map.remove(key) {
        XHR_BYTES.fetch_sub(old.body.len() as u64, Ordering::Relaxed);
    }
    XHR_BYTES.fetch_add(body.len() as u64, Ordering::Relaxed);
    map.insert(
        key.to_string(),
        XhrEntry { expires, status, hdrs, body },
    );
    // 总量护栏：按最早过期先删。
    while XHR_BYTES.load(Ordering::Relaxed) > XHR_CACHE_MAX_BYTES && map.len() > 1 {
        let Some(victim) = map
            .iter()
            .min_by_key(|(_, e)| e.expires)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        if victim == key {
            break; // 刚入库的不自删
        }
        if let Some(gone) = map.remove(&victim) {
            XHR_BYTES.fetch_sub(gone.body.len() as u64, Ordering::Relaxed);
        }
    }
}

/// 过期条目清扫（store 时顺带）。
fn xhr_sweep_expired(map: &mut HashMap<String, XhrEntry>) {
    let now = std::time::Instant::now();
    let gone: Vec<String> = map
        .iter()
        .filter(|(_, e)| e.expires <= now)
        .map(|(k, _)| k.clone())
        .collect();
    for k in gone {
        if let Some(e) = map.remove(&k) {
            XHR_BYTES.fetch_sub(e.body.len() as u64, Ordering::Relaxed);
        }
    }
}

/// 存路由：可缓存收集体后投递 Save（主路径零磁盘等待）。
pub(super) async fn cache_put(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    // ① 资产库：githubassets 白名单条目入库。
    if host == asset_store::ASSET_HOST {
        return collect_asset(log, req, resp).await;
    }
    if !cache_eligible(req, host) {
        return resp;
    }
    // 只缓存 200。
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let path = req.uri().path();
    let search_page = is_search_page(path);
    // 分类以实际 Content-Type 为准。
    let ct_lower = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();

    let doc_nav = is_document_nav(req);
    // 搜索页整页 HTML → "-p" 内存桶。
    let search_full_html =
        search_page && doc_nav && ct_lower.starts_with("text/html");
    // 软导航 HTML 片段 → 15 分钟内存缓存。
    let soft_html = !doc_nav && ct_lower.starts_with("text/html");

    // ② keep 骨架：仅首页 HTML，7 天跨会话。
    if keep_route(path, &ct_lower) && !soft_html {
        // 编码档按响应实际编码定。
        return collect_and_submit_keep(log, req.uri(), host, false, resp).await;
    }

    // ③ XHR 内存缓存：搜索页整页 + 数据正文 + 软导航片段 15 分钟。
    if is_xhr_body(&ct_lower) || soft_html || search_full_html {
        let (mut parts, body) = resp.into_parts();
        // 嗅探读走的前几帧要拼回，否则半帧。
        let mut peek: Vec<u8> = Vec::new();
        if let Some(p) = parts.extensions.remove::<super::PeekRaw>() {
            for b in p.0 {
                peek.extend_from_slice(&b);
            }
        }
        let collected = match http_body_util::BodyExt::collect(body).await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return hyper::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(protocol::full_body(Bytes::from_static(b"xhr collect failed")))
                    .unwrap();
            }
        };
        let bytes = if peek.is_empty() {
            collected
        } else {
            let mut full = Vec::with_capacity(peek.len() + collected.len());
            full.extend_from_slice(&peek);
            full.extend_from_slice(&collected);
            Bytes::from(full)
        };
        // 带 <html 根或超限 = 整页，不收。
        if soft_html {
            let enc = parts
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(body_encoding)
                .unwrap_or("identity");
            if !is_html_fragment(&ct_lower, &bytes, enc) {
                return hyper::Response::from_parts(parts, protocol::full_body(bytes));
            }
        }
        // Set-Cookie 只从缓存元数据剔除，响应原样给浏览器。
        let cache_hdrs: Vec<Vec<String>> = parts
            .headers
            .iter()
            .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
            .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
            .collect();
        // 按响应实际编码分桶。
        let enc = response_encoding(&parts.headers);
        // 三键互斥："-p" 整页 / "-h" 片段 / "-j" 数据。
        let kind = if search_full_html {
            "-p"
        } else if ct_lower.starts_with("text/html") {
            "-h"
        } else {
            "-j"
        };
        let key = xhr_cache_key(req.uri(), host, cookies, enc, kind);
        // 闸门/限流错误与限流降级页拒存，响应照常交回。
        let reject_reason = if xhr_should_reject(&bytes, enc) {
            Some("闸门/限流错误")
        } else if search_full_html && is_search_skeleton(&key, &bytes, enc) {
            Some("限流骨架")
        } else {
            None
        };
        if let Some(reason) = reject_reason {
            if search_full_html {
                (log)(&format!("[缓存] 搜索页拒存 {path} ({reason})"));
            } else {
                (log)(&format!("[缓存] XHR 拒存 {path} ({reason})"));
            }
        } else {
            xhr_store(&key, parts.status.as_u16(), cache_hdrs, bytes.clone());
            if super::quiet::first_time("xhrstore", path) {
                (log)(&format!(
                    "[缓存] {} 入库 {path} ({} {kind}) 15 分钟",
                    if search_full_html { "搜索页" } else { "XHR" },
                    fmt_size(bytes.len())
                ));
            }
        }
        return hyper::Response::from_parts(parts, protocol::full_body(bytes));
    }

    resp // 其余 Content-Type（图片/二进制等）透传不入
}

// ---------- 内部：管家线程 ----------

struct CacheTask {
    dir: std::path::PathBuf,
    msg: CacheMsg,
}

static WORKER_SENDER: OnceLock<mpsc::SyncSender<CacheTask>> = OnceLock::new();

/// 向管家投递任务；筐满/管家不可用 = 丢弃并打日志。
fn worker_send(msg: CacheMsg, log: &LogFn) -> bool {
    let msg = CacheTask {
        dir: page_cache_dir(),
        msg,
    };
    let tx = WORKER_SENDER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<CacheTask>(WORKER_CHANNEL_CAP);
        let log = log.clone();
        let _ = std::thread::Builder::new()
            .name("page-cache-worker".into())
            .spawn(move || worker_loop(log, rx));
        tx
    });
    match tx.try_send(msg) {
        Ok(()) => true,
        Err(e) => {
            (log)(&format!("[缓存] 任务筐投递失败({e})，本次丢弃"));
            false
        }
    }
}

/// 管家循环：串行消费任务筐，每条消息独立 panic 护栏。
fn worker_loop(log: LogFn, rx: mpsc::Receiver<CacheTask>) {
    while let Ok(task) = rx.recv() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let dir = &task.dir;
            match task.msg {
                CacheMsg::Save {
                    key,
                    bytes,
                    status,
                    hdrs,
                } => {
                    if let Err(e) = persist_page_entry_blocking(dir, &key, &bytes, status, &hdrs) {
                        (log)(&format!("[缓存] 后台写盘失败({e})，{key} 本次不缓存"));
                    }
                }
                CacheMsg::SaveAsset { url, bytes, hdrs } => {
                    if let Err(e) = asset_store::persist_blocking(dir, &url, &bytes, &hdrs) {
                        (log)(&format!("[资产] 后台写盘失败({e})，{url} 本次不入库"));
                    }
                }
                CacheMsg::Invalidate { host, path } => {
                    let k = invalidate_prefix_blocking(dir, &host, &path);
                    if k > 0 {
                        (log)(&format!(
                            "[缓存] 写后失效 {host}{path} (keep 快照标过期 {k})"
                        ));
                    }
                }
            }
        }));
    }
}

/// 清盘 keep（超 5MB 整盘重来）并返回条目数；顺带删 pages/ 残留。
fn wipe_pages(dir: &std::path::Path) -> usize {
    let n = std::fs::read_dir(dir.join("keep"))
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(dir.join("keep"));
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
    let _ = std::fs::remove_dir_all(dir.join("pages"));
    let _ = std::fs::create_dir_all(dir.join("keep"));
    BYTES_SINCE_WIPE.store(0, Ordering::Relaxed);
    n
}

/// 由 (status, 头, 体) 重建命中响应。
fn rebuild_cached_response(
    status: u16,
    headers: &[(hyper::header::HeaderName, hyper::header::HeaderValue)],
    body: Bytes,
) -> axum::response::Response<BoxBody> {
    let mut hdrmap = hyper::HeaderMap::new();
    for (k, v) in headers {
        hdrmap.insert(k.clone(), v.clone());
    }
    let mut resp = hyper::Response::builder()
        .status(status)
        .body(protocol::full_body(body))
        .unwrap();
    *resp.headers_mut() = hdrmap;
    resp.headers_mut().insert(
        "x-gitport-cache",
        hyper::header::HeaderValue::from_static("hit"),
    );
    resp
}

// ---------- 内部：目录与 ACL ----------

/// 测试用目录覆盖，生产构建不存在。
#[cfg(test)]
static CACHE_DIR_OVERRIDE: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

pub(super) fn page_cache_dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(d) = CACHE_DIR_OVERRIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
    {
        return d;
    }
    crate::settings::exe_dir().join(".cache")
}

static CACHE_ACL_APPLIED: OnceLock<()> = OnceLock::new();

/// 确保 .cache 存在，首次套 ACL。
fn ensure_cache_dir_with_acl(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    if CACHE_ACL_APPLIED.set(()).is_ok() {
        let _ = crate::winsec::restrict_dir_to_current_user(&dir.to_string_lossy());
    }
    true
}

/// Cookie 按出现序全拼（h2 会拆多行）。
fn all_cookies(hdrs: &hyper::HeaderMap) -> Option<String> {
    let mut joined = String::new();
    for v in hdrs.get_all("cookie") {
        let Ok(s) = v.to_str() else { continue };
        if !joined.is_empty() {
            joined.push_str("; ");
        }
        joined.push_str(s);
    }
    (!joined.is_empty()).then_some(joined)
}

/// 登录态 cookie 值，有值 = 已登录。
fn session_value(cookies: Option<&str>) -> Option<&str> {
    cookies?.split(';').map(str::trim).find_map(|kv| {
        kv.strip_prefix("user_session=")
            .or_else(|| kv.strip_prefix("__Host-user_session_same_site="))
    })
}

/// 身份标签：未登录 -cloggedout，登录 = 会话号摘要。
fn session_fingerprint(cookies: Option<&str>) -> String {
    match session_value(cookies) {
        Some(sess) => format!("-cs{}", page_file_name(sess)),
        None => "-cloggedout".into(),
    }
}

/// 拒存日志用：键去掉 "GET host" 前缀，露出路径+查询。
fn dbg_path(key: &str) -> &str {
    key.split_once(' ').map(|(_, rest)| rest).unwrap_or(key)
}

/// 搜索页内容分钥匙：存侧按 Content-Type、取侧按 Accept 预测。
fn search_variant(accept: Option<&str>) -> &'static str {
    let wants_json = accept
        .map(|a| {
            let a = a.to_ascii_lowercase();
            a.contains("application/json") && !a.contains("text/html")
        })
        .unwrap_or(false);
    if wants_json {
        "-json"
    } else {
        "-html"
    }
}

/// 取侧骨架变体：首页恒 "-html"，搜索页按 Accept 预测。
fn keep_lookup_variant(path: &str, accept: Option<&str>) -> &'static str {
    if is_search_page(path) {
        search_variant(accept)
    } else {
        "-html"
    }
}

/// keep 骨架键 = 方法 + host + 路径查询 + 变体 + 编码标签，不含身份标签（跨会话复用）。
fn live_cache_key(uri: &http::Uri, host: &str, enc: &str, variant: &str) -> String {
    format!("{}{variant}-k", page_cache_key(uri, host, enc))
}

fn page_cache_key(uri: &http::Uri, host: &str, enc: &str) -> String {
    let path = uri.path();
    let q = uri
        .query()
        .map(|q| normalize_query(uri.path(), q))
        .unwrap_or_default();
    // 编码进键。
    let enc_tag = match enc {
        "br" => "-br",
        "gzip" => "-gz",
        _ => "-id",
    };
    format!("GET {host}{path}{q}{enc_tag}")
}

/// /search 查询串归一化：补 p=1 + 参数排序；其他路径原样。
fn normalize_query(path: &str, q: &str) -> String {
    if path != "/search" {
        return format!("?{q}");
    }
    let mut pairs: Vec<&str> = q.split('&').filter(|s| !s.is_empty()).collect();
    pairs.retain(|s| *s != "p=1");
    // 补 p=1 让两种写法同键。
    if !pairs.iter().any(|s| s.starts_with("p=")) {
        pairs.push("p=1");
    }
    pairs.sort_unstable();
    format!("?{}", pairs.join("&"))
}

/// 正文压缩编码：gzip/br，其余 identity。
fn body_encoding(v: &str) -> &'static str {
    let t = v.trim();
    if t.eq_ignore_ascii_case("gzip") {
        "gzip"
    } else if t.eq_ignore_ascii_case("br") {
        "br"
    } else {
        "identity"
    }
}

/// 从响应头读实际编码，供缓存键分桶。
fn response_encoding(headers: &http::HeaderMap) -> &'static str {
    headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(body_encoding)
        .unwrap_or("identity")
}

/// 解压后取前 8KB 转小写。
fn plain_prefix(bytes: &[u8], enc: &str) -> String {
    let plain = super::defuse::decompress_partial(bytes, enc, 8192);
    String::from_utf8_lossy(&plain).to_lowercase()
}

/// 限流降级骨架（缺 embeddedData）拒存。
fn is_search_skeleton(key: &str, bytes: &[u8], enc: &str) -> bool {
    if !key.contains("/search?") {
        return false;
    }
    if key.contains("-json-") {
        return false; // 骨架判定只对 HTML 生效
    }
    let plain = super::defuse::decompress_partial(bytes, enc, PAGE_CACHE_MAX_BODY_BYTES);
    let text = String::from_utf8_lossy(&plain);
    !text.contains("react-app.embeddedData")
}

/// 软导航片段判定：text/html、无 <html 根、≤256KB。
fn is_html_fragment(ct_lower: &str, bytes: &[u8], enc: &str) -> bool {
    if !ct_lower.starts_with("text/html") || bytes.len() > HTML_FRAGMENT_MAX_BYTES {
        return false;
    }
    let p = plain_prefix(bytes, enc);
    !p.contains("<html") && !p.contains("<!doctype")
}

/// HTML 完整性：末 2KB 有 </html>，读写两侧都查。
fn html_complete(bytes: &[u8], enc: &str) -> bool {
    let full = super::defuse::decompress_partial(bytes, enc, 32 << 20);
    full.len() >= 7
        && full[full.len().saturating_sub(2048)..]
            .windows(7)
            .any(|w| w == b"</html>")
}

/// 闸门页标记：GitHub 拿这些页顶替你请求的 URL 回 200，存下会一直显示。
const GATE_MARKERS: &[&str] = &[
    "verify your two-factor authentication",
    "one-time verification of your recently configured 2fa",
    "two_factor_verification",
    "sessions/verified-device",
    "confirm your password",
    "your account has been suspended",
    "you have exceeded a secondary rate limit",
];

fn is_gate_page(plain: &str) -> bool {
    GATE_MARKERS.iter().any(|m| plain.contains(m))
}

/// XHR 入库门检：闸门/限流错误拒存，普通 error 字段照存。
fn xhr_should_reject(bytes: &[u8], enc: &str) -> bool {
    let plain = String::from_utf8_lossy(&super::defuse::decompress_partial(bytes, enc, 64 << 10))
        .to_ascii_lowercase();
    is_gate_page(&plain)
        || plain.contains("\"rate_limited\"")
        || plain.contains("secondary rate limit")
}

/// key → 文件名：稳定 64 位摘要 16 hex。
fn page_file_name(key: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&key, &mut h);
    format!("{:016x}", std::hash::Hasher::finish(&h))
}

/// 磁盘条目反序列化形态：状态码 + 规范化响应头 + 压缩体。
type DiskEntry = (
    u16,
    Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    Bytes,
);

/// 读单文件条目，损坏/截断/非 200 即 miss；仅测试使用。
#[cfg(test)]
fn load_disk_entry(key: &str) -> Option<DiskEntry> {
    load_disk_entry_reason(key).ok().map(|(e, _)| e)
}

/// 带拒绝原因的读取；第二个元素 = 骨架是否过期（SWR 触发）。
fn load_disk_entry_reason(key: &str) -> Result<(DiskEntry, bool), &'static str> {
    let path = entry_dir(&page_cache_dir()).join(page_file_name(key));
    let raw = std::fs::read(&path).map_err(|_| "无此条目")?;
    // SWR：过期骨架交旧 + 后台重拉。
    let mut swr_expired = false;
    if key.ends_with("-k") {
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX); // 取不到间隔按过期处理
        swr_expired = age > KEEP_MAX_AGE_MS;
    }
    let entry = super::entry::decode(&raw, key)?;
    let enc = entry
        .headers
        .iter()
        .find(|(k, _)| k.as_str() == "content-encoding")
        .and_then(|(_, v)| v.to_str().ok())
        .map(body_encoding)
        .unwrap_or("identity");
    let body = entry.body;
    let p = plain_prefix(&body, enc);
    if is_gate_page(&p) {
        return Err("闸门页"); // 当作 miss
    }
    // 读侧二道防线：限流骨架当 miss。
    if key.ends_with("-k") && is_search_skeleton(key, &body, enc) {
        return Err("骨架条目是限流空壳");
    }
    // 截断页删文件自愈。
    if key.ends_with("-k")
        && entry.headers.iter().any(|(k, v)| {
            k.as_str() == "content-type"
                && v.to_str()
                    .map(|v| v.starts_with("text/html"))
                    .unwrap_or(false)
        })
        && !html_complete(&body, enc)
    {
        let _ = std::fs::remove_file(&path);
        return Err("骨架条目截断(无</html>)");
    }
    Ok(((entry.status, entry.headers, body), swr_expired))
}

// ---------- 页面快照 SWR（过期交旧 + 后台重拉） ----------

/// 页面快照后台重拉去重：同键同时只跑一个。
static PAGE_REFRESHING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn page_refresh_done(key: &str) {
    let g = PAGE_REFRESHING.get_or_init(|| Mutex::new(HashSet::new()));
    lock(g).remove(key);
}

/// 过期快照后台重拉：200+完整才覆盖，失败 60s 再试。
fn spawn_page_refetch(
    log: &LogFn,
    host: &str,
    key: &str,
    path_q: &str,
    cookie: Option<&str>,
    bucket: &'static str,
) {
    let g = PAGE_REFRESHING.get_or_init(|| Mutex::new(HashSet::new()));
    if !lock(g).insert(key.to_string()) {
        return; // 同键在途去重
    }
    let host = host.to_string();
    let key = key.to_string();
    let path_q = path_q.to_string();
    let cookie = cookie.map(str::to_string);
    let log = log.clone();
    tokio::spawn(async move {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            // ① 通道：池内现成通道，没有就拨。
            let (up, _) = match crate::pool::get_or_build(&host, &log).await {
                Ok(v) => v,
                Err(e) => {
                    (log)(&format!(
                        "[缓存] 页面重拉第 {attempt} 次拨号失败({e}), 60s 后再试, 旧壳继续"
                    ));
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
            };
            // ② 请求：带 cookie + 按桶协商压缩。
            let mut b = hyper::Request::builder()
                .uri(format!("https://{host}{path_q}"))
                .header("accept", "text/html, */*")
                .header("user-agent", upstream::BROWSER_UA);
            b = match bucket {
                "br" => b.header("accept-encoding", "br"),
                "gzip" => b.header("accept-encoding", "gzip"),
                _ => b,
            };
            if let Some(c) = &cookie {
                b = b.header("cookie", c);
            }
            let req = match b.body(protocol::empty_body()) {
                Ok(r) => r,
                Err(e) => {
                    (log)(&format!("[缓存] 页面重拉请求构造失败({e}), 放弃重拉"));
                    page_refresh_done(&key);
                    return;
                }
            };
            let resp = match upstream::h2_send(&up, &req, &None::<Bytes>).await {
                Ok(r) => r,
                Err(e) => {
                    (log)(&format!(
                        "[缓存] 页面重拉第 {attempt} 次失败({e}), 60s 后再试, 旧壳继续"
                    ));
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
            };
            let st = resp.status();
            if st != http::StatusCode::OK {
                // 404/410 = 上游页面不存在，删快照。
                if st == http::StatusCode::NOT_FOUND || st == http::StatusCode::GONE {
                    let _ = std::fs::remove_file(
                        entry_dir(&page_cache_dir()).join(page_file_name(&key)),
                    );
                    (log)(&format!(
                        "[缓存] 页面重拉确认上游 {st}(页面已不存在), 删除快照, 下次访问直连见真实 404"
                    ));
                    page_refresh_done(&key);
                    return;
                }
                (log)(&format!(
                    "[缓存] 页面重拉第 {attempt} 次非 200({}), 60s 后再试, 旧壳继续",
                    st.as_u16()
                ));
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
            let (parts, body) = resp.into_parts();
            let hdrs: Vec<Vec<String>> = parts
                .headers
                .iter()
                .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
                .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
                .collect();
            let collected = match http_body_util::BodyExt::collect(body).await {
                Ok(c) => c,
                Err(e) => {
                    (log)(&format!(
                        "[缓存] 页面重拉第 {attempt} 次收体失败({e}), 60s 后再试, 旧壳继续"
                    ));
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
            };
            let bytes = collected.to_bytes();
            // ③ 门检：与正常写入共用同一套。
            let enc = response_encoding(&parts.headers);
            // 编码档按响应实际编码定。
            let real_key = format!("https://{host}{path_q}")
                .parse::<http::Uri>()
                .map(|uri| live_cache_key(&uri, &host, enc, "-html"))
                .unwrap_or_else(|_| key.clone());
            if real_key != key {
                // 旧键条目删掉，免得被旧编码客户端命中。
                let stale = entry_dir(&page_cache_dir()).join(page_file_name(&key));
                let _ = std::fs::remove_file(stale);
            }
            if let Some(why) = skeleton_reject_reason(&real_key, &bytes, enc, &parts.headers) {
                (log)(&format!(
                    "[缓存] 页面重拉第 {attempt} 次门检不过({why}), 60s 后再试, 旧壳继续"
                ));
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
            // ④ 覆盖入库，mtime 复新。
            match write_entry_file(
                &page_cache_dir(),
                &real_key,
                &bytes,
                http::StatusCode::OK.as_u16(),
                &hdrs,
            ) {
                Ok(_) => (log)(&format!(
                    "[缓存] 页面重拉完成, 快照已更新 (尝试 {attempt} 次)"
                )),
                Err(e) => (log)(&format!("[缓存] 页面重拉落盘失败({e}), 旧壳继续")),
            }
            page_refresh_done(&key);
            return;
        }
    });
}

/// 测试专用：绕开准入直读磁盘。
#[cfg(test)]
fn page_cache_get(key: &str) -> Option<axum::response::Response<BoxBody>> {
    let (status, hdrs, body) = load_disk_entry(key)?;
    Some(rebuild_cached_response(status, &hdrs, body))
}

// ---------- 内部：容量管理 ----------

/// 攒够 5MB 整盘重来。
static BYTES_SINCE_WIPE: AtomicU64 = AtomicU64::new(0);

fn maybe_wipe_on_growth(dir: &std::path::Path, written: usize) {
    let pending = BYTES_SINCE_WIPE.fetch_add(written as u64, Ordering::Relaxed) + written as u64;
    if pending >= PAGE_CACHE_MAX_BYTES {
        // 并发越线只让一个去清。
        if BYTES_SINCE_WIPE
            .compare_exchange(pending, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            wipe_pages(dir);
        }
    }
}

/// 条目落盘：tmp 写 + rename 原子覆盖。
fn write_entry_file(
    dir: &std::path::Path,
    key: &str,
    body: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    let buf = super::entry::encode(key, status, hdrs, body);
    // 记账口径 = 实际写入量。
    maybe_wipe_on_growth(dir, buf.len());
    let pages = entry_dir(dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&pages).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    // 纳秒时钟防重入。
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = tmp.join(format!("{}.{uniq:x}", page_file_name(key)));
    std::fs::write(&tmp_path, &buf).map_err(|e| e.to_string())?;
    let final_path = pages.join(page_file_name(key));
    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        e.to_string()
    })
}

/// 页面缓存落盘统一入口（全量格式）。
fn persist_page_entry_blocking(
    dir: &std::path::Path,
    key: &str,
    bytes: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    if !ensure_cache_dir_with_acl(dir) {
        return Err("缓存目录创建失败".to_string());
    }
    write_entry_file(dir, key, bytes, status, hdrs)
}

/// no-store 不落盘；private 不拒（已按会话分钥匙）。
fn resp_no_store(headers: &http::HeaderMap) -> bool {
    headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("no-store"))
}

/// 骨架入库门检（写入与重拉共用）：Some=拒存原因。
fn skeleton_reject_reason(
    key: &str,
    bytes: &[u8],
    enc: &str,
    headers: &http::HeaderMap,
) -> Option<&'static str> {
    if bytes.len() > PAGE_CACHE_MAX_BODY_BYTES {
        return Some("超 2MB 上限");
    }
    if resp_no_store(headers) {
        return Some("no-store");
    }
    if !html_complete(bytes, enc) {
        return Some("HTML 不完整");
    }
    let plain = plain_prefix(bytes, enc);
    if is_gate_page(&plain) {
        return Some("闸门页");
    }
    if is_search_skeleton(key, bytes, enc) {
        return Some("限流骨架");
    }
    None
}

/// keep 骨架收集体：门检后投递 Save，响应原样交回浏览器。
async fn collect_and_submit_keep(
    log: &LogFn,
    uri: &http::Uri,
    host: &str,
    search_page: bool,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ct.starts_with("text/html") {
        // keep 只收 HTML 骨架。
        return hyper::Response::from_parts(parts, body);
    }
    // 嗅探读走的前几帧要拼回，否则半页。
    let mut peek: Vec<u8> = Vec::new();
    if let Some(p) = parts.extensions.remove::<super::PeekRaw>() {
        for b in p.0 {
            peek.extend_from_slice(&b);
        }
    }
    match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => {
            let mut bytes = collected.to_bytes();
            if !peek.is_empty() {
                let mut full = Vec::with_capacity(peek.len() + bytes.len());
                full.extend_from_slice(&peek);
                full.extend_from_slice(&bytes);
                bytes = Bytes::from(full);
            }
            // 门检需先解压。
            let enc = response_encoding(&parts.headers);
            // 按响应实际编码分桶。
            let key = live_cache_key(uri, host, enc, "-html");
            // Set-Cookie 只从缓存元数据剔除。
            let cache_hdrs: Vec<Vec<String>> = parts
                .headers
                .iter()
                .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
                .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
                .collect();
            // 门检与重拉共用同一套。
            let reject = skeleton_reject_reason(&key, &bytes, enc, &parts.headers);
            if reject.is_none() {
                let status = parts.status.as_u16();
                worker_send(
                    CacheMsg::Save {
                        key: key.to_string(),
                        bytes: bytes.clone(), // Bytes 浅克隆，跨线程零拷贝
                        status,
                        hdrs: cache_hdrs,
                    },
                    log,
                );
            } else if search_page {
                // 拒存落日志。
                (log)(&format!(
                    "[缓存] 拒存 {} ({})",
                    dbg_path(&key),
                    reject.unwrap_or("未知原因")
                ));
            }
            let mut rebuilt = hyper::Response::builder()
                .status(parts.status)
                .body(protocol::full_body(bytes))
                .unwrap();
            *rebuilt.headers_mut() = parts.headers;
            rebuilt
        }
        Err(_) => {
            if search_page {
                (log)(&format!(
                    "[缓存] 拒存 {} (正文收集失败: 上游流中断)",
                    uri.path()
                ));
            }
            // 收集失败回 502。
            hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(protocol::full_body(Bytes::from_static(
                    b"page collect failed",
                )))
                .unwrap()
        }
    }
}

// ---------- 资产库入库（githubassets → 本地回放；强绑定入口在 asset_store::serve_or_fetch） ----------

/// 资产入库分支：白名单 200 体投管家保存。
async fn collect_asset<B>(
    log: &LogFn,
    req: &hyper::Request<B>,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let url = asset_store::asset_request_url(req, asset_store::ASSET_HOST);
    let name = asset_store::asset_dbg_name(&url).to_string();
    let (mut parts, body) = resp.into_parts();
    if parts.status != StatusCode::OK {
        return hyper::Response::from_parts(parts, body);
    }
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // 嗅探读走的前几帧要拼回，否则入库半帧。
    let mut peek: Vec<u8> = Vec::new();
    if let Some(p) = parts.extensions.remove::<super::PeekRaw>() {
        for b in p.0 {
            peek.extend_from_slice(&b);
        }
    }
    let collected = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(protocol::full_body(Bytes::from_static(b"asset collect failed")))
                .unwrap();
        }
    };
    let bytes = if peek.is_empty() {
        collected
    } else {
        let mut full = Vec::with_capacity(peek.len() + collected.len());
        full.extend_from_slice(&peek);
        full.extend_from_slice(&collected);
        Bytes::from(full)
    };
    if asset_store::storable(parts.status, &ct) {
        let cache_hdrs: Vec<Vec<String>> = parts
            .headers
            .iter()
            .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
            .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
            .collect();
        if worker_send(
            CacheMsg::SaveAsset {
                url: url.clone(),
                bytes: bytes.clone(), // Bytes 浅克隆，跨线程零拷贝
                hdrs: cache_hdrs,
            },
            log,
        ) && super::quiet::first_time("assetnew", &name)
        {
            (log)(&format!(
                "[资产] 入库 {name} ({})",
                fmt_size(bytes.len())
            ));
        }
    }
    hyper::Response::from_parts(parts, protocol::full_body(bytes))
}

/// keep 条目改标过期：mtime 拨到保质期外；set_times 无需额外状态。
fn mark_entry_expired(p: &std::path::Path) {
    let Ok(f) = std::fs::OpenOptions::new().write(true).open(p) else {
        return; // 文件已不在
    };
    let past =
        std::time::SystemTime::now() - std::time::Duration::from_millis(KEEP_MAX_AGE_MS + 60_000);
    let _ = f.set_times(std::fs::FileTimes::new().set_modified(past));
}

/// 写后失效：前缀匹配 + 父路径（至少两级）；返回标记数。
fn invalidate_prefix_blocking(dir: &std::path::Path, host: &str, path: &str) -> usize {
    let mut prefixes = vec![format!("GET {host}{path}")];
    if let Some(i) = path.rfind('/') {
        let parent = &path[..i];
        if parent.matches('/').count() >= 2 {
            prefixes.push(format!("GET {host}{parent}"));
        }
    }
    let mut marked = 0usize;
    // keep 快照只标过期不删，走 SWR 交旧 + 重拉。
    let Ok(rd) = std::fs::read_dir(dir.join("keep")) else {
        return 0;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Some(key) = read_page_key(&p) else {
            continue;
        };
        if !prefixes.iter().any(|pre| key.starts_with(pre)) {
            continue;
        }
        mark_entry_expired(&p);
        marked += 1;
    }
    marked
}

/// 只读页面文件 header 段取 key。
fn read_page_key(p: &std::path::Path) -> Option<String> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(p).ok()?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).ok()?;
    let hlen = u32::from_be_bytes(len_buf) as usize;
    let mut hbuf = vec![0u8; hlen];
    f.read_exact(&mut hbuf).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&hbuf).ok()?;
    v.get("key")?.as_str().map(str::to_string)
}

/// 写后失效入口：只投消息。
pub(super) fn invalidate_after_write(log: &LogFn, host: &str, path: &str) {
    worker_send(
        CacheMsg::Invalidate {
            host: host.to_string(),
            path: path.to_string(),
        },
        log,
    );
}

/// 清空缓存（测试专用）。
#[cfg(test)]
fn page_cache_clear() {
    BYTES_SINCE_WIPE.store(0, Ordering::Relaxed);
    lock(&XHR_CACHE).clear();
    XHR_BYTES.store(0, Ordering::Relaxed);
    let dir = page_cache_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let _ = std::fs::remove_dir_all(&p);
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/page_cache_tests.rs"]
mod page_cache_tests;
