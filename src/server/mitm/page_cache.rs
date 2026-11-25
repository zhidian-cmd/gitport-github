//! 页面缓存：github.com 的首页/搜索页骨架（keep/，7 天跨会话长寿命，键无会话号）+ JSON/纯文本
//! XHR 15 分钟内存缓存（仓库/搜索/首页全覆盖）；闸门页/未登录页/跨账号不缓存；仓库页零转换直出
//! （html 永远新鲜；跨发版冻结资产引用 = 旧 JS 配新数据，实测白屏）。
//! githubassets 资产按 URL 入库本地透明回放（immutable 一存永逸，时代中立：URL 即内容指纹）。
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

/// 唯一缓存域：github.com（只收首页/搜索页骨架与 JSON/纯文本 XHR）。
const CACHE_HOST: &str = "github.com";

/// 页面缓存上限 5MB（HTML 骨架单个 ~40KB，5MB 容百余份；浏览器不缓存 HTML，代理侧缓存价值高）。
const PAGE_CACHE_MAX_BYTES: u64 = 5 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）

/// 长寿命条目的保质期：GitHub 改版后旧骨架就是坏的，超期交旧 + 后台重拉（SWR，不判死）。
const KEEP_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 软导航 HTML 片段体积上限：超过按整页处理不收，避免大响应挤占内存池。
const HTML_FRAGMENT_MAX_BYTES: usize = 256 * 1024;

/// 请求是否为文档导航：只有 sec-fetch-dest=document 算整页导航；无该头（curl 等）保守按导航处理，
/// 避免把整页 HTML 误当软导航片段收进内存缓存。
fn is_document_nav<B>(req: &hyper::Request<B>) -> bool {
    req.headers()
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .map(|d| d.eq_ignore_ascii_case("document"))
        .unwrap_or(true)
}

/// 首页：纯骨架（会变的全是 XHR），跨会话长寿命缓存。
fn is_home_path(path: &str) -> bool {
    path == "/" || path.is_empty()
}

/// 搜索页：骨架与查询无关（结果全走 XHR），跨会话长寿命缓存。
fn is_search_page(path: &str) -> bool {
    path == "/search"
}

/// XHR 数据正文判定（存侧分类与 keep 改道共用同一口径）：标准 JSON、`+json` 家族
/// （vnd/problem/graphql-response 等）、ndjson、纯文本；其余类型不进内存缓存。
fn is_xhr_body(ct_lower: &str) -> bool {
    ct_lower.starts_with("application/json")
        || ct_lower.starts_with("text/plain")
        || ct_lower.contains("+json")
        || ct_lower.contains("ndjson")
}

/// 首页/搜索页骨架路由（纯函数形态便于测试）：XHR 数据是数据不是壳，改道 XHR 内存缓存（15 分钟）；
/// 只有非 XHR 正文才进 keep 分支（落盘门检仍只收完整 HTML）。
fn keep_route(path: &str, ct_lower: &str) -> bool {
    (is_home_path(path) || is_search_page(path)) && !is_xhr_body(ct_lower)
}

/// 条目目录：首页/搜索页骨架进 keep/（不再有会话目录 pages/）。
fn entry_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("keep")
}

/// 任务自带目录：发送时取一次，避免后台消息落到测试换过的全局目录上。
enum CacheMsg {
    Save {
        key: String,
        bytes: Bytes,
        status: u16,
        hdrs: Vec<Vec<String>>,
    },
    /// githubassets 资产入库（管家线程落盘，主路径零等待）。
    SaveAsset {
        url: String,
        bytes: Bytes,
        hdrs: Vec<Vec<String>>,
    },
    /// 写操作成功后的 keep 快照标过期（SWR：交旧 + 后台重拉，异步）。
    Invalidate { host: String, path: String },
}

// ---------- 对外唯二入口 ----------

/// 准入：github.com 的 GET 且非 no-cache（全候选；入库分类在响应阶段按 Content-Type 定）。只有 Ctrl+F5 才直通。
fn cache_eligible<B>(req: &hyper::Request<B>, host: &str) -> bool {
    cache_eligible_rules(
        host,
        req.method(),
        req.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
    )
}

/// 准入规则的纯函数形态：拆出来才测得到「Ctrl+F5 直通」这条分支。
fn cache_eligible_rules(host: &str, method: &Method, cache_control: Option<&str>) -> bool {
    host == CACHE_HOST
        && *method == Method::GET
        && !cache_control
            .map(|c| c.contains("no-cache"))
            .unwrap_or(false)
}

/// 取路由：XHR 内存命中（15 分钟 TTL）→ 首页/搜索页骨架 keep 命中 → 未命中走上游。
/// githubassets 资产不在此处理：mitm_http 的资产库强绑定分支接管（命中回放 / miss 独立拉取）。
pub(super) fn cache_take<B>(
    log: &LogFn,
    req: &hyper::Request<B>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    if host != CACHE_HOST || req.method() != Method::GET || !cache_eligible(req, host) {
        return None; // Ctrl+F5(no-cache) 等直通场景全部走上游
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let enc = upstream::encoding_bucket(req);

    // ① XHR 内存命中（15 分钟 TTL，键含 cs 身份标签防跨账号）：dashboard/通知/搜索数据等全部 JSON/纯文本。
    if let Some((status, hdrs, body)) = xhr_take(&xhr_cache_key(req.uri(), host, cookies, enc)) {
        if super::quiet::first_time("xhrhit", &path) {
            (log)(&format!("[缓存] XHR 回放 {path} ({})", fmt_size(body.len())));
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

    // ② keep 命中：首页/搜索页骨架（键无会话号，跨会话/跨重启命中）；SWR 过期交旧 + 后台重拉。
    let search_page = is_search_page(req.uri().path());
    if !(is_home_path(req.uri().path()) || search_page) {
        return None; // 其他页面骨架不缓存：列表页含服务端渲染数据，仓库页防旧 JS 配新数据白屏
    }
    let variant = keep_lookup_variant(
        req.uri().path(),
        req.headers().get("accept").and_then(|v| v.to_str().ok()),
    );
    let key = live_cache_key(req.uri(), host, enc, variant);
    let ((status, hdrs, body), swr_expired) =
        match load_disk_entry_reason(&key, session_value(cookies).is_some())
        {
            Ok(v) => v,
            Err(reason) => {
                // 盘上有条目却被读侧拒绝 = "存了却命中不了"：落日志才排查得动。
                if search_page && reason != "无此条目" {
                    (log)(&format!("[缓存] 命中失败 {path} ({reason})"));
                }
                return None;
            }
        };
    // 命中要留痕：写盘是静默的，没有这行用户无从判断"到底用没用缓存"。
    // 小正文（跟班 XHR 常只有几十字节）按字节显示，别被整数除法抹成 0KB。
    if super::quiet::first_time("cachehit", &path) {
        (log)(&format!("[缓存] 命中 {path} ({}) 本地", fmt_size(body.len())));
    }
    // v6.11 SWR：过期 -k/-rk 快照不判死——交旧（浏览器缓存直出）+ 后台静默重拉（带 cookie）。
    if swr_expired {
        (log)(&format!("[缓存] 页面快照过期, 交旧 + 后台重拉 {path}"));
        spawn_page_refetch(
            log,
            host,
            &key,
            &path,
            cookies,
            upstream::encoding_bucket(req),
            session_value(cookies).is_some(),
        );
    }
    Some(rebuild_cached_response(status, &hdrs, body))
}

/// 大小显示：小正文按字节，别被整数除法抹成 0KB。
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

/// XHR 内存缓存键：完整 URL + 身份标签（通知/计数含账号数据，跨登录必须失效）+ 编码标签。
fn xhr_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, enc: &str) -> String {
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
    format!("GET {host}{path}{q}{cookie_tag}{enc_tag}")
}

/// XHR 回放：命中且未过期 → (状态, 头, 体)；过期惰性删除 → None。
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

/// XHR 入库：15 分钟 TTL；总量超 5MB 按过期时间最早先淘汰（无单条上限——规格 X4 修订）。
fn xhr_store(key: &str, status: u16, hdrs: Vec<Vec<String>>, body: Bytes) {
    let expires = std::time::Instant::now() + XHR_TTL;
    let mut map = lock(&XHR_CACHE);
    xhr_sweep_expired(&mut map); // 顺带清扫：过期条目腾位，总量记账同步
    if let Some(old) = map.remove(key) {
        XHR_BYTES.fetch_sub(old.body.len() as u64, Ordering::Relaxed);
    }
    XHR_BYTES.fetch_add(body.len() as u64, Ordering::Relaxed);
    map.insert(
        key.to_string(),
        XhrEntry { expires, status, hdrs, body },
    );
    // 总量护栏：按过期时间最早先删（即将到期的先腾位），删到限额以内。
    while XHR_BYTES.load(Ordering::Relaxed) > XHR_CACHE_MAX_BYTES && map.len() > 1 {
        let Some(victim) = map
            .iter()
            .min_by_key(|(_, e)| e.expires)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        if victim == key {
            break; // 刚入库的不自删（下轮写入再平衡）
        }
        if let Some(gone) = map.remove(&victim) {
            XHR_BYTES.fetch_sub(gone.body.len() as u64, Ordering::Relaxed);
        }
    }
}

/// 过期条目批量清扫（store 时顺带，无后台定时）。
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

/// 存路由：不可缓存原样透传；可缓存收集体后投递 Save（主路径零磁盘等待）。
pub(super) async fn cache_put(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    // ① 资产库：githubassets 全部经此入库（白名单）/404 剔胚，响应原样交回浏览器。
    if host == asset_store::ASSET_HOST {
        return collect_asset(log, req, resp).await;
    }
    if !cache_eligible(req, host) {
        return resp;
    }
    // 只缓存 200；304 不落日志——每页十几个计数 XHR 都走这条路，留痕只会刷屏。
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let path = req.uri().path();
    let search_page = is_search_page(path);
    // 分类以实际 Content-Type 为准：HTML → keep 骨架；JSON/纯文本 → XHR 内存缓存。
    let ct_lower = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();

    // 软导航 HTML 片段：非 document 导航的 text/html 是局部数据（conduit/filter 等），
    // 与 XHR 同走 15 分钟内存缓存；整页 HTML 由 keep_route 走 keep 骨架或直出。
    let soft_html = !is_document_nav(req) && ct_lower.starts_with("text/html");

    // ② keep 骨架：首页/搜索页 HTML，7 天跨会话（键无会话号）。
    //    数据正文（JSON/ndjson）与软导航片段都不进 keep。
    if keep_route(path, &ct_lower) && !soft_html {
        let key = live_cache_key(req.uri(), host, upstream::encoding_bucket(req), "-html");
        return collect_and_submit_keep(
            log,
            &key,
            search_page,
            session_value(cookies).is_some(),
            resp,
        )
        .await;
    }

    // ③ XHR 内存缓存：数据正文 + 软导航 HTML 片段 15 分钟（不再枚举前缀）。
    if is_xhr_body(&ct_lower) || soft_html {
        let (mut parts, body) = resp.into_parts();
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
        // 声称是片段却实际带 <html 根或超限 = 整页 HTML，不收，原样交回（防误收整页）。
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
        // Set-Cookie 只从缓存元数据剔除（回灌旧值会冻 cookie），响应原样给浏览器。
        let cache_hdrs: Vec<Vec<String>> = parts
            .headers
            .iter()
            .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
            .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
            .collect();
        let key = xhr_cache_key(req.uri(), host, cookies, upstream::encoding_bucket(req));
        xhr_store(&key, parts.status.as_u16(), cache_hdrs, bytes.clone());
        if super::quiet::first_time("xhrstore", path) {
            (log)(&format!(
                "[缓存] XHR 入库 {path} ({}) 15 分钟",
                fmt_size(bytes.len())
            ));
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
                    let (d, k) = invalidate_prefix_blocking(dir, &host, &path);
                    if d + k > 0 {
                        (log)(&format!(
                            "[缓存] 写后失效 {host}{path} (keep 快照标过期 {k})"
                        ));
                    }
                }
            }
        }));
    }
}

/// 清盘 keep（缓存可再生：骨架超 5MB 就整盘重来，不做淘汰排序），返回条目数；一切错误吞掉。
fn wipe_pages(dir: &std::path::Path) -> usize {
    let n = std::fs::read_dir(dir.join("keep"))
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(dir.join("keep"));
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
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

/// 测试用目录覆盖：可重设（每个测试自己的目录），生产构建里不存在。
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

/// 确保 .cache 存在，首次触达套一次 ACL（页面含个人信息）。
fn ensure_cache_dir_with_acl(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    if CACHE_ACL_APPLIED.set(()).is_ok() {
        let _ = crate::winsec::restrict_dir_to_current_user(&dir.to_string_lossy());
    }
    true
}

/// Cookie 按出现序全拼：大 Cookie 会被 h2 拆多行，只读第一行会漏掉后面的 user_session，把登录记成未登录。
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

/// 登录态 cookie 的值（GitHub 的两种 user_session 写法）。有值 = 已登录。
fn session_value(cookies: Option<&str>) -> Option<&str> {
    cookies?.split(';').map(str::trim).find_map(|kv| {
        kv.strip_prefix("user_session=")
            .or_else(|| kv.strip_prefix("__Host-user_session_same_site="))
    })
}

/// 身份标签：未登录 -cloggedout，登录 = 会话号稳定摘要；不用账号名（客户端自报明文可伪造），轮换会话只损失一次命中。
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

/// 搜索页内容分钥匙：存侧看 Content-Type、取侧按 Accept 预测，猜错只是 miss；同 URL 两种正文必须分开。
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

/// 取侧骨架变体：首页恒 "-html"（与存侧一致，修历史上取侧用空串导致首页骨架永不命中的 bug）；
/// 搜索页按 Accept 预测，猜错只是 miss。
fn keep_lookup_variant(path: &str, accept: Option<&str>) -> &'static str {
    if is_search_page(path) {
        search_variant(accept)
    } else {
        "-html"
    }
}

/// keep 骨架键 = 方法 + host + 路径查询 + 变体 + 编码标签；**不含会话号/身份标签**——
/// 骨架是纯壳（无账号数据），跨会话/跨登录/跨重启命中（旧版键带身份标签，换登录即孤儿——已修复）。
fn live_cache_key(uri: &http::Uri, host: &str, enc: &str, variant: &str) -> String {
    format!("{}{variant}-k", page_cache_key(uri, host, enc))
}

fn page_cache_key(uri: &http::Uri, host: &str, enc: &str) -> String {
    let path = uri.path();
    let q = uri
        .query()
        .map(|q| normalize_query(uri.path(), q))
        .unwrap_or_default();
    // 编码进键：br 条目不能给只收 gzip 的 curl。
    let enc_tag = match enc {
        "br" => "-br",
        "gzip" => "-gz",
        _ => "-id",
    };
    format!("GET {host}{path}{q}{enc_tag}")
}

/// /search 查询串归一化：默认页补 p=1、参数按键名排序；其他路径原样（个别接口参数顺序有语义）。
fn normalize_query(path: &str, q: &str) -> String {
    if path != "/search" {
        return format!("?{q}");
    }
    let mut pairs: Vec<&str> = q.split('&').filter(|s| !s.is_empty()).collect();
    pairs.retain(|s| *s != "p=1");
    // 没给页码 = 第一页；补 p=1 让两种写法同键。
    if !pairs.iter().any(|s| s.starts_with("p=")) {
        pairs.push("p=1");
    }
    pairs.sort_unstable();
    format!("?{}", pairs.join("&"))
}

/// 这段正文的压缩编码（决定门检怎么解压）：gzip/br，其余按 identity。
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

/// 解压后取前 8KB 并转小写：主站正文恒压缩（gzip/br），不解压扫不到字面量。
fn plain_prefix(bytes: &[u8], enc: &str) -> String {
    let plain = super::defuse::decompress_partial(bytes, enc, 8192);
    String::from_utf8_lossy(&plain).to_lowercase()
}

/// 限流降级骨架（缺 embeddedData）不入缓存，否则一次降级会被刷新固化成“一直坏”。
fn is_search_skeleton(key: &str, bytes: &[u8], enc: &str) -> bool {
    if !key.contains("/search?") {
        return false;
    }
    if key.contains("-json-") {
        return false; // JSON 正文本就没有 HTML 结果载体，骨架判定只对 HTML 分支生效
    }
    let plain = super::defuse::decompress_partial(bytes, enc, PAGE_CACHE_MAX_BODY_BYTES);
    let text = String::from_utf8_lossy(&plain);
    !text.contains("react-app.embeddedData")
}

/// 未登录页：带会话却拿到这类 body = 会话已死，不存也不当命中（防污染）。
fn is_logged_out_body(plain: &str) -> bool {
    plain.contains("logged-out env-") || plain.contains("class=\"logged-out")
}

/// 软导航 HTML 片段判定：text/html 响应、解压后无 <html 根、体积在上限内——
/// 配合调用处的"非 document 导航"条件，整页 HTML 不会误收；片段供 React 软导航填充局部。
fn is_html_fragment(ct_lower: &str, bytes: &[u8], enc: &str) -> bool {
    if !ct_lower.starts_with("text/html") || bytes.len() > HTML_FRAGMENT_MAX_BYTES {
        return false;
    }
    let p = plain_prefix(bytes, enc);
    !p.contains("<html") && !p.contains("<!doctype")
}

/// HTML 完整性（末 2KB 有 </html>）：h2 响应无 content-length，中途断流时 collect 仍 Ok，截断页进 keep/ 会 7 天内反复命中=必现白屏；读写两侧都查。
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

/// key → 文件名：稳定 64 位摘要的 16 hex。碰撞由读时 key 校验兜底，只会 miss 不会串页。
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
fn load_disk_entry(
    key: &str,
    // 带会话却拿到未登录页 = 会话已死；匿名页必须能正常命中。
    logged_in: bool,
) -> Option<DiskEntry> {
    load_disk_entry_reason(key, logged_in).ok().map(|(e, _)| e)
}

/// 带拒绝原因的读取，供命中侧按需落日志。第二个元素 = 首页骨架是否过期（SWR 触发）。
fn load_disk_entry_reason(key: &str, logged_in: bool) -> Result<(DiskEntry, bool), &'static str> {
    let path = entry_dir(&page_cache_dir()).join(page_file_name(key));
    let raw = std::fs::read(&path).map_err(|_| "无此条目")?;
    // v6.11 SWR：-k 首页骨架过期不判死——交旧 + 后台静默重拉（过期标记随条目返回）。
    let mut swr_expired = false;
    if key.ends_with("-k") {
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX); // 取不到间隔（含 mtime 在未来：系统时间回拨过）按过期处理，交旧+后台重拉
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
    if (logged_in && is_logged_out_body(&p)) || is_gate_page(&p) {
        return Err("会话已死的未登录页/闸门页"); // 当作 miss（旧版存下的也自愈）
    }
    // keep 条目（首页骨架）必须是完整文档：截断页删文件自愈，别让它活满 7 天。
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

// ---------- 页面快照 SWR（v6.11：过期交旧 + 后台静默重拉，前台零等待） ----------

/// 页面快照后台重拉去重：同键同时只跑一个。
static PAGE_REFRESHING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn page_refresh_done(key: &str) {
    let g = PAGE_REFRESHING.get_or_init(|| Mutex::new(HashSet::new()));
    lock(g).remove(key);
}

/// 过期快照后台静默重拉：带 cookie 拉最新壳，200+完整+会话存活才覆盖；失败 60s 再试直到成功或确认页面不存在，前台零感知。
fn spawn_page_refetch(
    log: &LogFn,
    host: &str,
    key: &str,
    path_q: &str,
    cookie: Option<&str>,
    bucket: &'static str,
    logged_in: bool,
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
            // ① 通道：池内现成通道，没有就拨（单流）
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
            // ② 请求：带 cookie + 按桶协商压缩
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
                // 404/410 = 页面在上游已不存在 → 删该仓库的快照（相对底稿的增量/全量副本），底稿全局共用不动；
                // 下次访问 miss 直连见真实 404，上游误报时直连重拉自动重建
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
            // ③ 门检：完整 + 会话存活，才覆盖（重拉的货不可用，旧壳继续顶）
            let enc = parts
                .headers
                .iter()
                .find(|(k, _)| k.as_str() == "content-encoding")
                .and_then(|(_, v)| v.to_str().ok())
                .map(body_encoding)
                .unwrap_or("identity");
            let plain = super::defuse::decompress_partial(&bytes, enc, 64 << 20);
            if !html_complete(&plain, "identity") {
                (log)(&format!(
                    "[缓存] 页面重拉第 {attempt} 次不完整, 60s 后再试, 旧壳继续"
                ));
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
            let n = plain.len().min(8192);
            let p8 = String::from_utf8_lossy(&plain[..n]).to_lowercase();
            if logged_in && is_logged_out_body(&p8) {
                (log)("[缓存] 页面重拉回未登录页(会话已死), 放弃重拉, 旧壳继续");
                page_refresh_done(&key);
                return;
            }
            // ④ 覆盖入库（全量格式，替换旧骨架）；覆盖后 mtime 复新，过期标记自动解除。
            match write_entry_file(
                &page_cache_dir(),
                &key,
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

/// 测试专用：绕开准入直读磁盘；`page_cache_get_logged_in` 模拟带会话的请求方。
#[cfg(test)]
fn page_cache_get(key: &str) -> Option<axum::response::Response<BoxBody>> {
    read_cached(key, false)
}

#[cfg(test)]
fn page_cache_get_logged_in(key: &str) -> Option<axum::response::Response<BoxBody>> {
    read_cached(key, true)
}

#[cfg(test)]
fn read_cached(key: &str, logged_in: bool) -> Option<axum::response::Response<BoxBody>> {
    let (status, hdrs, body) = load_disk_entry(key, logged_in)?;
    Some(rebuild_cached_response(status, &hdrs, body))
}

// ---------- 内部：容量管理 ----------

/// 攒够上限就整盘重来（缓存可再生，不做淘汰排序）。
static BYTES_SINCE_WIPE: AtomicU64 = AtomicU64::new(0);

fn maybe_wipe_on_growth(dir: &std::path::Path, written: usize) {
    let pending = BYTES_SINCE_WIPE.fetch_add(written as u64, Ordering::Relaxed) + written as u64;
    if pending >= PAGE_CACHE_MAX_BYTES {
        // 并发越线时只让一个去清：抢到计数的动手，其余跳过。
        if BYTES_SINCE_WIPE
            .compare_exchange(pending, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            wipe_pages(dir);
        }
    }
}

/// 条目落盘：tmp 写全量 + rename 原子覆盖，永远存不出半页。
fn write_entry_file(
    dir: &std::path::Path,
    key: &str,
    body: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    let buf = super::entry::encode(key, status, hdrs, body);
    // 记账口径必须等于实际写入量：4 字节长度前缀 + 头部 JSON + 正文。
    maybe_wipe_on_growth(dir, buf.len());
    let pages = entry_dir(dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&pages).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    // 纳秒时钟防极端重入（管家线程本已串行）
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

/// no-store 一律不落盘；private 不拒——GitHub 用它表达浏览器别共享，代理已按会话号哈希分钥匙语义等价，全拒会干掉页面缓存。
fn resp_no_store(headers: &http::HeaderMap) -> bool {
    headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("no-store"))
}

/// 收集体、复判体积与会话污染后投递 Save；响应原样交回浏览器。
/// keep 骨架收集体：门检（类型/体积/no-store/污染/闸门/完整性）后投递 Save，响应原样交回浏览器。
async fn collect_and_submit_keep(
    log: &LogFn,
    key: &str,
    search_page: bool,
    has_session: bool,
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
        // keep 只收 HTML 骨架；JSON/纯文本数据走 XHR 内存缓存（调用方已分流）。
        return hyper::Response::from_parts(parts, body);
    }
    // 嗅探读走的前几帧要拼回，否则交付并缓存半页。
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
            // 污染/闸门检测要先解压才看得见标记。
            let enc = parts
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(body_encoding)
                .unwrap_or("identity");
            // Set-Cookie 只从缓存元数据剔除（回灌旧值会冻 cookie），响应原样给浏览器。
            let cache_hdrs: Vec<Vec<String>> = parts
                .headers
                .iter()
                .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
                .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
                .collect();
            // 不缓存"顶替真实内容"的页：未登录页（会话已死）与各类闸门页。
            let plain = plain_prefix(&bytes, enc);
            // 首页/搜索骨架(-k)跨会话存活 7 天，截断页绝不能入库——宁可这次不缓存。
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
                && !resp_no_store(&parts.headers)
                && html_complete(&bytes, enc)
                && !(has_session && is_logged_out_body(&plain))
                && !is_gate_page(&plain)
                && !is_search_skeleton(key, &bytes, enc);
            if cacheable {
                let status = parts.status.as_u16();
                worker_send(
                    CacheMsg::Save {
                        key: key.to_string(),
                        bytes: bytes.clone(), // Bytes 引用计数浅克隆，跨线程零拷贝
                        status,
                        hdrs: cache_hdrs,
                    },
                    log,
                );
            } else if search_page {
                // 拒存要说清是哪条门拦的，否则"翻页页进不了缓存"查不动。
                let why = if bytes.len() > PAGE_CACHE_MAX_BODY_BYTES {
                    "超 2MB 上限"
                } else if has_session && is_logged_out_body(&plain) {
                    "未登录页(会话已死)"
                } else if is_gate_page(&plain) {
                    "闸门页"
                } else if is_search_skeleton(key, &bytes, enc) {
                    "限流骨架"
                } else {
                    "未知原因"
                };
                (log)(&format!("[缓存] 拒存 {} ({why})", dbg_path(key)));
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
                    dbg_path(key)
                ));
            }
            // 收集失败：无内容可交付，回 502
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

/// 资产入库分支：收集白名单内的 200 体投管家保存（响应原样交回浏览器，不等写盘）。
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
                bytes: bytes.clone(), // Bytes 引用计数浅克隆，跨线程零拷贝
                hdrs: cache_hdrs,
            },
            log,
        ) && super::quiet::first_time("assetnew", &name)
        {
            // 小正文（GitHub 的迷你 chunk 常只有几百字节）按字节显示，别被整数除法抹成 0KB。
            let size = if bytes.len() < 1024 {
                format!("{}B", bytes.len())
            } else {
                format!("{}KB", bytes.len() / 1024)
            };
            (log)(&format!("[资产] 入库 {name} ({size})"));
        }
    }
    hyper::Response::from_parts(parts, protocol::full_body(bytes))
}

/// keep 条目“改标过期”（v6.12）：mtime 拨到保质期线之外——读侧年龄判定自然按过期处理（交旧 + 后台重拉），
/// 重拉覆盖入库后 mtime 复新，标记自动解除。set_times 让“只标不删”不需要任何额外状态。
fn mark_entry_expired(p: &std::path::Path) {
    let Ok(f) = std::fs::OpenOptions::new().write(true).open(p) else {
        return; // 文件已不在（并发自愈删除）：无需标记
    };
    let past =
        std::time::SystemTime::now() - std::time::Duration::from_millis(KEEP_MAX_AGE_MS + 60_000);
    let _ = f.set_times(std::fs::FileTimes::new().set_modified(past));
}

/// 写后失效：前缀匹配，父路径也匹配（写端点多是子路径；至少两级，免得 /o 扫全表）。
/// 返回 (删除的会话条目数, 标记过期的 keep 快照数)，调用方据此决定是否落日志。
fn invalidate_prefix_blocking(dir: &std::path::Path, host: &str, path: &str) -> (usize, usize) {
    let mut prefixes = vec![format!("GET {host}{path}")];
    if let Some(i) = path.rfind('/') {
        let parent = &path[..i];
        if parent.matches('/').count() >= 2 {
            prefixes.push(format!("GET {host}{parent}"));
        }
    }
    let mut deleted = 0usize;
    let mut marked = 0usize;
    // 会话条目在 pages/（照删）；仓库页快照/首页骨架在 keep/（v6.12 起不删——标数据过期：
    // 旧壳照常可交，下次命中走既有 SWR 管道交旧 + 后台重拉，重拉覆盖后自动解除）。
    for sub in ["pages", "keep"] {
        let Ok(rd) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Some(key) = read_page_key(&p) else {
                continue;
            };
            if !prefixes.iter().any(|pre| key.starts_with(pre)) {
                continue;
            }
            if sub == "keep" {
                mark_entry_expired(&p);
                marked += 1;
            } else {
                let _ = std::fs::remove_file(&p);
                deleted += 1;
            }
        }
    }
    (deleted, marked)
}

/// 只读页面文件的 header 段取 key（失效前缀匹配用，不读 body）。
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

/// 写后失效入口：只投消息，磁盘删除交给管家。
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
