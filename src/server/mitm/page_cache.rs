//! 列表页缓存：只缓存 github.com 的列表页（搜索/issue/PR/commit/通知…），其余直通上游。
//! 存储：pages/<hash> = [4B 头长][header JSON][body]，tmp+rename 原子落盘，管家线程串行做磁盘活。
//! 寿命按会话算：连续导航一直有效，空闲超阈值整盘清空；Ctrl+F5 与写操作即时失效。
//! 红线：不做后台 SWR（旧 cookie 重用会被判凭据泄露）；闸门页/未登录页/跨账号不缓存。
use super::BoxBody;
use crate::pool::{now_ms, LogFn};
use crate::server::upstream::{self, Incoming};
use bytes::Bytes;
use http::{Method, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::OnceLock;

/// 会话攒到这么多就整盘清空。
const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）

/// 唯一缓存域：github.com（只收 HTML 列表页）。
const CACHE_HOST: &str = "github.com";

/// 列表页路径段：末段命中，或后跟一个非数字段；数字结尾当详情页。
const LIST_SEGMENTS: &[&str] = &[
    "search", "issues", "pulls", "commits", "releases", "discussions",
    "notifications", "feed", "trending", "explore", "topics",
    "stargazers", "watchers", "forks", "activity",
];

fn is_list_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some(last) = segs.last() else {
        return false;
    };
    // 新建/编辑表单不缓存：里面的防伪 token 可能已被轮换踢掉。
    if matches!(*last, "new" | "edit") {
        return false;
    }
    if LIST_SEGMENTS.contains(last) {
        return true;
    }
    let numeric = last.chars().all(|c| c.is_ascii_digit());
    !numeric && segs.len() >= 2 && LIST_SEGMENTS.contains(&segs[segs.len() - 2])
}

/// 跟班 XHR 前缀：一次搜索页要拖 12 个（10 个 count + 黑鸟计数 + 缓存预热），
/// 每个 250-600ms，是"退回搜索列表慢"的主因。它们不是文档导航，但同样按会话缓存。
const XHR_PREFIXES: &[&str] = &[
    "/search/count",
    "/search/blackbird_count",
    "/search/warm_blackbird_caches",
    "/in-product-messaging/",
    "/github-copilot/chat/repositories_search",
    // 首页的跟班：会变的全在这些接口里（见 README 的首页那节）
    "/dashboard/",
    "/productivity_dashboard/",
    "/_filter/",
    "/_side-panels/",
    "/notifications/indicator",
    "/cmc_internal/",
];

fn is_xhr_path(path: &str) -> bool {
    XHR_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// 首页：纯骨架（会变的全是 XHR），可以跨会话长寿命缓存。
fn is_home_path(path: &str) -> bool {
    path == "/" || path.is_empty()
}

/// 条目落点：键尾 `-k` = 跨会话长寿命（keep/），其余 = 会话存储（pages/）。
/// 会话清盘只清 pages/，所以骨架能在多次会话之间一直活着。
fn entry_dir(dir: &std::path::Path, key: &str) -> std::path::PathBuf {
    if key.ends_with("-k") {
        dir.join("keep")
    } else {
        dir.join("pages")
    }
}

/// 长寿命条目的保质期：GitHub 改版后旧骨架就是坏的，超期当 miss 重取。
const KEEP_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 正文类型闸门：列表页只收 HTML；跟班 XHR 放宽到 JSON/纯文本
/// （`/search/count` 回的是 HTML 片段，黑鸟计数回 JSON）。
fn body_type_allowed(content_type: Option<&str>, xhr: bool) -> bool {
    let Some(ct) = content_type else { return false };
    let ct = ct.trim();
    if xhr {
        ct.starts_with("text/html")
            || ct.starts_with("application/json")
            || ct.starts_with("text/plain")
    } else {
        ct.starts_with("text/html")
    }
}

/// 会话间隔：导航间隔超过它就算离开过 GitHub，下一页面整盘清空。
const IDLE_SESSION_GAP_MS: u64 = 15 * 60 * 1000;

/// 最近一次文档导航的时间（0 = 本进程还没导航过，视为上一会话的残留）。
static LAST_NAV_MS: AtomicU64 = AtomicU64::new(0);
/// 会话号：进程首启用启动时刻，之后换会话 +1，进缓存键——旧条目当场失效。
static SESSION_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 记一次导航；返回是否该换新会话（swap 保证并发只有一个请求换会话）。
fn note_nav() -> bool {
    let now = now_ms();
    let prev = LAST_NAV_MS.swap(now, Ordering::Relaxed);
    if prev == 0 {
        // 进程首启：会话号取启动时刻而非从 1 递增——否则重启后又拿回 -s2，
        // 与上一轮留在盘上的条目撞号，并发标签可能命中旧会话的页面。
        SESSION_EPOCH.store(now.max(1), Ordering::Relaxed);
        return true;
    }
    // 时钟被校正往回跳时差值是 0，也要换会话，否则缓存比预期多活。
    if now < prev || now.saturating_sub(prev) >= IDLE_SESSION_GAP_MS {
        SESSION_EPOCH.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

#[cfg(test)]
fn set_last_nav(ms: u64) {
    LAST_NAV_MS.store(ms, Ordering::Relaxed);
}

/// 任务自带目录：发送时取一次（测试里每个测试一个目录），管家处理时不再读全局——
/// 否则后台消息会落到当时碰巧在用的目录上，把别的测试正在删的目录写炸。
enum CacheMsg {
    Save {
        key: String,
        bytes: Bytes,
        status: u16,
        hdrs: Vec<Vec<String>>,
    },
    /// 写操作成功后的缓存失效（异步，POST 响应路径不等它）。
    Invalidate {
        host: String,
        path: String,
    },
    /// 空闲后重新开始浏览：整盘清空，本次会话从空白积累。
    Purge,
}

// ---------- 对外唯二入口 ----------

/// 文档导航：不论值不值得缓存，都算"还在浏览"（决定会话是否延续）。
fn is_doc_nav(req: &hyper::Request<Incoming>) -> bool {
    req.method() == Method::GET
        && match req.headers().get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
            Some(d) => d == "document",
            None => true, // curl/git 等本机工具无该头：同一用户，命中无妨
        }
}

/// 跟班 XHR：可缓存，但不驱动会话寿命（后台轮询不该把缓存一直养着）。
fn is_xhr_nav(req: &hyper::Request<Incoming>, host: &str) -> bool {
    host == CACHE_HOST && req.method() == Method::GET && is_xhr_path(req.uri().path())
}

/// 值不值得缓存：github.com 的列表页（文档导航）+ 跟班 XHR。
/// Ctrl+F5（`Cache-Control: no-cache`）才直通；`max-age=0` 不拦——浏览器后退/前进
/// 也带这个头，当成强制刷新会让缓存永远命不中（实测确认过）。
fn cache_eligible(req: &hyper::Request<Incoming>, host: &str) -> bool {
    host == CACHE_HOST
        && req.method() == Method::GET
        && !req
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|c| c.contains("no-cache"))
            .unwrap_or(false)
        && (is_xhr_path(req.uri().path())
            || (is_doc_nav(req)
                && (is_list_path(req.uri().path()) || is_home_path(req.uri().path()))))
}

/// 取路由：命中 = 纯本地读（对 GitHub 零请求）；未命中/空闲后第一页 = None，走上游。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    let xhr = is_xhr_nav(req, host);
    if !is_doc_nav(req) && !xhr {
        return None;
    }
    // 新会话：先清上一会话的盘（交给管家，不阻塞本页），这一页必回源。
    // 只有文档导航驱动会话——XHR/轮询不算"你还在逛"。
    if is_doc_nav(req) && note_nav() {
        if !worker_send(CacheMsg::Purge, log) {
            LAST_NAV_MS.store(0, Ordering::Relaxed); // 清盘没投递出去：下次导航重试
        }
        // 首页骨架存在 keep/，清盘动不到它——这一页照样能命中。
        if !is_home_path(req.uri().path()) {
            return None;
        }
    }
    if !cache_eligible(req, host) {
        return None;
    }
    let cookies = req.headers().get("cookie").and_then(|v| v.to_str().ok());
    let key = live_cache_key(req.uri(), host, cookies, upstream::accepts_gzip(req));
    let (status, hdrs, body) = load_disk_entry(&key, session_value(cookies).is_some())?;
    // 命中要留痕：写盘是静默的，没有这行用户无从判断"到底用没用缓存"。
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    // 小正文（跟班 XHR 常只有几十字节）按字节显示，别被整数除法抹成 0KB。
    let size = if body.len() < 1024 {
        format!("{}B", body.len())
    } else {
        format!("{}KB", body.len() / 1024)
    };
    (log)(&format!("[缓存] 命中 {path} ({size} 本地)"));
    Some(rebuild_cached_response(status, &hdrs, body))
}

/// 存路由：不可缓存原样透传；可缓存收集体后投递 Save（主路径零磁盘等待）。
pub(super) async fn cache_put(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    if !cache_eligible(req, host) {
        return resp;
    }
    // 只缓存 200：拦截页回放与 304 空体回放都踩过。
    if resp.status() != StatusCode::OK {
        return resp;
    }
    // Content-Length 粗筛（压缩后大小）；chunked 无该头靠 collect 后的 2MB 上限兜底。
    if let Some(cl) = resp.headers().get("content-length").and_then(|v| v.to_str().ok()) {
        if let Ok(n) = cl.parse::<u64>() {
            if n > PAGE_CACHE_MAX_BODY_BYTES as u64 {
                return resp;
            }
        }
    }
    let xhr = is_xhr_path(req.uri().path());
    let cookies = req.headers().get("cookie").and_then(|v| v.to_str().ok());
    let key = live_cache_key(req.uri(), host, cookies, upstream::accepts_gzip(req));
    let has_session = session_value(cookies).is_some();
    collect_and_submit(log, &key, xhr, has_session, resp).await
}

// ---------- 内部：管家线程 ----------

struct CacheTask {
    dir: std::path::PathBuf,
    msg: CacheMsg,
}

static WORKER_SENDER: OnceLock<mpsc::SyncSender<CacheTask>> = OnceLock::new();

/// 向管家投递任务；筐满/管家不可用 = 丢弃并打日志（缓存写是 best-effort）。
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
                CacheMsg::Invalidate { host, path } => {
                    invalidate_prefix_blocking(dir, &host, &path);
                }
                CacheMsg::Purge => {
                    let n = wipe_pages(dir);
                    (log)(&format!(
                        "[缓存] 空闲超 {} 分钟, 整盘清空 {n} 条(会话#{} 从空白积累)",
                        IDLE_SESSION_GAP_MS / 60_000,
                        SESSION_EPOCH.load(Ordering::Relaxed)
                    ));
                }
            }
        }));
    }
}

/// 整盘清空 pages/tmp，返回条目数；一切错误吞掉（手删目录/文件占用都不断）。
fn wipe_pages(dir: &std::path::Path) -> usize {
    let n = std::fs::read_dir(dir.join("pages"))
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(dir.join("pages"));
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
    let _ = std::fs::create_dir_all(dir.join("pages"));
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
        .body(upstream::full_body(body))
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

fn page_cache_dir() -> std::path::PathBuf {
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

/// 登录态 cookie 的值（GitHub 的两种 user_session 写法）。有值 = 已登录。
fn session_value(cookies: Option<&str>) -> Option<&str> {
    cookies?.split(';').map(str::trim).find_map(|kv| {
        kv.strip_prefix("user_session=")
            .or_else(|| kv.strip_prefix("__Host-user_session_same_site="))
    })
}

/// 账号名（GitHub 稳定下发的 dotcom_user）；只认干净的值，脏值当没有。
fn account_name(cookies: Option<&str>) -> Option<&str> {
    cookies?.split(';').map(str::trim).find_map(|kv| {
        let u = kv.strip_prefix("dotcom_user=")?;
        let sane = !u.is_empty()
            && u.len() <= 64
            && u.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        sane.then_some(u)
    })
}

/// 身份标签：未登录 "-cloggedout"，登录 "-c<账号>"（同机双账号不能串页；
/// 取不到账号时哈希 user_session 值，不能哈希整条 Cookie）。
fn session_fingerprint(cookies: Option<&str>) -> String {
    let Some(sess) = session_value(cookies) else {
        return "-cloggedout".into();
    };
    match account_name(cookies) {
        Some(u) => format!("-c{u}"),
        None => format!("-cs{:016x}", fnv1a(sess)),
    }
}

/// 缓存键 = 方法 + host + 路径/查询 + 身份标签 + 编码标签（纯函数，便于测试）。
/// 当前会话可用的键：会话号拼在纯键外面，旧会话的条目自然查不到。
fn live_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, gzip: bool) -> String {
    let base = page_cache_key(uri, host, cookies, gzip);
    if is_home_path(uri.path()) {
        format!("{base}-k") // 骨架：不带会话号，跨会话复用
    } else {
        format!("{base}-s{}", SESSION_EPOCH.load(Ordering::Relaxed))
    }
}

fn page_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, gzip: bool) -> String {
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let cookie_tag = session_fingerprint(cookies);
    // 编码进键：gzip 那条不能给没声明 gzip 的 curl。
    let enc_tag = if gzip { "-gz" } else { "-id" };
    format!("GET {host}{}{q}{cookie_tag}{enc_tag}", uri.path())
}

/// 这段正文是不是 gzip（决定要不要先解压）。
fn is_gzip_encoding(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("gzip")
}

/// 解压后取前 8KB 并转小写：主站正文恒 gzip，不解压扫不到字面量。
fn plain_prefix(bytes: &[u8], gzip: bool) -> String {
    let plain = if gzip {
        super::defuse::gunzip_partial(bytes, 8192)
    } else {
        bytes[..bytes.len().min(4096)].to_vec()
    };
    String::from_utf8_lossy(&plain).to_lowercase()
}

/// 未登录页：带会话却拿到这类 body = 会话已死，不存也不当命中（防污染）。
fn is_logged_out_body(plain: &str) -> bool {
    plain.contains("logged-out env-") || plain.contains("class=\"logged-out")
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

/// key → 文件名：FNV-1a 64 位散列的 16 hex。碰撞由读时 key 校验兜底。
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn page_file_name(key: &str) -> String {
    format!("{:016x}", fnv1a(key))
}

/// 读单文件条目；损坏/截断/非 200 = None（miss 自愈）。
fn load_disk_entry(
    key: &str,
    // 请求方带不带会话：带会话却拿到未登录页 = 会话已死（污染）；匿名浏览存下的
    // 匿名页必须能正常命中，否则未登录用户的缓存等于全废。
    logged_in: bool,
) -> Option<(
    u16,
    Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    Bytes,
)> {
    let path = entry_dir(&page_cache_dir(), key).join(page_file_name(key));
    let raw = std::fs::read(&path).ok()?;
    // 长寿命条目按 mtime 判保质期（GitHub 改版后旧骨架就是坏的）。
    if key.ends_with("-k") {
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if age > KEEP_MAX_AGE_MS {
            return None;
        }
    }
    if raw.len() < 4 {
        return None;
    }
    let hlen = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let end = 4usize.checked_add(hlen)?;
    if raw.len() < end {
        return None; // 截断：miss 自愈
    }
    let header: serde_json::Value = serde_json::from_slice(&raw[4..end]).ok()?;
    if header.get("key")?.as_str()? != key {
        return None; // 哈希碰撞：不服务错页
    }
    let status = u16::try_from(header.get("status")?.as_u64()?).ok()?;
    if status != 200 {
        return None; // 非 200（拦截页/304）：当 miss
    }
    let headers = header.get("headers")?.as_array()?;
    let mut hdrs: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)> =
        Vec::with_capacity(headers.len());
    for pair in headers {
        let (Some(k), Some(v)) = (pair.get(0)?.as_str(), pair.get(1)?.as_str()) else {
            continue;
        };
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            hdrs.push((name, val));
        }
    }
    let gzip = hdrs.iter().any(|(k, v)| {
        k.as_str() == "content-encoding" && v.to_str().map(is_gzip_encoding).unwrap_or(false)
    });
    let body = &raw[end..];
    let plain = plain_prefix(body, gzip);
    if (logged_in && is_logged_out_body(&plain)) || is_gate_page(&plain) {
        return None; // 会话已死的未登录页 / 闸门页：当作 miss（旧版存下的也自愈）
    }
    Some((status, hdrs, Bytes::copy_from_slice(body)))
}

/// 测试专用：绕开准入直读磁盘。`page_cache_get_logged_in` 模拟带会话的请求方
/// （用来验证"带会话却拿到未登录页"要被当 miss）。
#[cfg(test)]
fn page_cache_get(key: &str) -> Option<axum::response::Response<BoxBody>> {
    read_cached(key, false)
}

#[cfg(test)]
fn page_cache_get_logged_in(key: &str) -> Option<axum::response::Response<BoxBody>> {
    read_cached(key, true)
}

#[cfg(test)]
fn read_cached(
    key: &str,
    logged_in: bool,
) -> Option<axum::response::Response<BoxBody>> {
    let (status, hdrs, body) = load_disk_entry(key, logged_in)?;
    Some(rebuild_cached_response(status, &hdrs, body))
}

// ---------- 内部：容量管理 ----------

/// 攒够上限就整盘重来（缓存可再生，不做淘汰排序）。
static BYTES_SINCE_WIPE: AtomicU64 = AtomicU64::new(0);

fn maybe_wipe_on_growth(dir: &std::path::Path, written: usize) {
    let pending = BYTES_SINCE_WIPE.fetch_add(written as u64, Ordering::Relaxed) + written as u64;
    if pending >= PAGE_CACHE_MAX_BYTES {
        // 并发写同时越线时只让一个去清：谁把计数从 pending 抢回 0 谁动手，
        // 没抢到的直接跳过（删目录是幂等的，但没必要每个线程都遍历一遍）。
        if BYTES_SINCE_WIPE
            .compare_exchange(pending, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            wipe_pages(dir);
        }
    }
}

/// 旧版 cacache 残留（index-v5/content-v2）一次性清掉，防白占磁盘。
static LEGACY_CACHE_PURGED: OnceLock<()> = OnceLock::new();
fn purge_legacy_cache(dir: &std::path::Path) {
    if LEGACY_CACHE_PURGED.set(()).is_ok() {
        for sub in ["index-v5", "content-v2"] {
            let _ = std::fs::remove_dir_all(dir.join(sub));
        }
    }
}

/// 落盘：tmp 写全量 + rename 原子覆盖，永远存不出半页。
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
    purge_legacy_cache(dir);
    maybe_wipe_on_growth(dir, 4 + bytes.len());
    let header = serde_json::json!({
        "key": key,
        "status": status,
        "headers": hdrs,
    });
    let hbytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    let pages = entry_dir(dir, key);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&pages).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(4 + hbytes.len() + bytes.len());
    buf.extend_from_slice(&(hbytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&hbytes);
    buf.extend_from_slice(bytes);
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

/// 收集体、复判（体积/会话污染）后投递 Save；响应原样或重建交给浏览器。
/// `xhr` = 跟班请求：正文类型放宽到 HTML 片段 / JSON / 纯文本。
async fn collect_and_submit(
    log: &LogFn,
    key: &str,
    xhr: bool,
    has_session: bool,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let allowed = body_type_allowed(
        parts.headers.get("content-type").and_then(|v| v.to_str().ok()),
        xhr,
    );
    if !allowed {
        return hyper::Response::from_parts(parts, body);
    }
    // 嗅探读走的前几帧要拼回，否则交付并缓存半页。
    let mut peek: Vec<u8> = Vec::new();
    if let Some(p) = parts.extensions.remove::<super::PeekRaw>() {
        for b in p.0 {
            peek.extend_from_slice(&b);
        }
    }
    // 污染/闸门检测要先解压才看得见标记。
    let gzip = parts
        .headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(is_gzip_encoding)
        .unwrap_or(false);
    // Set-Cookie 只从缓存元数据剔除（回灌旧值会冻 cookie），响应原样给浏览器。
    let cache_hdrs: Vec<Vec<String>> = parts
        .headers
        .iter()
        .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
        .map(|(k, v)| {
            vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()]
        })
        .collect();
    match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => {
            let mut bytes = collected.to_bytes();
            if !peek.is_empty() {
                let mut full = Vec::with_capacity(peek.len() + bytes.len());
                full.extend_from_slice(&peek);
                full.extend_from_slice(&bytes);
                bytes = Bytes::from(full);
            }
            // 不缓存"顶替真实内容"的页：未登录页（会话已死）与各类闸门页。
            let plain = plain_prefix(&bytes, gzip);
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
                && !(has_session && is_logged_out_body(&plain))
                && !is_gate_page(&plain);
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
            }
            let mut rebuilt = hyper::Response::builder()
                .status(parts.status)
                .body(upstream::full_body(bytes))
                .unwrap();
            *rebuilt.headers_mut() = parts.headers;
            rebuilt
        }
        Err(_) => {
            // 收集失败：无内容可交付，回 502
            hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(upstream::full_body(Bytes::from_static(b"page collect failed")))
                .unwrap()
        }
    }
}

/// 写后失效：前缀匹配，父路径也匹配（写端点多是子路径；至少两级，免得 /o 扫全表）。
fn invalidate_prefix_blocking(dir: &std::path::Path, host: &str, path: &str) {
    let mut prefixes = vec![format!("GET {host}{path}")];
    if let Some(i) = path.rfind('/') {
        let parent = &path[..i];
        if parent.matches('/').count() >= 2 {
            prefixes.push(format!("GET {host}{parent}"));
        }
    }
    let Ok(rd) = std::fs::read_dir(dir.join("pages")) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if read_page_key(&p).is_some_and(|k| prefixes.iter().any(|pre| k.starts_with(pre))) {
            let _ = std::fs::remove_file(&p);
        }
    }
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
mod page_cache_tests {
    use super::*;

    /// 目录覆盖是进程级单值，用锁串行；每个测试自己的临时目录。
    static DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn own_dir(tag: &str) -> (std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
        let guard = DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("gitport_pc_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        *CACHE_DIR_OVERRIDE.lock().unwrap_or_else(|p| p.into_inner()) = Some(dir.clone());
        (dir, guard)
    }

    fn log_sink() -> LogFn {
        std::sync::Arc::new(|_: &str| {})
    }

    /// 高熵伪随机体（容量测试要接近原始体积）。
    fn pseudo_body(i: usize, n: usize) -> String {
        let mut s = String::new();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ (i as u64).wrapping_mul(0xFF51_AFD7);
        for _ in 0..n {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s.push(char::from_u32((33 + ((x >> 33) % 90)) as u32).unwrap_or('a'));
        }
        s
    }

    /// pages 目录的条目数与总字节（单文件存储的账）。
    fn pages_stat(dir: &std::path::Path) -> (usize, u64) {
        let Ok(rd) = std::fs::read_dir(dir.join("pages")) else {
            return (0, 0);
        };
        let mut n = 0usize;
        let mut total = 0u64;
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                if md.is_file() {
                    n += 1;
                    total += md.len();
                }
            }
        }
        (n, total)
    }

    fn test_hdrs() -> Vec<Vec<String>> {
        vec![
            vec!["content-type".into(), "text/html; charset=utf-8".into()],
            vec!["etag".into(), "W/\"evict\"".into()],
        ]
    }

    /// A. 读写往返、类型闸门、坏文件自愈、PeekRaw 拼回。
    #[tokio::test]
    async fn roundtrip_gates_and_self_heal() {
        let (dir, _dir_guard) = own_dir("rw");
        let log = log_sink();

        // ① 写入后命中，带 hit 头
        let hdrs = vec![
            vec!["content-type".into(), "text/html; charset=utf-8".into()],
            vec!["etag".into(), "W/\"test\"".into()],
        ];
        persist_page_entry_blocking(
            &dir,
            "GET github.com/search?q=x-cabc",
            b"<html>ok</html>",
            200,
            &hdrs,
        )
        .unwrap();
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 1, "应有一个缓存条目");
        let hit = page_cache_get("GET github.com/search?q=x-cabc").expect("应命中");
        assert_eq!(hit.headers().get("x-gitport-cache").unwrap(), "hit");
        let bytes = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(bytes.as_ref(), b"<html>ok</html>");

        // ② 非 HTML 不缓存（类型闸门在投递前，无后台写无竞速）
        let resp = hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(upstream::full_body(Bytes::from_static(b"{}")))
            .unwrap();
        let _ = collect_and_submit(&log, "GET github.com/api/x", false, false, resp).await;
        assert!(page_cache_get("GET github.com/api/x").is_none(), "非 HTML 不缓存");

        // ②c 正文类型闸门（纯函数，落盘有时序所以不断言命中）
        assert!(body_type_allowed(Some("text/html; charset=utf-8"), false));
        assert!(body_type_allowed(Some("application/json; charset=utf-8"), true));
        assert!(body_type_allowed(Some("text/plain; charset=utf-8"), true));
        assert!(
            !body_type_allowed(Some("application/json; charset=utf-8"), false),
            "列表页不收 JSON"
        );
        assert!(!body_type_allowed(None, true), "没有 content-type 不收");

        // ③ 覆盖写、截断文件、hash 碰撞都不得串页或报错
        let ck = "GET github.com/cover-me";
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v1</html>", 200, &test_hdrs());
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v2</html>", 200, &test_hdrs());
        let hit = page_cache_get(ck).expect("覆盖写后应命中");
        let v = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(v.as_ref(), b"<html>v2</html>", "覆盖写应读到新内容");
        // 截断文件 = miss（写一半被杀）
        let cpath = dir.join("pages").join(page_file_name(ck));
        std::fs::write(&cpath, b"\x10\x00\x00\x00short").unwrap();
        assert!(page_cache_get(ck).is_none(), "截断文件应判 miss");
        // 文件名确定性：同 key 永远同文件（跨重启可复现），异 key 必异文件
        assert_eq!(page_file_name(ck), page_file_name(ck));
        assert_ne!(page_file_name(ck), page_file_name("GET github.com/other"));
        // 碰撞防护：文件里存的 key 与请求 key 不符 → 拒服，不串页
        let bad_path = dir.join("pages").join(page_file_name("GET github.com/spoof"));
        let bad_hdr = serde_json::to_vec(&serde_json::json!({
            "key": "GET github.com/someone-else",
            "status": 200,
            "headers": test_hdrs(),
            "cachedAt": now_ms(),
        }))
        .unwrap();
        let mut bad_buf = (bad_hdr.len() as u32).to_be_bytes().to_vec();
        bad_buf.extend_from_slice(&bad_hdr);
        bad_buf.extend_from_slice(b"<html>x</html>");
        std::fs::write(&bad_path, &bad_buf).unwrap();
        assert!(
            page_cache_get("GET github.com/spoof").is_none(),
            "header key 不符应拒服（防串页）"
        );

        // ④ 嗅探前缀必须拼回，否则交付并缓存半页
        let mut sniffed = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(upstream::full_body(Bytes::from_static(b"world</html>")))
            .unwrap();
        sniffed
            .extensions_mut()
            .insert(super::super::PeekRaw(vec![Bytes::from_static(
                b"<html>hello ",
            )]));
        let out =
            collect_and_submit(&log, "GET github.com/peek", false, false, sniffed).await;
        let body = http_body_util::BodyExt::collect(out.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            body.as_ref(),
            b"<html>hello world</html>",
            "嗅探前缀丢失 = 交付半页"
        );

        // ⑤b 首页骨架（-k）跨会话存活：会话清盘只清 pages/
        let home = "GET github.com/-cloggedout-gz-k";
        let _ = persist_page_entry_blocking(&dir, home, b"<html>home</html>", 200, &test_hdrs());
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/issues-s1",
            b"<html>i</html>",
            200,
            &test_hdrs(),
        );
        wipe_pages(&dir);
        assert!(page_cache_get(home).is_some(), "首页骨架必须跨会话存活");
        assert!(
            page_cache_get("GET github.com/issues-s1").is_none(),
            "会话条目应被清掉"
        );

        // ⑤ gzip 条目读回：头/正文仍是压缩态，且读侧的解压判断不瞎
        // （只测"解压函数认得出来"不够，得把存→读整条链走一遍）
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, b"<html><body>list</body></html>").unwrap();
        let gz = enc.finish().unwrap();
        let gz_hdrs = vec![
            vec!["content-type".into(), "text/html; charset=utf-8".into()],
            vec!["content-encoding".into(), "gzip".into()],
        ];
        let _ = persist_page_entry_blocking(&dir, "GET github.com/issues-gz", &gz, 200, &gz_hdrs);
        let hit = page_cache_get("GET github.com/issues-gz").expect("gzip 条目应命中");
        assert_eq!(
            hit.headers().get("content-encoding").unwrap(),
            "gzip",
            "编码头必须原样带回"
        );
        let back = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(back.as_ref(), gz.as_slice(), "正文应原样是压缩字节");
        // 同一份压缩字节里装的若是闸门页，读侧也要认出来（第二道防线）
        let mut gate = b"<html><head><title>Verify your two-factor authentication</title></head><body>"
            .to_vec();
        gate.extend_from_slice(&vec![b'g'; 4000]);
        let mut enc2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc2, &gate).unwrap();
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/issues-gz-gate",
            &enc2.finish().unwrap(),
            200,
            &gz_hdrs,
        );
        assert!(
            page_cache_get("GET github.com/issues-gz-gate").is_none(),
            "读侧也要认出压缩的闸门页"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B. 超量：一个会话攒过上限就整盘重来（不排序、不逐个淘汰）。
    #[test]
    fn capacity_wipe_on_growth() {
        let (dir, _dir_guard) = own_dir("cap");
        for i in 0..3 {
            let body = pseudo_body(i, 1200);
            let _ = persist_page_entry_blocking(
                &dir,
                &format!("GET github.com/p{i}"),
                body.as_bytes(),
                200,
                &test_hdrs(),
            );
        }
        assert_eq!(pages_stat(&dir).0, 3, "前提：攒了 3 条");
        maybe_wipe_on_growth(&dir, PAGE_CACHE_MAX_BYTES as usize);
        assert_eq!(pages_stat(&dir).0, 0, "超量应整盘清空");

        // ⑥ 清空：pages 条目全没（page_cache_clear 是测试专用工具）
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/again",
            b"<html>a</html>",
            200,
            &test_hdrs(),
        );
        assert!(page_cache_get("GET github.com/again").is_some(), "前提：有条目");
        page_cache_clear();
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 0, "清空后条目应为零");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C. 键的语义（身份 / 编码 / 会话边界）、写后失效、未登录页防污染、闸门页。
    #[tokio::test]
    async fn keys_invalidation_and_pollution() {
        let (dir, _dir_guard) = own_dir("key");
        let log = log_sink();

        // ⑧ 会话边界：空闲超阈值（或进程第一页）→ 清盘并从空白重来；紧跟的请求不再清
        set_last_nav(0);
        assert!(note_nav(), "进程启动/空闲后的第一页必须判为新会话");
        assert!(!note_nav(), "紧跟其后的第二页不该再清盘（swap 只让第一个请求拿到旧时间戳）");
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/old-session",
            b"<html>o</html>",
            200,
            &test_hdrs(),
        );
        assert!(page_cache_get("GET github.com/old-session").is_some(), "前提：有旧条目");
        assert_eq!(wipe_pages(&dir), 1, "应清掉上一会话的 1 条");
        assert_eq!(wipe_pages(&dir), 0, "空目录再清一次不得报错");
        assert!(
            page_cache_get("GET github.com/old-session").is_none(),
            "清盘后上一会话的条目不得再命中"
        );

        // ⑨ 写后失效：同路径前缀删除
        let sk = "GET github.com/settings/profile-cabc";
        let _ = persist_page_entry_blocking(&dir, sk, b"<html>s</html>", 200, &test_hdrs());
        assert!(page_cache_get(sk).is_some(), "前提：条目已缓存");
        invalidate_after_write(&log, "github.com", "/settings/profile");
        invalidate_prefix_blocking(&dir, "github.com", "/settings/profile");
        assert!(page_cache_get(sk).is_none(), "写操作后磁盘条目应失效");

        // ⑨b 子路径写端点：评论后议题页失效
        let issue_key = "GET github.com/o/r/issues/5-calice-gz";
        let other_key = "GET github.com/o/r/pulls/9-calice-gz";
        for k in [issue_key, other_key] {
            let _ = persist_page_entry_blocking(
                &dir,
                k,
                b"<html>i</html>",
                200,
                &test_hdrs(),
            );
        }
        invalidate_prefix_blocking(&dir, "github.com", "/o/r/issues/5/comment");
        assert!(
            page_cache_get(issue_key).is_none(),
            "评论后议题页必须失效（父路径匹配）"
        );
        assert!(page_cache_get(other_key).is_some(), "无关页面不得被牵连");

        // ⑩ 身份标签：账号进键（同机两个账号不得共享页面）
        let a = session_fingerprint(Some("user_session=abc; dotcom_user=alice"));
        let a2 = session_fingerprint(Some("user_session=zzz; dotcom_user=alice"));
        let b = session_fingerprint(Some("dotcom_user=bob; user_session=q"));
        assert_eq!(a, "-calice", "登录态标签带账号名");
        assert_eq!(a, a2, "同账号轮换 user_session 不换键");
        assert_ne!(a, b, "不同账号必须分键（A 的设置页不能给 B）");
        assert_eq!(session_fingerprint(None), "-cloggedout", "未登录固定标签");
        assert_eq!(
            session_fingerprint(Some("_gh_sess=r1; _octo=GH1")),
            "-cloggedout",
            "只有 _gh_sess 不算登录"
        );
        // 拿不到 dotcom_user：退回 session 值哈希，仍按账号分开（轮换只损失命中）
        let h1 = session_fingerprint(Some("user_session=abc"));
        let h2 = session_fingerprint(Some("user_session=xyz"));
        assert!(h1.starts_with("-cs") && h1 != h2, "{h1} / {h2}");
        // _gh_sess 每个响应都轮换：兜底哈希只取 user_session 值，键必须稳住
        assert_eq!(
            session_fingerprint(Some("user_session=abc; _gh_sess=r1; _octo=GH1.1")),
            session_fingerprint(Some("user_session=abc; _gh_sess=r2; _octo=GH1.1")),
            "轮换 _gh_sess 不得换键（否则每请求一个新的缓存文件）"
        );
        // 键里同时带身份与编码：curl 与浏览器不会互串
        let uri: http::Uri = "https://github.com/settings/profile?tab=x".parse().unwrap();
        let alice = "user_session=s1; dotcom_user=alice";
        let bob = "user_session=s2; dotcom_user=bob";
        let gz = page_cache_key(&uri, "github.com", Some(alice), true);
        let id = page_cache_key(&uri, "github.com", Some(alice), false);
        assert!(gz.contains("?tab=x") && gz.ends_with("-calice-gz"), "{gz}");
        assert!(id.ends_with("-calice-id"), "{id}");
        assert_ne!(
            gz,
            page_cache_key(&uri, "github.com", Some(bob), true),
            "同机换账号必须换键"
        );
        // ⑩a 首页键带 -k（不带会话号，跨会话复用）
        let home_uri: http::Uri = "https://github.com/".parse().unwrap();
        assert!(
            live_cache_key(&home_uri, "github.com", Some(alice), true).ends_with("-k"),
            "首页骨架键必须带 -k"
        );

        // ⑩b 换会话后旧键必须失效（不依赖清盘是否成功）
        let k_before = live_cache_key(&uri, "github.com", Some(alice), true);
        set_last_nav(0);
        assert!(note_nav(), "伪造一次空闲");
        let k_after = live_cache_key(&uri, "github.com", Some(alice), true);
        assert_ne!(k_before, k_after, "换会话后同一页面必须是新键");
        // ⑩c 两次"进程首启"的会话号必须不同：否则重启后又拿回 -s2，与上一轮的盘上条目撞号
        let k1 = {
            set_last_nav(0);
            note_nav();
            live_cache_key(&uri, "github.com", None, true)
        };
        std::thread::sleep(std::time::Duration::from_millis(3));
        let k2 = {
            set_last_nav(0);
            note_nav();
            live_cache_key(&uri, "github.com", None, true)
        };
        assert_ne!(k1, k2, "重启后会话号不得与上一轮相同");

        // ⑪ 未登录页不入缓存（带会话却拿到登录页 = 会话已死）
        let poisoned = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(upstream::full_body(Bytes::from_static(
                b"<html><body class=\"logged-out env-production\">sign in</body></html>",
            )))
            .unwrap();
        let _ = collect_and_submit(&log, "GET github.com/-cauthed-poison", false, true, poisoned).await;
        assert!(
            page_cache_get_logged_in("GET github.com/-cauthed-poison").is_none(),
            "会话死亡期间的未登录页不得进缓存"
        );

        // ⑪d 匿名页双向判定：未登录浏览存下的页面，匿名请求必须能命中；
        // 同一份正文被带会话的请求拿到才算污染。少了前者，未登录用户的缓存全废
        // （线上症状：缓存写进去了却永远不命中）。
        let anon = b"<html><body class=\"logged-out env-production\">results</body></html>";
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/search-cloggedout-gz",
            anon,
            200,
            &test_hdrs(),
        );
        assert!(
            page_cache_get("GET github.com/search-cloggedout-gz").is_some(),
            "匿名页必须能命中（否则未登录用户的缓存等于全废）"
        );
        assert!(
            page_cache_get_logged_in("GET github.com/search-cloggedout-gz").is_none(),
            "带会话却拿到未登录页 = 会话已死，仍要当 miss"
        );

        // ⑪b gzip 正文：不解压就永远看不到标记（主站正文恒 gzip，旧版这道守卫等于没有）
        let mut html = b"<html><body class=\"logged-out env-production\">".to_vec();
        html.extend_from_slice(&vec![b'x'; 6000]);
        html.extend_from_slice(b"</body></html>");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &html).unwrap();
        let gzbody = enc.finish().unwrap();
        assert!(
            !is_logged_out_body(&plain_prefix(&gzbody, false)),
            "压缩体裸扫扫不到——这就是旧版失效的原因"
        );
        assert!(
            is_logged_out_body(&plain_prefix(&gzbody, true)),
            "解压后必须认出未登录页"
        );
        let poisoned_gz = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .header("content-encoding", "gzip")
            .body(upstream::full_body(Bytes::from(gzbody)))
            .unwrap();
        let _ = collect_and_submit(
            &log,
            "GET github.com/-cauthed-gz-poison", false,
            true,
            poisoned_gz,
        )
        .await;
        assert!(
            page_cache_get_logged_in("GET github.com/-cauthed-gz-poison").is_none(),
            "gzip 未登录页同样不得入缓存"
        );

        // ⑪c 闸门页：按请求 URL 回 200，写入侧与读侧都必须拦
        let gate_html = b"<html><head><title>Verify your two-factor authentication (2FA) settings</title></head><body><h1>Verify your two-factor authentication (2FA) settings</h1><p>This is a one-time verification of your recently configured 2FA credentials.</p></body></html>";
        assert!(
            is_gate_page(&plain_prefix(gate_html, false)),
            "2FA 验证页必须识别"
        );
        assert!(
            !is_gate_page(&plain_prefix(
                b"<html><body class=\"logged-in env-production\">repo</body></html>",
                false
            )),
            "普通页面不得误判"
        );
        // 写入侧：与登录态无关，一律不存
        let gate = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(upstream::full_body(Bytes::from_static(gate_html)))
            .unwrap();
        let _ = collect_and_submit(&log, "GET github.com/o/r-gate", false, false, gate).await;
        assert!(
            page_cache_get("GET github.com/o/r-gate").is_none(),
            "闸门页不得入缓存"
        );
        // 读侧：已存下的闸门页命中时也判 miss
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/o/r-old-gate",
            gate_html,
            200,
            &test_hdrs(),
        );
        assert!(
            page_cache_get_logged_in("GET github.com/o/r-old-gate").is_none(),
            "旧的闸门页条目必须当 miss"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// D. 手删缓存目录：读 miss、写自愈重建、各类删除/淘汰不得报错或停摆。
    #[test]
    fn survives_manual_cache_delete() {
        let (dir, _dir_guard) = own_dir("manual");
        let k = "GET github.com/manual";
        let _ = persist_page_entry_blocking(&dir, k, b"<html>m</html>", 200, &test_hdrs());
        assert!(page_cache_get(k).is_some(), "前提：有条目");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(page_cache_get(k).is_none(), "目录没了 = miss，不能报错");
        invalidate_prefix_blocking(&dir, "github.com", "/manual"); // 不得 panic
        maybe_wipe_on_growth(&dir, 1); // 不得 panic
        wipe_pages(&dir); // 不得 panic
        let _ = persist_page_entry_blocking(&dir, k, b"<html>m2</html>", 200, &test_hdrs());
        assert!(page_cache_get(k).is_some(), "写入应自愈重建目录");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// E. 只缓存列表页：列表命中，仓库首页/文件/详情/设置一律不缓存。
    #[test]
    fn list_path_gate() {
        for p in [
            "/search",
            "/o/r/issues",
            "/o/r/pulls",
            "/o/r/commits/main",
            "/o/r/issues/assigned",
            "/o/r/releases",
            "/notifications",
            "/trending/python",
            "/topics/rust",
            "/o/r/stargazers",
        ] {
            assert!(is_list_path(p), "{p} 应判为列表页");
        }
        for p in [
            "/",
            "/o/r",
            "/o/r/blob/main/README.md",
            "/o/r/tree/main/src",
            "/o/r/issues/5",
            "/o/r/pull/123",
            "/o/r/commit/abc123",
            "/o/r/releases/tag/v1.0.0",
            "/o/r/issues/new", // 表单页：防伪 token 会被轮换踢掉
            "/o/r/releases/new",
            "/o/r/issues/5/edit",
            "/settings/profile",
            "/u/r/main/f.txt",
        ] {
            assert!(!is_list_path(p), "{p} 不该缓存");
        }
        // 跟班 XHR 前缀：列表页规则管不着它们，得单独放行
        for p in [
            "/search/count",
            "/search/blackbird_count",
            "/search/warm_blackbird_caches",
            "/in-product-messaging/",
            "/github-copilot/chat/repositories_search",
        ] {
            assert!(is_xhr_path(p), "{p} 应判为跟班 XHR");
        }
        for p in ["/", "/o/r", "/o/r/issues", "/search"] {
            assert!(!is_xhr_path(p), "{p} 不该判为跟班 XHR");
        }
        // 首页：纯骨架，单独放行
        assert!(is_home_path("/"));
        assert!(is_home_path(""));
        assert!(!is_home_path("/feed"));
        assert!(!is_home_path("/o/r"));
    }

}
