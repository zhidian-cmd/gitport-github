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

/// 搜索列表页：GitHub 翻页是 React 软导航（sec-fetch-dest: empty）而非文档
/// 导航——按导航形态收会导致翻页页永远不入缓存（2026-10-27 对照实验：同 URL
/// document 入库、empty 被拒），来回翻页、从仓库退回全靠现拉转圈。
/// 存取两侧同步放行；会话清盘仍只认文档导航（软导航不续命，与 XHR 同待遇）。
fn is_search_page(path: &str) -> bool {
    path == "/search"
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
    cache_eligible_rules(
        host,
        req.method(),
        req.uri().path(),
        req.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        is_doc_nav(req),
    )
}

/// 准入规则的纯函数形态：拆出来才测得到「Ctrl+F5 直通」这条分支。
fn cache_eligible_rules(
    host: &str,
    method: &Method,
    path: &str,
    cache_control: Option<&str>,
    doc_nav: bool,
) -> bool {
    host == CACHE_HOST
        && method == Method::GET
        && !cache_control
            .map(|c| c.contains("no-cache"))
            .unwrap_or(false)
        && (is_xhr_path(path)
            || is_search_page(path)
            || (doc_nav && (is_list_path(path) || is_home_path(path))))
}

/// 取路由：命中 = 纯本地读（对 GitHub 零请求）；未命中/空闲后第一页 = None，走上游。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    let xhr = is_xhr_nav(req, host);
    let search_page = is_search_page(req.uri().path());
    if !is_doc_nav(req) && !xhr && !search_page {
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
    let variant = if search_page {
        search_variant(req.headers().get("accept").and_then(|v| v.to_str().ok()))
    } else {
        ""
    };
    let key = live_cache_key(req.uri(), host, cookies, upstream::accepts_gzip(req), variant);
    let (status, hdrs, body) = match load_disk_entry_reason(&key, session_value(cookies).is_some())
    {
        Ok(v) => v,
        Err(reason) => {
            // 盘上有条目却被读侧拒绝 = "存了却命中不了"：落日志才排查得动。
            if search_page && reason != "无此条目" {
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| req.uri().path().to_string());
                (log)(&format!("[缓存] 命中失败 {path} ({reason})"));
            }
            return None;
        }
    };
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
    // 拒存日志只认主站 /search：全量打会淹没日志（POST/非列表页每请求都走这里）。
    // 静默拒存曾让"翻页页为什么进不了缓存"排查了一整晚（2026-10-28）。
    let search_dbg = host == CACHE_HOST
        && req.method() == Method::GET
        && req.uri().path().starts_with("/search");
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    if !cache_eligible(req, host) {
        if search_dbg {
            (log)(&format!("[缓存] 拒存 {path_q} (非准入)"));
        }
        return resp;
    }
    // 只缓存 200：拦截页回放与 304 空体回放都踩过。
    // 304 不落日志：那是浏览器条件请求命中了 GitHub 校验器、拿自己本地那份渲染，
    // 每页十几个计数 XHR 全走这条路——留痕只会刷屏（2026-10-28 实测 21 条拒存 20 条是它）。
    if resp.status() != StatusCode::OK {
        if search_dbg && resp.status() != StatusCode::NOT_MODIFIED {
            (log)(&format!(
                "[缓存] 拒存 {path_q} (上游状态 {})",
                resp.status().as_u16()
            ));
        }
        return resp;
    }
    // Content-Length 粗筛（压缩后大小）；chunked 无该头靠 collect 后的 2MB 上限兜底。
    if let Some(cl) = resp.headers().get("content-length").and_then(|v| v.to_str().ok()) {
        if let Ok(n) = cl.parse::<u64>() {
            if n > PAGE_CACHE_MAX_BODY_BYTES as u64 {
                if search_dbg {
                    (log)(&format!("[缓存] 拒存 {path_q} (声明体积超上限)"));
                }
                return resp;
            }
        }
    }
    let xhr = is_xhr_path(req.uri().path());
    let cookies = req.headers().get("cookie").and_then(|v| v.to_str().ok());
    let search_page = is_search_page(req.uri().path());
    // 分钥匙以实际 Content-Type 为准：GitHub 按请求 Accept 回 JSON 或 HTML，
    // 两种正文同 URL 不同物（存侧不区分会导致 HTML 导航拿到 JSON）。
    let ct_lower = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    let variant = if search_page {
        if ct_lower.starts_with("application/json") {
            "-json"
        } else {
            "-html"
        }
    } else {
        ""
    };
    let key = live_cache_key(req.uri(), host, cookies, upstream::accepts_gzip(req), variant);
    let has_session = session_value(cookies).is_some();
    collect_and_submit(log, &key, xhr, search_page, has_session, resp).await
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

/// 拒存日志用：键去掉 "GET host" 前缀，露出路径+查询。
fn dbg_path(key: &str) -> &str {
    key.split_once(' ').map(|(_, rest)| rest).unwrap_or(key)
}

/// 请求方要不要 JSON：GitHub 搜索页按 Accept 内容协商——`application/json`
/// 回 JSON（React 软导航的数据请求），否则回 HTML（2026-10-28 实测）。
/// 两种正文同 URL 不同物，必须分钥匙存取，否则 HTML 导航会拿到 JSON。
fn accept_wants_json(accept: Option<&str>) -> bool {
    let Some(a) = accept else {
        return false;
    };
    let a = a.to_ascii_lowercase();
    a.contains("application/json") && !a.contains("text/html")
}

/// 搜索页的内容分钥匙：存侧以实际 Content-Type 为准（-html / -json），
/// 取侧按请求 Accept 预测——预测错了只是 miss 重取，不会拿错正文。
fn search_variant(accept: Option<&str>) -> &'static str {
    if accept_wants_json(accept) {
        "-json"
    } else {
        "-html"
    }
}

/// 缓存键 = 方法 + host + 路径/查询 + 身份标签 + 编码标签（纯函数，便于测试）。
/// 当前会话可用的键：会话号拼在纯键外面，旧会话的条目自然查不到。
fn live_cache_key(
    uri: &http::Uri,
    host: &str,
    cookies: Option<&str>,
    gzip: bool,
    variant: &str,
) -> String {
    let base = page_cache_key(uri, host, cookies, gzip);
    if is_home_path(uri.path()) {
        format!("{base}-k") // 骨架：不带会话号，跨会话复用
    } else {
        format!("{base}{variant}-s{}", SESSION_EPOCH.load(Ordering::Relaxed))
    }
}

fn page_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, gzip: bool) -> String {
    let q = uri
        .query()
        .map(|q| normalize_query(uri.path(), q))
        .unwrap_or_default();
    let cookie_tag = session_fingerprint(cookies);
    // 编码进键：gzip 那条不能给没声明 gzip 的 curl。
    let enc_tag = if gzip { "-gz" } else { "-id" };
    format!("GET {host}{}{q}{cookie_tag}{enc_tag}", uri.path())
}

/// /search 查询串归一化：去掉 p=1（与无 p 同页——GitHub 翻页链接两种形态都有，
/// 实测缓存目录曾同时躺这两个条目）+ 参数按键名排序（防将来重排）。
/// 只对 /search 生效：其他路径的参数顺序保持原样，个别接口参数顺序有语义。
fn normalize_query(path: &str, q: &str) -> String {
    if path != "/search" {
        return format!("?{q}");
    }
    let mut pairs: Vec<&str> = q.split('&').filter(|s| !s.is_empty()).collect();
    pairs.retain(|s| *s != "p=1");
    pairs.sort_unstable();
    if pairs.is_empty() {
        String::new()
    } else {
        format!("?{}", pairs.join("&"))
    }
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

/// GitHub blackbird 限流降级页:搜索返回"无结果"骨架(26KB 上下,缺结果数据
/// 载体 embeddedData)。入缓存会被刷新反复命中,把一次性降级固化成"一直坏"
/// (2026-10-27 实证:dev-sidecar 与 github 两词的条目均无 embeddedData,
/// 而正常页——含真实零结果页——恒有)。骨架不存,刷新回源,恢复即自愈。
fn is_search_skeleton(key: &str, bytes: &[u8], gzip: bool) -> bool {
    if !key.contains("/search?") {
        return false;
    }
    if key.contains("-json-") {
        return false; // JSON 正文本就没有 HTML 结果载体，骨架判定只对 HTML 分支生效
    }
    let plain = if gzip {
        super::defuse::gunzip_partial(bytes, PAGE_CACHE_MAX_BODY_BYTES)
    } else {
        bytes.to_vec()
    };
    let text = String::from_utf8_lossy(&plain);
    !text.contains("react-app.embeddedData")
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

/// 磁盘条目反序列化形态：状态码 + 规范化响应头 + 压缩体。
type DiskEntry = (
    u16,
    Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    Bytes,
);

/// 读单文件条目；损坏/截断/非 200 = None（miss 自愈）。
/// 仅测试使用：生产路径走 load_disk_entry_reason（带拒绝原因）。
#[cfg(test)]
fn load_disk_entry(
    key: &str,
    // 请求方带不带会话：带会话却拿到未登录页 = 会话已死（污染）；匿名浏览存下的
    // 匿名页必须能正常命中，否则未登录用户的缓存等于全废。
    logged_in: bool,
) -> Option<DiskEntry> {
    load_disk_entry_reason(key, logged_in).ok()
}

/// 带拒绝原因的读取："存了却命中不了"曾只能靠猜（2026-10-28 排查翻页缓存），
/// 原因交给命中侧按需落日志。
fn load_disk_entry_reason(
    key: &str,
    logged_in: bool,
) -> Result<DiskEntry, &'static str> {
    let path = entry_dir(&page_cache_dir(), key).join(page_file_name(key));
    let raw = std::fs::read(&path).map_err(|_| "无此条目")?;
    // 长寿命条目按 mtime 判保质期（GitHub 改版后旧骨架就是坏的）。
    if key.ends_with("-k") {
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if age > KEEP_MAX_AGE_MS {
            return Err("长寿命条目过期");
        }
    }
    if raw.len() < 4 {
        return Err("文件过短");
    }
    let Some(hlen_bytes) = raw.get(0..4) else {
        return Err("文件过短");
    };
    let hlen = u32::from_be_bytes([hlen_bytes[0], hlen_bytes[1], hlen_bytes[2], hlen_bytes[3]])
        as usize;
    let end = 4usize.checked_add(hlen).ok_or("头部长度溢出")?;
    if raw.len() < end {
        return Err("条目截断"); // miss 自愈
    }
    let header: serde_json::Value =
        serde_json::from_slice(&raw[4..end]).map_err(|_| "元数据损坏")?;
    if header.get("key").and_then(|k| k.as_str()) != Some(key) {
        return Err("哈希碰撞"); // 不服务错页
    }
    let Some(st) = header.get("status").and_then(|v| v.as_u64()) else {
        return Err("状态码损坏");
    };
    let status = u16::try_from(st).map_err(|_| "状态码损坏")?;
    if status != 200 {
        return Err("条目非 200"); // 拦截页/304：当 miss
    }
    let Some(headers) = header.get("headers").and_then(|v| v.as_array()) else {
        return Err("头部字段损坏");
    };
    let mut hdrs: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)> =
        Vec::with_capacity(headers.len());
    for pair in headers {
        let (Some(k), Some(v)) = (
            pair.get(0).and_then(|x| x.as_str()),
            pair.get(1).and_then(|x| x.as_str()),
        ) else {
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
        return Err("会话已死的未登录页/闸门页"); // 当作 miss（旧版存下的也自愈）
    }
    Ok((status, hdrs, Bytes::copy_from_slice(body)))
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
    let header = serde_json::json!({
        "key": key,
        "status": status,
        "headers": hdrs,
    });
    let hbytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    // 记账口径必须等于实际写入量：4 字节长度前缀 + 头部 JSON + 正文。
    // 只算正文字节会让 200MB 上限实际超出一两 MB。
    maybe_wipe_on_growth(dir, 4 + hbytes.len() + bytes.len());
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
    let mut allowed = body_type_allowed(Some(&ct), xhr);
    if !allowed && search_page
        && (ct.starts_with("text/html") || ct.starts_with("application/json"))
    {
        // 搜索页的软导航按 Accept 协商出 JSON 或 HTML（2026-10-28 实测），
        // 两者都是正经正文，分钥匙后照存。
        allowed = true;
    }
    if !allowed {
        if key.contains("/search?") {
            (log)(&format!(
                "[缓存] 拒存 {} (正文类型不符: {})",
                dbg_path(key),
                if ct.is_empty() { "无" } else { &ct }
            ));
        }
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
                && !is_gate_page(&plain)
                && !is_search_skeleton(key, &bytes, gzip);
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
            } else if key.contains("/search?") {
                // 拒存要说清是哪条门拦的，否则"翻页页进不了缓存"查不动。
                let why = if bytes.len() > PAGE_CACHE_MAX_BODY_BYTES {
                    "超 2MB 上限"
                } else if has_session && is_logged_out_body(&plain) {
                    "未登录页(会话已死)"
                } else if is_gate_page(&plain) {
                    "闸门页"
                } else if is_search_skeleton(key, &bytes, gzip) {
                    "限流骨架"
                } else {
                    "未知原因"
                };
                (log)(&format!("[缓存] 拒存 {} ({why})", dbg_path(key)));
            }
            let mut rebuilt = hyper::Response::builder()
                .status(parts.status)
                .body(upstream::full_body(bytes))
                .unwrap();
            *rebuilt.headers_mut() = parts.headers;
            rebuilt
        }
        Err(_) => {
            if key.contains("/search?") {
                (log)(&format!(
                    "[缓存] 拒存 {} (正文收集失败: 上游流中断)",
                    dbg_path(key)
                ));
            }
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
mod page_cache_tests;
