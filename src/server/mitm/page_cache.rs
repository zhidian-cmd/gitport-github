//! 页面缓存：github.com 列表页/首页骨架按会话分存（pages/<hash>），闸门页/未登录页/跨账号不缓存；
//! 仓库页不缓存（零转换直出——html 永远新鲜；跨发版冻结资产引用 = 旧 JS 配新数据，实测白屏）；
//! githubassets 资产按 URL 入库本地透明回放（immutable 一存永逸，时代中立：URL 即内容指纹）。
use super::{asset_store, BoxBody};
use crate::server::protocol::{self, Incoming};
use crate::server::upstream;
use crate::util::{lock, now_ms, LogFn};
use bytes::Bytes;
use http::{Method, StatusCode};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};

/// 会话攒到这么多就整盘清空。
const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）

/// 唯一缓存域：github.com（只收 HTML 列表页）。
const CACHE_HOST: &str = "github.com";

/// 列表页路径段：末段命中，或后跟一个非数字段；数字结尾当详情页。
const LIST_SEGMENTS: &[&str] = &[
    "search",
    "issues",
    "pulls",
    "commits",
    "releases",
    "discussions",
    "notifications",
    "feed",
    "trending",
    "explore",
    "topics",
    "stargazers",
    "watchers",
    "forks",
    "activity",
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

/// 跟班 XHR 前缀：一次搜索页要拖十几个，是“退回搜索列表慢”的主因，同样按会话缓存。
const XHR_PREFIXES: &[&str] = &[
    "/search/count",
    "/search/blackbird_count",
    "/search/warm_blackbird_caches",
    "/search/custom_scopes",
    "/in-product-messaging/",
    "/github-copilot/chat/repositories_search",
    "/conduit/",
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

/// 搜索列表页：翻页走 React 软导航，必须按路径认而不是按导航形态认，否则翻页永远不入缓存。
fn is_search_page(path: &str) -> bool {
    path == "/search"
}

/// 键尾 -k 进跨会话 keep/，其余进会话目录 pages/（清盘只清后者）；v6.9 资产缓存已物理删除。
fn entry_dir(dir: &std::path::Path, key: &str) -> std::path::PathBuf {
    if key.ends_with("-k") {
        dir.join("keep")
    } else {
        dir.join("pages")
    }
}

/// 长寿命条目的保质期：GitHub 改版后旧骨架就是坏的，超期当 miss 重取。
const KEEP_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 正文类型闸门：列表页只收 HTML，跟班 XHR 放宽到 JSON/纯文本。
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
        // 会话号取启动时刻：从 1 递增会在重启后与盘上旧条目撞号。
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
    /// 写操作成功后的缓存失效（异步，POST 响应路径不等它）。
    Invalidate { host: String, path: String },
    /// 空闲后重新开始浏览：整盘清空，本次会话从空白积累。
    Purge,
}

// ---------- 对外唯二入口 ----------

/// 文档导航：不论值不值得缓存，都算"还在浏览"（决定会话是否延续）。
fn is_doc_nav<B>(req: &hyper::Request<B>) -> bool {
    req.method() == Method::GET
        && match req
            .headers()
            .get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok())
        {
            Some(d) => d == "document",
            None => true, // curl/git 等本机工具无该头：同一用户，命中无妨
        }
}

/// 跟班 XHR：可缓存，但不驱动会话寿命（后台轮询不该把缓存一直养着）。
fn is_xhr_nav<B>(req: &hyper::Request<B>, host: &str) -> bool {
    host == CACHE_HOST && req.method() == Method::GET && is_xhr_path(req.uri().path())
}

/// 准入：github.com 的列表页（文档导航）+ 跟班 XHR；只有 Ctrl+F5 才直通，max-age=0 不算。
fn cache_eligible<B>(req: &hyper::Request<B>, host: &str) -> bool {
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

/// 取路由：命中 = 纯本地读；未命中/空闲后第一页 = None，走上游。
/// githubassets 资产不在此处理：mitm_http 的资产库强绑定分支接管（命中回放 / miss 独立拉取）。
pub(super) fn cache_take<B>(
    log: &LogFn,
    req: &hyper::Request<B>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    let xhr = is_xhr_nav(req, host);
    let search_page = is_search_page(req.uri().path());
    if !is_doc_nav(req) && !xhr && !search_page {
        return None;
    }
    // 新会话：先让管家清上一会话的盘，这一页必回源；只有文档导航驱动会话。
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
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let variant = if search_page {
        search_variant(req.headers().get("accept").and_then(|v| v.to_str().ok()))
    } else {
        ""
    };
    let key = live_cache_key(
        req.uri(),
        host,
        cookies,
        upstream::encoding_bucket(req),
        variant,
    );
    let ((status, hdrs, body), swr_expired) =
        match load_disk_entry_reason(&key, session_value(cookies).is_some())
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
    // 命中是常态：每路径只留首条，否则浏览高峰整页都是「缓存命中」。
    if super::quiet::first_time("cachehit", &path) {
        (log)(&format!("[缓存] 命中 {path} ({size} 本地)"));
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
    // ② 其余页面：原有准入/收集/入库流程（仓库页在准入里排除——html 永不缓存、零转换直出）。
    // 拒存日志只认主站 /search，全量打会淹没日志。
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
    // 只缓存 200；304 不落日志——每页十几个计数 XHR 都走这条路，留痕只会刷屏。
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
    if let Some(cl) = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
    {
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
    let cookies = all_cookies(req.headers());
    let cookies = cookies.as_deref();
    let search_page = is_search_page(req.uri().path());
    // 分钥匙以实际 Content-Type 为准：同 URL 可能回 JSON 也可能回 HTML。
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
    let key = live_cache_key(
        req.uri(),
        host,
        cookies,
        upstream::encoding_bucket(req),
        variant,
    );
    let has_session = session_value(cookies).is_some();
    collect_and_submit(log, &key, xhr, search_page, has_session, resp).await
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
                            "[缓存] 写后失效 {host}{path} (会话条目删除 {d}, keep 快照标过期 {k})"
                        ));
                    }
                }
                CacheMsg::Purge => {
                    let n = wipe_pages(dir);
                    (log)(&format!(
                        "[缓存] 空闲超 {} 分钟, 清空 {n} 条",
                        IDLE_SESSION_GAP_MS / 60_000
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

/// 缓存键 = 方法 + host + 路径查询 + 身份标签 + 编码标签；会话号拼在外面，旧会话自然查不到。
fn live_cache_key(
    uri: &http::Uri,
    host: &str,
    cookies: Option<&str>,
    enc: &str,
    variant: &str,
) -> String {
    let base = page_cache_key(uri, host, cookies, enc);
    if is_home_path(uri.path()) {
        // v6.11：首页骨架跨会话存 keep/、7 天重同步（旧壳 immutable 直出，数据走 XHR）。
        // 仓库页不缓存（html 零转换直出），其余带会话号。
        format!("{base}-k")
    } else {
        format!("{base}{variant}-s{}", SESSION_EPOCH.load(Ordering::Relaxed))
    }
}

fn page_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, enc: &str) -> String {
    let path = uri.path();
    let q = uri
        .query()
        .map(|q| normalize_query(uri.path(), q))
        .unwrap_or_default();
    let cookie_tag = session_fingerprint(cookies);
    // 编码进键：br 条目不能给只收 gzip 的 curl。
    let enc_tag = match enc {
        "br" => "-br",
        "gzip" => "-gz",
        _ => "-id",
    };
    format!("GET {host}{path}{q}{cookie_tag}{enc_tag}")
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
    let path = entry_dir(&page_cache_dir(), key).join(page_file_name(key));
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
                        entry_dir(&page_cache_dir(), &key).join(page_file_name(&key)),
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
    let pages = entry_dir(dir, key);
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
    if !allowed
        && search_page
        && (ct.starts_with("text/html") || ct.starts_with("application/json"))
    {
        // 搜索页软导航按 Accept 协商出 JSON 或 HTML，分钥匙后照存。
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
            // 首页骨架(-k)跨会话存活 7 天，截断页绝不能入库——宁可这次不缓存。
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
                && !resp_no_store(&parts.headers)
                && (!key.ends_with("-k") || html_complete(&bytes, enc))
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
            } else if key.contains("/search?") {
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
            if key.contains("/search?") {
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
