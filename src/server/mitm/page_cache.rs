//! 页面缓存：github.com 列表页/仓库页快照按会话分存（存 pages/<hash>），闸门页/未登录页/
//! 跨账号不缓存。资产（JS/CSS）一律直连不缓存——v6.9 实测 48 分钟 132 个资产请求 0 命中，
//! 机制与开关已物理删除（要找回来翻 git 历史）。
use super::BoxBody;
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

/// 仓库首页：/owner/repo（两段，可带尾斜杠）。整页 HTML 列表语义。
fn is_repo_home(path: &str) -> bool {
    path.split('/').filter(|s| !s.is_empty()).count() == 2 && !path.is_empty()
}

/// 缓存键的路径归一：仓库首页补尾斜杠（/owner/repo 与 /owner/repo/ 同键）。
fn canonical_path(path: &str) -> String {
    if is_repo_home(path) && !path.ends_with('/') {
        format!("{path}/")
    } else {
        path.to_string()
    }
}

/// /owner/repo → /owner/repo/ 的完整 URI（保留查询串），本地 301 的键用。
fn slash_uri(req: &hyper::Request<Incoming>, host: &str) -> http::Uri {
    let q = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    format!("https://{host}{}/{q}", req.uri().path())
        .parse()
        .unwrap_or_else(|_| req.uri().clone())
}

/// 条目落点：键尾 `-k`/`-rk` 进跨会话目录 keep/，其余进会话目录 pages/（清盘只清后者）。
/// v6.9 资产缓存整体停用并物理删除：实测 48 分钟 132 个 githubassets 请求 0 命中
/// （没变的 URL 浏览器自己消化，换哈希的代理也没见过），机制与开关一并移除。
fn entry_dir(dir: &std::path::Path, key: &str) -> std::path::PathBuf {
    if key.ends_with("-k") || key.ends_with("-rk") {
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
    /// 写操作成功后的缓存失效（异步，POST 响应路径不等它）。
    Invalidate { host: String, path: String },
    /// 空闲后重新开始浏览：整盘清空，本次会话从空白积累。
    Purge,
}

// ---------- 对外唯二入口 ----------

/// 文档导航：不论值不值得缓存，都算"还在浏览"（决定会话是否延续）。
fn is_doc_nav(req: &hyper::Request<Incoming>) -> bool {
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
fn is_xhr_nav(req: &hyper::Request<Incoming>, host: &str) -> bool {
    host == CACHE_HOST && req.method() == Method::GET && is_xhr_path(req.uri().path())
}

/// 准入：github.com 的列表页（文档导航）+ 跟班 XHR；只有 Ctrl+F5 才直通，max-age=0 不算。
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
            || (doc_nav && (is_list_path(path) || is_home_path(path) || is_repo_home(path))))
}

/// 取路由：命中 = 纯本地读（对 GitHub 零请求）；未命中/空闲后第一页 = None，走上游。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    // 仓库首页无尾杠：尾杠版已在缓存 → 本地 301（省一次上游往返；
    // 浏览器落到尾杠地址后相对链接才解析得对）。尾杠版没缓存则正常回源。
    if is_repo_home(req.uri().path()) && !req.uri().path().ends_with('/') {
        let cookies = all_cookies(req.headers());
        let slash_key = live_cache_key(
            &slash_uri(req, host),
            host,
            cookies.as_deref(),
            upstream::encoding_bucket(req),
            "",
        );
        if load_disk_entry_reason(&slash_key, false).is_ok() {
            let resp = axum::response::Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(hyper::header::LOCATION, format!("{}/", req.uri().path()))
                .body(BoxBody::new(protocol::full_body(Bytes::new())))
                .ok()?;
            (log)(&format!("[缓存] 本地 301 {}", req.uri().path()));
            return Some(resp);
        }
        return None;
    }
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
                CacheMsg::Invalidate { host, path } => {
                    invalidate_prefix_blocking(dir, &host, &path);
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

/// 全部 Cookie 头按出现序拼接：浏览器的大 Cookie 会被 h2 拆成多行，
/// 只读第一行会漏掉排在后面的 user_session —— 登录流量就会被记成 -cloggedout。
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

/// 身份标签：未登录 -cloggedout，登录 -c<账号>；取不到账号就哈希 session 值，不能哈希整条 Cookie。
fn session_fingerprint(cookies: Option<&str>) -> String {
    let Some(sess) = session_value(cookies) else {
        return "-cloggedout".into();
    };
    match account_name(cookies) {
        Some(u) => format!("-c{u}"),
        // 会话号散列进标签：稳定摘要即可，读取侧按 key 校验，无碰撞风险。
        // 会话号散列进标签（复用 page_file_name 的稳定摘要），读取侧按 key 校验。
        None => format!("-cs{}", page_file_name(sess)),
    }
}

/// 拒存日志用：键去掉 "GET host" 前缀，露出路径+查询。
fn dbg_path(key: &str) -> &str {
    key.split_once(' ').map(|(_, rest)| rest).unwrap_or(key)
}

/// 搜索页的内容分钥匙：存侧看实际 Content-Type，取侧按 Accept 预测，猜错只是 miss。
/// GitHub 搜索页按 Accept 协商，同 URL 两种正文必须分钥匙。
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
    if is_home_path(uri.path())
        || (is_repo_home(uri.path()) && !uri.path().starts_with("/settings"))
    {
        // v6.11：仓库页快照与首页骨架同待遇——跨会话存 keep/，7 天温和重同步。
        // 发版换哈希在窗口内隐身：旧壳引用旧 chunk，浏览器 immutable 缓存直出。
        // 页面数据（提交/文件列表）走独立 XHR 实时直通，壳旧不影响数据新。
        // /settings/* 是账号敏感页（两段路径会被仓库页启发式误中），保持会话键。
        // 仓库页用 -rk 标记：走底稿+分段增量存储（首页骨架 -k 保持全量存储）。
        if is_repo_home(uri.path()) {
            format!("{base}-rk")
        } else {
            format!("{base}-k")
        }
    } else {
        format!("{base}{variant}-s{}", SESSION_EPOCH.load(Ordering::Relaxed))
    }
}

fn page_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, enc: &str) -> String {
    let path = canonical_path(uri.path());
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

/// /search 查询串归一化：默认页显式补 p=1（无 p 与 p=1 同键），参数按键名排序；
/// 其他路径保持原样，个别接口参数顺序有语义。
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

/// HTML 是否完整（末 2KB 内有 </html>）：GitHub 的 h2 响应没有 content-length，
/// 上游流中途断掉时 collect 仍返回 Ok —— 截断页落进 keep/ 会被 7 天寿命内
/// 的每次后退命中，等于必现白屏。读写两侧都用它把关。
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

/// 带拒绝原因的读取，供命中侧按需落日志。第二个元素 = 页面快照是否过期（SWR 触发）。
fn load_disk_entry_reason(key: &str, logged_in: bool) -> Result<(DiskEntry, bool), &'static str> {    let path = entry_dir(&page_cache_dir(), key).join(page_file_name(key));
    let raw = std::fs::read(&path).map_err(|_| "无此条目")?;
    // v6.11 SWR：-k/-rk 快照过期不判死——交旧 + 后台静默重拉（过期标记随条目返回）。
    let mut swr_expired = false;
    if key.ends_with("-k") || key.ends_with("-rk") {
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        swr_expired = age > KEEP_MAX_AGE_MS;
    }
    if raw.len() < 4 {
        return Err("文件过短");
    }
    let hlen =
        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
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
    let enc = hdrs.iter().find(|(k, _)| k.as_str() == "content-encoding")
        .and_then(|(_, v)| v.to_str().ok())
        .map(body_encoding)
        .unwrap_or("identity");
    let body = &raw[end..];
    let segs = header.get("stoenc").and_then(|v| v.as_str()) == Some("segs");
    // v6.11 分段快照：底稿+增量还原明文；门检跑明文；交付重压 gzip
    //（头里 content-encoding: gzip 与重压后的体一致；content-length 剥掉由 hyper 按实际体重设）。
    let (hdrs, out_body) = if segs {
        let base = load_repo_base(&page_cache_dir()).ok_or("底稿缺失")?;
        let full = seg_decode(&base, body).ok_or("分段增量损坏")?;
        let n = full.len().min(8192);
        let p8 = String::from_utf8_lossy(&full[..n]).to_lowercase();
        if (logged_in && is_logged_out_body(&p8)) || is_gate_page(&p8) {
            return Err("会话已死的未登录页/闸门页"); // 旧快照自愈
        }
        if !html_complete(full.as_slice(), "identity") {
            // 快照还原不完整：连底稿一起清掉，下次全部重建（自愈）
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(base_repo_path(&page_cache_dir()));
            return Err("快照条目截断(无</html>)");
        }
        let mut h = hdrs;
        h.retain(|(k, _)| k.as_str() != "content-length");
        (h, Bytes::from(gz_compress(full.as_slice())))
    } else {
        let p = plain_prefix(body, enc);
        if (logged_in && is_logged_out_body(&p)) || is_gate_page(&p) {
            return Err("会话已死的未登录页/闸门页"); // 当作 miss（旧版存下的也自愈）
        }
        // keep 条目（首页骨架/仓库页快照）必须是完整文档：截断页删文件自愈，别让它活满 7 天。
        if key.ends_with("-k")
            && hdrs.iter().any(|(k, v)| {
                k.as_str() == "content-type"
                    && v.to_str()
                        .map(|v| v.starts_with("text/html"))
                        .unwrap_or(false)
            })
            && !html_complete(body, enc)
        {
            let _ = std::fs::remove_file(&path);
            return Err("骨架条目截断(无</html>)");
        }
        (hdrs, Bytes::copy_from_slice(body))
    };
    Ok(((status, hdrs, out_body), swr_expired))
}

// ---------- 页面快照 SWR（v6.11：过期交旧 + 后台静默重拉，前台零等待） ----------

/// 页面快照后台重拉去重：同键同时只跑一个。
static PAGE_REFRESHING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn page_refresh_done(key: &str) {
    let g = PAGE_REFRESHING.get_or_init(|| Mutex::new(HashSet::new()));
    lock(g).remove(key);
}

/// 过期页面快照的后台静默重拉：带 cookie 拉最新壳，200+完整+会话存活才覆盖。
/// 重试循环：代理在跑就一直拉（失败 60s 后再试），直到成功入库或确认页面不存在；
/// 全程前台零感知（旧壳继续服务）。
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
            let (up, _) = match crate::pool::get_or_build(&host, None, &path_q, &log).await {
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
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36",
                );
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
                // 404/410 = 页面在上游已不存在 → 永久放弃（旧壳继续顶）
                if st == http::StatusCode::NOT_FOUND || st == http::StatusCode::GONE {
                    (log)(&format!(
                        "[缓存] 页面重拉确认上游 {st}(页面已不存在), 放弃重拉, 旧壳继续"
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
            // ④ 覆盖入库（全量格式，替换旧快照）
            let header = serde_json::json!({
                "key": key,
                "status": http::StatusCode::OK.as_u16(),
                "headers": hdrs,
            });
            match write_entry_file(&page_cache_dir(), &key, &bytes, &header) {
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

// ---------- 底稿 + 分段增量（v6.11：仓库页快照存储，强制不随 GitHub 更新） ----------

/// 底稿文件：第一份仓库页快照的解压原文，冻结不随发版更新。
const BASE_REPO_FILE: &str = "base-repo.html";
/// 分段引用阈值：≥32 字节的相同段引用底稿，更短差异并入字面量。
const SEG_MIN_MATCH: usize = 32;

fn base_repo_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(BASE_REPO_FILE)
}

/// 读底稿（明文）。缺失/过小 = None（调用方决定是否立底稿）。
fn load_repo_base(dir: &std::path::Path) -> Option<Vec<u8>> {
    let b = std::fs::read(base_repo_path(dir)).ok()?;
    (b.len() >= SEG_MIN_MATCH).then_some(b)
}

/// 立底稿：明文落盘（tmp+rename 原子写，防半截底稿）。
fn store_repo_base(dir: &std::path::Path, plain: &[u8]) {
    let tmp = dir.join("tmp");
    let _ = std::fs::create_dir_all(&tmp);
    let final_path = base_repo_path(dir);
    let tmp_path = tmp.join(BASE_REPO_FILE);
    if std::fs::write(&tmp_path, plain).is_ok() {
        let _ = std::fs::rename(&tmp_path, &final_path);
    }
}

/// 分段增量编码：底稿里找 ≥32 字节的相同段（贪心最长匹配，8 字节索引），
/// 段间差异存字面量。序列化 = [4B op 数] + 每 op [4B 字面长][字面][4B 底稿位][4B 段长]。
fn seg_encode(base: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut index: std::collections::HashMap<[u8; 8], Vec<u32>> = std::collections::HashMap::new();
    if base.len() >= 8 {
        for i in 0..=(base.len() - 8) {
            index.entry(base[i..i + 8].try_into().unwrap()).or_default().push(i as u32);
        }
    }
    let mut ops: Vec<(Vec<u8>, u32, u32)> = Vec::new();
    let mut lit: Vec<u8> = Vec::new();
    let mut np = 0usize;
    while np + 8 <= plain.len() {
        let key: [u8; 8] = plain[np..np + 8].try_into().unwrap();
        let mut best: Option<(usize, usize)> = None;
        if let Some(cands) = index.get(&key) {
            for (j, &cand) in cands.iter().enumerate() {
                if j >= 64 {
                    break; // 候选上限：病态重复标记防炸
                }
                let cu = cand as usize;
                let mut l = 8usize;
                while cu + l < base.len() && np + l < plain.len() && base[cu + l] == plain[np + l] {
                    l += 1;
                }
                if l >= SEG_MIN_MATCH && best.map(|(_, bl)| l > bl).unwrap_or(true) {
                    best = Some((cu, l));
                }
            }
        }
        match best {
            Some((cand, l)) => {
                ops.push((std::mem::take(&mut lit), cand as u32, l as u32));
                np += l;
            }
            None => {
                lit.push(plain[np]);
                np += 1;
            }
        }
    }
    if np < plain.len() {
        lit.extend_from_slice(&plain[np..]);
    }
    ops.push((std::mem::take(&mut lit), 0, 0)); // 尾字面量（copy 0,0 = 无）

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&(ops.len() as u32).to_be_bytes());
    for (l, cpos, clen) in ops {
        out.extend_from_slice(&(l.len() as u32).to_be_bytes());
        out.extend_from_slice(&l);
        out.extend_from_slice(&cpos.to_be_bytes());
        out.extend_from_slice(&clen.to_be_bytes());
    }
    out
}

/// 分段增量解码：底稿 + op 序列 → 精确明文。任何损坏 = None（调用方当 miss 自愈）。
fn seg_decode(base: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut p = 4usize;
    let mut out = Vec::with_capacity(base.len());
    for _ in 0..n {
        if p + 4 > data.len() {
            return None;
        }
        let ll = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize;
        p += 4;
        if p + ll > data.len() {
            return None;
        }
        out.extend_from_slice(&data[p..p + ll]);
        p += ll;
        if p + 8 > data.len() {
            return None;
        }
        let cpos = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize;
        let clen = u32::from_be_bytes([data[p + 4], data[p + 5], data[p + 6], data[p + 7]]) as usize;
        p += 8;
        if cpos + clen > base.len() {
            return None;
        }
        out.extend_from_slice(&base[cpos..cpos + clen]);
    }
    Some(out)
}

/// 明文 → gzip（分段快照交付用：头里 content-encoding 与重压后的体保持一致）。
fn gz_compress(plain: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(plain);
    e.finish().unwrap_or_default()
}

/// 条目落盘：tmp 写全量 + rename 原子覆盖，永远存不出半页。
fn write_entry_file(
    dir: &std::path::Path,
    key: &str,
    body: &[u8],
    header: &serde_json::Value,
) -> Result<(), String> {
    let hbytes = serde_json::to_vec(header).map_err(|e| e.to_string())?;
    // 记账口径必须等于实际写入量：4 字节长度前缀 + 头部 JSON + 正文。
    maybe_wipe_on_growth(dir, 4 + hbytes.len() + body.len());
    let pages = entry_dir(dir, key);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&pages).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(4 + hbytes.len() + body.len());
    buf.extend_from_slice(&(hbytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&hbytes);
    buf.extend_from_slice(body);
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

/// 页面缓存落盘统一入口：仓库页快照（-rk）走底稿+分段增量，其余走全量。
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
    // v6.11：仓库页快照（-rk）走底稿+分段增量存储（强制不随 GitHub 发版更新）
    if key.ends_with("-rk") {
        return persist_repo_snapshot(dir, key, bytes, status, hdrs);
    }
    write_entry_file(
        dir,
        key,
        bytes,
        &serde_json::json!({
            "key": key,
            "status": status,
            "headers": hdrs,
        }),
    )
}

/// 仓库页快照入库：解压明文 → 底稿缺失则立底稿 → 分段增量编码 →
/// 增量不比全量 gzip 体小时自动改存全量（自愈，永不亏损）。
fn persist_repo_snapshot(
    dir: &std::path::Path,
    key: &str,
    bytes: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    let enc = hdrs
        .iter()
        .find(|pair| pair.len() >= 2 && pair[0].eq_ignore_ascii_case("content-encoding"))
        .and_then(|pair| pair.get(1))
        .map(|v| v.as_str().to_string())
        .map(|v| body_encoding(&v))
        .unwrap_or("identity");
    let plain = super::defuse::decompress_partial(bytes, enc, 64 << 20);
    // 底稿：缺失或过小则立底稿（本页即底稿）
    let base = match load_repo_base(dir) {
        Some(b) if b.len() >= SEG_MIN_MATCH => b,
        _ => {
            store_repo_base(dir, &plain);
            plain.clone()
        }
    };
    let delta = seg_encode(&base, &plain);
    // 自动兜底：增量不比全量 gzip 体小 → 存全量（自愈，永不亏损）
    if delta.len() >= bytes.len() {
        let header = serde_json::json!({
            "key": key,
            "status": status,
            "headers": hdrs,
        });
        return write_entry_file(dir, key, bytes, &header);
    }
    let header = serde_json::json!({
        "key": key,
        "status": status,
        "headers": hdrs,
        "stoenc": "segs",
    });
    write_entry_file(dir, key, &delta, &header)
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
            let plain = plain_prefix(&bytes, enc);
            // 首页骨架(-k)跨会话存活 7 天，截断页绝不能入库——宁可这次不缓存。
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
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

/// 写后失效：前缀匹配，父路径也匹配（写端点多是子路径；至少两级，免得 /o 扫全表）。
fn invalidate_prefix_blocking(dir: &std::path::Path, host: &str, path: &str) {
    let mut prefixes = vec![format!("GET {host}{path}")];
    if let Some(i) = path.rfind('/') {
        let parent = &path[..i];
        if parent.matches('/').count() >= 2 {
            prefixes.push(format!("GET {host}{parent}"));
        }
    }
    // 会话条目在 pages/，仓库页快照在 keep/（v6.11 起仓库页换 -k 键），两处都要扫。
    for sub in ["pages", "keep"] {
        let Ok(rd) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if read_page_key(&p).is_some_and(|k| prefixes.iter().any(|pre| k.starts_with(pre))) {
                let _ = std::fs::remove_file(&p);
            }
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
#[path = "../../tests/server/mitm/page_cache_tests.rs"]
mod page_cache_tests;
