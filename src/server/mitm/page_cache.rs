//! 页面缓存（github.com 文档导航 GET，cacache 内容寻址磁盘缓存）。
//! 架构：取/存两个路由 + 一个后台管家线程。
//! - cache_take：命中秒回（对 GitHub 零请求）；
//! - cache_put：资格判定 + 收集体（≤2MB）+ 投递 Save 消息（主路径零磁盘等待）；
//! - 管家线程（懒启动，专用 OS 线程串行消费任务筐）：写盘、容量淘汰（200MB）、
//!   孤儿内容块回收。磁盘 IO 永不阻塞请求路径。
//! 新鲜度模型（2026-10-23 定案）：**没有后台验证**。
//! 之前的 ETag 后台验证回放"命中时刻冻结的会话 cookie"，与浏览器实时轮换的
//! _gh_sess 交错出现，被 GitHub 风控判定为会话固定 → 当天三次强制下线。
//! 现在的新鲜度 = 你自己的写操作（POST 后同路径条目即删）+ 会话指纹分键；
//! 页面内容 = 上次访问时的样子（用户明确接受的取舍，Ctrl+F5 绕过缓存取最新）。
//! cookie 语义：单用户本地代理，cookie 全量转发 GitHub（等同浏览器行为）；
//! 仅镜像腿剥离（镜像站是第三方，不认识会话，剥离防凭证泄露）。
use super::{get_direct, BoxBody, UpstreamInfo};
use crate::pool::LogFn;
use crate::server::upstream::Incoming;
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};

const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）
const VALIDATE_WINDOW_MS: u64 = 10 * 60 * 1000; // 同页验证窗口
const VALIDATE_COOLDOWN_MS: u64 = 2000; // 全局验证冷却（防点击风暴）

/// 管家线程的任务消息：目前只有 Save（写盘+淘汰+孤儿回收）。
enum CacheMsg {
    Save {
        key: String,
        bytes: Bytes,
        status: u16,
        hdrs: Vec<Vec<String>>,
    },
    Validate {
        key: String,
        pq: String,
        cookies: Option<String>,
        ua: Option<String>,
        etag: String,
    },
}

// ---------- 对外唯二入口：取 / 存 ----------
// 知识收拢：可缓存判定、键构造（含会话指纹）、元数据与索引、
// 容量淘汰全部在本模块内；调用方只见 cache_take / cache_put 两个路由。

/// 取/存共用的可缓存判定。
fn cache_eligible(req: &hyper::Request<Incoming>, host: &str) -> bool {
    host == "github.com"
        && req.method() == Method::GET
        && (match req.headers().get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
            Some(d) => d == "document",
            None => true, // curl/git 等本机工具无该头：同一用户，命中无妨
        })
        && !req
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|c| c.contains("no-cache") || c.contains("max-age=0"))
            .unwrap_or(false)
        && page_cache_allowed(&req.uri().path().to_string())
}

/// 取路由：主调用路径唯一入口。命中 = 纯本地磁盘读（对 GitHub 零请求）；
/// 命中时"摸"一下条目（重写索引刷新时间戳）防被容量淘汰误杀；
/// 未命中/不可缓存 = None，主路走上游。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<(axum::response::Response<BoxBody>, Option<String>)> {
    if !cache_eligible(req, host) {
        return None;
    }
    let key = page_cache_key(req, host);
    let (cached, etag) = page_cache_get(&key)?;
    (log)(&format!("[缓存] 命中 {}", req.uri()));
    // 摸一下：重写索引刷新时间戳（内容去重，只更新索引行 ~0.1ms），
    // 防止频繁访问的页面因"写入时间旧"被容量淘汰误杀（偶发转圈的根因）
    touch_cache_entry(&key);
    // SWR：同页验证窗口（10 分钟）过期且过全局冷却 → 向管家投一条
    // If-None-Match 静默保鲜任务（只带 user_session，不带 _gh_sess——
    // 后者每请求轮换，回放旧值 = 会话固定信号）。
    let now_ms = now_millis();
    let last_start = LAST_VALIDATE_START.load(std::sync::atomic::Ordering::Relaxed);
    let cooldown_ok = now_ms.saturating_sub(last_start) >= VALIDATE_COOLDOWN_MS;
    let due = {
        let map = last_verified_map().lock().unwrap();
        validation_due(&map, &key, now_ms)
    };
    if due && cooldown_ok && etag.is_some() {
        LAST_VALIDATE_START.store(now_ms, std::sync::atomic::Ordering::Relaxed);
        mark_validated(&mut last_verified_map().lock().unwrap(), &key, now_ms);
        let cookies = swr_session_cookie(req);
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();
        let etag2 = etag.clone().unwrap_or_default();
        worker_send(
            CacheMsg::Validate {
                key: key.clone(),
                pq,
                cookies,
                ua,
                etag: etag2,
            },
            log,
        );
    }
    Some((cached, etag))
}

/// 存路由：上游响应唯一入口。内部复判可缓存性、构造键（含会话指纹）、
/// 剥离 Set-Cookie、收集体并投递 Save 消息；不可缓存原样透传。
/// 主路径零磁盘等待：写盘在管家线程。
pub(super) async fn cache_put(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    if !cache_eligible(req, host) {
        return resp;
    }
    // Content-Length 粗筛（压缩后大小）：超限直接放行不缓存，collect 前先挡一道。
    // chunked 无该头则放行进 collect（解压后仍有 2MB 上限二次保护）。
    if let Some(cl) = resp.headers().get("content-length").and_then(|v| v.to_str().ok()) {
        if let Ok(n) = cl.parse::<u64>() {
            if n > PAGE_CACHE_MAX_BODY_BYTES as u64 {
                return resp;
            }
        }
    }
    let key = page_cache_key(req, host);
    collect_and_submit(log, &key, resp).await
}

// ---------- 内部：管家线程 ----------

static WORKER_SENDER: OnceLock<mpsc::SyncSender<CacheMsg>> = OnceLock::new();
static WORKER_LOG: OnceLock<LogFn> = OnceLock::new();

/// 每个缓存页上次后台验证的时间（毫秒历元）。内存态：重启后为空，
/// 每页首次命中验证一次，本来就是正确语义。
static LAST_VERIFIED: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static LAST_VALIDATE_START: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// 向管家投递任务；筐满/管家不可用 = 丢弃并打日志（缓存写是 best-effort）。
/// 日志用管家初始化时捕获的 WORKER_LOG（投递方无需自带）。
fn worker_send(msg: CacheMsg, log: &LogFn) -> bool {
    let tx = WORKER_SENDER.get_or_init(|| {
        let _ = WORKER_LOG.set(log.clone());
        let (tx, rx) = mpsc::sync_channel::<CacheMsg>(WORKER_CHANNEL_CAP);
        let log2 = log.clone();
        let _ = std::thread::Builder::new()
            .name("page-cache-worker".into())
            .spawn(move || worker_loop(log2, rx));
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

/// 管家循环：专用 OS 线程串行消费任务筐。磁盘写在这个线程上做（阻塞无害）。
fn worker_loop(log: LogFn, rx: mpsc::Receiver<CacheMsg>) {
    while let Ok(msg) = rx.recv() {
        match msg {
            CacheMsg::Save {
                key,
                bytes,
                status,
                hdrs,
            } => {
                let dir = page_cache_dir();
                if let Err(e) =
                    persist_page_entry_blocking(&dir, &key, &bytes, status, &hdrs)
                {
                    (log)(&format!("[缓存] 后台写盘失败({e})，{key} 本次不缓存"));
                }
            }
            CacheMsg::Validate {
                key,
                pq,
                cookies,
                ua,
                etag,
            } => {
                // 网络验证（慢）不阻塞磁盘循环——立即 spawn 异步跑
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle_spawn_validate(log.clone(), key, pq, cookies, ua, etag);
                }));
            }
        }
    }
}

// ---------- 内部：目录与 ACL ----------

#[cfg(test)]
static CACHE_DIR_OVERRIDE: std::sync::OnceLock<std::path::PathBuf> =
    std::sync::OnceLock::new();

fn page_cache_dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(d) = CACHE_DIR_OVERRIDE.get() {
        return d.clone();
    }
    crate::settings::exe_dir().join(".cache")
}

static CACHE_ACL_APPLIED: OnceLock<()> = OnceLock::new();

/// 确保 .cache 目录存在；本进程首次触达时套一次 Windows ACL
/// （icacls 断继承 + 只授当前用户与 SYSTEM，与 ca.key/settings.json 同款手段）。
/// 页面 HTML 含个人信息（仪表盘/动态流/用户名），不给同机其他账户留读取面。
/// ACL 随目录持久化，跨重启仍有效；icacls 是进程 spawn，OnceLock 保证只跑一次。
fn ensure_cache_dir_with_acl(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    if CACHE_ACL_APPLIED.set(()).is_ok() {
        let _ = crate::winsec::restrict_dir_to_current_user(&dir.to_string_lossy());
    }
    true
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 页面可缓存判定（2026-10-23 定案：全量缓存，唯一禁区=登录态翻转三件套）。
/// 通知页同权：内容陈旧由用户自行刷新（Ctrl+F5 绕过缓存取最新）；
/// 搜索碎片（count/blackbird/warm）是 XHR 碎片，已被
/// sec-fetch-dest=document 闸门排除，无需路径名单。
/// 保留 /login /logout /session：登录表单的 CSRF token 绑定匿名会话
/// _gh_sess（每请求轮换），缓存页的旧 token 提交必被拒 → 锁死登录页；
/// 登出被截胡 = 假登出。这是功能边界，不是缓存策略。
fn page_cache_allowed(path: &str) -> bool {
    !path.starts_with("/login")
        && !path.starts_with("/logout")
        && !path.starts_with("/session")
}

fn last_verified_map() -> &'static Mutex<HashMap<String, u64>> {
    LAST_VERIFIED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 距上次验证是否已过窗口（纯判定，便于测试）。
fn validation_due(map: &HashMap<String, u64>, key: &str, now_ms: u64) -> bool {
    match map.get(key) {
        Some(t) => now_ms.saturating_sub(*t) >= VALIDATE_WINDOW_MS,
        None => true,
    }
}

fn mark_validated(map: &mut HashMap<String, u64>, key: &str, now_ms: u64) {
    map.insert(key.to_string(), now_ms);
}

/// SWR 验证专用的会话 cookie：只取 user_session（长效鉴权 token，不轮换），
/// 不带 _gh_sess（每请求轮换的 Rails 会话 cookie，回放旧值 = 会话固定信号）。
/// GitHub 看 user_session 做鉴权 → 登录态页面内容正确，无轮换冲突。
fn swr_session_cookie(req: &hyper::Request<Incoming>) -> Option<String> {
    let cookies = req.headers().get("cookie").and_then(|v| v.to_str().ok())?;
    let session = cookies
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("user_session="))
        .filter(|v| !v.is_empty())?;
    Some(format!("user_session={session}"))
}

/// 会话指纹：只取 user_session（长效鉴权 cookie，不随请求轮换）的值做 FNV。
/// 整个 cookie header 的哈希会被 _gh_sess 每请求轮换打散——每次导航键都变，
/// 登录态缓存永不命中。无 user_session = 未登录 → 固定标签。
/// 登录/登出/多账号三态天然分离：取路由按指纹给对应状态的缓存页。
fn session_fingerprint(cookies: Option<&str>) -> String {
    let session = cookies.and_then(|c| {
        c.split(';')
            .map(str::trim)
            .find_map(|kv| kv.strip_prefix("user_session=").filter(|v| !v.is_empty()))
    });
    match session {
        Some(v) => {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in v.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x100000001b3);
            }
            format!("-c{h:016x}")
        }
        None => "-cloggedout".into(),
    }
}

fn page_cache_key(req: &hyper::Request<Incoming>, host: &str) -> String {
    let uri = req.uri();
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    // 会话指纹进键：登录/登出态的同一 URL 页面内容不同，防串页
    let cookie_tag =
        session_fingerprint(req.headers().get("cookie").and_then(|v| v.to_str().ok()));
    format!("GET {host}{}{q}{cookie_tag}", uri.path())
}

/// 命中缓存：返回重建的响应（纯本地磁盘读，对 GitHub 零请求）。
fn page_cache_get(key: &str) -> Option<(axum::response::Response<BoxBody>, Option<String>)> {
    let dir = page_cache_dir();
    let md = cacache::metadata_sync(&dir, key).ok()??;
    let status = u16::try_from(md.metadata.get("status")?.as_u64()?).ok()?;
    let headers = md.metadata.get("headers")?.as_array()?;
    let body = cacache::read_sync(&dir, key).ok()?;
    let mut hdrmap = hyper::HeaderMap::new();
    for pair in headers {
        let (Some(k), Some(v)) = (pair.get(0)?.as_str(), pair.get(1)?.as_str()) else {
            continue;
        };
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            hdrmap.insert(name, val);
        }
    }
    let etag = hdrmap
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let mut resp = hyper::Response::builder()
        .status(status)
        .body(BoxBody::new(
            http_body_util::Full::new(Bytes::from(body)).map_err(std::io::Error::other),
        ))
        .unwrap();
    *resp.headers_mut() = hdrmap;
    resp.headers_mut().insert(
        "x-gitport-cache",
        hyper::header::HeaderValue::from_static("hit"),
    );
    Some((resp, etag))
}

/// 淘汰超限的最旧页面（按 cacache 索引的写入时间），直到总体积回到上限内；
/// 随后回收孤儿内容块（被淘汰条目的内容若无残余引用 → 删块，防磁盘无限累积）。
fn enforce_page_cache_limit(dir: &std::path::Path, cap_bytes: u64) {
    let entries: Vec<cacache::Metadata> = cacache::list_sync(dir).flatten().collect();
    let total: u64 = entries.iter().map(|m| m.size as u64).sum();
    if total <= cap_bytes {
        return;
    }
    let mut sorted = entries;
    // 同毫秒写入的条目按 key 字典序破并列——淘汰顺序确定，不随索引遍历顺序漂移
    sorted.sort_by(|a, b| a.time.cmp(&b.time).then_with(|| a.key.cmp(&b.key)));
    let mut acc = total;
    let mut evicted: Vec<cacache::Integrity> = Vec::new();
    for m in sorted {
        if acc <= cap_bytes {
            break;
        }
        acc = acc.saturating_sub(m.size as u64);
        evicted.push(m.integrity.clone());
        let _ = cacache::remove_sync(dir, &m.key);
    }
    gc_orphaned_content(dir, &evicted);
}

/// 孤儿内容块回收：cacache 的 remove 只删索引不删内容（内容按哈希去重共享），
/// 被删条目的内容若已无任何索引条目引用 → remove_hash_sync 删块。
fn gc_orphaned_content(dir: &std::path::Path, removed: &[cacache::Integrity]) {
    if removed.is_empty() {
        return;
    }
    let referenced: HashSet<String> = cacache::list_sync(dir)
        .flatten()
        .map(|m| m.integrity.to_string())
        .collect();
    for sri in removed {
        if !referenced.contains(&sri.to_string()) {
            let _ = cacache::remove_hash_sync(dir, sri);
        }
    }
}

/// 命中缓存"摸一下"：重写索引行刷新时间戳（内容去重不重复写 blob，~0.1ms），
/// 防止频繁访问的页面因"写入时间旧"被容量淘汰误杀（偶发转圈的根因）。
fn touch_cache_entry(key: &str) {
    let dir = page_cache_dir();
    // 读元数据拿已有 headers/status，原样重写（内容 blob 已去重不重复写）
    if let Ok(Some(md)) = cacache::metadata_sync(&dir, key) {
        let status = md.metadata.get("status").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
        let hdrs: Vec<Vec<String>> = md
            .metadata
            .get("headers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|pair| {
                        let k = pair.get(0)?.as_str()?.to_string();
                        let v = pair.get(1)?.as_str()?.to_string();
                        Some(vec![k, v])
                    })
                    .collect()
            })
            .unwrap_or_default();
        // 读取内容 blob 并原样写回（cacache 去重 → 同哈希不重复写 blob，只更新索引）
        if let Ok(body) = cacache::read_sync(&dir, key) {
            let meta = serde_json::json!({
                "url": key,
                "status": status,
                "headers": hdrs,
            });
            let w = cacache::WriteOpts::new()
                .size(body.len())
                .metadata(meta)
                .open_sync(&dir, key);
            if let Ok(mut w) = w {
                use std::io::Write as _;
                let _ = w.write_all(&body);
                let _ = w.commit();
            }
        }
    }
}

/// 后台半段（管家线程内执行）：建目录（含 ACL）→ 容量淘汰 → 写 cacache 条目。
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
    enforce_page_cache_limit(dir, PAGE_CACHE_MAX_BYTES);
    let meta = serde_json::json!({
        "url": key,
        "status": status,
        "headers": hdrs,
    });
    let mut w = cacache::WriteOpts::new()
        .size(bytes.len()) // 索引 size 默认 0，必须显式设置，容量淘汰才有依据
        .metadata(meta)
        .open_sync(dir, key)
        .map_err(|e| e.to_string())?;
    use std::io::Write as _;
    w.write_all(bytes).map_err(|e| e.to_string())?;
    w.commit().map(|_| ()).map_err(|e| e.to_string())
}

/// 管家线程里 Validate 的异步执行入口（通过 tokio Handle spawn 调用）。
fn handle_spawn_validate(
    log: LogFn,
    key: String,
    pq: String,
    cookies: Option<String>,
    ua: Option<String>,
    etag: String,
) {
    let rt = tokio::runtime::Handle::current();
    rt.spawn(async move {
        swr_revalidate(&log, &key, &pq, cookies, ua, etag).await;
    });
}

/// 后台 SWR 验证：If-None-Match 条件请求（只带 user_session，不带 _gh_sess
/// ——后者每请求轮换，回放旧值 = 会话固定信号，曾致三次强制下线）。
/// 304 → 只记账（内容没变）；200 → 静默换新；404/410 → 删死链。
/// 失败（网络抖动）→ 保留原页，下个窗口再试。
async fn swr_revalidate(
    log: &LogFn,
    key: &str,
    path_and_query: &str,
    cookies: Option<String>,
    ua: Option<String>,
    etag: String,
) {
    let uri = format!("https://github.com{path_and_query}");
    let mut builder = hyper::Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .header("accept", "text/html")
        .header("accept-encoding", "gzip")
        .header("if-none-match", etag);
    builder = builder.header(
        "user-agent",
        ua.unwrap_or_else(|| "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into()),
    );
    if let Some(c) = cookies {
        builder = builder.header("cookie", c);
    }
    let Ok(out) = builder.body(BoxBody::new(
        http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
    )) else {
        return;
    };
    let info = UpstreamInfo::default();
    let resp = match get_direct(log, &out, "github.com", &info, true, &None).await {
        Ok(r) => r,
        Err(e) => {
            (log)(&format!("[缓存] 后台验证失败({e})，{} 保留原页", path_and_query));
            return;
        }
    };
    match resp.status().as_u16() {
        304 => (log)(&format!("[缓存] 后台验证 304，{} 内容未变", path_and_query)),
        200 | 201 => {
            (log)(&format!("[缓存] 后台验证 200，{} 静默换新", path_and_query));
            let _ = collect_and_submit(log, key, resp).await;
        }
        404 | 410 => {
            (log)(&format!("[缓存] 后台验证 404，{} 已是死链，删除", path_and_query));
            if let Ok(Some(md)) = cacache::metadata_sync(&page_cache_dir(), key) {
                gc_orphaned_content(&page_cache_dir(), &[md.integrity]);
            }
            let _ = cacache::remove_sync(&page_cache_dir(), key);
        }
        _ => {}
    }
}

/// 收集体并投递 Save 消息；返回重建的响应（克隆体交浏览器，零磁盘等待）。
async fn collect_and_submit(
    log: &LogFn,
    key: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let is_html = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|c| c.starts_with("text/html"))
        .unwrap_or(false);
    if !is_html {
        return hyper::Response::from_parts(parts, body);
    }
    parts.headers.remove("set-cookie");
    match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES {
                let hdrs: Vec<Vec<String>> = parts
                    .headers
                    .iter()
                    .map(|(k, v)| {
                        vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()]
                    })
                    .collect();
                let status = parts.status.as_u16();
                worker_send(
                    CacheMsg::Save {
                        key: key.to_string(),
                        bytes: bytes.clone(),
                        status,
                        hdrs,
                    },
                    log,
                );
            }
            let mut rebuilt = hyper::Response::builder()
                .status(parts.status)
                .body(BoxBody::new(
                    http_body_util::Full::new(bytes).map_err(std::io::Error::other),
                ))
                .unwrap();
            *rebuilt.headers_mut() = parts.headers;
            rebuilt
        }
        Err(_) => {
            // 收集失败（罕见）：无内容可交付，回 502 兜底
            hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from_static(b"page collect failed"))
                        .map_err(std::io::Error::other),
                ))
                .unwrap()
        }
    }
}

/// 写操作后的缓存失效：POST/PUT/DELETE 成功（2xx/3xx）即删除同路径前缀的
/// 缓存条目——否则改完设置/发完评论跳回来看到的是旧页面（像保存失败）。
/// 随后回收孤儿内容块（被删条目的内容若无残余引用 → 删块）。
pub(super) fn invalidate_after_write(host: &str, path: &str) {
    let prefix = format!("GET {host}{path}");
    let dir = page_cache_dir();
    let mut evicted: Vec<cacache::Integrity> = Vec::new();
    for entry in cacache::list_sync(&dir).flatten() {
        if entry.key.starts_with(&prefix) {
            evicted.push(entry.integrity.clone());
            let _ = cacache::remove_sync(&dir, &entry.key);
        }
    }
    gc_orphaned_content(&dir, &evicted);
}

/// 清空缓存（测试专用；生产路径靠容量淘汰与写失效，无定时清空）。
#[cfg(test)]
fn page_cache_clear() {
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

    /// 不可压缩的伪随机体（LCG）：cacache 压缩存储，重复内容会被压瘪，
    /// 容量淘汰测试必须用高熵内容才能让 on-disk size 接近原始体积。
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

    fn test_hdrs() -> Vec<Vec<String>> {
        vec![
            vec!["content-type".into(), "text/html; charset=utf-8".into()],
            vec!["etag".into(), "W/\"evict\"".into()],
        ]
    }

    /// 单测试顺序覆盖（OnceLock 全局只能设一次，多测试并行会互相踩目录）：
    /// roundtrip → 非 HTML 排除 → 排除名单 → 容量淘汰+孤儿回收 → 清空 → 写失效。
    #[tokio::test]
    async fn page_cache_disk_all_scenarios() {
        let dir = std::env::temp_dir().join(format!("gitport_pc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CACHE_DIR_OVERRIDE.set(dir.clone()).ok();

        // ① roundtrip：写入（直接走 blocking 写，避免与管家线程竞速）→ 命中带 hit 头
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
        let n = cacache::list_sync(&dir).filter_map(|r| r.ok()).count();
        assert_eq!(n, 1, "应有一个缓存条目");
        let (hit, etag) = page_cache_get("GET github.com/search?q=x-cabc").expect("应命中");
        assert_eq!(hit.headers().get("x-gitport-cache").unwrap(), "hit");
        assert_eq!(etag.as_deref(), Some("W/\"test\""));
        let bytes = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(bytes.as_ref(), b"<html>ok</html>");

        // ② 非 HTML 不缓存（is_html 闸门在投递前，无后台写无竞速）
        let resp = hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(BoxBody::new(
                http_body_util::Full::new(Bytes::from_static(b"{}"))
                    .map_err(std::io::Error::other),
            ))
            .unwrap();
        let log: LogFn = std::sync::Arc::new(|_: &str| {});
        let _ = collect_and_submit(&log, "GET github.com/api/x", resp).await;
        assert!(page_cache_get("GET github.com/api/x").is_none(), "非 HTML 不缓存");

        // ③ 排除名单定案（全量缓存，唯一禁区=登录态翻转三件套）：
        // 通知页同权（陈旧由用户自行刷新）；搜索碎片已被 sec-fetch-dest 闸门排除
        assert!(page_cache_allowed("/"));
        assert!(page_cache_allowed("/notifications"));
        assert!(page_cache_allowed("/search?q=x&type=repositories"));
        assert!(page_cache_allowed("/settings/profile"), "设置页已解除排除");
        assert!(!page_cache_allowed("/login"));
        assert!(!page_cache_allowed("/logout"));
        assert!(!page_cache_allowed("/session/xxx"));

        // ④ 容量淘汰（字节上限）+ 孤儿回收：1.2KB × 5 页，上限 2KB
        let small_cap: u64 = 2 * 1024;
        for i in 0..5 {
            let body = pseudo_body(i, 1200);
            let _ = persist_page_entry_blocking(
                &dir,
                &format!("GET github.com/p{i}"),
                body.as_bytes(),
                200,
                &test_hdrs(),
            );
            std::thread::sleep(std::time::Duration::from_millis(25)); // Windows 粗时钟：拉开索引 time
        }
        let entries: Vec<cacache::Metadata> =
            cacache::list_sync(&dir).filter_map(|r| r.ok()).collect();
        let total: u64 = entries.iter().map(|m| m.size as u64).sum();
        assert!(total > small_cap, "前提：插入总量超限，淘汰才该发生");
        enforce_page_cache_limit(&dir, small_cap);
        let entries: Vec<cacache::Metadata> =
            cacache::list_sync(&dir).filter_map(|r| r.ok()).collect();
        let total: u64 = entries.iter().map(|m| m.size as u64).sum();
        assert!(total <= small_cap, "淘汰后总体积应回到上限内");
        assert!(page_cache_get("GET github.com/p0").is_none(), "最旧应被淘汰");

        // ⑤ 清空：cacache 条目全没（page_cache_clear 是测试专用工具）
        page_cache_clear();
        let n = cacache::list_sync(&dir).filter_map(|r| r.ok()).count();
        assert_eq!(n, 0, "清空后条目应为零");

        // ⑥ 写操作失效：POST 成功后同路径前缀条目删除（设置页缓存的安全搭档）
        let sk = "GET github.com/settings/profile-cabc";
        let _ = persist_page_entry_blocking(&dir, sk, b"<html>s</html>", 200, &test_hdrs());
        assert!(page_cache_get(sk).is_some(), "前提：条目已缓存");
        invalidate_after_write("github.com", "/settings/profile");
        assert!(page_cache_get(sk).is_none(), "写操作后应失效");

        // ⑦ 会话指纹：_gh_sess 轮换不换键；user_session 变化换键；未登录固定标签
        let s1 = session_fingerprint(Some("user_session=abc; _gh_sess=r1"));
        let s1b = session_fingerprint(Some("user_session=abc; _gh_sess=r2"));
        let s2 = session_fingerprint(Some("user_session=def; _gh_sess=r1"));
        let s0 = session_fingerprint(None);
        assert_eq!(s1, s1b, "_gh_sess 轮换不应换键");
        assert_ne!(s1, s2, "换账号应换键");
        assert_eq!(s0, "-cloggedout", "未登录固定标签");
        assert_ne!(s1, s0, "登录/未登录必须分键");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
