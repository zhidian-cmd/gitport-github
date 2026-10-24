//! 页面缓存：GitHub 文档导航 GET 的本地秒回层（单文件存储 + 管家线程）。
//! 取：cache_take 直读 pages/<hash>，命中秒回、过 TTL 当 miss。
//! 存：cache_put 过闸（host 白名单 / 仅 200 / 正文类型 / ≤2MB / 会话污染）后投递 Save。
//! 存储：pages/<hash> = [4B BE 头长][header JSON][body]，tmp + rename 原子落盘。
//! 管家线程（串行、单条 panic 护栏）：落盘、Touch 刷 mtime、按前缀失效、容量管理。
//! 新鲜度：TTL 按 host（+动态页）分治，绝对时钟命中不续期 + POST 成功即删 + F5 绕过。
//! 容量：每累计 8MB 查一次；软顶 200MB 按 mtime 淘汰，硬顶 250MB 全清重来。
//! 红线：不做 SWR/后台 ETag 验证——_gh_sess 轮换，旧 cookie 重用被 GitHub
//!   判定账号泄露（详见 mitm/mod.rs 调用点）；也不用 cacache（去重/校验用不上，
//!   每次写入却要付全表扫描）。
use super::BoxBody;
use crate::pool::{now_ms, LogFn};
use crate::server::upstream::{self, Incoming};
use bytes::Bytes;
use http::{Method, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::OnceLock;

const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024; // 软顶：按 mtime 淘汰最旧
const PAGE_CACHE_HARD_BYTES: u64 = 250 * 1024 * 1024; // 硬顶：整个 pages 清空重来
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）
/// 增量记账步长：累计写入超此值才查一次容量（dirent+stat，不读内容）。
const CAPACITY_CHECK_STRIDE: u64 = 8 * 1024 * 1024;

/// 可缓存 host + 允许的正文类型。一张表：加域只改这里，
/// 准入（cache_host）与类型闸门（body_type_allowed）不会各改各的。
/// 其余内容域要么被 sec-fetch-dest 闸门挡掉，要么走流式路径到不了写入点。
const PAGE_CACHE_TYPES: &[(&str, &[&str])] = &[
    ("github.com", &["text/html"]),
    (
        "gist.githubusercontent.com",
        &["text/html", "text/plain", "text/markdown"],
    ),
    (
        "raw.githubusercontent.com",
        &["text/html", "text/plain", "text/markdown"],
    ),
];

fn cache_host(host: &str) -> bool {
    PAGE_CACHE_TYPES.iter().any(|(h, _)| *h == host)
}

/// TTL 按 host 分治。主站给长兜底（HTML 97% 是框架壳，动态数据走 XHR；
/// 要看最新按 F5 即直达上游）；raw 是分支寻址的直变文本，给短窗口。
const TTL_MS_GITHUB: u64 = 24 * 60 * 60 * 1000; // 24 小时：主站框架
const TTL_MS_GIST: u64 = 30 * 60 * 1000; // 30 分钟：gist 页面
const TTL_MS_RAW: u64 = 10 * 60 * 1000; // 10 分钟：raw 文本文件
const TTL_MS_DEFAULT: u64 = 30 * 60 * 1000; // 兜底（白名单外 host 本就走不到缓存）
/// 搜索/列表类动态页：SSR 内联的列表会变（新仓库、排序、个性化）。结果过时
/// 比慢更伤信任——用户反复刷新重搜，反而多打 GitHub。
const TTL_MS_DYNAMIC: u64 = 5 * 60 * 1000;
/// 动态页路径段：任一出现即短 TTL（搜索、列表、时间线、账号设置）。
/// 设置页是服务端渲染的真内容（邮箱、token 列表、SSH key），不是框架壳，
/// 别处改了这里要立刻能看到。
const DYNAMIC_SEGMENTS: &[&str] = &[
    "search", "issues", "pulls", "commits", "releases", "discussions",
    "notifications", "feed", "trending", "explore", "topics", "settings",
];

/// 动态页判定：带 query（?q= / ?page= / ?sort= …）或路径含动态段。
fn is_dynamic_page(path: &str, has_query: bool) -> bool {
    has_query || path.split('/').any(|seg| DYNAMIC_SEGMENTS.contains(&seg))
}

/// 按 host（+ 动态页判定）取 TTL（纯函数，便于测试）。
fn ttl_for(host: &str, path: &str, has_query: bool) -> u64 {
    if host == "github.com" && is_dynamic_page(path, has_query) {
        return TTL_MS_DYNAMIC;
    }
    match host {
        "github.com" => TTL_MS_GITHUB,
        "gist.githubusercontent.com" => TTL_MS_GIST,
        "raw.githubusercontent.com" => TTL_MS_RAW,
        _ => TTL_MS_DEFAULT,
    }
}

/// 管家线程的任务消息：落盘 / 摸热度 / 按前缀失效。
enum CacheMsg {
    Save {
        key: String,
        bytes: Bytes,
        status: u16,
        hdrs: Vec<Vec<String>>,
        cached_at: u64,
    },
    Touch {
        key: String,
    },
    /// 写操作成功后的缓存失效（异步，POST 响应路径不等它）。
    Invalidate {
        host: String,
        path: String,
    },
}

// ---------- 对外唯二入口 ----------

/// 取/存共用的可缓存判定。
fn cache_eligible(req: &hyper::Request<Incoming>, host: &str) -> bool {
    cache_host(host)
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

/// 时钟路由（纯判定，便于测试）：条目写入超 ttl → 过期。
fn ttl_expired(ttl_ms: u64, cached_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(cached_at_ms) > ttl_ms
}

/// 取路由：命中 = 纯本地读（对 GitHub 零请求）；过期或未命中 = None，走上游。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    if !cache_eligible(req, host) {
        return None;
    }
    let key = page_cache_key(
        req.uri(),
        host,
        req.headers().get("cookie").and_then(|v| v.to_str().ok()),
        upstream::accepts_gzip(req),
    );
    let (status, hdrs, body, cached_at_ms) = load_disk_entry(&key)?;
    let ttl = ttl_for(host, req.uri().path(), req.uri().query().is_some());
    if ttl_expired(ttl, cached_at_ms, now_ms()) {
        return None; // 过期 → 上游刷新
    }
    worker_send(CacheMsg::Touch { key }, log);
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
    // 只缓存 200：拦截页回放（封锁窗口过后仍是旧拦截页）与 304 空体回放
    // 都是实际踩过的坑。
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
    let cookies = req.headers().get("cookie").and_then(|v| v.to_str().ok());
    let key = page_cache_key(req.uri(), host, cookies, upstream::accepts_gzip(req));
    let has_session = session_value(cookies).is_some();
    collect_and_submit(log, host, &key, has_session, resp).await
}

// ---------- 内部：管家线程 ----------

static WORKER_SENDER: OnceLock<mpsc::SyncSender<CacheMsg>> = OnceLock::new();
static WORKER_LOG: OnceLock<LogFn> = OnceLock::new();

/// 向管家投递任务；筐满/管家不可用 = 丢弃并打日志（缓存写是 best-effort）。
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

/// 管家循环：串行消费任务筐，磁盘活都在这个线程上做（阻塞无害）。
/// 每条消息独立 panic 护栏——缓存无声停摆极难排查。
fn worker_loop(log: LogFn, rx: mpsc::Receiver<CacheMsg>) {
    while let Ok(msg) = rx.recv() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match msg {
                CacheMsg::Save {
                    key,
                    bytes,
                    status,
                    hdrs,
                    cached_at,
                } => {
                    let dir = page_cache_dir();
                    if let Err(e) = persist_page_entry_blocking(
                        &dir, &key, &bytes, status, &hdrs, cached_at,
                    ) {
                        (log)(&format!("[缓存] 后台写盘失败({e})，{key} 本次不缓存"));
                    }
                }
                CacheMsg::Touch { key } => {
                    touch_cache_entry_blocking(&page_cache_dir(), &key);
                }
                CacheMsg::Invalidate { host, path } => {
                    invalidate_prefix_blocking(&page_cache_dir(), &host, &path);
                }
            }
        }));
    }
}

/// 由 (status, 头对, 体) 重建缓存响应：命中路径唯一出口。
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

/// 确保 .cache 存在；本进程首次触达套一次 ACL（仅当前用户+SYSTEM）——
/// 页面含个人信息，不给同机其他账户留读取面。
fn ensure_cache_dir_with_acl(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    if CACHE_ACL_APPLIED.set(()).is_ok() {
        let _ = crate::winsec::restrict_dir_to_current_user(&dir.to_string_lossy());
    }
    true
}

/// 唯一路径禁区 = 登录态翻转三件套。登录表单的 CSRF token 绑定每请求轮换的
/// _gh_sess，旧 token 提交必被拒 = 锁死登录页；登出被截胡 = 假登出。
fn page_cache_allowed(path: &str) -> bool {
    !path.starts_with("/login")
        && !path.starts_with("/logout")
        && !path.starts_with("/session")
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

/// 缓存身份标签：未登录 = "-cloggedout"，登录 = "-c<账号>"。
/// 账号必须进键——同机两个 GitHub 账号（两个浏览器）都算"已登录"，
/// 只区分登录态会把 A 的设置页发给 B。账号取 dotcom_user；
/// 取不到就退回 user_session **值**的短哈希（Cookie 头里的 _gh_sess 每个响应都轮换，
/// 哈希整条会让键每请求变一次、缓存永远不命中）。
fn session_fingerprint(cookies: Option<&str>) -> String {
    let Some(sess) = session_value(cookies) else {
        return "-cloggedout".into();
    };
    match account_name(cookies) {
        Some(u) => format!("-c{u}"),
        None => format!("-cs{:016x}", fnv1a(sess)),
    }
}

/// 缓存键 = 方法 + host + 路径/查询 + 身份标签 + 编码标签。
/// 纯函数：身份与编码都由调用方给，测试能直接钉住两类串页边界。
fn page_cache_key(uri: &http::Uri, host: &str, cookies: Option<&str>, gzip: bool) -> String {
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    // 会话指纹进键：登录/登出态、以及不同账号的同一 URL 页面内容不同，防串页
    let cookie_tag = session_fingerprint(cookies);
    // 编码进键：浏览器那条存的是 gzip，没声明 gzip 的 curl 命中同一条只会拿到压缩乱码
    let enc_tag = if gzip { "-gz" } else { "-id" };
    format!("GET {host}{}{q}{cookie_tag}{enc_tag}", uri.path())
}

/// 「这段正文是不是 gzip」的唯一判定：存/取两侧的污染检测都按它决定要不要先解压。
fn is_gzip_encoding(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("gzip")
}

/// 未登录页检测：带会话却拿到这类 body = 会话已死，不存也不当命中（防污染）。
/// 必须先按编码解一段再扫——主站正文恒 gzip，直接扫压缩字节永远扫不到这几个字面量。
fn is_logged_out_body(bytes: &[u8], gzip: bool) -> bool {
    let plain = if gzip {
        super::defuse::gunzip_partial(bytes, 8192)
    } else {
        bytes[..bytes.len().min(4096)].to_vec()
    };
    let chunk = String::from_utf8_lossy(&plain);
    chunk.contains("logged-out env-") || chunk.contains("class=\"logged-out")
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

/// 读单文件条目 → (status, 头对, 体, cached_at)。缺环/损坏/截断/非 200 = None
/// （miss 自愈，下次访问重写覆盖）。
fn load_disk_entry(
    key: &str,
) -> Option<(
    u16,
    Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    Bytes,
    u64,
)> {
    let raw = std::fs::read(page_cache_dir().join("pages").join(page_file_name(key))).ok()?;
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
    if is_logged_out_body(body, gzip) {
        return None; // 未登录污染条目：当作 miss
    }
    // 无此字段视为远古：过期 = miss，被重写覆盖。
    let cached_at_ms = header.get("cachedAt").and_then(|v| v.as_u64()).unwrap_or(0);
    Some((status, hdrs, Bytes::copy_from_slice(body), cached_at_ms))
}

/// 测试专用：绕开准入直读磁盘，返回重建响应 + cached_at。
#[cfg(test)]
fn page_cache_get(
    key: &str,
) -> Option<(axum::response::Response<BoxBody>, u64)> {
    let (status, hdrs, body, cached_at) = load_disk_entry(key)?;
    Some((rebuild_cached_response(status, &hdrs, body), cached_at))
}

// ---------- 内部：容量管理（单文件存储，无孤儿概念） ----------

/// 增量记账（管家线程单线程消费，无并发竞态）。
static BYTES_SINCE_CHECK: AtomicU64 = AtomicU64::new(0);

fn maybe_enforce_capacity(dir: &std::path::Path, incoming: usize) {
    let pending =
        BYTES_SINCE_CHECK.fetch_add(incoming as u64, Ordering::Relaxed) + incoming as u64;
    if pending >= CAPACITY_CHECK_STRIDE {
        BYTES_SINCE_CHECK.store(0, Ordering::Relaxed);
        enforce_capacity(dir, PAGE_CACHE_MAX_BYTES, PAGE_CACHE_HARD_BYTES);
    }
}

/// 容量管理：dirent + stat，不读内容。硬顶全清 > 软顶按 mtime 删最旧；
/// 顺手清 tmp 残留（进程被杀时的 rename 垃圾）。
fn enforce_capacity(dir: &std::path::Path, soft_cap: u64, hard_cap: u64) {
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
    let pages = dir.join("pages");
    let Ok(rd) = std::fs::read_dir(&pages) else {
        return;
    };
    let mut entries: Vec<(std::path::PathBuf, std::time::SystemTime, u64)> = Vec::new();
    let mut total = 0u64;
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        total = total.saturating_add(md.len());
        entries.push((e.path(), md.modified().unwrap_or(std::time::UNIX_EPOCH), md.len()));
    }
    if total >= hard_cap {
        let _ = std::fs::remove_dir_all(&pages);
        let _ = std::fs::create_dir_all(&pages);
        return;
    }
    if total <= soft_cap {
        return;
    }
    // mtime 升序删最旧；同时刻按路径字典序，顺序确定不漂移
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let mut acc = total;
    for (p, _, sz) in entries {
        if acc <= soft_cap {
            break;
        }
        let _ = std::fs::remove_file(&p);
        acc = acc.saturating_sub(sz);
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

/// 摸一下：只刷 mtime（淘汰热度），cached_at（TTL 基准）不动。
fn touch_cache_entry_blocking(dir: &std::path::Path, key: &str) {
    let Ok(f) = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("pages").join(page_file_name(key)))
    else {
        return;
    };
    let times = std::fs::FileTimes::new().set_modified(std::time::SystemTime::now());
    let _ = f.set_times(times);
}

/// 落盘：tmp 写全量 + rename 原子覆盖（Windows 上即原子覆盖，实测确认），
/// 永远存不出半页。cached_at 写进 header，Touch 只刷 mtime 时它不动。
fn persist_page_entry_blocking(
    dir: &std::path::Path,
    key: &str,
    bytes: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
    cached_at: u64,
) -> Result<(), String> {
    if !ensure_cache_dir_with_acl(dir) {
        return Err("缓存目录创建失败".to_string());
    }
    purge_legacy_cache(dir);
    maybe_enforce_capacity(dir, 4 + bytes.len());
    let header = serde_json::json!({
        "key": key,
        "status": status,
        "headers": hdrs,
        "cachedAt": cached_at,
    });
    let hbytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    let pages = dir.join("pages");
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

/// 正文类型闸门（表驱动，与 cache_host 同源）：主站只收 HTML；gist/raw 加纯文本
/// （浏览器直开 raw 是 document 导航但内容是 text/plain）。二进制一律不收。
fn body_type_allowed(host: &str, content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return false };
    let ct = ct.trim();
    PAGE_CACHE_TYPES
        .iter()
        .find(|(h, _)| *h == host)
        .map(|(_, types)| types.iter().any(|t| ct.starts_with(t)))
        .unwrap_or(false)
}

/// 收集体、复判（体积/会话污染）后投递 Save；响应原样或重建交给浏览器。
async fn collect_and_submit(
    log: &LogFn,
    host: &str,
    key: &str,
    has_session: bool,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let allowed = body_type_allowed(
        host,
        parts.headers.get("content-type").and_then(|v| v.to_str().ok()),
    );
    if !allowed {
        return hyper::Response::from_parts(parts, body);
    }
    // gh_defuse 嗅探时已读走的前几帧存在 PeekRaw 里：不拼回去等于给浏览器半张页面，
    // 还会把半页写进缓存（github.com 24h）——网络早恢复了页面一直是坏的。
    let mut peek: Vec<u8> = Vec::new();
    if let Some(p) = parts.extensions.remove::<super::PeekRaw>() {
        for b in p.0 {
            peek.extend_from_slice(&b);
        }
    }
    // 污染检测要先解开正文才看得见标记：主站正文恒 gzip（上游强制）。
    let gzip = parts
        .headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(is_gzip_encoding)
        .unwrap_or(false);
    // Set-Cookie 只从缓存元数据里剔除（防命中回灌旧值）；响应原样给浏览器，
    // 剥离会让 cookie jar 冻结、轮换后变未登录页。
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
            // 可缓存 = 体积达标 且 非"带会话却拿到未登录页"（会话死亡防污染）
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
                && !(has_session && is_logged_out_body(&bytes, gzip));
            if cacheable {
                let status = parts.status.as_u16();
                worker_send(
                    CacheMsg::Save {
                        key: key.to_string(),
                        bytes: bytes.clone(), // Bytes 引用计数浅克隆，跨线程零拷贝
                        status,
                        hdrs: cache_hdrs,
                        cached_at: now_ms(),
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

/// 写后失效：删同路径前缀的页面文件。文件名是哈希，只能读每个文件的
/// header 段做前缀匹配（不读 body）；低频事件，管家线程异步做。
///
/// 写端点几乎都是子路径（评论 POST `/o/r/issues/5/comment`、star POST `/o/r/star`），
/// 页面在**父路径**上——只匹配自身路径会一条都删不掉。父路径至少两级才收，
/// 免得 `/o` 这种根前缀把整片缓存扫光。
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

/// 写后失效入口：改完设置/发完评论跳回来必须看到新页面（否则像保存失败）。
/// 只投消息，磁盘删除交给管家线程。
pub(super) fn invalidate_after_write(log: &LogFn, host: &str, path: &str) {
    worker_send(
        CacheMsg::Invalidate {
            host: host.to_string(),
            path: path.to_string(),
        },
        log,
    );
}

/// 清空缓存（测试专用；生产路径靠容量淘汰与写失效，无定时清空）。
#[cfg(test)]
fn page_cache_clear() {
    BYTES_SINCE_CHECK.store(0, Ordering::Relaxed);
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

    /// 目录覆盖是进程级单值（管家线程也要看得见），所以取目录时用一把锁串行、
    /// 每个测试分到自己的临时目录：一个场景失败不再挡住其他场景。
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

    /// 不可压缩的伪随机体（LCG）：高熵内容，容量淘汰测试的 on-disk size
    /// 才能接近原始体积。
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

    /// A. 读/写往返、正文类型闸门、坏文件自愈、PeekRaw 前缀拼回。
    #[tokio::test]
    async fn roundtrip_gates_and_self_heal() {
        let (dir, _dir_guard) = own_dir("rw");
        let log = log_sink();

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
            now_ms(),
        )
        .unwrap();
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 1, "应有一个缓存条目");
        let (hit, cached_at) = page_cache_get("GET github.com/search?q=x-cabc").expect("应命中");
        assert_eq!(hit.headers().get("x-gitport-cache").unwrap(), "hit");
        assert!(
            now_ms().saturating_sub(cached_at) < 60_000,
            "cached_at 应为写入时刻: {cached_at}"
        );
        let bytes = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(bytes.as_ref(), b"<html>ok</html>");

        // ② 非 HTML 不缓存（body_type_allowed 闸门在投递前，无后台写无竞速）
        let resp = hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(upstream::full_body(Bytes::from_static(b"{}")))
            .unwrap();
        let _ = collect_and_submit(&log, "github.com", "GET github.com/api/x", false, resp).await;
        assert!(page_cache_get("GET github.com/api/x").is_none(), "非 HTML 不缓存");

        // ②b 正文类型闸门按 host 放行：raw/gist 的 text/plain 可缓存，
        // github.com 的 text/plain 与 raw 的二进制仍不收
        assert!(body_type_allowed("github.com", Some("text/html; charset=utf-8")));
        assert!(!body_type_allowed("github.com", Some("text/plain")));
        assert!(body_type_allowed(
            "raw.githubusercontent.com",
            Some("text/plain; charset=utf-8")
        ));
        assert!(body_type_allowed(
            "gist.githubusercontent.com",
            Some("text/plain; charset=utf-8")
        ));
        assert!(!body_type_allowed(
            "raw.githubusercontent.com",
            Some("application/octet-stream")
        ));
        assert!(!body_type_allowed("raw.githubusercontent.com", None));
        // 白名单单一来源：类型表里的每个 host 都必须同时过准入（不会一边加一边忘）
        for (h, _) in PAGE_CACHE_TYPES {
            assert!(cache_host(h), "{h} 在类型表里但过不了准入");
            assert!(body_type_allowed(h, Some("text/html")), "{h} 应允许 HTML");
        }
        assert!(!cache_host("example.com"), "表外 host 不得可缓存");

        // ③ 覆盖写与坏文件自愈（单文件 rename 语义）：
        // 同 key 重写读到新内容（rename 原子覆盖，无窗口无半页）；
        // 截断文件 = miss 自愈（不服务半页）；header key 不符 = 拒服（防串页）。
        let ck = "GET github.com/cover-me";
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v1</html>", 200, &test_hdrs(), now_ms());
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v2</html>", 200, &test_hdrs(), now_ms());
        let (hit, _) = page_cache_get(ck).expect("覆盖写后应命中");
        let v = http_body_util::BodyExt::collect(hit.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(v.as_ref(), b"<html>v2</html>", "覆盖写应读到新内容");
        // 截断文件 = miss（模拟写一半进程被杀，下次重写覆盖）
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

        // ④ PeekRaw 前缀必须拼回：gh_defuse 嗅探吃掉的前几帧不能丢，
        // 否则半页交付给浏览器、半页进缓存躺 24h。
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
            collect_and_submit(&log, "github.com", "GET github.com/peek", false, sniffed).await;
        let body = http_body_util::BodyExt::collect(out.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            body.as_ref(),
            b"<html>hello world</html>",
            "嗅探前缀丢失 = 交付半页"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B. 容量：软顶按 mtime 淘汰最旧、硬顶整个清空、清空工具。
    #[test]
    fn capacity_soft_and_hard() {
        let (dir, _dir_guard) = own_dir("cap");

        // ⑤ 容量淘汰（软顶按 mtime 删最旧）：1.2KB × 5 页，上限 2KB。
        // 硬顶给 u64::MAX——硬顶熔断（全清）单独在 ⑤b 验。
        let small_cap: u64 = 2 * 1024;
        for i in 0..5 {
            let body = pseudo_body(i, 1200);
            let _ = persist_page_entry_blocking(
                &dir,
                &format!("GET github.com/p{i}"),
                body.as_bytes(),
                200,
                &test_hdrs(),
                now_ms(),
            );
            std::thread::sleep(std::time::Duration::from_millis(25)); // Windows 粗时钟：拉开 mtime
        }
        let (_, total) = pages_stat(&dir);
        assert!(total > small_cap, "前提：插入总量超限，淘汰才该发生: {total}");
        enforce_capacity(&dir, small_cap, u64::MAX);
        let (_, total) = pages_stat(&dir);
        assert!(total <= small_cap, "淘汰后总体积应回到上限内: {total}");
        assert!(page_cache_get("GET github.com/p0").is_none(), "最旧应被淘汰");
        assert!(
            page_cache_get("GET github.com/p4").is_some(),
            "最新应保留"
        );

        // ⑤b 硬顶熔断：总量超硬顶 → 整个 pages 清空重来（网页缓存而已）
        for i in 0..3 {
            let body = pseudo_body(10 + i, 1200);
            let _ = persist_page_entry_blocking(
                &dir,
                &format!("GET github.com/hard{i}"),
                body.as_bytes(),
                200,
                &test_hdrs(),
                now_ms(),
            );
        }
        let (_, total_before) = pages_stat(&dir);
        let hard_cap: u64 = 3 * 1024;
        assert!(total_before > hard_cap, "前提：总量超硬顶: {total_before}");
        enforce_capacity(&dir, u64::MAX, hard_cap);
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 0, "超硬顶应清空全部: {n}");

        // ⑥ 清空：pages 条目全没（page_cache_clear 是测试专用工具）
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/again",
            b"<html>a</html>",
            200,
            &test_hdrs(),
            now_ms(),
        );
        assert!(page_cache_get("GET github.com/again").is_some(), "前提：有条目");
        page_cache_clear();
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 0, "清空后条目应为零");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C. 键的语义（路径禁区 / TTL / 身份 / 编码）、写后失效、未登录页防污染、Touch。
    #[tokio::test]
    async fn keys_ttl_invalidation_and_pollution() {
        let (dir, _dir_guard) = own_dir("key");
        let log = log_sink();

        // ⑦ 排除名单定案（全量缓存，唯一禁区=登录态翻转三件套）
        assert!(page_cache_allowed("/"));
        assert!(page_cache_allowed("/notifications"));
        assert!(page_cache_allowed("/search?q=x&type=repositories"));
        assert!(page_cache_allowed("/settings/profile"), "设置页已解除排除");
        assert!(!page_cache_allowed("/login"));
        assert!(!page_cache_allowed("/logout"));
        assert!(!page_cache_allowed("/session/xxx"));

        // ⑧ 时钟路由（纯判定）：TTL 内不过期，超 TTL 过期
        assert!(!ttl_expired(TTL_MS_DEFAULT, now_ms() - 29 * 60 * 1000, now_ms()));
        assert!(ttl_expired(TTL_MS_DEFAULT, now_ms() - 31 * 60 * 1000, now_ms()));
        assert!(ttl_expired(TTL_MS_DEFAULT, 0, now_ms()), "_epoch 视为远古条目: 过期");
        // per-host TTL：主站框架 24h / gist 30min / raw 10min / 兜底 30min
        assert_eq!(ttl_for("github.com", "/", false), 24 * 60 * 60 * 1000);
        assert_eq!(ttl_for("gist.githubusercontent.com", "/u/abc", false), 30 * 60 * 1000);
        assert_eq!(ttl_for("raw.githubusercontent.com", "/u/r/main/f.txt", false), 10 * 60 * 1000);
        assert_eq!(ttl_for("example.com", "/", false), TTL_MS_DEFAULT, "名单外走兜底");
        // 动态页短窗口：搜索/列表/带 query 一律 5min（结果会变，过时比慢更伤）
        assert_eq!(ttl_for("github.com", "/search", false), TTL_MS_DYNAMIC);
        assert_eq!(ttl_for("github.com", "/search", true), TTL_MS_DYNAMIC);
        assert_eq!(ttl_for("github.com", "/dotnetcore/CAP/issues", false), TTL_MS_DYNAMIC);
        assert_eq!(ttl_for("github.com", "/dotnetcore/CAP/commits/main", false), TTL_MS_DYNAMIC);
        assert_eq!(ttl_for("github.com", "/feed", false), TTL_MS_DYNAMIC);
        assert_eq!(
            ttl_for("github.com", "/dotnetcore/CAP", true),
            TTL_MS_DYNAMIC,
            "带 query 的仓库页也算动态视图"
        );
        assert_eq!(
            ttl_for("github.com", "/dotnetcore/CAP", false),
            24 * 60 * 60 * 1000,
            "仓库首帧仍吃长桶"
        );
        // gist/raw 不参与动态页规则
        assert_eq!(ttl_for("gist.githubusercontent.com", "/u/abc", true), 30 * 60 * 1000);
        assert_eq!(ttl_for("raw.githubusercontent.com", "/u/r/main/f.txt", true), 10 * 60 * 1000);
        // 24h 窗口：23h 前写入不过期，25h 前过期
        assert!(!ttl_expired(
            ttl_for("github.com", "/", false),
            now_ms() - 23 * 60 * 60 * 1000,
            now_ms()
        ));
        // 设置页吃短窗：正文是真表单值（邮箱/token/SSH key），别处改完要立刻看到
        assert_eq!(
            ttl_for("github.com", "/settings/profile", false),
            TTL_MS_DYNAMIC,
            "设置页不该吃 24h 桶"
        );
        assert_eq!(
            ttl_for("github.com", "/settings/tokens/new", false),
            TTL_MS_DYNAMIC
        );
        assert!(ttl_expired(
            ttl_for("github.com", "/", false),
            now_ms() - 25 * 60 * 60 * 1000,
            now_ms()
        ));
        // 动态页 5min 窗口：3min 不过期，6min 过期
        assert!(!ttl_expired(
            ttl_for("github.com", "/search", false),
            now_ms() - 3 * 60 * 1000,
            now_ms()
        ));
        assert!(ttl_expired(
            ttl_for("github.com", "/search", false),
            now_ms() - 6 * 60 * 1000,
            now_ms()
        ));
        // raw 10min 窗口：9min 不过期，11min 过期
        assert!(!ttl_expired(
            ttl_for("raw.githubusercontent.com", "/u/r/main/f.txt", false),
            now_ms() - 9 * 60 * 1000,
            now_ms()
        ));
        assert!(ttl_expired(
            ttl_for("raw.githubusercontent.com", "/u/r/main/f.txt", false),
            now_ms() - 11 * 60 * 1000,
            now_ms()
        ));

        // ⑨ 写操作失效：POST 成功后同路径前缀条目删除（设置页缓存的安全搭档）。
        // 磁盘删除在管家线程内执行（请求路径只投消息），这里直接驱动 blocking
        // 本体验证删除语义。
        let sk = "GET github.com/settings/profile-cabc";
        let _ = persist_page_entry_blocking(&dir, sk, b"<html>s</html>", 200, &test_hdrs(), now_ms());
        assert!(page_cache_get(sk).is_some(), "前提：条目已缓存");
        invalidate_after_write(&log, "github.com", "/settings/profile");
        invalidate_prefix_blocking(&dir, "github.com", "/settings/profile");
        assert!(page_cache_get(sk).is_none(), "写操作后磁盘条目应失效");

        // ⑨b 子路径写端点：评论 POST /o/r/issues/5/comment，页面在父路径 /o/r/issues/5。
        // 只匹配自身路径一条都删不掉（这正是旧版"评论完看不到新评论"的原因）。
        let issue_key = "GET github.com/o/r/issues/5-calice-gz";
        let other_key = "GET github.com/o/r/pulls/9-calice-gz";
        for k in [issue_key, other_key] {
            let _ = persist_page_entry_blocking(
                &dir,
                k,
                b"<html>i</html>",
                200,
                &test_hdrs(),
                now_ms(),
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

        // ⑪ 未登录页写入防污染：请求带会话（has_session=true）但响应是
        // 未登录页（body 含 logged-out 标记）→ 不缓存
        let poisoned = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(upstream::full_body(Bytes::from_static(
                b"<html><body class=\"logged-out env-production\">sign in</body></html>",
            )))
            .unwrap();
        let _ = collect_and_submit(&log, "github.com", "GET github.com/-cauthed-poison", true, poisoned).await;
        assert!(
            page_cache_get("GET github.com/-cauthed-poison").is_none(),
            "会话死亡期间的未登录页不得进缓存"
        );

        // ⑪b gzip 正文：不解压就永远看不到标记（主站正文恒 gzip，旧版这道守卫等于没有）
        let mut html = b"<html><body class=\"logged-out env-production\">".to_vec();
        html.extend_from_slice(&vec![b'x'; 6000]);
        html.extend_from_slice(b"</body></html>");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &html).unwrap();
        let gzbody = enc.finish().unwrap();
        assert!(
            !is_logged_out_body(&gzbody, false),
            "压缩体裸扫扫不到——这就是旧版失效的原因"
        );
        assert!(is_logged_out_body(&gzbody, true), "解压后必须认出未登录页");
        let poisoned_gz = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .header("content-encoding", "gzip")
            .body(upstream::full_body(Bytes::from(gzbody)))
            .unwrap();
        let _ = collect_and_submit(
            &log,
            "github.com",
            "GET github.com/-cauthed-gz-poison",
            true,
            poisoned_gz,
        )
        .await;
        assert!(
            page_cache_get("GET github.com/-cauthed-gz-poison").is_none(),
            "gzip 未登录页同样不得入缓存"
        );

        // ⑫ Touch 保留 cachedAt（TTL 基准不被摸掉）：写入带 cachedAt=旧值 →
        // touch 后重读，cachedAt 不变（淘汰热度刷新但新鲜度基准不动）
        let old_ts = now_ms() - 10 * 60 * 1000;
        let _ = persist_page_entry_blocking(
            &dir,
            "GET github.com/touch-me",
            b"<html>t</html>",
            200,
            &test_hdrs(),
            old_ts,
        );
        touch_cache_entry_blocking(&dir, "GET github.com/touch-me");
        let (_, touched_at) = page_cache_get("GET github.com/touch-me").expect("touch 后应可读");
        assert_eq!(touched_at, old_ts, "Touch 不得刷新 cached_at（TTL 基准）");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
