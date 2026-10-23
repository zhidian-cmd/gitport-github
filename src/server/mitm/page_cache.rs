//! 页面缓存（github.com 文档导航 GET，cacache 内容寻址磁盘缓存）。
//! 命中秒回 + 后台 SWR 保鲜（10 分钟窗口）+ 会话指纹键 + 200MB 字节上限。
use super::{get_direct, BoxBody, UpstreamInfo};
use crate::server::upstream::Incoming;
use crate::pool::LogFn;
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ---------- 页面缓存（github.com 文档导航 GET，cacache 内容寻址磁盘缓存）----------
// 存放：exe 同目录 .cache/（自动生成，cacache 格式：内容寻址 + 键索引 + 元数据）。
// 新鲜度：命中即秒回（零上游请求）；距上次后台验证超过窗口（10 分钟）才追加一条
// If-None-Match 条件请求（带会话 cookie，GitHub 实测支持 304）——
// 304 只记账、200 静默换新、404/410 删死链。休眠期无命中，验证自然停摆。
// 删除：持续 2.5 小时无流量 → 整目录清空（last_activity 跨重启记账）；
// 容量：条目体积合计超 200MB → 按写入时间淘汰最旧。
// cookie 语义：单用户本地代理，cookie 全量转发 GitHub（等同浏览器行为）；
// 仅镜像腿剥离（镜像站是第三方，不认识会话，剥离防凭证泄露）。
const PAGE_CACHE_IDLE_SECS: u64 = 150 * 60; // 2.5 小时
const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024;
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const VALIDATE_WINDOW_MS: u64 = 10 * 60 * 1000; // 同页验证窗口
const VALIDATE_COOLDOWN_MS: u64 = 2000; // 全局验证冷却（防点击风暴）

static LAST_ACTIVITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ACTIVITY_LAST_WRITE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// 每个缓存页上次后台验证的时间（毫秒历元）。内存态即可：重启后为空，
/// 每页首次命中验证一次，本来就是正确语义。
static LAST_VERIFIED: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static LAST_VALIDATE_START: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---------- 对外唯二入口：取 / 存 ----------
// 知识收拢：可缓存判定、键构造（含会话指纹）、窗口节流、元数据与索引、
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
        && page_cache_allowed(&req.uri().path().to_string(), has_session_cookie(req))
}

/// 取路由：主调用路径唯一入口。闲置记账与安全网清空在此收口；
/// 命中返回 (响应, etag) 并按窗口派生后台 SWR 验证；未命中/不可缓存 = None。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<(axum::response::Response<BoxBody>, Option<String>)> {
    if touch_activity() {
        page_cache_clear(); // 2.5h 无流量的磁盘安全网
    }
    if !cache_eligible(req, host) {
        return None;
    }
    let key = page_cache_key(req, host);
    let (cached, etag) = page_cache_get(&key)?;
    (log)(&format!("[缓存] 命中 {}", req.uri()));
    // SWR：同页验证窗口（10 分钟）过期且过全局冷却 → 后台一次
    // If-None-Match 静默保鲜（带会话 cookie）。窗口内点多少次都不问。
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
        let cookies = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
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
        let log2 = log.clone();
        let key2 = key.clone();
        let etag2 = etag.clone().unwrap_or_default();
        tokio::spawn(async move {
            swr_revalidate(&log2, &key2, &pq, cookies, ua, etag2).await;
        });
    }
    Some((cached, etag))
}

/// 存路由：上游响应唯一入口。内部复判可缓存性、构造键（含会话指纹）、
/// 剥离 Set-Cookie、写元数据与索引、容量淘汰；不可缓存原样透传。
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
    page_cache_collect_and_dispatch(log, key, resp).await
}

#[cfg(test)]
static CACHE_DIR_OVERRIDE: std::sync::OnceLock<std::path::PathBuf> =
    std::sync::OnceLock::new();

fn last_verified_map() -> &'static Mutex<HashMap<String, u64>> {
    LAST_VERIFIED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn page_cache_dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(d) = CACHE_DIR_OVERRIDE.get() {
        return d.clone();
    }
    crate::settings::exe_dir().join(".cache")
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

/// 上次流量的记账秒数：先读内存，首次从文件恢复（跨重启仍能判定闲置时长）。
fn last_activity_secs() -> u64 {
    let mem = LAST_ACTIVITY.load(std::sync::atomic::Ordering::Relaxed);
    if mem != 0 {
        return mem;
    }
    let f = page_cache_dir().join("last_activity");
    let v = std::fs::read_to_string(f)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    LAST_ACTIVITY.store(v, std::sync::atomic::Ordering::Relaxed);
    v
}

/// 记一次流量，并判断是否应清空缓存（持续 PAGE_CACHE_IDLE_SECS 无流量，跨重启生效）。
/// 记账文件最多 30s 落盘一次（每请求写盘太吵）。
fn touch_activity() -> bool {
    let now = now_secs();
    let prev = last_activity_secs();
    LAST_ACTIVITY.store(now, std::sync::atomic::Ordering::Relaxed);
    let last_write = ACTIVITY_LAST_WRITE.load(std::sync::atomic::Ordering::Relaxed);
    if last_write == 0 || now.saturating_sub(last_write) >= 30 {
        ACTIVITY_LAST_WRITE.store(now, std::sync::atomic::Ordering::Relaxed);
        let dir = page_cache_dir();
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("last_activity"), now.to_string());
    }
    prev != 0 && now.saturating_sub(prev) > PAGE_CACHE_IDLE_SECS
}

/// 清空缓存（保留 last_activity 记账文件，不能用 cacache::clear_sync——
/// 它会把目录里所有条目连记账文件一起 remove_dir_all）。
fn page_cache_clear() {
    let dir = page_cache_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_name() == "last_activity" {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            let _ = std::fs::remove_dir_all(&p);
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
    last_verified_map().lock().unwrap().clear();
}

/// 浏览器是否带着 GitHub 会话 cookie（登录态标志）。
fn has_session_cookie(req: &hyper::Request<Incoming>) -> bool {
    req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("user_session") || c.contains("logged_in"))
        .unwrap_or(false)
}

/// 页面可缓存判定。
/// 根路径按登录态分治（用户定案）：未登录（无会话 cookie）的营销页长期稳定，
/// 可缓存、回访秒开；登录态下 / 会 302 仪表盘（本就不落盘）；**会话已死但
/// cookie 还在的中间态明确不缓存**——防"死会话看到的页面"污染登录态键（实测踩过）。
fn page_cache_allowed(path: &str, has_session: bool) -> bool {
    if path == "/" {
        return !has_session;
    }
    !path.starts_with("/notifications")
        && !path.starts_with("/settings")
        && !path.starts_with("/login")
        && !path.starts_with("/logout")
        && !path.starts_with("/session")
        && !path.starts_with("/search/count")
        && !path.starts_with("/search/blackbird")
        && !path.starts_with("/search/warm")
}

fn page_cache_key(req: &hyper::Request<Incoming>, host: &str) -> String {
    let uri = req.uri();
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    // 会话身份进键：登录/登出态的同一 URL 页面内容不同，防串页
    let cookie_tag = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|c| format!("-c{}", {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in c.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x100000001b3);
            }
            format!("{h:016x}")
        }))
        .unwrap_or_else(|| "-c0".into());
    format!("GET {host}{}{q}{cookie_tag}", uri.path())
}

/// 命中缓存：返回重建的响应 + 该页的 ETag（后台验证用）。
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

/// 淘汰超限的最旧页面（按 cacache 索引的写入时间），直到总体积回到上限内。
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
    for m in sorted {
        if acc <= cap_bytes {
            break;
        }
        acc = acc.saturating_sub(m.size as u64);
        let _ = cacache::remove_sync(dir, &m.key);
    }
}

/// 缓冲 200 text/html 页面进 cacache（≤2MB；Set-Cookie 不落盘，防旧会话回灌），
/// 并原样重建响应交付。
/// 前台半段：收集体（≤2MB 保护）→ 立即克隆构建响应交还浏览器；
/// 写盘整体丢给后台（spawn_blocking），主路径零磁盘等待。
async fn page_cache_collect_and_dispatch(
    log: &LogFn,
    key: String,
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
                let dir = page_cache_dir();
                let log2 = log.clone();
                let key2 = key.clone();
                let write_bytes = bytes.clone();
                // 后台写盘：失败只打日志，与当前请求无关
                tokio::spawn(async move {
                    let r = tokio::task::spawn_blocking(move || {
                        persist_page_entry_blocking(&dir, &key2, &write_bytes, status, &hdrs)
                    })
                    .await;
                    if let Err(e) = r {
                        (log2)(&format!("[缓存] 后台写盘失败({e})，{} 本次不缓存", key));
                    }
                });
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
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from_static(b"page collect failed"))
                        .map_err(std::io::Error::other),
                ))
                .unwrap()
        }
    }
}

/// 后台半段（spawn_blocking 内执行）：建目录 → 容量淘汰 → 写 cacache 条目。
fn persist_page_entry_blocking(
    dir: &std::path::Path,
    key: &str,
    bytes: &[u8],
    status: u16,
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
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

/// 后台 SWR 验证：If-None-Match 条件请求（带会话 cookie + 命中时捕获的 UA）。
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
            let _ = page_cache_collect_and_dispatch(log, key.to_string(), resp).await;
        }
        404 | 410 => {
            (log)(&format!("[缓存] 后台验证 404，{} 已是死链，删除", path_and_query));
            let _ = cacache::remove_sync(&page_cache_dir(), key);
            last_verified_map().lock().unwrap().remove(key);
        }
        _ => {}
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
    /// roundtrip → 非 HTML 排除 → 排除名单 → 验证窗口判定 → 容量淘汰 → 清空。
    #[tokio::test]
    async fn page_cache_disk_all_scenarios() {
        let dir = std::env::temp_dir().join(format!("gitport_pc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CACHE_DIR_OVERRIDE.set(dir.clone()).ok();
        assert!(!touch_activity(), "首次流量不触发清空");

        // ① roundtrip：写入（直接走 blocking 写，避免与后台写竞速）→ 命中带 hit 头 + etag 回传
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

        // ② 非 HTML 不缓存
        let resp = hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(BoxBody::new(
                http_body_util::Full::new(Bytes::from_static(b"{}"))
                    .map_err(std::io::Error::other),
            ))
            .unwrap();
        let log: LogFn = std::sync::Arc::new(|_: &str| {});
        let _ = page_cache_collect_and_dispatch(&log, "GET github.com/api/x".into(), resp).await;
        assert!(page_cache_get("GET github.com/api/x").is_none(), "非 HTML 不缓存");

        // ③ 排除名单；根路径分状态（用户定案）：未登录营销页可缓存，
        // 登录态/死会话中间态不缓存（实测踩过：未登录首页缓存回放）
        assert!(page_cache_allowed("/", false), "未登录营销页可缓存");
        assert!(!page_cache_allowed("/", true), "登录态下 / 会 302，不缓存");
        assert!(!page_cache_allowed("/notifications", false));
        assert!(!page_cache_allowed("/search/count?q=x", false));
        assert!(page_cache_allowed("/search?q=x&type=repositories", false));

        // ④ 验证窗口判定（纯逻辑）：未验证 → due；窗口内 → not due；超窗 → due
        let mut vmap: HashMap<String, u64> = HashMap::new();
        assert!(validation_due(&vmap, "k", 10_000_000));
        mark_validated(&mut vmap, "k", 10_000_000);
        assert!(!validation_due(&vmap, "k", 10_000_000 + VALIDATE_WINDOW_MS - 1));
        assert!(validation_due(&vmap, "k", 10_000_000 + VALIDATE_WINDOW_MS));

        // ⑤ 容量淘汰（字节上限）：1KB × 5 页，上限 2KB → 淘汰最旧直到 ≤2KB
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

        // ⑥ 清空：cacache 条目全没，last_activity 记账保留
        page_cache_clear();
        let n = cacache::list_sync(&dir).filter_map(|r| r.ok()).count();
        assert_eq!(n, 0, "清空后条目应为零");
        assert!(dir.join("last_activity").exists(), "记账文件应保留");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
