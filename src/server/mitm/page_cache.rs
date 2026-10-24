//! 页面缓存（文档导航 GET，单文件存储 + 管家线程）。
//! 架构：取/存两个路由 + 一个后台管家线程。
//! - cache_take：命中秒回（对 GitHub 零请求）。单文件直读（pages/<hash>），
//!   TTL 按 host 分治（github.com 24h / gist 30min / raw 10min，过期 = miss）；
//! - cache_put：资格判定（host 白名单 + GET + document 导航 + 无 no-cache）
//!   + 状态白名单（只缓存 200）+ 正文类型闸门（按 host）+ 收集体（≤2MB）
//!   + 投递 Save 消息（主路径零磁盘等待）；
//! - 管家线程（懒启动，专用 OS 线程串行消费任务筐，每条消息独立 panic 护栏）：
//!   原子写（tmp + rename）、容量管理（增量记账 + 软顶淘汰 + 硬顶全清）、
//!   命中摸一下（set_times 刷新 mtime，cachedAt 不动）、写后失效。
//! 存储格式：pages/<fnv1a(key) 16hex> = [4B BE header 长][header JSON][body]。
//! header JSON 含 key（读时校验，防哈希碰撞 serve 错页）、status、headers、cachedAt。
//! 不引入 cacache：内容寻址去重/完整性校验/双树索引在单用户页面缓存场景全无
//! 收益（页面间内容不共享；半页由 rename 原子写杜绝；容量 dirent+stat 即够），
//! 却带来每次写入全表 list_sync + 孤儿回收的常驻成本（2026-10-24 弃用）。
//! 新鲜度模型（时钟路由 + 事件路由混合）：
//! - 时钟路由：条目写入超该 host 的 TTL → 过期 → miss → 上游刷新；TTL 基准是
//!   header 里的 cached_at（首缓存时刻），命中"摸一下"只刷新 mtime（淘汰热度），
//!   不动 cached_at——两者分离，互不打架；
//! - 事件路由：POST/PUT/DELETE/PATCH 成功 → 同路径前缀条目即删（写失效）；
//! - 会话死亡防污染：请求带会话 cookie 但响应是未登录页（body 含
//!   logged-out 标记）→ 不缓存（防 -cauthed 键空间被营销页污染）。
//! TTL 定值依据（2026-10-24）：HTML 文档 97% 是应用框架（实证可见文本仅 3%），
//! 动态数据走 XHR 实时拉；浏览器 F5（max-age=0）被准入排除，想换新有直达出口，
//! 故框架给 24h 长兜底；raw 是分支寻址的直变文本，给 10min 短窗口。
//! SWR/后台 ETag 验证明确否决：_gh_sess 轮换，后台验证只能带上一时刻的旧
//! cookie，GitHub 侧将废弃会话重用判定为账号泄露（详见 mitm/mod.rs 调用点注释）。
//! cookie 语义：单用户本地代理，cookie 全量转发 GitHub（等同浏览器行为）；
//! Set-Cookie 原样到达浏览器（GitHub 靠它做会话轮换/续期，剥离 = 会话冻结）；
//! 仅镜像腿剥离 cookie（镜像站是第三方，不认识会话，剥离防凭证泄露）。
//! 状态白名单（只缓存 200）：403/400 风控拦截页进缓存 = 封锁窗口过后仍回放
//! 旧拦截页（defuse 的 IP 轮换被缓存短路，请求根本到不了上游）；304 是空体
//! 条件响应，回放给没有自身浏览器缓存的客户端（curl/隐身窗）= 空体 304。
//! 旧条目里的非 200 一律当 miss（读 header 即判，不再服务）。
//! 容量策略（2026-10-24 定）：增量记账——累计写入超 8MB 才查一次容量；
//! 软顶 200MB 按 mtime 删最旧回到上限；硬顶 250MB 整个 pages 清空重来
//! （网页缓存而已，清了重拉，好过每次写入全表扫描）。
use super::BoxBody;
use crate::pool::{now_ms, LogFn};
use crate::server::upstream::Incoming;
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::OnceLock;

const PAGE_CACHE_MAX_BYTES: u64 = 200 * 1024 * 1024; // 软顶：按 mtime 淘汰最旧
const PAGE_CACHE_HARD_BYTES: u64 = 250 * 1024 * 1024; // 硬顶：整个 pages 清空重来
const PAGE_CACHE_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORKER_CHANNEL_CAP: usize = 64; // 任务筐上限：满了丢弃（缓存写是 best-effort）
/// 增量记账步长：累计写入超此值才做一次容量检查（dirent+stat，不读文件内容），
/// 把全表扫描从"每次写"降为"每 8MB 一次"（管家线程单线程消费，无并发累加竞态）。
const CAPACITY_CHECK_STRIDE: u64 = 8 * 1024 * 1024;

/// 可缓存 host 白名单：仅文档导航类页面/文本。
/// - github.com：主站 document 页面（HTML 框架）
/// - gist.githubusercontent.com：gist 页面 + gist raw 文本（document 语义同主站）
/// - raw.githubusercontent.com：浏览器直开的文本文件
/// 其余内容域不进：图片/脚本/API 被 sec-fetch-dest 闸门天然挡着（加了也接不到），
/// 大文件下载走流式路径到不了缓存写入点，不可变内容浏览器缓存已最优。
const PAGE_CACHE_HOSTS: &[&str] = &[
    "github.com",
    "gist.githubusercontent.com",
    "raw.githubusercontent.com",
];

/// 时钟路由 TTL（按 host 分治，2026-10-24 定）：条目写入（cached_at）超过此时长
/// → 视为过期（miss → 上游刷新）。定值依据：HTML 文档 97% 是应用框架（实证可见
/// 文本仅占 3%），动态数据走 XHR 实时拉；浏览器 F5（max-age=0）被准入排除，
/// 想换新有直达出口，故框架给长兜底。raw 是分支寻址的直变文本，给短窗口。
const TTL_MS_GITHUB: u64 = 24 * 60 * 60 * 1000; // 24 小时：主站框架
const TTL_MS_GIST: u64 = 30 * 60 * 1000; // 30 分钟：gist 页面
const TTL_MS_RAW: u64 = 10 * 60 * 1000; // 10 分钟：raw 文本文件
const TTL_MS_DEFAULT: u64 = 30 * 60 * 1000; // 兜底（白名单外 host 本就走不到缓存）

/// 按 host 取 TTL（纯函数，便于测试）。
fn ttl_for_host(host: &str) -> u64 {
    match host {
        "github.com" => TTL_MS_GITHUB,
        "gist.githubusercontent.com" => TTL_MS_GIST,
        "raw.githubusercontent.com" => TTL_MS_RAW,
        _ => TTL_MS_DEFAULT,
    }
}

/// 管家线程的任务消息：写盘（含容量淘汰与孤儿回收）、命中摸一下（刷新淘汰热度）、
/// 或写后失效（删同路径前缀条目）。
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
    /// 写操作（POST/PUT/DELETE/PATCH 成功）后的缓存失效。全表 list_sync +
    /// 孤儿回收是磁盘重活：投递管家线程异步做，POST 响应路径不等它
    /// （同步版曾让每次写操作白吃一次全表扫描）。
    Invalidate {
        host: String,
        path: String,
    },
}

// ---------- 对外唯二入口：取 / 存 ----------
// 知识收拢：可缓存判定、键构造（含会话指纹）、时钟 TTL、元数据与索引、
// 容量淘汰全部在本模块内；调用方只见 cache_take / cache_put 两个路由。

/// 取/存共用的可缓存判定。
fn cache_eligible(req: &hyper::Request<Incoming>, host: &str) -> bool {
    PAGE_CACHE_HOSTS.contains(&host)
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

/// 取路由：主调用路径唯一入口。命中 = 纯本地读（对 GitHub 零请求）：
/// 单文件直读（4B 头长 + header JSON + body）。TTL 过期或未命中 = None，
/// 主路走上游（拿最新内容并重缓存）。
pub(super) fn cache_take(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    if !cache_eligible(req, host) {
        return None;
    }
    let key = page_cache_key(req, host);
    let (status, hdrs, body, cached_at_ms) = load_disk_entry(&key)?;
    if ttl_expired(ttl_for_host(host), cached_at_ms, now_ms()) {
        return None; // 时钟路由：过期 → 上游刷新
    }
    worker_send(CacheMsg::Touch { key }, log);
    Some(rebuild_cached_response(status, &hdrs, body))
}

/// 存路由：上游响应唯一入口。内部复判可缓存性、构造键（含会话指纹）、
/// 收集体并投递 Save 消息；不可缓存原样透传。主路径零磁盘等待。
pub(super) async fn cache_put(
    log: &LogFn,
    req: &hyper::Request<Incoming>,
    host: &str,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    if !cache_eligible(req, host) {
        return resp;
    }
    // 状态白名单：只缓存 200。GitHub 风控拦截页(403 restricted / 400 Whoa)与
    // 304 条件响应都曾被原样缓存：拦截页进缓存 = 封锁窗口过后仍回放旧拦截页
    // （defuse 的 IP 轮换被缓存短路，请求根本到不了上游）；304 是空体响应，
    // 回放给没有自身浏览器缓存的客户端(curl/隐身窗/第二浏览器)= 空体 304。
    if resp.status() != StatusCode::OK {
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
    let has_session = session_fingerprint(req.headers().get("cookie").and_then(|v| v.to_str().ok()))
        == "-cauthed";
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

/// 管家循环：专用 OS 线程串行消费任务筐。磁盘写在这个线程上做（阻塞无害）。
/// 每条消息独立 panic 护栏：单条 panic 不带崩管家线程（缓存无声停摆极难排查）。
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
        .body(BoxBody::new(
            http_body_util::Full::new(body).map_err(std::io::Error::other),
        ))
        .unwrap();
    *resp.headers_mut() = hdrmap;
    resp.headers_mut().insert(
        "x-gitport-cache",
        hyper::header::HeaderValue::from_static("hit"),
    );
    resp
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

/// 页面可缓存判定（全量缓存，唯一禁区=登录态翻转三件套）。
/// 通知页同权：内容陈旧由 TTL 或用户自行刷新（Ctrl+F5 绕过缓存取最新）；
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

/// 会话指纹：单用户代理只需区分「已登录」和「未登录」两个状态。
/// 不哈希 user_session 的值——GitHub 会安全轮换 user_session（值变化），
/// 值哈希会导致每次轮换后全部缓存键失效。二态指纹永远稳定：
/// 有 user_session = 已登录 → "-cauthed"；无 = 未登录 → "-cloggedout"。
fn session_fingerprint(cookies: Option<&str>) -> String {
    let has_session = cookies
        .map(|c| {
            c.split(';').map(str::trim).any(|kv| {
                kv.starts_with("user_session=") || kv.starts_with("__Host-user_session_same_site=")
            })
        })
        .unwrap_or(false);
    if has_session {
        "-cauthed".into()
    } else {
        "-cloggedout".into()
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

/// 检测 body 是否为未登录页面（GitHub 未登录时 body 带 logged-out class 标记）。
/// 请求带会话 cookie 但响应是未登录页 = 会话已死 → 不缓存/不当命中（防污染）。
fn is_logged_out_body(bytes: &[u8]) -> bool {
    let check_len = bytes.len().min(4096);
    let chunk = String::from_utf8_lossy(&bytes[..check_len]);
    chunk.contains("logged-out env-") || chunk.contains("class=\"logged-out")
}

/// key → 文件名：FNV-1a 64 位散列的 16 hex。确定性（跨进程/重启稳定）、零依赖；
/// 碰撞由读时 header 里的 key 校验兜底（不符 = miss，丢一页不串页）。
fn page_file_name(key: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// 读磁盘条目：单文件 = [4B BE header 长][header JSON][body]。
/// 返回 (status, 已解析头对, 体, cached_at)。任何一环缺失/损坏 = None（miss，
/// 截断文件自愈：下次同 URL 访问重写覆盖）。非 200 一律当 miss——旧版曾把
/// 403/400 拦截页与 304 空体响应写进缓存，自愈路径就是不再服务它们。
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
        return None; // 非 200 旧条目（拦截页/304）：当 miss，不服务
    }
    let body = &raw[end..];
    if is_logged_out_body(body) {
        return None; // 未登录污染条目：当作 miss
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
    // cached_at 取 header 里的首缓存时刻（touch 不改它）；无此字段视为远古
    // （过期 = miss，被上游刷新重写覆盖）。
    let cached_at_ms = header.get("cachedAt").and_then(|v| v.as_u64()).unwrap_or(0);
    Some((status, hdrs, Bytes::copy_from_slice(body), cached_at_ms))
}

/// 命中缓存：返回重建的响应 + 条目的 cached_at（毫秒历元，TTL 判定用）。
/// 仅测试用：线上命中走 cache_take，这里直读磁盘。
#[cfg(test)]
fn page_cache_get(
    key: &str,
) -> Option<(axum::response::Response<BoxBody>, u64)> {
    let (status, hdrs, body, cached_at) = load_disk_entry(key)?;
    Some((rebuild_cached_response(status, &hdrs, body), cached_at))
}

// ---------- 内部：容量管理（单文件存储，无孤儿概念） ----------

/// 增量记账：累计写入超步长才查一次容量。管家线程单线程消费，无并发累加竞态；
/// 全表扫描从 cacache 时代的"每次写"降为"每 8MB 一次"。
static BYTES_SINCE_CHECK: AtomicU64 = AtomicU64::new(0);

fn maybe_enforce_capacity(dir: &std::path::Path, incoming: usize) {
    let pending =
        BYTES_SINCE_CHECK.fetch_add(incoming as u64, Ordering::Relaxed) + incoming as u64;
    if pending >= CAPACITY_CHECK_STRIDE {
        BYTES_SINCE_CHECK.store(0, Ordering::Relaxed);
        enforce_capacity(dir, PAGE_CACHE_MAX_BYTES, PAGE_CACHE_HARD_BYTES);
    }
}

/// 容量管理（管家线程内执行）：dirent + stat，不读任何文件内容。
/// - 硬顶（250MB）：整个 pages 清空重来——网页缓存而已，清了重拉；
/// - 软顶（200MB）：按 mtime 升序删最旧，直到回到上限内；
/// - 顺手清 tmp 垃圾（进程曾被杀时的 rename 残留）。
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
    // mtime 升序 = 最旧先删；同时刻按路径字典序，淘汰顺序确定不漂移
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

/// 旧版（cacache）残留清理：index-v5/content-v2 两棵树随弃用作废，一次性删掉，
/// 防旧数据白占磁盘（新存储只认 pages/）。
static LEGACY_CACHE_PURGED: OnceLock<()> = OnceLock::new();
fn purge_legacy_cache(dir: &std::path::Path) {
    if LEGACY_CACHE_PURGED.set(()).is_ok() {
        for sub in ["index-v5", "content-v2"] {
            let _ = std::fs::remove_dir_all(dir.join(sub));
        }
    }
}

/// 命中缓存"摸一下"（管家线程内执行）：set_times 刷新 mtime（淘汰热度），
/// header 里的 cached_at（TTL 基准）不动——两者分离，互不打架。
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

/// 后台半段（管家线程内执行）：建目录（含 ACL）→ 清旧版残留 → 增量容量记账
/// → tmp 写全量 + rename 原子落页。cached_at 写进 header（TTL 基准，
/// Touch 刷 mtime 时保留）。std::fs::rename 在 Windows 上即原子覆盖
/// （底层 MoveFileExW + MOVEFILE_REPLACE_EXISTING，2026-10-24 实测确认；
/// 曾以为不覆盖而先删旧页再 rename，多一步还引入 miss 窗口，已删）。
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
    // tmp 名带纳秒时钟：管家单线程串行，仅防极端重入
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

/// 正文类型闸门（按 host 放行）：github.com 只收 text/html（页面框架）；
/// gist 域既有 HTML 页面也有 raw 文本（text/plain），raw 域是浏览器直开的
/// 文本文件（text/plain / text/markdown）。二进制（octet-stream、图片等）
/// 一律不收——大文件与不可变内容本就不该进页面缓存。
fn body_type_allowed(host: &str, content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return false };
    let ct = ct.trim();
    match host {
        "github.com" => ct.starts_with("text/html"),
        "gist.githubusercontent.com" | "raw.githubusercontent.com" => {
            ct.starts_with("text/html")
                || ct.starts_with("text/plain")
                || ct.starts_with("text/markdown")
        }
        _ => false,
    }
}

/// 收集体并投递 Save 消息；返回重建的响应（克隆体交浏览器，零磁盘等待）。
/// 会话死亡防污染：请求带会话 cookie 但响应是未登录页 → 不缓存（原样透传）。
async fn collect_and_submit(
    log: &LogFn,
    host: &str,
    key: &str,
    has_session: bool,
    resp: axum::response::Response<BoxBody>,
) -> axum::response::Response<BoxBody> {
    let (parts, body) = resp.into_parts();
    let allowed = body_type_allowed(
        host,
        parts.headers.get("content-type").and_then(|v| v.to_str().ok()),
    );
    if !allowed {
        return hyper::Response::from_parts(parts, body);
    }
    // Set-Cookie 必须到达浏览器（GitHub 靠它做会话轮换/续期，剥离 = 浏览器
    // cookie 冻结 → 轮换后旧值被拒 → 未登录页）。只从缓存元数据中排除
    // （防缓存命中回灌旧值），响应本身原样透传。
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
            let bytes = collected.to_bytes();
            // 可缓存 = 体积达标 且 非"带会话却拿到未登录页"（会话死亡防污染）
            let cacheable = bytes.len() <= PAGE_CACHE_MAX_BODY_BYTES
                && !(has_session && is_logged_out_body(&bytes));
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

/// 写后失效（管家线程内执行）：删同路径前缀的页面文件。
/// 文件名是哈希，前缀匹配需读每个文件的 header 段（只读 4B+header，不读 body）；
/// 失效是低频事件（POST 成功才触发），管家线程异步做，成本可接受。
fn invalidate_prefix_blocking(dir: &std::path::Path, host: &str, path: &str) {
    let prefix = format!("GET {host}{path}");
    let Ok(rd) = std::fs::read_dir(dir.join("pages")) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if read_page_key(&p).is_some_and(|k| k.starts_with(&prefix)) {
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

/// 写操作后的缓存失效：POST/PUT/DELETE 成功（2xx/3xx）即删同路径前缀条目——
/// 否则改完设置/发完评论跳回来看到旧页面（像保存失败）。磁盘删除是管家线程的
/// 异步活（读全部 header 匹配前缀），POST 响应路径只投递消息，不等。
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

    /// 单测试顺序覆盖（OnceLock 全局只能设一次，多测试并行会互相踩目录）：
    /// roundtrip → 非 HTML 排除 → 排除名单 → TTL 过期 → 容量淘汰
    /// → 清空 → 写失效 → 未登录页写入防污染
    /// → 时钟路由纯判定 → Touch 保留 cachedAt → 覆盖写与坏文件自愈。
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
            .body(BoxBody::new(
                http_body_util::Full::new(Bytes::from_static(b"{}"))
                    .map_err(std::io::Error::other),
            ))
            .unwrap();
        let log: LogFn = std::sync::Arc::new(|_: &str| {});
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

        // ③ 排除名单定案（全量缓存，唯一禁区=登录态翻转三件套）
        assert!(page_cache_allowed("/"));
        assert!(page_cache_allowed("/notifications"));
        assert!(page_cache_allowed("/search?q=x&type=repositories"));
        assert!(page_cache_allowed("/settings/profile"), "设置页已解除排除");
        assert!(!page_cache_allowed("/login"));
        assert!(!page_cache_allowed("/logout"));
        assert!(!page_cache_allowed("/session/xxx"));

        // ④ 时钟路由（纯判定）：TTL 内不过期，超 TTL 过期
        assert!(!ttl_expired(TTL_MS_DEFAULT, now_ms() - 29 * 60 * 1000, now_ms()));
        assert!(ttl_expired(TTL_MS_DEFAULT, now_ms() - 31 * 60 * 1000, now_ms()));
        assert!(ttl_expired(TTL_MS_DEFAULT, 0, now_ms()), "_epoch 视为远古条目: 过期");
        // per-host TTL 表：github.com 框架 24h / gist 30min / raw 10min / 兜底 30min
        assert_eq!(ttl_for_host("github.com"), 24 * 60 * 60 * 1000);
        assert_eq!(ttl_for_host("gist.githubusercontent.com"), 30 * 60 * 1000);
        assert_eq!(ttl_for_host("raw.githubusercontent.com"), 10 * 60 * 1000);
        assert_eq!(ttl_for_host("example.com"), TTL_MS_DEFAULT, "名单外走兜底");
        // 24h 窗口：23h 前写入不过期，25h 前过期
        assert!(!ttl_expired(
            ttl_for_host("github.com"),
            now_ms() - 23 * 60 * 60 * 1000,
            now_ms()
        ));
        assert!(ttl_expired(
            ttl_for_host("github.com"),
            now_ms() - 25 * 60 * 60 * 1000,
            now_ms()
        ));
        // raw 10min 窗口：9min 不过期，11min 过期
        assert!(!ttl_expired(
            ttl_for_host("raw.githubusercontent.com"),
            now_ms() - 9 * 60 * 1000,
            now_ms()
        ));
        assert!(ttl_expired(
            ttl_for_host("raw.githubusercontent.com"),
            now_ms() - 11 * 60 * 1000,
            now_ms()
        ));

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
        let _ = persist_page_entry_blocking(&dir, "GET github.com/again", b"<html>a</html>", 200, &test_hdrs(), now_ms());
        assert!(page_cache_get("GET github.com/again").is_some(), "前提：有条目");
        page_cache_clear();
        let (n, _) = pages_stat(&dir);
        assert_eq!(n, 0, "清空后条目应为零");

        // ⑦ 写操作失效：POST 成功后同路径前缀条目删除（设置页缓存的安全搭档）。
        // 磁盘删除在管家线程内执行（请求路径只投消息），这里直接驱动 blocking
        // 本体验证删除语义。
        let sk = "GET github.com/settings/profile-cabc";
        let _ = persist_page_entry_blocking(&dir, sk, b"<html>s</html>", 200, &test_hdrs(), now_ms());
        assert!(page_cache_get(sk).is_some(), "前提：条目已缓存");
        invalidate_after_write(&log, "github.com", "/settings/profile");
        invalidate_prefix_blocking(&dir, "github.com", "/settings/profile");
        assert!(page_cache_get(sk).is_none(), "写操作后磁盘条目应失效");

        // ⑧ 会话指纹（二态）：有会话 cookie = 已登录；无 = 未登录。
        // 不哈希 user_session 的值——GitHub 安全轮换 user_session 会导致值变化 → 键全失效
        let s1 = session_fingerprint(Some("user_session=abc; _gh_sess=r1"));
        let s1b = session_fingerprint(Some("user_session=xyz; _gh_sess=r2"));
        let s0 = session_fingerprint(None);
        assert_eq!(s1, s1b, "user_session 值轮换不应换键（同一用户）");
        assert_eq!(s1, "-cauthed", "登录态固定标签");
        assert_eq!(s0, "-cloggedout", "未登录固定标签");
        assert_ne!(s1, s0, "登录/未登录必须分键");

        // ⑨ 未登录页写入防污染：请求带会话（has_session=true）但响应是
        // 未登录页（body 含 logged-out 标记）→ 不缓存
        let poisoned = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(BoxBody::new(
                http_body_util::Full::new(Bytes::from_static(
                    b"<html><body class=\"logged-out env-production\">sign in</body></html>",
                ))
                .map_err(std::io::Error::other),
            ))
            .unwrap();
        let _ = collect_and_submit(&log, "github.com", "GET github.com/-cauthed-poison", true, poisoned).await;
        assert!(
            page_cache_get("GET github.com/-cauthed-poison").is_none(),
            "会话死亡期间的未登录页不得进缓存"
        );

        // ⑩ Touch 保留 cachedAt（TTL 基准不被摸掉）：写入带 cachedAt=旧值 →
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

        // ⑪ 覆盖写与坏文件自愈（单文件 rename 语义）：
        // 同 key 重写读到新内容（rename 原子覆盖，无窗口无半页）；
        // 截断文件 = miss 自愈（不服务半页）；header key 不符 = 拒服（防串页）。
        let ck = "GET github.com/cover-me";
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v1</html>", 200, &test_hdrs(), now_ms());
        let _ = persist_page_entry_blocking(&dir, ck, b"<html>v2</html>", 200, &test_hdrs(), now_ms());
        let (hit, _) = page_cache_get(ck).expect("覆盖写后应命中");
        let v = http_body_util::BodyExt::collect(hit.into_body()).await.unwrap().to_bytes();
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
