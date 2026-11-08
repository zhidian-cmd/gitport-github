//! MITM：池内域名本地终结 TLS，按 route::master_route 分流；拦截页本地识别 gh_defuse。
use super::protocol::{self, BoxBody, Incoming, REQUEST_BUDGET};
use super::upstream::{self, stream_on, ERR_BUDGET_TIMEOUT};
use crate::certgen::Authority;
use crate::config;
use crate::pool;
use crate::util::LogFn;
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioExecutor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod defuse;
mod direct_split;
mod merge;
mod page_cache;
pub(crate) mod quiet;
mod redirect_memo;

pub(crate) mod mirror;

pub use mirror::{calibrate_chains, last_calibrate_report, set_calibrate_report, CALIB_RUNNING};

use defuse::gh_defuse;
use mirror::chain_fetch;

const CONTENT_REQUEST_BUDGET: Duration = Duration::from_secs(4); // 内容域 .133 直连腿响应头预算
pub fn mitm_scope(authority: Option<&Arc<Authority>>, host: &str) -> bool {
    if authority.is_none() || !crate::settings::mitm() {
        return false;
    }
    crate::pool::route::is_managed(host)
}
pub async fn handle_connect_mitm(
    srv: &crate::server::ProxyServer,
    mut client: tokio::net::TcpStream,
    host: &str,
) {
    use tokio::io::AsyncWriteExt;
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let Some(authority) = &srv.authority else {
        return;
    };
    let acceptor = crate::certgen::tls_acceptor_of(authority);
    let accept = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_boring::accept(&acceptor, client),
    )
    .await;
    let Ok(Ok(tls)) = accept else {
        (srv.log)(&format!("[MITM] {host} 客户端握手失败"));
        return;
    };
    let alpn = tls
        .ssl()
        .selected_alpn_protocol()
        .map(|p| p.to_vec())
        .unwrap_or_default();
    // ALPN 必记：connection closed 类错误只可能来自 h1 服务端，凭 ALPN 归因。
    let alpn_name = match alpn.as_slice() {
        b"h2" => "h2",
        b"http/1.1" => "http/1.1",
        _ => "none",
    };
    if quiet::first_time("tunnel", host) {
        (srv.log)(&format!(
            "[MITM] {host} 隧道已解密(alpn={alpn_name}), 按域名路由转发"
        ));
    }
    let log = srv.log.clone();
    let svc = hyper::service::service_fn(move |req| {
        let log = log.clone();
        async move { Ok::<_, std::convert::Infallible>(mitm_http(log, req).await) }
    });
    let result = if alpn == b"h2" {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
            .await
    };
    if let Err(e) = result {
        let msg = e.to_string();
        // 浏览器掐断本地连接是高频日常，不刷屏；协议类真错误仍保留。
        let benign = msg.contains("connection error")
            || e.is_incomplete_message()
            || e.is_closed()
            || e.is_body_write_aborted();
        // h1 侧写响应体失败不在 is_closed() 里，以前被印成「服务层错误」像真故障。
        // 归回客户端断开，且同 host 只留首条（与隧道解密行共用 quiet 表）。
        if client_gone_text(&msg) {
            if quiet::first_time("client-gone", host) {
                (srv.log)(&format!("[MITM] {host} 客户端已断开"));
            }
        } else if !benign {
            (srv.log)(&format!("[MITM] {host} 服务层错误: {e}"));
        }
    }
}

/// 客户端提前断开时 hyper / 系统 socket 给的文案：只认这几类，别把真故障吞掉。
fn client_gone_text(msg: &str) -> bool {
    msg.contains("error writing a body to connection")
        || msg.contains("broken pipe")
        || msg.contains("connection reset")
        || msg.contains("connection closed")
}
/// 本次请求实际命中的上游 IP（响应头 X-GitPort-Upstream 回填）；单写者、收尾时读一次。
pub(super) type UpstreamInfo = Arc<Mutex<String>>;

#[derive(Clone)]
pub(super) struct PeekRaw(pub Vec<Bytes>);
async fn mitm_http(
    log: LogFn,
    mut req: hyper::Request<Incoming>,
) -> axum::response::Response<BoxBody> {
    // h2 用 :authority；隧道内 h1 origin-form 无 host，回退 Host 头。
    let mut host = {
        let from_uri = crate::server::host_only(req.uri().host().unwrap_or("")).to_lowercase();
        if from_uri.is_empty() {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|h| crate::server::host_only(h).to_lowercase())
                .unwrap_or_default()
        } else {
            from_uri
        }
    };
    // 主站上 /owner/repo/zip/refs/... 是 codeload 被不对口 IP 用 301 踢回来的死路径，
    // GitHub 主站本身没有这个路由。那条 301 没带缓存头，浏览器会永久记住；此后即使把
    // codeload 的路由修对，浏览器也直接跳到这条 404 路径、根本不再问代理。这里内部按
    // codeload 转发（路径一字不改，codeload 用的就是同一串），不再回任何 3xx，旧缓存失效。
    if let Some(alias) = codeload_alias_host(&host, req.uri().path()) {
        host = alias.to_string();
        if let Some(v) = req.headers_mut().get_mut(http::header::HOST) {
            *v = HeaderValue::from_static("codeload.github.com");
        }
    }
    // GitHub 前端遥测只占带宽不影响功能（实测 436 个请求里 325 个是它），读掉请求体再回 204。
    if is_telemetry(&host, &path_of(req.uri())) {
        let _ = http_body_util::BodyExt::collect(req.into_body()).await;
        return no_content();
    }

    let info = UpstreamInfo::default();
    // 页面缓存命中即秒回；勿加 SWR/ETag 验证，旧 cookie 重用会被判账号泄露。
    if let Some(cached) = page_cache::cache_take(&log, &req, &host) {
        return write_upstream(cached, "cache", &info);
    }
    // 头像入口 302 记忆：跳转目标按用户稳定，记住后本地直答，省掉每次渲染的来回。
    if req.method() == Method::GET {
        if let Some(loc) =
            redirect_memo::cached_location(&host, req.uri().path(), req.uri().query())
        {
            let _ = http_body_util::BodyExt::collect(req.into_body()).await;
            let resp = hyper::Response::builder()
                .status(StatusCode::FOUND)
                .header("location", loc)
                .header("cache-control", "no-cache")
                .body(protocol::full_body(Bytes::new()))
                .unwrap();
            return write_upstream(resp, "302memo", &info);
        }
    }
    let Ok(out) = upstream::upstream_request(&req, &host) else {
        return mitm_unavailable(&req, &host, "上游请求构造失败, 代理正在按表自动重试。");
    };

    let is_simple = req.method() == Method::GET || req.method() == Method::HEAD;
    let path = path_of(req.uri());
    // git 智能协议 POST 与声明超限转流式（缓冲路径 >1MB 必 502，push 必挂）。
    let mut streaming_reason = stream_decision(req.method(), &path, declared_content_len(&req));
    let mut overflow_prefix: Option<Vec<u8>> = None;
    let mut replay: Option<Bytes> = None;
    if streaming_reason.is_none() {
        let mut buf = Vec::new();
        let limit = upstream::MAX_REPLAY_BODY + 1;
        while let Some(frame) = http_body_util::BodyExt::frame(req.body_mut()).await {
            match frame {
                Ok(f) => {
                    if let Ok(data) = f.into_data() {
                        buf.extend_from_slice(&data);
                        if buf.len() > limit {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        if buf.len() > upstream::MAX_REPLAY_BODY {
            streaming_reason = Some("实际超限(缓冲转流式)");
            overflow_prefix = Some(buf);
        } else if !buf.is_empty() {
            replay = Some(Bytes::from(buf));
        }
    }
    if let Some(reason) = streaming_reason {
        let body = match overflow_prefix {
            Some(prefix) => {
                upstream::prepend_body(vec![Bytes::from(prefix)], incoming_to_body(req.into_body()))
            }
            None => incoming_to_body(req.into_body()),
        };
        return stream_passthrough(&log, &out, &host, &info, body, reason).await;
    }
    let out_body = match &replay {
        Some(b) => out.map(|_| protocol::full_body(b.clone())),
        None => out,
    };
    if is_simple
        && matches!(
            pool::route::master_route(&host, req.method().as_str(), &path),
            pool::route::Route::Mirror
        )
    {
        let chain_host = pool::route::mirror_chain_host(&host, &path);
        let new_bytes =
            mirror::range_bytes(req.headers().get("range").and_then(|v| v.to_str().ok()));
        // 直连同台：候选 = 镜像链 + 直连，ECT 统一派发；全部候选耗尽才 502。
        match mirror_or_direct(
            &log, &out_body, &host, chain_host, new_bytes, &info, &replay,
        )
        .await
        {
            Ok(resp) => return resp,
            // 原因落日志：熔断中/凭据串仅直连/链全灭，一眼可辨，不再吞。
            Err(e) => (log)(&format!("[MITM] {host}{path} 镜像与直连均不可用({e})")),
        }
        return mitm_unavailable(
            &req,
            &host,
            "镜像与直连均不可用, 疑似封锁窗口期, 代理正在按表自动重试。",
        );
    }
    // README 大图：只用池里现成的伪装 SNI 直连连接，多段 Range 并发拉再按字节边界合流。
    // 不进镜像链、不扩 IP、不新拨连接；池冷或任一段没回 206 就交回下面的单流路径。
    if is_simple {
        if let Some(resp) =
            direct_split::try_direct_split(&log, &out_body, &host, &info).await
        {
            return write_upstream(resp, "direct-split", &info);
        }
    }
    let mut resp = match get_direct(&log, &out_body, &host, &info, is_simple, &replay).await {
        Ok(r) => r,
        Err(e) => {
            match pool::route::fallback_for(&host) {
                pool::route::Fallback::MirrorDns if is_simple => {
                    let chain_host = pool::route::mirror_chain_host(&host, &path);
                    let new_bytes = mirror::range_bytes(
                        req.headers().get("range").and_then(|v| v.to_str().ok()),
                    );
                    // 直连刚失败过会带 45s 降权，ECT 自动跳过它——语义就是兜底的最后一次机会。
                    match mirror_or_direct(
                        &log, &out_body, &host, chain_host, new_bytes, &info, &replay,
                    )
                    .await
                    {
                        Ok(resp) => return resp,
                        Err(_) => (log)(&format!("[MITM] {host}{path} 直连和镜像都试不通")),
                    }
                }
                _ => {
                    (log)(&format!(
                        "[MITM] {host}{} 上游失败: {e}",
                        path_of(req.uri())
                    ));
                }
            }
            if is_simple {
                match dns_direct_fetch(&log, &out_body, &host, &info, &replay).await {
                    Ok(r) => return write_upstream(r, "dns", &info),
                    Err(de) => {
                        (log)(&format!("[MITM] {host}{path} DNS 备用直连也失败({de})"));
                    }
                }
            }
            return mitm_unavailable(
                &req,
                &host,
                "直连与镜像链均不可用, 疑似封锁窗口期, 代理正在按表自动重试。",
            );
        }
    };
    if is_simple
        && (host == "github.com" || host == "api.github.com")
        && resp.status().as_u16() >= 400
    {
        match gh_defuse(&log, &host, &info, &out_body, &replay).await {
            Ok(r) => resp = r,
            Err(e) => {
                (log)(&format!(
                    "[MITM] {host}{} 风控页重试也失败: {e}",
                    path_of(req.uri())
                ));
                return mitm_unavailable(
                    &req,
                    &host,
                    "全部边缘均返回风控拦截页, 代理正在按表自动重试。",
                );
            }
        }
    }
    // 写操作成功后缓存失效：内存热点同步清，磁盘半场交给管家线程。
    if host == "github.com"
        && matches!(
            req.method(),
            &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
        )
        && (resp.status().is_success() || resp.status().is_redirection())
    {
        page_cache::invalidate_after_write(&log, &host, req.uri().path());
    }
    // 存路由：可缓存性/元数据/索引判定都在 page_cache 模块内部
    let mut resp = page_cache::cache_put(&log, &req, &host, resp).await;
    // 不对口 IP 回的 301 曾没带缓存头被浏览器永久记住；codeload 一旦出 3xx 就禁缓存，
    // 免得换 IP 修好后旧重定向还赖在浏览器里。
    if host == "codeload.github.com" && resp.status().is_redirection() {
        resp.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
    }
    write_upstream(resp, "direct", &info)
}
/// codeload 的规范路径：/owner/repo/(zip|tar.gz)/refs/... 只存在于 codeload.github.com。
/// 出现在 github.com 上必然是那条被错 IP 踢回来的死路径，主站一律 404。
fn is_codeload_alias_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segs.len() >= 4 && matches!(segs[2], "zip" | "tar.gz") && segs[3] == "refs"
}

/// 只在 github.com 上认这条死路径，别的主站/内容域同名路径一律不碰。
fn codeload_alias_host(host: &str, path: &str) -> Option<&'static str> {
    (host == "github.com" && is_codeload_alias_path(path)).then_some("codeload.github.com")
}

fn stream_decision(method: &Method, path: &str, declared_len: Option<u64>) -> Option<&'static str> {
    if *method == Method::GET || *method == Method::HEAD {
        return None;
    }
    if *method == Method::POST
        && (path.ends_with("/git-receive-pack") || path.ends_with("/git-upload-pack"))
    {
        return Some("git 智能协议");
    }
    if declared_len.is_some_and(|n| n as usize > upstream::MAX_REPLAY_BODY) {
        return Some("声明超限");
    }
    None
}
fn declared_content_len(req: &hyper::Request<Incoming>) -> Option<u64> {
    req.headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}
fn incoming_to_body(body: Incoming) -> BoxBody {
    BoxBody::new(body.map_err(std::io::Error::other))
}
fn plain_502() -> axum::response::Response<BoxBody> {
    axum::response::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(protocol::full_body(Bytes::from_static(
            b"upstream unavailable",
        )))
        .unwrap()
}
/// 流式直通：体不进缓冲边收边泵，响应头一到立即交付，泵失败不覆盖已交付的响应。
async fn stream_passthrough(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    body: BoxBody,
    reason: &str,
) -> axum::response::Response<BoxBody> {
    let path = path_of(out.uri());
    let t0 = Instant::now();
    let mut body = Some(body);
    let ips = pool::route::dial_targets(host)
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.ip)
        .collect::<Vec<_>>();
    let (fut, send, guard, up) = 'conn: {
        let cached = if upstream::prefer_own_channel(host) {
            upstream::cached_h2_own(host, &ips, None)
        } else {
            upstream::cached_h2_in(&ips, None)
        };
        if let Some(up) = cached {
            match upstream::h2_open_stream(&up, out, false).await {
                Ok((fut, send, guard)) => break 'conn (fut, send, guard, up),
                Err(e) => {
                    upstream::drop_h2_id(&up.ip, up.id);
                    (log)(&format!("[流式] {host}{path} 缓存连接失效({e}), 新拨重试"));
                }
            }
        }
        // 流式请求不许捡现成连接：body 没有副本，发出去就收不回。
        match upstream::dial_upstream(host, log).await {
            Ok(up) => match upstream::h2_open_stream(&up, out, false).await {
                Ok((fut, send, guard)) => break 'conn (fut, send, guard, up),
                Err(e) => {
                    upstream::drop_h2_id(&up.ip, up.id);
                    (log)(&format!("[流式] {host}{path} 新拨连接握手即死({e})"));
                }
            },
            Err(e) => (log)(&format!("[流式] {host}{path} 拨号失败: {e}")),
        }
        (log)(&format!("[流式] {host}{path} 两条连接腿均失败, 放弃"));
        return plain_502();
    };
    let pump = body
        .take()
        .map(|b| upstream::h2_spawn_pump(send, b, log.clone()));
    let timed = tokio::time::timeout(
        std::time::Duration::from_secs(upstream::STREAM_HEAD_BUDGET_SECS),
        upstream::h2_recv_response(fut, guard),
    )
    .await;
    match timed {
        Ok(Ok(resp)) => {
            *info.lock().unwrap() = up.ip.clone();
            pool::cursor_note(host, &up.ip, true, up.slot);
            upstream::note_latency(&up.ip, up.id, t0.elapsed().as_millis() as u64);
            (log)(&format!(
                "[流式] {host}{path} 直通({reason}), 响应头 {}ms",
                t0.elapsed().as_millis()
            ));
            write_upstream(resp, "stream", info)
        }
        Ok(Err(e)) => {
            if let Some(h) = &pump {
                h.abort();
            }
            (log)(&format!("[流式] {host}{path} 上游响应失败: {e}"));
            plain_502()
        }
        Err(_) => {
            if let Some(h) = &pump {
                h.abort();
            }
            (log)(&format!(
                "[流式] {host}{path} 响应头预算({}s)超时",
                upstream::STREAM_HEAD_BUDGET_SECS
            ));
            plain_502()
        }
    }
}
/// 前端遥测端点：不转发，直接 204。
fn is_telemetry(host: &str, path: &str) -> bool {
    host == "collector.github.com"
        || host == "alive.github.com"
        || (host == "api.github.com" && path.starts_with("/_private/browser/"))
}

fn no_content() -> axum::response::Response<BoxBody> {
    axum::response::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(protocol::empty_body())
        .unwrap()
}

pub(super) fn path_of(uri: &http::Uri) -> String {
    uri.path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default()
}
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// 内容域 4s（vs 8s）：黑洞必烧满预算，罩更久纯浪费。
fn request_budget(is_content: bool) -> Duration {
    if is_content {
        CONTENT_REQUEST_BUDGET
    } else {
        REQUEST_BUDGET
    }
}

/// 搜索请求固定走主通道：GitHub 反爬对同会话跨 IP 敏感，漂移会被降级成无结果骨架。
fn is_search_path(path: &str) -> bool {
    path.starts_with("/search")
}

/// 复用失败的文案：断链和超时是两种病，别用一句话糊过去。
/// 断链 = 连接已经没了，发出去就报错（微秒级）；超时 = 请求发出去了、对端不答，烧满整个预算。
/// 混成"连接已断"会让人把"边缘不答"误判成链路故障，排查方向直接跑偏。
fn reuse_failure_text(why: &str, budget: Duration) -> String {
    if why == ERR_BUDGET_TIMEOUT {
        format!("响应超时({}s) 放弃复用", budget.as_secs())
    } else {
        format!("连接已断({why})")
    }
}

/// 复用失败出声一次就够：一次页面加载会连着撞几条同 host 的连接，别拿同样的行刷屏。
/// 复用失败记账：首条立刻留痕，之后每 60 秒汇总一行（次数 + 超时/断开分项 + 最近 IP）。
/// 旧行为是每 host 每种失败只打第一条——反复发生的证据反而被抹掉了，排查时看不到。
fn note_reuse_failure(log: &LogFn, host: &str, ip: &str, why: &str, budget: Duration) {
    struct Acc {
        n: u32,
        timeouts: u32,
        last_ip: String,
        last_text: String,
        since: std::time::Instant,
    }
    static ACC: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Acc>>> =
        std::sync::OnceLock::new();

    let timeout = why == ERR_BUDGET_TIMEOUT;
    let text = reuse_failure_text(why, budget);
    let mut g = ACC
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if g.len() >= 128 {
        g.clear();
    }
    let e = g.entry(host.to_string()).or_insert_with(|| Acc {
        n: 0,
        timeouts: 0,
        last_ip: String::new(),
        last_text: String::new(),
        since: std::time::Instant::now(),
    });
    e.n += 1;
    if timeout {
        e.timeouts += 1;
    }
    e.last_ip = ip.to_string();
    e.last_text = text.clone();

    if e.n == 1 {
        // 窗口内首条：立刻留痕，单次失败也查得到。
        (log)(&format!("[MITM] {host} 复用失败({text}), IP {ip}, 重新建连"));
        return;
    }
    if e.since.elapsed() >= Duration::from_secs(60) {
        let (n, t, last_ip, last_text) = (e.n, e.timeouts, e.last_ip.clone(), e.last_text.clone());
        (log)(&format!(
            "[MITM] {host} 60s 内复用失败 {n} 次(超时 {t} / 断开 {}), 最近: {last_text}, IP {last_ip}",
            n - t
        ));
        e.n = 0;
        e.timeouts = 0;
        e.since = std::time::Instant::now();
    }
}

/// 直连腿组装（两条路径共用）：charge 在 future 首行，镜像胜出丢弃 future 时零残留。
#[allow(clippy::too_many_arguments)] // 直连腿组装的字面清单, 强行并参只会丢语义
fn direct_leg<'a>(
    chain_host: &str,
    new_bytes: u64,
    big: bool,
    log: &LogFn,
    out: &'a hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    body: &Option<Bytes>,
) -> mirror::DirectLeg<'a> {
    let load = mirror::mirror_load_for(&mirror::direct_load_key(chain_host));
    let log2 = log.clone();
    let host2 = host.to_string();
    let body2 = body.clone();
    let info2 = info.clone();
    let fetch = Box::pin(async move {
        let mut guard = mirror::LoadGuard::charge(load, new_bytes, big);
        match get_direct(&log2, out, &host2, &info2, true, &body2).await {
            Ok(resp) => {
                // 头已到：码表重跑，IP 表串发拨号/等待不进速度样本。
                guard.restart_mark();
                let (parts, body) = resp.into_parts();
                let body = http_body_util::BodyExt::map_frame(body, move |frame| {
                    if let Some(n) = frame.data_ref().map(|d| d.len() as u64) {
                        guard.on_frame(n);
                    }
                    frame
                });
                Ok(hyper::Response::from_parts(parts, BoxBody::new(body)))
            }
            Err(e) => Err(e),
        }
    });
    mirror::DirectLeg { fetch }
}

/// 两条路径共用的镜像链派发：组装直连腿 + chain_fetch + 按胜出者写诊断头。
async fn mirror_or_direct(
    log: &LogFn,
    out_body: &hyper::Request<BoxBody>,
    host: &str,
    chain_host: &str,
    new_bytes: u64,
    info: &UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let fetch = direct_leg(
        chain_host,
        new_bytes,
        pool::route::is_big_file_host(chain_host),
        log,
        out_body,
        host,
        info,
        replay,
    );
    let resp = chain_fetch(log, out_body, host, fetch, info, replay).await?;
    let route = resp
        .extensions()
        .get::<&'static str>()
        .copied()
        .unwrap_or("mirror");
    Ok(write_upstream(resp, route, info))
}

/// 直连腿：通道获取一站式在 pool::get_or_build，这里只管发请求与记账。
/// 通道失败摘掉换一条重试一次，再败交上层按 fallback 走镜像/DNS。
pub(super) async fn get_direct(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    _is_simple: bool,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let path = path_of(out.uri());
    let want_slot = if is_search_path(&path) { Some(1) } else { None };
    let is_content = pool::route::is_content(host);
    let budget = request_budget(is_content);
    let (mut up, mut fresh) = pool::get_or_build(host, want_slot, log).await?;
    let mut retried = false;
    loop {
        match stream_on(&up, out, body, budget).await {
            Ok((resp, ms)) => {
                let id = up.id;
                let slot = up.slot;
                let ip = up.ip.clone();
                // 服务端回 421 = 这个 IP 服务不了这个 host：边级长冷却，换下一条。
                // 边状态按路由键记（子域请求的 host ≠ 路由键，按 host 记永远对不上）。
                if resp.status() == StatusCode::MISDIRECTED_REQUEST {
                    if let Some(row) = pool::route::route_for(host) {
                        pool::edges::mark_reject(&ip, &row.key);
                    }
                    upstream::drop_h2_id(&ip, id);
                    (log)(&format!(
                        "[MITM] {host} <- {ip} 被拒(421), 该 IP 冷却 4 小时, 换下一个"
                    ));
                    if retried {
                        return Err("421 边缘连续拒绝".to_string());
                    }
                    retried = true;
                    (up, fresh) = pool::get_or_build(host, want_slot, log).await?;
                    continue;
                }
                *info.lock().unwrap() = ip.clone();
                // HTTP 交换完成即回写（是不是风控页这里看不见）；成功只清短冷却，洗不掉风控冷却。
                pool::cursor_note(host, &ip, true, slot);
                upstream::note_latency(&ip, id, ms);
                // 头像入口的 302 顺手记一笔：下次同入口本地直答（见 redirect_memo）。
                redirect_memo::observe_response(host, out.uri(), resp.status(), resp.headers());
                if fresh {
                    (log)(&format!("[上游] {host}{path} 新连接 {ip}, {ms}ms"));
                } else {
                    quiet::note_reuse(log, host, &ip, ms);
                }
                return Ok(resp);
            }
            Err(e) => {
                // 通道失败：摘通道 + 记账（骑来的不罚 IP，新拨的罚边冷却），换一条重试一次。
                pool::report_failure(&up, host, fresh);
                if fresh {
                    (log)(&format!(
                        "[MITM] {host} 新连接 {} 失败({e}), 换一条重试",
                        up.ip
                    ));
                } else {
                    note_reuse_failure(log, host, &up.ip, &e, budget);
                }
                if retried {
                    return Err(e);
                }
                retried = true;
                (up, fresh) = pool::get_or_build(host, want_slot, log).await?;
            }
        }
    }
}

fn write_upstream(
    resp: hyper::Response<BoxBody>,
    route: &str,
    info: &UpstreamInfo,
) -> axum::response::Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    parts.headers.remove("connection");
    parts.headers.remove("transfer-encoding");
    if !route.is_empty() {
        parts
            .headers
            .insert("x-gitport-route", HeaderValue::from_str(route).unwrap());
    }
    let ip = info.lock().unwrap().clone();
    if !ip.is_empty() {
        parts
            .headers
            .insert("x-gitport-upstream", HeaderValue::from_str(&ip).unwrap());
    }
    let prefix = parts
        .extensions
        .remove::<PeekRaw>()
        .map(|p| p.0)
        .unwrap_or_default();
    let out_body = if prefix.is_empty() {
        body // BoxBody 错误已是 io::Error，无需再映射
    } else {
        upstream::prepend_body(prefix, body)
    };
    axum::response::Response::from_parts(parts, out_body)
}
fn mitm_unavailable(
    req: &hyper::Request<Incoming>,
    host: &str,
    reason: &str,
) -> axum::response::Response<BoxBody> {
    if req.method() != Method::GET {
        return plain_502();
    }
    let ui_port = config::webui_port();
    let host = html_escape(host);
    let html = format!(
        "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"refresh\" content=\"8\"><title>{host} 暂时不可用</title>\
<style>body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
background:#0b0e14;color:#e8ecf3;font-family:\"Segoe UI\",\"Microsoft YaHei\",sans-serif}}\
.c{{max-width:420px;padding:40px;text-align:center;line-height:1.8}}\
.dot{{width:10px;height:10px;border-radius:50%;background:#d29922;display:inline-block;\
margin-right:10px;animation:p 1.2s ease-out infinite}}\
@keyframes p{{0%{{box-shadow:0 0 0 0 rgba(210,153,34,.4)}}70%{{box-shadow:0 0 0 8px rgba(210,153,34,0)}}100%{{box-shadow:0 0 0 0 rgba(210,153,34,0)}}}}\
h1{{font-size:19px;margin:0 0 14px}}p{{font-size:13.5px;color:#98a2b3;margin:6px 0}}\
code{{font-family:Consolas,monospace;color:#3fb950}}a{{color:#3fb950;text-decoration:none}}</style></head>\
<body><div class=\"c\"><h1><span class=\"dot\"></span>{host} 暂时不可用</h1>\
<p>{reason}</p>\
<p>本页每 8 秒自动刷新, 窗口一过即可打开。</p>\
<p>状态可查看工作台 <a href=\"http://127.0.0.1:{ui_port}\">127.0.0.1:{ui_port}</a>。</p>\
</div></body></html>",
    );
    axum::response::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/html; charset=utf-8")
        .header("retry-after", "8")
        .body(protocol::full_body(Bytes::from(html)))
        .unwrap()
}
/// 串发+镜像全灭后按系统解析真名 SNI 直拨（池表漂移自愈）；仅 GET/HEAD，成功入缓存。
async fn dns_direct_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|e| format!("系统 DNS 解析失败: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host} 系统 DNS 无解析记录"));
    }
    (log)(&format!(
        "[DNS直连] {host} 系统解析 {} 个候选, 真名 SNI 逐个尝试",
        addrs.len()
    ));
    // 与 get_direct 口径一致：白名单域名不算内容域；预算与候选地址无关，循环外算一次。
    let budget_content = pool::route::is_content(host);
    for addr in addrs.iter().take(4) {
        let ip = addr.ip().to_string();
        // 这个 IP 已经有通道就直接用：兜底路径也绝不为了再发一次请求而并存两条。
        let up = if let Some(up) = upstream::cached_h2_in(std::slice::from_ref(&ip), None) {
            up
        } else {
            let conn = match pool::dial::dial_one(&ip, host, host, true).await {
                Ok(c) => c,
                Err(e) => {
                    (log)(&format!("[DNS直连] {host} <- {ip} 拨号失败({e})"));
                    continue;
                }
            };
            let up = match upstream::h2_from_dialed(host, conn, &ip, 1, log).await {
                Ok(u) => u,
                Err(e) => {
                    (log)(&format!("[DNS直连] {host} <- {ip} h2 失败({e})"));
                    continue;
                }
            };
            // 拨完立刻入库：晚一秒都可能让别的 host 对同一 IP 又拨一条。
            upstream::store_h2(&ip, up)
        };
        match stream_on(&up, out, body, request_budget(budget_content)).await {
            Ok((resp, ms)) => {
                let id = up.id;
                *info.lock().unwrap() = ip.clone();
                upstream::note_latency(&ip, id, ms);
                (log)(&format!(
                    "[DNS直连] {host}{} 新连接 {ip}, 成功({ms}ms)",
                    path_of(out.uri())
                ));
                return Ok(resp);
            }
            Err(e) => {
                upstream::drop_h2(&ip);
                (log)(&format!(
                    "[DNS直连] {host} <- {ip} 请求失败({e}), 换下个解析 IP"
                ));
            }
        }
    }
    Err(format!(
        "{host} 系统 DNS 直连腿全灭({} 个候选)",
        addrs.len().min(4)
    ))
}

#[cfg(test)]
#[path = "../../tests/server/mitm/mod.rs"]
mod tests;
