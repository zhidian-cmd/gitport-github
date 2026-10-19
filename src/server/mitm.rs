//! MITM：池内域名本地终结 TLS，按 route::master_route 分流（直连串发 / 内容域回落镜像链 / 大文件域镜像 only / 流式直通）。
//! 拦截页(403 restricted/400 Whoa)本地识别 gh_defuse。
use super::upstream::{self, BoxBody, Incoming, REQUEST_BUDGET};
use crate::certgen::Authority;
use crate::config;
use crate::pool::{self, dial::Dialed, LogFn};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioExecutor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
const MIRROR_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// 内容域 .133 真名腿的响应头预算：黑洞时快速失败回落镜像；只罩响应头，体不限。
const CONTENT_REQUEST_BUDGET: Duration = Duration::from_secs(4);
const MIRROR_CHAIN_CAP: usize = 5;

/// 内容域小文件镜像链限前 5 家（仍串行）；大文件与 github.com 用全链。
fn mirror_chain_cap(host: &str) -> Option<usize> {
    (host != "github.com" && !pool::route::is_big_file_host(host)).then_some(MIRROR_CHAIN_CAP)
}
const GET_DIRECT_MAX_ATTEMPTS: usize = 24;
pub fn mitm_scope(authority: Option<&Arc<Authority>>, host: &str) -> bool {
    if authority.is_none() || !crate::settings::mitm() {
        return false;
    }
    !pool::pool_for(host).is_empty()
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
    let cfg = crate::certgen::tls_config_of(authority);
    let accept = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_rustls::TlsAcceptor::from(cfg).accept(client),
    )
    .await;
    let Ok(Ok(tls)) = accept else {
        (srv.log)(&format!("[MITM] {host} 客户端握手失败"));
        return;
    };
    let alpn = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p.to_vec())
        .unwrap_or_default();
// ALPN 必记：connection closed 类错误只可能来自 h1 服务端，凭 ALPN 归因。
    let alpn_name = match alpn.as_slice() {
        b"h2" => "h2",
        b"http/1.1" => "http/1.1",
        _ => "none",
    };
    (srv.log)(&format!(
        "[MITM] {host} 隧道已解密(alpn={alpn_name}), 按域名路由转发"
    ));
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
        (srv.log)(&format!("[MITM] {host} 服务层错误: {e}"));
    }
}
#[derive(Default, Clone)]
struct UpstreamInfo {
    ip: Arc<Mutex<String>>,
}
impl UpstreamInfo {
    fn set(&self, ip: &str) {
        *self.ip.lock().unwrap() = ip.to_string();
    }
    fn get(&self) -> String {
        self.ip.lock().unwrap().clone()
    }
}
async fn mitm_http(
    log: LogFn,
    mut req: hyper::Request<Incoming>,
) -> axum::response::Response<BoxBody> {
// h2 用 :authority；隧道内 h1 origin-form 无 host，回退 Host 头。
    let host = {
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
    if host == "collector.github.com" || host == "alive.github.com" {
        return axum::response::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(BoxBody::new(
                http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}),
            ))
            .unwrap();
    }

    let upgrade = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase() == "websocket")
        .unwrap_or(false);
    if upgrade {
        return mitm_upgrade(log, req, &host).await;
    }
    let info = UpstreamInfo::default();
    let Ok(out) = upstream::upstream_request(&req, &host) else {
        return mitm_unavailable(&req, &host);
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
            Some(prefix) => chain_prefix_body(prefix, incoming_to_body(req.into_body())),
            None => incoming_to_body(req.into_body()),
        };
        return stream_passthrough(&log, &out, &host, &info, body, reason).await;
    }
    let out_body = match &replay {
        Some(b) => out.map(|_| {
            BoxBody::new(
                http_body_util::Full::new(b.clone()).map_err(|never| std::io::Error::other(never)),
            )
        }),
        None => out,
    };
    if is_simple
        && matches!(
            pool::route::master_route(&host, req.method().as_str(), &path),
            pool::route::Route::Mirror
        )
    {
        if let Ok(resp) = chain_fetch(&log, &out_body, &host).await {
            let resp = counted_mirror(resp, &host, &path, req.method() == &Method::HEAD, &log);
            return write_upstream(resp, "mirror", &info);
        }
        (log)(&format!("[MITM] {host}{path} 镜像链全灭, 不回落直连"));
        return mitm_unavailable(&req, &host);
    }
    let name = pool::pool_for(&host);
    let mut resp = match get_direct(&log, &out_body, &host, &info, is_simple, &replay).await {
        Ok(r) => r,
        Err(e) => {
            match pool::route::fallback_for(&name, &host) {
                pool::route::Fallback::MirrorDns if is_simple => {
                    if let Ok(r) = chain_fetch(&log, &out_body, &host).await {
                        let r = counted_mirror(r, &host, &path, req.method() == &Method::HEAD, &log);
                        return write_upstream(r, "mirror", &info);
                    }
                    (log)(&format!("[MITM] {host}{path} 直连全灭且镜像链全灭"));
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
                        (log)(&format!("[MITM] {host}{path} DNS 直连腿也失败({de})"));
                    }
                }
            }
            return mitm_unavailable(&req, &host);
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
                    "[MITM] {host}{} 拦截页化解失败: {e}",
                    path_of(req.uri())
                ));
                return mitm_unavailable(&req, &host);
            }
        }
    }
    write_upstream(resp, "direct", &info)
}
fn stream_decision(
    method: &Method,
    path: &str,
    declared_len: Option<u64>,
) -> Option<&'static str> {
    if *method == Method::GET || *method == Method::HEAD {
        return None;
    }
    if *method == Method::POST
        && (path.ends_with("/git-receive-pack") || path.ends_with("/git-upload-pack"))
    {
        return Some("git 智能协议");
    }
    if declared_len.map_or(false, |n| n as usize > upstream::MAX_REPLAY_BODY) {
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
    let mut body = body;
    let stream = futures_util::stream::poll_fn(move |cx| {
        match hyper::body::Body::poll_frame(std::pin::Pin::new(&mut body), cx) {
            std::task::Poll::Ready(Some(Ok(f))) => std::task::Poll::Ready(Some(Ok(f))),
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Some(Err(std::io::Error::other(e))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}
fn chain_prefix_body(prefix: Vec<u8>, rest: BoxBody) -> BoxBody {
    let mut prefix = Some(prefix);
    let mut rest = rest;
    let stream = futures_util::stream::poll_fn(move |cx| {
        if let Some(p) = prefix.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(p)))));
        }
        hyper::body::Body::poll_frame(std::pin::Pin::new(&mut rest), cx)
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}
fn plain_502() -> axum::response::Response<BoxBody> {
    axum::response::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(BoxBody::new(
            http_body_util::Full::new(Bytes::from_static(b"upstream unavailable"))
                .map_err(|never| std::io::Error::other(never)),
        ))
        .unwrap()
}
/// 流式直通：体不进缓冲边收边泵（h2 背压分片），单次尝试不重发。
/// 响应头一到立即交付；泵失败绝不覆盖已交付的响应。
async fn stream_passthrough(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    body: BoxBody,
    reason: &str,
) -> axum::response::Response<BoxBody> {
    let name = pool::pool_for(host);
    let path = path_of(out.uri());
    let t0 = Instant::now();
    let mut body = Some(body);
    let (fut, send, up) = 'conn: {
        if let Some(up) = upstream::cached_h2(host) {
            match upstream::h2_stream_head(&up, out).await {
                Ok((fut, send)) => break 'conn (fut, send, up),
                Err(e) => {
                    upstream::drop_h2(host, &up.ip);
                    (log)(&format!("[流式] {host}{path} 缓存连接失效({e}), 新拨重试"));
                }
            }
        }
        match upstream::dial_h2(name, host, CancellationToken::new(), log).await {
            Ok(up) => match upstream::h2_stream_head(&up, out).await {
                Ok((fut, send)) => break 'conn (fut, send, up),
                Err(e) => {
                    upstream::drop_h2(host, &up.ip);
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
        upstream::h2_recv_response(fut),
    )
    .await;
    match timed {
        Ok(Ok(resp)) => {
            info.set(&up.ip);
            if !name.is_empty() {
                pool::serial_note(name, &up.ip, "ok");
            }
            (log)(&format!(
                "[流式] {host}{path} 直通({reason}), 响应头 {}ms",
                t0.elapsed().as_millis()
            ));
            write_upstream(resp, "stream", &info)
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
fn path_of(uri: &http::Uri) -> String {
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
/// 嗅探响应体判 GitHub 风控拦截页。
/// 上游强制 gzip 后边收边解压判前 4KB，已消费原始压缩帧原样保留（PeekRaw）。
async fn is_gh_block_page(resp: &mut hyper::Response<BoxBody>) -> bool {
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if !ct.contains("text/html") {
        return false;
    }
    let enc = resp
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !enc.is_empty() && enc != "identity" && enc != "gzip" {
        return false;
    }
    let gz = enc == "gzip";
    let mut raw: Vec<Bytes> = Vec::new();
    let mut comp: Vec<u8> = Vec::new();
    let mut plain: Vec<u8> = Vec::new();
    let body = resp.body_mut();
    while plain.len() < 4096 && raw.len() < 8 {
        match http_body_util::BodyExt::frame(body).await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if gz {
                        comp.extend_from_slice(&data);
                        plain = gunzip_partial(&comp, 8192);
                    } else {
                        plain.extend_from_slice(&data);
                    }
                    raw.push(data);
                    if gz && comp.len() > 128 * 1024 {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    if raw.is_empty() {
        return false;
    }
    resp.extensions_mut().insert(PeekRaw(raw));
    if plain.is_empty() {
        return false;
    }
    let chunk = String::from_utf8_lossy(&plain[..plain.len().min(4096)]).to_lowercase();
    chunk.contains("has been restricted")
        || chunk.contains("whoa there")
        || (resp.status() == http::StatusCode::BAD_REQUEST && chunk.contains("bad request"))
}

fn gunzip_partial(data: &[u8], max: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(data)
        .take(max as u64)
        .read_to_end(&mut out);
    out
}
#[derive(Clone)]
struct PeekRaw(Vec<Bytes>);
async fn try_cached(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    name: &str,
    is_simple: bool,
    is_content: bool,
    path: &str,
    t0: Instant,
    body: &Option<Bytes>,
) -> Option<Result<hyper::Response<BoxBody>, String>> {
    let up = upstream::cached_h2(host)?;
    let attempt_req = build_request(out, body);
// 内容域 4s（vs 8s）：黑洞必烧满预算，罩更久纯浪费。
    let budget = if is_content {
        CONTENT_REQUEST_BUDGET
    } else {
        REQUEST_BUDGET
    };
    let timed = tokio::time::timeout(budget, upstream::h2_send(&up, &attempt_req, body));
    match timed.await {
        Ok(Ok(resp)) => {
            info.set(&up.ip);
            if !name.is_empty() {
                pool::serial_note(name, &up.ip, "ok");
            }
            if is_content {
                pool::content_direct_ok(host);
            }
            (log)(&format!(
                "[上游] {host}{path} 复用连接, {}ms",
                t0.elapsed().as_millis()
            ));
            Some(Ok(resp))
        }
        _ => {
            upstream::drop_h2(host, &up.ip);
            (log)(&format!("[MITM] {host} 复用连接失效({}), 重走串发", up.ip));
            (!is_simple).then(|| Err("POST 等非简单方法不重发(复用连接失效)".to_string()))
        }
    }
}
/// 直连串发：完整请求逐个试，响应头到手=成功置顶，超时/黑洞=垫底换下一个。
/// fresh 语义：每 attempt 新拨号，垫底后下一 attempt 必换 IP。
async fn get_direct(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    is_simple: bool,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let name = pool::pool_for(host);
    let path = path_of(out.uri());
    let t0 = Instant::now();
    let is_content = pool::route::is_content_host(host);
    if name == "edge" && is_content && pool::content_direct_open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    if let Some(r) = try_cached(
        log, out, host, info, name, is_simple, is_content, &path, t0, body,
    )
    .await
    {
        return r;
    }
// per-host 拨号单飞：锁只罩拨号等待不罩发送（持锁到发送曾致 129 并发串行 34s FCP）。
    let dial_lock = upstream::host_dial_lock(host);
    let mut guard = Some(dial_lock.lock().await);
    if name == "edge" && is_content && pool::content_direct_open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    if upstream::cached_h2(host).is_some() {
        guard.take();
        if let Some(r) = try_cached(
            log, out, host, info, name, is_simple, is_content, &path, t0, body,
        )
        .await
        {
            return r;
        }
        guard = Some(dial_lock.lock().await);
    }
    let _dial_guard = guard;
    for attempt in 0..GET_DIRECT_MAX_ATTEMPTS {
        let up = match upstream::dial_h2(name, host, CancellationToken::new(), log).await {
            Ok(up) => up,
            Err(e) => {
                (log)(&format!(
                    "[MITM] {host} 上游第 {} 次尝试失败({e}), 垫底换候选",
                    attempt + 1
                ));
                if !is_simple {
                    return Err(format!("POST 等非简单方法不重发({e})"));
                }
                if is_content {
                    pool::content_direct_fail(host);
                    return Err(format!("内容域直连全灭({e})"));
                }
                continue;
            }
        };
        let attempt_req = build_request(out, body);
        let budget = if is_content {
            CONTENT_REQUEST_BUDGET
        } else {
            REQUEST_BUDGET
        };
        let timed = tokio::time::timeout(budget, upstream::h2_send(&up, &attempt_req, body));
        let e = match timed.await {
            Ok(Ok(resp)) => {
                info.set(&up.ip);
                if !name.is_empty() {
                    pool::serial_note(name, &up.ip, "ok"); // 数据到手 = 真成功, 置顶
                }
                upstream::store_h2(host, up.clone());
                if is_content {
                    pool::content_direct_ok(host); // 直连恢复：清除熔断
                }
                (log)(&format!(
                    "[上游] {host}{path} 新连接 {}, {}ms",
                    up.ip,
                    t0.elapsed().as_millis()
                ));
                return Ok(resp);
            }
            Ok(Err(e)) => e,
            Err(_) => "响应预算超时".to_string(),
        };
        // 数据层失败：本次拨到的 IP 垫底，下一轮自动换候选。
        // 垫底只认幂等且无镜像兜底的失败——POST/内容域失败不代表 IP 死，垫底会让池序被噪声刷换。
        if !name.is_empty() && is_simple && !is_content {
            pool::serial_note(name, &up.ip, "noreply");
        }
        upstream::drop_h2(host, &up.ip);
        (log)(&format!(
            "[MITM] {host} 上游第 {} 次尝试失败({e}), 垫底换候选",
            attempt + 1
        ));
        if !is_simple {
            return Err(format!("POST 等非简单方法不重发({e})"));
        }
        if is_content {
            pool::content_direct_fail(host);
            return Err(format!("内容域直连全灭({e})"));
        }
        continue; // GET/HEAD: 换下一个候选重发完整请求
    }
    Err("直连串发全灭(完整请求逐个试完)".to_string())
}

async fn gh_defuse(
    log: &LogFn,
    host: &str,
    info: &UpstreamInfo,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let name = pool::pool_for(host);
    let is_simple = true;
    let mut resp = get_direct(log, out, host, info, is_simple, body).await?;
    let mut tried = 0; // 已垫底重试候选数(仅日志)
    let mut seen = std::collections::HashSet::new(); // 本轮已试 IP
    let mut empty_ip_retries = 0u8; // 归属缺失分支的重试上限
    loop {
        if !is_gh_block_page(&mut resp).await {
            return Ok(resp);
        }
        let ip = info.get();
        if name.is_empty() {
            return Ok(resp); // 非池域名: 无表可换, 诚实透传
        }
        if ip.is_empty() {
            empty_ip_retries += 1;
            if empty_ip_retries > 3 {
                return Ok(resp);
            }
            resp = match get_direct(log, out, host, info, is_simple, body).await {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            continue;
        }
        pool::serial_note(name, &ip, "block"); // 错误页垫底: 重试自动跳过该 IP
                                               // 风控页 = 该 IP 的连接不可信(HTTP 层成功所以连接活着) —— 必须同步
                                               // 清复用槽, 否则下一个请求缓存命中又拿到坏连接: 垫底→重拨→再命中→
                                               // 再垫底乒乓死循环(2026-10-15 实锤: 单 IP 重试计数刷到 129, 每个请求
                                               // 白烧一次完整往返, 搜索/进仓库全部变慢)
        upstream::drop_h2(host, &ip);
        // 2026-10-14 起直连腿每请求新拨号(fresh), 无共享连接池可丢 ——
        // 垫底后下一 attempt 的 serial_dial 必然跳过该 IP
        tried += 1;
        // 整表轮换完一圈(同 IP 再现) = 全员拦截页: 再转只会重复, 交回 GitHub
        // 真实拦截响应终止。垫底+拔连接必须发生在终止判定之前 —— 否则交付时
        // 坏连接仍挂在复用缓存, 下个请求乒乓(2026-10-17 复审补充)
        if !seen.insert(ip.to_string()) {
            (log)(&format!(
                "[MITM] {host} 全部可用边缘均返回拦截页({tried}), 交付真实响应"
            ));
            return Ok(resp);
        }
        (log)(&format!(
            "[MITM] {host} 边缘 {ip} 返回风控拦截页, 垫底换 IP 重试({tried})"
        ));
        resp = match get_direct(log, out, host, info, is_simple, body).await {
            Ok(r) => r,
            Err(e) => return Err(e), // 重试全灭(所有候选试遍): 交回错误
        };
    }
}
/// 交付计数体：统计实际推给客户端的字节数。
/// 推完记"推完"，被提前关记"推了 N/总 M 后连接终止"——区分"没发够"与"客户端自己关"。
struct CountingBody {
    inner: BoxBody,
    sent: u64,
    total: Option<u64>,
    done: bool,
    log: LogFn,
    tag: String,
}
impl CountingBody {
    fn new(inner: BoxBody, total: Option<u64>, log: LogFn, tag: String) -> Self {
        Self {
            inner,
            sent: 0,
            total,
            done: false,
            log,
            tag,
        }
    }
    fn summary(&self) -> String {
        match self.total {
            Some(t) => format!("{}B/{}B", self.sent, t),
            None => format!("{}B", self.sent),
        }
    }
}
impl hyper::body::Body for CountingBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    this.sent += d.len() as u64;
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => {
                this.done = true;
                (this.log)(&format!("[交付] {} 推完({})", this.tag, this.summary()));
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
impl Drop for CountingBody {
    fn drop(&mut self) {
        if !self.done {
            (self.log)(&format!(
                "[交付] {} 推了({})后连接终止(客户端关闭或响应被弃)",
                self.tag,
                self.summary()
            ));
        }
    }
}
/// 镜像大响应（>1MB）包交付计数体；小响应与 HEAD 不包（HEAD 无体，包了误报 0B 终止）。
/// 只罩镜像腿（直连腿字节账由 [隧道] ↑↓ 覆盖）。
fn counted_mirror(
    resp: hyper::Response<BoxBody>,
    host: &str,
    path: &str,
    is_head: bool,
    log: &LogFn,
) -> hyper::Response<BoxBody> {
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if is_head || total.map_or(true, |t| t <= 1024 * 1024) {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(CountingBody::new(
        body,
        total,
        log.clone(),
        format!("{host}{path}"),
    ));
    hyper::Response::from_parts(parts, body)
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
    let ip = info.get();
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
<p>当前处于封锁窗口期, 代理正在按表自动重试。</p>\
<p>本页每 8 秒自动刷新, 窗口一过即可打开。</p>\
<p>状态可查看工作台 <a href=\"http://127.0.0.1:{ui_port}\">127.0.0.1:{ui_port}</a>。</p>\
</div></body></html>",
    );
    axum::response::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/html; charset=utf-8")
        .header("retry-after", "8")
        .body(BoxBody::new(
            http_body_util::Full::new(Bytes::from(html))
                .map_err(|never| std::io::Error::other(never)),
        ))
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
    for addr in addrs.iter().take(4) {
        let ip = addr.ip().to_string();
        let conn = match pool::dial::dial_one(host, &ip, pool::dial::MODE_SNI, true).await {
            Ok(c) => c,
            Err(e) => {
                (log)(&format!("[DNS直连] {host} <- {ip} 拨号失败({e})"));
                continue;
            }
        };
        let up = match upstream::h2_from_dialed(host, conn, &ip, "真名(系统DNS)", log).await {
            Ok(u) => u,
            Err(e) => {
                (log)(&format!("[DNS直连] {host} <- {ip} h2 失败({e})"));
                continue;
            }
        };
        let attempt_req = build_request(out, body);
        let budget = if pool::route::is_content_host(host) {
            CONTENT_REQUEST_BUDGET
        } else {
            REQUEST_BUDGET
        };
        let timed = tokio::time::timeout(budget, upstream::h2_send(&up, &attempt_req, body));
        match timed.await {
            Ok(Ok(resp)) => {
                info.set(&ip);
                upstream::store_h2(host, up); // 入缓存: 后续请求走复用快路径
                (log)(&format!(
                    "[DNS直连] {host}{} 新连接 {ip}, 成功",
                    path_of(out.uri())
                ));
                return Ok(resp);
            }
            _ => {
                upstream::drop_h2(host, &ip);
                (log)(&format!("[DNS直连] {host} <- {ip} 请求失败, 换下个解析 IP"));
            }
        }
    }
    Err(format!(
        "{host} 系统 DNS 直连腿全灭({} 个候选)",
        addrs.len().min(4)
    ))
}
async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
) -> Result<hyper::Response<BoxBody>, String> {
    // 凭据查询串拒走镜像：signed URL 等价 bearer，交第三方镜像即外泄。
    if let Some(q) = out.uri().query() {
        if has_credential_query(q) {
            return Err(format!("{host} 查询串含凭据参数, 拒绝镜像(防外泄)"));
        }
    }
    let orig_url = format!(
        "https://{host}{}",
        out.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default()
    );
    let path = path_of(out.uri());
    // 链归属与请求 host 解耦：release 附件走 release-assets 专属链（github.com 链头慢且中断）。
    // URL 仍用原 host 构造（镜像自己跟随 302 落点），熔断/限长/链序按归属 host。
    let chain_host = pool::route::mirror_chain_host(host, &path);
    if chain_host != host {
        (log)(&format!(
            "[镜像] {host}{path} 归属链 {chain_host}（不用 {host} 自己的链）"
        ));
    }
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let cond = out
        .headers()
        .get("if-none-match")
        .or_else(|| out.headers().get("if-modified-since"))
        .and_then(|v| v.to_str().ok());
    if let Some(r) = range {
        (log)(&format!("[镜像] {host}{path} 客户端 Range: {r}"));
    }
    if let Some(c) = cond {
        (log)(&format!("[镜像] {host}{path} 客户端条件请求: {c}"));
    }
    let chain = pool::mirror_chain(chain_host);
    if chain.is_empty() {
        return Err(format!("{host} 无镜像链({chain_host})"));
    }
    if pool::mirror_breaker_open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(chain.len())
        .min(chain.len());
    for (i, m) in chain.iter().take(limit).enumerate() {
        let req = match mirror_request(out, m, &orig_url) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 请求构造失败({e}), 链内下一个"));
                continue;
            }
        };
        let t0 = Instant::now();
        match mirror_do(req, m, log).await {
            Ok(resp) => {
                let skipped = if i == 0 {
                    String::new()
                } else {
                    format!(", 跳过前 {i} 个")
                };
                (log)(&format!(
                    "[镜像] {host}{path} via {m} (链位 {}/{len}{skipped}, 头 {ms}ms)",
                    i + 1,
                    len = chain.len(),
                    ms = t0.elapsed().as_millis()
                ));
                pool::mirror_breaker_clear(chain_host); // 链是活的: 清全灭熔断
                return Ok(resp);
            }
            Err(e) => {
                (log)(&format!(
                    "[镜像] {host} {m} 失败({e}, {}ms), 链内下一个",
                    t0.elapsed().as_millis()
                ));
            }
        }
    }
    pool::mirror_breaker_set(chain_host); // 整链烧完仍全灭: 熔断 60s, 后续图快速失败
    Err(format!("{host} 镜像链全灭({chain_host} 链 {limit} 个)"))
}
fn build_request(out: &hyper::Request<BoxBody>, body: &Option<Bytes>) -> hyper::Request<BoxBody> {
    let mut builder = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri());
    for (k, v) in out.headers() {
        builder = builder.header(k, v);
    }
    let body = match body {
        Some(b) => {
            BoxBody::new(http_body_util::Full::new(b.clone()).map_err(|never| match never {}))
        }
        None => BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(|never| match never {})),
    };
    builder.body(body).expect("请求构造不会失败")
}
fn mirror_request(
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
) -> Result<hyper::Request<BoxBody>, String> {
    let url = format!("{mirror}/{orig_url}");
    let mut builder = hyper::Request::builder().method(out.method()).uri(url);
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if upstream::is_hop_by_hop(&low)
            || matches!(low.as_str(), "cookie" | "authorization" | "host" | "referer")
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    let body =
        BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(|e| std::io::Error::other(e)));
    builder.body(body).map_err(|e| e.to_string())
}
/// 镜像腿单发：5s 响应头预算 + 假页拒判（≥400 或 text/html 不算成绩）。
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    let client = upstream::mirror_client(log);
    let timed = tokio::time::timeout(MIRROR_HEAD_TIMEOUT, client.request(req));
    let resp = match timed.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("镜像响应头预算超时".to_string()),
    };
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    // 镜像须直出内容：3xx=甩锅、HTML=假站、≥400=拒绝；304 例外（缓存热时合法响应，曾误判致整链全灭）。
    let st = resp.status().as_u16();
    if (st >= 300 && st != 304) || ct.contains("text/html") {
        return Err(format!("{mirror} 状态 {st}"));
    }
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(http_body_util::BodyExt::map_err(
        body,
        std::io::Error::other,
    ));
    Ok(hyper::Response::from_parts(parts, body))
}
fn has_credential_query(query: &str) -> bool {
    query.split('&').any(|kv| {
        let name = kv.split('=').next().unwrap_or("").to_lowercase();
        name == "token"
            || name == "sig"
            || name == "signature"
            || name == "jwt"
            || name == "auth"
            || name == "access_token"
            || name == "session_token"
            || name == "awsaccesskeyid"
            || name.starts_with("x-amz-")
    })
}
pub const CALIBRATE_TEMPLATES: &[(&str, &str)] = &[
    (
        "github.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.5.1/git-lfs-windows-amd64-v3.5.1.zip",
    ),
    (
        "raw.githubusercontent.com",
        "https://raw.githubusercontent.com/torvalds/linux/master/README",
    ),
    (
        "gist.githubusercontent.com",
        "https://gist.githubusercontent.com/octocat/6cad326836d38bd3a7ae/raw/db9c55113504e46fa076e7df3a04ce592e2e86d8/hello_world.rb",
    ),
    (
        "avatars.githubusercontent.com",
        "https://avatars.githubusercontent.com/u/1?v=4&size=64",
    ),
    (
        "user-images.githubusercontent.com",
        "https://user-images.githubusercontent.com/543273/64829357-7d195e00-d5ce-11e9-91f1-e58deb6e7bbf.png",
    ),
    (
        "codeload.github.com",
        "https://codeload.github.com/torvalds/linux/tar.gz/refs/tags/v2.6.11",
    ),
    (
        "objects.githubusercontent.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.5.1/git-lfs-windows-amd64-v3.5.1.zip",
    ),
    (
        "release-assets.githubusercontent.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.0.2/git-lfs-windows-amd64-v3.0.2.zip",
    ),
    (
        "media.githubusercontent.com",
        "https://media.githubusercontent.com/media/torvalds/linux/master/README",
    ),
];
// 两模式：Throughput=大文件四链 11 家并发竞速（12s 窗口按实收字节排名）；Ttfb=内容域五链响应头测速。
// 铁律：host 间严格串行——同一镜像服务多条链，跨链并发互相污染测量；并发只在手动低频校准，常规流量竞速已废。
pub enum CalibMode {
    Throughput,
    Ttfb,
}

static CALIB_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static CALIB_REPORT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn calibrate_running() -> bool {
    CALIB_RUNNING.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn last_calibrate_report() -> String {
    CALIB_REPORT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

pub fn set_calibrate_report(r: Option<String>) {
    if let Ok(mut g) = CALIB_REPORT.lock() {
        *g = r;
    }
}

pub fn try_begin_calibrate() -> bool {
    !CALIB_RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst)
}

pub fn end_calibrate() {
    CALIB_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
}

const CALIB_THROUGHPUT_WINDOW: Duration = Duration::from_secs(12);
const CALIB_THROUGHPUT_CAP: u64 = 5 * 1024 * 1024;

fn mirror_get(uri: http::Uri) -> Result<hyper::Request<BoxBody>, String> {
    hyper::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("user-agent", "Mozilla/5.0")
        .header("accept", "*/*")
        .body(BoxBody::new(
            http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
        ))
        .map_err(|e| e.to_string())
}

async fn throughput_probe(
    mirror: &str,
    tmpl: &str,
    log: &LogFn,
) -> Result<(u64, u128), String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let req = mirror_get(uri)?;
    let client = upstream::mirror_client(log);
    let start = tokio::time::Instant::now();
    let deadline = start + CALIB_THROUGHPUT_WINDOW;
    let resp = match tokio::time::timeout_at(deadline, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("窗口内未见响应头".to_string()),
    };
    let st = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if st >= 300 || ct.contains("text/html") {
        return Err(format!("{mirror} 状态 {st}"));
    }
    let mut body = resp.into_body();
    let mut n: u64 = 0;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() || n >= CALIB_THROUGHPUT_CAP {
            break;
        }
        match tokio::time::timeout(remain, http_body_util::BodyExt::frame(&mut body)).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(d) = frame.into_data() {
                    n += d.len() as u64;
                }
            }
            _ => break, // EOF / 上游错 / 窗口到
        }
    }
    let ms = start.elapsed().as_millis();
    Ok((n, ms))
}

/// 单 host 内 11 家并发竞速：同窗口起跑按字节数排名，失败(负)沉底。
async fn throughput_race(
    host: &str,
    chain: &[String],
    tmpl: &str,
    log: &LogFn,
) -> Vec<(String, i64)> {
    let host = host.to_string();
    let mut joins = tokio::task::JoinSet::new();
    for m in chain {
        let m = m.clone();
        let tmpl = tmpl.to_string();
        let host = host.clone();
        let log = log.clone();
        joins.spawn(async move {
            let r = throughput_probe(&m, &tmpl, &log).await;
            match &r {
                Ok((bytes, ms)) => {
                    (log)(&format!(
                        "[校准] {host} {m} 吞吐 {}KB ({ms}ms 内)",
                        bytes / 1024
                    ));
                }
                Err(e) => {
                    (log)(&format!("[校准] {host} {m} 失败({e})"));
                }
            }
            (m, r.map(|(b, _)| b as i64).unwrap_or(-1))
        });
    }
    let mut rows: Vec<(String, i64)> = Vec::new();
    while let Some(r) = joins.join_next().await {
        if let Ok(row) = r {
            rows.push(row);
        }
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1)); // 字节数降序，失败(负)沉底
    rows
}

async fn calibrate_one(mirror: &str, tmpl: &str, log: &LogFn) -> Result<u16, String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let resp = mirror_do(mirror_get(uri)?, mirror, log).await?;
    Ok(resp.status().as_u16())
}
pub async fn calibrate_chains(log: &LogFn, mode: CalibMode) -> String {
    let chains = pool::mirror_chains_snapshot();
    let mut report = String::new();
    for (host, chain) in chains {
        let big = pool::route::is_big_file_host(&host);
        let eligible = match mode {
            CalibMode::Throughput => big,
            CalibMode::Ttfb => !big,
        };
        if !eligible {
            continue;
        }
        let Some((_, tmpl)) = CALIBRATE_TEMPLATES.iter().find(|(h, _)| *h == host) else {
            continue;
        };
        let rows = match mode {
            CalibMode::Throughput => throughput_race(&host, &chain, tmpl, log).await,
            CalibMode::Ttfb => {
                let mut rows: Vec<(String, i64)> = Vec::new();
                for m in &chain {
                    let t0 = Instant::now();
                    let res = calibrate_one(m, tmpl, log).await;
                    let ms = t0.elapsed().as_millis() as i64;
                    match res {
                        Ok(st) => {
                            (log)(&format!("[校准] {host} {m} {ms}ms {st}"));
                            rows.push((m.clone(), ms));
                        }
                        Err(e) => {
                            (log)(&format!("[校准] {host} {m} 失败({e})"));
                            rows.push((m.clone(), -ms));
                        }
                    }
                }
                rows.sort_by_key(|(_, ms)| -*ms); // TTFB：小者优；失败(负)沉底
                rows
            }
        };
        let new_chain: Vec<String> = rows.iter().map(|(m, _)| m.clone()).collect();
        let summary: Vec<String> = rows
            .iter()
            .map(|(m, v)| {
                if *v > 0 {
                    let human = match mode {
                        CalibMode::Throughput => format!("{}KB", v / 1024),
                        CalibMode::Ttfb => format!("{}ms", v),
                    };
                    format!("{}({})", m.trim_start_matches("https://"), human)
                } else {
                    format!("{}(失败)", m.trim_start_matches("https://"))
                }
            })
            .collect();
        report.push_str(&format!("{host}\n  {}\n", summary.join(" -> ")));
        pool::set_mirror_chain(&host, &new_chain, "校准");
    }
    if report.is_empty() {
        "无可校准的镜像链".to_string()
    } else {
        report
    }
}
async fn mitm_upgrade(
    log: LogFn,
    req: hyper::Request<Incoming>,
    host: &str,
) -> axum::response::Response<BoxBody> {
    let mut req = req;
    let upgraded = match hyper::upgrade::on(&mut req).await {
        Ok(u) => u,
        Err(_) => return mitm_unavailable(&req, host),
    };
    let name = pool::pool_for(host);
    let (mut conn, _ip, _shape) = if !pool::serial_pool(name) {
        let addr = format!("{host}:443");
        let tcp = match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(t)) => t,
            _ => return mitm_unavailable(&req, host),
        };
        let _ = tcp.set_nodelay(true);
        (Dialed::Plain(tcp), "system-dns".to_string(), String::new())
    } else {
        match pool::serial_dial(name, host, CancellationToken::new(), true, Some(&log)).await {
            Ok(v) => v,
            Err(_) => return mitm_unavailable(&req, host),
        }
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\n",
        req.method(),
        req.uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
    );
    for (k, v) in req.headers() {
        head.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
    }
    head.push_str("\r\n");
    use tokio::io::AsyncWriteExt;
    if conn.write_all(head.as_bytes()).await.is_err() {
        return mitm_unavailable(&req, host);
    }
    let (mut ar, mut aw) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
    let (mut br, mut bw) = tokio::io::split(conn);
    let down = tokio::spawn(async move { tokio::io::copy(&mut br, &mut aw).await.unwrap_or(0) });
    let _up = tokio::io::copy(&mut ar, &mut bw).await;
    let _ = down.await;
    axum::response::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(BoxBody::new(
            http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}),
        ))
        .unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mirror_chain_cap_scope() {
        for h in [
            "raw.githubusercontent.com",
            "camo.githubusercontent.com",
            "avatars.githubusercontent.com",
            "user-images.githubusercontent.com",
            "media.githubusercontent.com",
            "gist.githubusercontent.com",
        ] {
            assert_eq!(mirror_chain_cap(h), Some(5), "{h} 应限长 5 家");
        }
        for h in [
            "codeload.github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "github.com",
        ] {
            assert_eq!(mirror_chain_cap(h), None, "{h} 应用全链");
        }
    }
    #[test]
    fn mirror_request_strips_identity_and_hop_by_hop() {
        let out = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://raw.githubusercontent.com/a/b")
            .header("cookie", "logged_in=yes")
            .header("authorization", "Bearer tok")
            .header("connection", "close")
            .header("keep-alive", "timeout=5")
            .header("upgrade", "websocket")
            .header("te", "trailers")
            .header("range", "bytes=0-1023")
            .header("accept-encoding", "gzip")
            .header("user-agent", "UA/1.0")
            .body(BoxBody::new(
                http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
            ))
            .unwrap();
        let req = mirror_request(
            &out,
            "https://gh-proxy.com",
            "https://raw.githubusercontent.com/a/b",
        )
        .unwrap();
        let h = req.headers();
        for gone in [
            "cookie",
            "authorization",
            "host",
            "referer",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
        ] {
            assert!(h.get(gone).is_none(), "{gone} 应被剥除");
        }
        assert_eq!(h.get("range").unwrap(), "bytes=0-1023", "业务头必须保留");
        assert_eq!(h.get("accept-encoding").unwrap(), "gzip");
        assert_eq!(h.get("user-agent").unwrap(), "UA/1.0");
        let uri = req.uri().to_string();
        assert!(
            uri.starts_with("https://gh-proxy.com/https://raw.githubusercontent.com/"),
            "拼 URL 形态: {uri}"
        );
    }
    #[tokio::test]
    async fn gzip_sniff_detects_block_and_keeps_raw_prefix() {
        use std::io::Write;
        fn gzip(data: &[u8]) -> Vec<u8> {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        let mut html = b"<!doctype html><html><body><h1>".to_vec();
        html.extend_from_slice(&vec![b'a'; 2000]);
        html.extend_from_slice(b"</h1><p>Whoa there, pardner!</p></body></html>");
        let compressed = gzip(&html);
        let body = BoxBody::new(
            http_body_util::Full::new(Bytes::from(compressed.clone()))
                .map_err(std::io::Error::other),
        );
        let (parts, _) = hyper::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let mut resp = hyper::Response::from_parts(parts, body);
        assert!(is_gh_block_page(&mut resp).await, "gzip 压缩的拦截页应被判定");
        let raw = resp
            .extensions()
            .get::<PeekRaw>()
            .expect("必须保留原始压缩帧")
            .0
            .clone();
        let joined: Vec<u8> = raw.iter().flat_map(|b| b.to_vec()).collect();
        assert!(!joined.is_empty());
        assert!(
            compressed.starts_with(&joined),
            "写回前缀必须是原始压缩流的真前缀"
        );
        let normal = gzip(b"<!doctype html><html><body>hello</body></html>");
        let body2 = BoxBody::new(
            http_body_util::Full::new(Bytes::from(normal)).map_err(std::io::Error::other),
        );
        let (parts2, _) = hyper::Response::builder()
            .header("content-type", "text/html")
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let mut resp2 = hyper::Response::from_parts(parts2, body2);
        assert!(!is_gh_block_page(&mut resp2).await);
    }
    #[test]
    fn mirrors_pool_health() {
        assert!(
            pool::MIRRORS.len() >= 6,
            "镜像候选过少: {}",
            pool::MIRRORS.len()
        );
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for m in pool::MIRRORS {
            assert!(m.starts_with("https://"), "镜像须为 https: {m}");
            assert!(seen.insert(*m), "镜像链接重复: {m}");
        }
        assert_eq!(pool::CONTENT_HOSTS.len(), pool::DEFAULT_CHAINS.len());
        for (host, chain) in pool::DEFAULT_CHAINS {
            assert!(
                pool::CONTENT_HOSTS.contains(host),
                "默认链 host 越界: {host}"
            );
            let mut seen_c: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for m in *chain {
                assert!(pool::MIRRORS.contains(m), "{host} 默认链含池外镜像 {m}");
                assert!(seen_c.insert(*m), "{host} 默认链有重复: {m}");
            }
        }
        for h in pool::CONTENT_HOSTS {
            assert!(
                CALIBRATE_TEMPLATES.iter().any(|(host, _)| host == h),
                "{h} 缺校准模板"
            );
        }
    }
    #[test]
    fn release_asset_path_gate() {
        use pool::route::{master_route, Route};
        let mirror = |host: &str, path: &str| {
            matches!(master_route(host, "GET", path), Route::Mirror)
        };
        let not_mirror = |host: &str, path: &str| {
            !matches!(master_route(host, "GET", path), Route::Mirror)
        };
        assert!(mirror(
            "github.com",
            "/torvalds/linux/archive/refs/tags/v6.6.tar.gz"
        ));
        assert!(mirror(
            "github.com",
            "/cli/cli/releases/download/v2.0.0/gh_2.0.0_windows_amd64.zip"
        ));
        assert!(mirror(
            "github.com",
            "/docmirror/dev-sidecar/releases/latest/download/DevSidecar.exe"
        ));
        assert!(not_mirror("github.com", "/torvalds/linux/releases"));
        assert!(not_mirror("github.com", "/torvalds/linux/releases/tag/v6.6"));
        assert!(not_mirror(
            "github.com",
            "/torvalds/linux/info/refs?service=git-upload-pack"
        ));
        assert!(not_mirror("github.com", "/torvalds/linux/git-upload-pack"));
        assert!(not_mirror(
            "api.github.com",
            "/repos/x/y/releases/assets/1"
        ));
        assert!(mirror("codeload.github.com", "/x/y/legacy.tar.gz"));
    }

    #[test]
    fn stream_decision_contract() {
        use upstream::MAX_REPLAY_BODY;
        assert_eq!(
            stream_decision(
                &Method::POST,
                "/fastgh/fgit.git/git-receive-pack",
                Some(100)
            ),
            Some("git 智能协议")
        );
        assert_eq!(
            stream_decision(&Method::POST, "/fastgh/fgit.git/git-upload-pack", None),
            Some("git 智能协议")
        );
        assert_eq!(
            stream_decision(
                &Method::GET,
                "/fastgh/fgit.git/info/refs?service=git-receive-pack",
                None
            ),
            None
        );
        assert_eq!(
            stream_decision(&Method::PUT, "/some/upload", Some(MAX_REPLAY_BODY as u64 + 1)),
            Some("声明超限")
        );
        assert_eq!(
            stream_decision(&Method::POST, "/api/x", Some(MAX_REPLAY_BODY as u64)),
            None
        );
        assert_eq!(stream_decision(&Method::POST, "/api/x", None), None);
        assert_eq!(stream_decision(&Method::GET, "/x", Some(u64::MAX)), None);
        assert_eq!(stream_decision(&Method::HEAD, "/x", Some(u64::MAX)), None);
    }

    #[tokio::test]
    async fn counting_body_logs_completion_and_truncation() {
        use hyper::body::Body;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let l = logs.clone();
        let log: LogFn = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
        let two_chunks = || {
            BoxBody::new(http_body_util::StreamBody::new(futures_util::stream::iter(
                vec![
                    Ok(hyper::body::Frame::data(Bytes::from_static(b"01234"))),
                    Ok(hyper::body::Frame::data(Bytes::from_static(b"56789"))),
                ],
            )))
        };
        let counted = CountingBody::new(two_chunks(), Some(10), log.clone(), "t/full".into());
        let out = http_body_util::BodyExt::collect(counted).await.unwrap();
        assert_eq!(out.to_bytes().len(), 10);
        let mut counted = CountingBody::new(two_chunks(), Some(10), log.clone(), "t/part".into());
        let f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut counted).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.into_data().unwrap().len(), 5);
        drop(counted);
        let lines = logs.lock().unwrap();
        assert!(
            lines.iter().any(|s| s.contains("t/full 推完(10B/10B)")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|s| s.contains("t/part 推了(5B/10B)后连接终止")),
            "{lines:?}"
        );
    }

    #[test]
    fn counted_mirror_skips_head_and_small() {
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let l = logs.clone();
        let log: LogFn = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
        let big = BoxBody::new(
            http_body_util::Full::new(bytes::Bytes::from_static(b"0123456789"))
                .map_err(|never| match never {}),
        );
        let big_resp = hyper::Response::builder()
            .status(StatusCode::OK)
            .header("content-length", "132855191")
            .body(big)
            .unwrap();
        let r = counted_mirror(big_resp, "h", "/p", true, &log);
        drop(r);
        let small = hyper::Response::builder()
            .status(StatusCode::OK)
            .header("content-length", "10")
            .body(BoxBody::new(
                http_body_util::Full::new(bytes::Bytes::from_static(b"0123456789"))
                    .map_err(|never| match never {}),
            ))
            .unwrap();
        let r = counted_mirror(small, "h", "/p", false, &log);
        drop(r);
        let lines = logs.lock().unwrap();
        assert!(lines.is_empty(), "HEAD 与小响应都不该有交付日志: {lines:?}");
    }
}
