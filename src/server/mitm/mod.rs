//! MITM：池内域名本地终结 TLS，按 route::master_route 分流（直连串发 / 内容域回落镜像链 / 大文件域直连同台 ECT 派发 / 流式直通）。
//! 拦截页(403 restricted/400 Whoa)本地识别 gh_defuse。
use super::upstream::{self, BoxBody, Incoming, REQUEST_BUDGET};
use crate::certgen::Authority;
use crate::config;
use crate::pool::{self, LogFn};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioExecutor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod defuse;
mod mirror;
mod page_cache;
mod redirect_memo;

pub use mirror::{calibrate_chains, last_calibrate_report, set_calibrate_report, CALIB_RUNNING};

use defuse::gh_defuse;
use mirror::chain_fetch;


const CONTENT_REQUEST_BUDGET: Duration = Duration::from_secs(4); // 内容域 .133 直连腿响应头预算
const GET_DIRECT_MAX_ATTEMPTS: usize = 24;
pub fn mitm_scope(authority: Option<&Arc<Authority>>, host: &str) -> bool {
    if authority.is_none() || !crate::settings::mitm() {
        return false;
    }
    !config::pool_for(host).is_empty()
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
        // 浏览器掐断本地连接(RST/提前关闭/写体中止)是高频日常行为(切页/取消/回收连接),
        // 不当错误刷屏; 协议类等真错误仍保留。GitHub 侧故障有各自的行([串发]/[镜像]/[上游])。
        let benign = e.to_string().contains("connection error")
            || e.is_incomplete_message()
            || e.is_closed()
            || e.is_body_write_aborted();
        if !benign {
            (srv.log)(&format!("[MITM] {host} 服务层错误: {e}"));
        }
    }
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
    // GitHub 前端遥测（Datadog RUM / error beacon）只占带宽、不影响页面功能。
    // 实测 api.github.com 436 个请求里 325 个是它（p50 690ms），把搜索/GraphQL 挤在后面。
    // 必须先把请求体读掉再回 204：body 不消费会让 hyper 重置连接，反而逼浏览器重开。
    if is_telemetry(&host, &path_of(req.uri())) {
        let _ = http_body_util::BodyExt::collect(req.into_body()).await;
        return no_content();
    }

    let info = UpstreamInfo::default();
    // 页面缓存命中即秒回；细节全在 page_cache 模块。
    // 勿加 SWR/后台 ETag 验证：_gh_sess 轮换，旧 cookie 重用被 GitHub 判定
    // 账号泄露（与 /login 排除同源的安全边界）。要看最新按 F5 直达上游。
    if let Some(cached) = page_cache::cache_take(&log, &req, &host) {
        return write_upstream(cached, "cache", &info);
    }
    // 头像入口 302 记忆：github.com/<user>.png 是「302 + no-cache」入口，浏览器
    // 每次渲染页面都要重问一遍跳转（一个来回 260-310ms × 十几个并行）。跳转目标
    // 按用户稳定，记住后本地直答——浏览器行为不变，只是来回归零。fast path 无日志。
    if req.method() == Method::GET {
        if let Some(loc) =
            redirect_memo::cached_location(&host, req.uri().path(), req.uri().query())
        {
            let _ = http_body_util::BodyExt::collect(req.into_body()).await;
            let resp = hyper::Response::builder()
                .status(StatusCode::FOUND)
                .header("location", loc)
                .header("cache-control", "no-cache")
                .body(upstream::full_body(Bytes::new()))
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
            Some(prefix) => upstream::prepend_body(
                vec![Bytes::from(prefix)],
                incoming_to_body(req.into_body()),
            ),
            None => incoming_to_body(req.into_body()),
        };
        return stream_passthrough(&log, &out, &host, &info, body, reason).await;
    }
    let out_body = match &replay {
        Some(b) => out.map(|_| upstream::full_body(b.clone())),
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
            mirror::range_bytes_of(req.headers().get("range").and_then(|v| v.to_str().ok()));
        // 直连同台：候选 = 镜像链 + 直连，ECT 统一派发；链空时候选=仅直连。
        // 直连失败记 60s 降权(与镜像同款)，全部候选(含直连)耗尽才 502。
        match mirror_or_direct(&log, &out_body, &host, chain_host, new_bytes, &info, &replay).await {
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
    let name = config::pool_for(&host);
    let mut resp = match get_direct(&log, &out_body, &host, &info, is_simple, &replay).await {
        Ok(r) => r,
        Err(e) => {
            match pool::route::fallback_for(name, &host) {
                pool::route::Fallback::MirrorDns if is_simple => {
                    let chain_host = pool::route::mirror_chain_host(&host, &path);
                    let new_bytes = mirror::range_bytes_of(
                        req.headers().get("range").and_then(|v| v.to_str().ok()),
                    );
                    // 直连刚在全灭分支失败过: load 会带 60s 降权, chain_fetch 内
                    // ECT 自动跳过直连优先镜像——语义即"兜底最后一次机会"。
                    match mirror_or_direct(&log, &out_body, &host, chain_host, new_bytes, &info, &replay).await
                    {
                        Ok(resp) => return resp,
                        Err(_) => (log)(&format!("[MITM] {host}{path} 直连全灭且镜像链全灭")),
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
                        (log)(&format!("[MITM] {host}{path} DNS 直连腿也失败({de})"));
                    }
                }
            }
            return mitm_unavailable(&req, &host, "直连与镜像链均不可用, 疑似封锁窗口期, 代理正在按表自动重试。");
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
                return mitm_unavailable(&req, &host, "全部边缘均返回风控拦截页, 代理正在按表自动重试。");
            }
        }
    }
    // 写操作成功后的缓存失效：改完设置/发完评论跳回来必须看到新页面
    // （内存热点同步清 + 磁盘半场投递管家线程，见 page_cache 模块）
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
    let resp = page_cache::cache_put(&log, &req, &host, resp).await;
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
        .body(upstream::full_body(Bytes::from_static(b"upstream unavailable")))
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
    let name = config::pool_for(host);
    let path = path_of(out.uri());
    let t0 = Instant::now();
    let mut body = Some(body);
    let (fut, send, up) = 'conn: {
        if let Some(up) = upstream::cached_h2(host) {
            match upstream::h2_open_stream(&up, out, false).await {
                Ok((fut, send)) => break 'conn (fut, send, up),
                Err(e) => {
                    upstream::drop_h2_id(host, up.id);
                    (log)(&format!("[流式] {host}{path} 缓存连接失效({e}), 新拨重试"));
                }
            }
        }
        match upstream::dial_upstream(name, host, log).await {
            Ok((up, _fresh)) => match upstream::h2_open_stream(&up, out, false).await {
                Ok((fut, send)) => break 'conn (fut, send, up),
                Err(e) => {
                    upstream::drop_h2_id(host, up.id);
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
            *info.lock().unwrap() = up.ip.clone();
            if !name.is_empty() {
                pool::cursor_note(name, host, &up.ip, true, false, up.slot);
                upstream::note_latency(host, up.id, t0.elapsed().as_millis() as u64);
            }
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
        .body(upstream::empty_body())
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

/// GitHub 搜索(blackbird)反爬对同会话跨 IP 敏感:会话在双通道间漂移会被
/// 降级成"无结果"骨架页(2026-10-27 实证)。搜索系请求固定走主通道。
fn is_search_path(path: &str) -> bool {
    path.starts_with("/search")
}

/// 在给定连接上发一次请求、等响应头，返回 (响应, 耗时ms)。
/// 三处调用点（复用快路径 / 串发新拨 / 系统 DNS 直连）共用这一份：
/// 请求必须每次重建（BoxBody 不可克隆），预算与记账口径也只该有一处。
async fn send_once(
    up: &upstream::H2Upstream,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
    budget: Duration,
) -> Result<(hyper::Response<BoxBody>, u64), String> {
    let t0 = Instant::now();
    match tokio::time::timeout(budget, upstream::h2_send(up, out, body)).await {
        Ok(r) => r.map(|resp| (resp, t0.elapsed().as_millis() as u64)),
        Err(_) => Err("响应预算超时".to_string()),
    }
}

/// 直连腿组装(主路径与兜底路径共用一份)：charge 在 future 首行——镜像胜出
/// 丢弃本 future 时零残留, Err/取消靠 guard Drop 归还(字节+流数)。
fn direct_leg<'a>(
    chain_host: &str,
    new_bytes: u64,
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
        let mut guard = mirror::LoadGuard::charge(load, new_bytes);
        match get_direct(&log2, out, &host2, &info2, true, &body2).await {
            Ok(resp) => {
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

/// 主路径/兜底路径共用的镜像链派发：组装直连腿 + chain_fetch + 按实际胜出者
/// 写诊断头。Err = 候选全灭(原因透传，交 502 日志)。
async fn mirror_or_direct(
    log: &LogFn,
    out_body: &hyper::Request<BoxBody>,
    host: &str,
    chain_host: &str,
    new_bytes: u64,
    info: &UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let fetch = direct_leg(chain_host, new_bytes, log, out_body, host, info, replay);
    let resp = chain_fetch(log, out_body, host, fetch).await?;
    let route = resp
        .extensions()
        .get::<&'static str>()
        .copied()
        .unwrap_or("mirror");
    Ok(write_upstream(resp, route, info))
}

async fn try_cached(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    is_simple: bool,
    body: &Option<Bytes>,
) -> Option<Result<hyper::Response<BoxBody>, String>> {
    // name/path/want_slot/is_content 均可由 host/out 现场推导, 不占参数位。
    let name = config::pool_for(host);
    let path = path_of(out.uri());
    let want_slot = if is_search_path(&path) { Some(1) } else { None };
    let is_content = pool::route::host_is_content(host) && !config::is_whitelist(host);
    let up = upstream::cached_h2_in(host, want_slot)?;
    match send_once(&up, out, body, request_budget(is_content)).await {
        Ok((resp, ms)) => {
            *info.lock().unwrap() = up.ip.clone();
            if !name.is_empty() {
                pool::cursor_note(name, host, &up.ip, true, false, up.slot);
            }
            upstream::note_latency(host, up.id, ms);
            if is_content {
                pool::CONTENT_BREAKER.clear(host);
            }
            // 复用路径同样要学 302：头像请求几乎总走这里，只挂拨号分支会漏。
            redirect_memo::observe_response(host, out.uri(), resp.status(), resp.headers());
            (log)(&format!("[上游] {host}{path} 复用连接#{}, {ms}ms", up.id));
            Some(Ok(resp))
        }
        Err(why) => {
            upstream::drop_h2_id(host, up.id);
            (log)(&format!(
                "[MITM] {host} 复用连接失效({}, {why}), 重走串发",
                up.ip
            ));
            (!is_simple).then(|| Err("POST 等非简单方法不重发(复用连接失效)".to_string()))
        }
    }
}

pub(super) async fn get_direct(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    is_simple: bool,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let name = config::pool_for(host);
    let path = path_of(out.uri());
    let want_slot = if is_search_path(&path) { Some(1) } else { None };
    // copilot-proxy 的后缀是 githubusercontent.com，会误命中内容域熔断；
    // 它走 edge 的白名单族（Azure 段），不该被内容域的熔断拦住。
    let is_content = pool::route::host_is_content(host) && !config::is_whitelist(host);
    if name == "edge" && is_content && pool::CONTENT_BREAKER.open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    if let Some(r) = try_cached(log, out, host, info, is_simple, body).await {
        return r;
    }
// per-host 拨号单飞：锁只罩拨号等待不罩发送（持锁到发送曾致 129 并发串行 34s FCP）。
    let dial_lock = upstream::host_dial_lock(host);
    let mut guard = Some(dial_lock.lock().await);
    if name == "edge" && is_content && pool::CONTENT_BREAKER.open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    // 必须重查：等锁期间别人可能刚建好连接，直接用就不会一起排队拨号。
    // （曾经为省掉"两条都失效时多烧一个预算"砍掉过这里，结果一条连接收 GOAWAY 时
    //  18 个在途请求各自拨号，单飞锁前排成 10 秒以上的队。）
    if upstream::cached_h2_in(host, want_slot).is_some() {
        guard.take();
        if let Some(r) = try_cached(log, out, host, info, is_simple, body).await {
            return r;
        }
        guard = Some(dial_lock.lock().await);
    }
    let _dial_guard = guard;
    for attempt in 0..GET_DIRECT_MAX_ATTEMPTS {
        // 拿到拨号锁后再看一眼池子:等锁期间冷启动竞速的第二个任务可能已经
        // 建成入库——排队者直接复用它,这就是"晚成者把排队的塞进自己这里"。
        // fresh = 连接尚不在池中,发送成功后由这里入库;复用/竞速入库的不再重存。
        let (up, fresh) = match upstream::cached_h2_in(host, want_slot) {
            Some(up) => (up, false),
            None => match upstream::dial_upstream(name, host, log).await {
                Ok((up, fresh)) => (up, fresh),
                Err(e) => {
                    (log)(&format!(
                        "[MITM] {host} 上游第 {} 次尝试失败({e}), 垫底换候选",
                        attempt + 1
                    ));
                    if !is_simple {
                        return Err(format!("POST 等非简单方法不重发({e})"));
                    }
                    if is_content {
                        pool::CONTENT_BREAKER.set(host);
                        return Err(format!("内容域直连全灭({e})"));
                    }
                    continue;
                }
            },
        };
        let e = match send_once(&up, out, body, request_budget(is_content)).await {
            Ok((resp, ms)) => {
                let id = up.id;
                let up_slot = up.slot;
                let up_ip = up.ip.clone();
                *info.lock().unwrap() = up_ip.clone();
                if !name.is_empty() {
                    pool::cursor_note(name, host, &up_ip, true, false, up_slot); // 数据到手 = 真成功, 置顶
                }
                if fresh {
                    upstream::store_h2(host, up);
                    upstream::maybe_spawn_second(host, log); // 高频 host 后台补第二条
                } // 竞速路径不补:race 的另一任务就是第二条,补建会与它抢跑
                upstream::note_latency(host, id, ms); // 新连接也要记账，否则择优池没有它的样本
                if is_content {
                    pool::CONTENT_BREAKER.clear(host); // 直连恢复：清除熔断
                }
                // 头像入口的 302 顺手记一笔：下次同入口本地直答（见 redirect_memo）。
                redirect_memo::observe_response(host, out.uri(), resp.status(), resp.headers());
                (log)(&format!("[上游] {host}{path} 新连接 {up_ip}, {ms}ms"));
                return Ok(resp);
            }
            Err(e) => e,
        };
        // 数据层失败：本次拨到的 IP 垫底，下一轮自动换候选。
        // 垫底只认幂等且无镜像兜底的失败——POST/内容域失败不代表 IP 死，垫底会让池序被噪声刷换。
        if !name.is_empty() && is_simple && !is_content {
            pool::cursor_note(name, host, &up.ip, false, false, up.slot);
        }
        upstream::drop_h2_id(host, up.id);
        (log)(&format!(
            "[MITM] {host} 上游第 {} 次尝试失败({e}), 垫底换候选",
            attempt + 1
        ));
        if !is_simple {
            return Err(format!("POST 等非简单方法不重发({e})"));
        }
        if is_content {
            pool::CONTENT_BREAKER.set(host);
            return Err(format!("内容域直连全灭({e})"));
        }
        continue; // GET/HEAD: 换下一个候选重发完整请求
    }
    Err("直连串发全灭(完整请求逐个试完)".to_string())
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
        .body(upstream::full_body(Bytes::from(html)))
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
    // 与 get_direct 的口径一致：白名单域名不算内容域（copilot-proxy 后缀会误命中）。
    // 预算跟候选地址无关，循环外算一次。
    let budget_content = pool::route::host_is_content(host) && !config::is_whitelist(host);
    for addr in addrs.iter().take(4) {
        let ip = addr.ip().to_string();
        let conn = match pool::dial::dial_one(host, &ip, host, true).await {
            Ok(c) => c,
            Err(e) => {
                (log)(&format!("[DNS直连] {host} <- {ip} 拨号失败({e})"));
                continue;
            }
        };
        let up = match upstream::h2_from_dialed(host, conn, &ip, "真名(系统DNS)", 1, log).await {
            Ok(u) => u,
            Err(e) => {
                (log)(&format!("[DNS直连] {host} <- {ip} h2 失败({e})"));
                continue;
            }
        };
        match send_once(&up, out, body, request_budget(budget_content)).await {
            Ok((resp, ms)) => {
                let id = up.id;
                *info.lock().unwrap() = ip.clone();
                upstream::store_h2(host, up); // 入缓存: 后续请求走复用快路径
                upstream::note_latency(host, id, ms);
                (log)(&format!(
                    "[DNS直连] {host}{} 新连接 {ip}, 成功({ms}ms)",
                    path_of(out.uri())
                ));
                return Ok(resp);
            }
            Err(e) => {
                upstream::drop_h2(host, &ip);
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
mod tests {
    /// 审计 #1 回归: 镜像胜出时直连 future 未钧即弃——charge 在 future 内,
    /// 零残留, 账面不得出现幽灵在途字节/流数。
    #[test]
    fn direct_leg_unpolled_leaves_zero_debt() {
        let key = mirror::direct_load_key("debt.test");
        let load = mirror::mirror_load_for(&key);
        load.in_flight_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
        load.in_flight_streams.store(0, std::sync::atomic::Ordering::Relaxed);
        let out = hyper::Request::builder()
            .uri("https://debt.test/f")
            .body(upstream::empty_body())
            .unwrap();
        let log: LogFn = Arc::new(|_: &str| {});
        let info = UpstreamInfo::default();
        let leg = direct_leg("debt.test", 8 * 1024 * 1024, &log, &out, "debt.test", &info, &None);
        drop(leg);
        assert_eq!(
            load.in_flight_bytes.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "未钧即弃不得留下幽灵在途字节"
        );
        assert_eq!(
            load.in_flight_streams.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "流数同样不得泄漏"
        );
    }
    use super::*;


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
    fn telemetry_paths_intercepted_only() {
        assert!(is_telemetry("api.github.com", "/_private/browser/rum?ddforward=x"));
        assert!(is_telemetry("api.github.com", "/_private/browser/errors"));
        assert!(is_telemetry("collector.github.com", "/"));
        assert!(is_telemetry("alive.github.com", "/"));
        assert!(!is_telemetry("api.github.com", "/graphql"));
        assert!(!is_telemetry("api.github.com", "/search/suggestions"));
        assert!(!is_telemetry("github.com", "/_private/browser/rum"));
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
}
