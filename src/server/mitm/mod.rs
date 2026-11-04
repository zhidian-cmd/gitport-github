//! MITM：池内域名本地终结 TLS，按 route::master_route 分流；拦截页本地识别 gh_defuse。
use super::protocol::{self, BoxBody, Incoming, REQUEST_BUDGET};
use super::upstream;
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
mod merge;
mod page_cache;
pub(crate) mod quiet;
mod redirect_memo;

pub(crate) mod mirror;

pub use mirror::{calibrate_chains, last_calibrate_report, set_calibrate_report, CALIB_RUNNING};

use defuse::gh_defuse;
use mirror::chain_fetch;

const CONTENT_REQUEST_BUDGET: Duration = Duration::from_secs(4); // 内容域 .133 直连腿响应头预算
const GET_DIRECT_MAX_ATTEMPTS: usize = 24;
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
        match upstream::dial_upstream(host, log, false).await {
            Ok((up, _fresh)) => match upstream::h2_open_stream(&up, out, false).await {
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

/// 在给定连接上发一次请求、等响应头；三处调用点共用，请求每次重建（BoxBody 不可克隆）。
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

/// 失败发生在请求写出之前（连接已死、h2 拒绝接帧）：这条连接从没承载过该请求，
/// 对已缓存 body 的非幂等方法也可以安全换连接重发。
fn failed_before_send(why: &str) -> bool {
    why.starts_with("h2 流配额") || why.starts_with("h2 发送")
}

async fn try_cached(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    ips: &[String],
    info: &UpstreamInfo,
    is_simple: bool,
    body: &Option<Bytes>,
) -> Option<Result<hyper::Response<BoxBody>, String>> {
    // 流式请求（body 未缓存，>1MB 上传/git push）发出去就收不回，复用一条可能已死的连接
    // 等于赌命：这类请求直接新建连接，代价一次握手，换"失败不必整页重来"。
    if !is_simple && body.is_none() {
        return None;
    }
    // path/want_slot/is_content 均可由 host/out 现场推导, 不占参数位。
    let path = path_of(out.uri());
    let want_slot = if is_search_path(&path) { Some(1) } else { None };
    let is_content = pool::route::is_content(host);
    // 会话域（含 api）优先用自己建的通道；内容域双通道，池里谁快用谁。
    let up = if upstream::prefer_own_channel(host) {
        upstream::cached_h2_own(host, ips, want_slot)?
    } else {
        upstream::cached_h2_in(ips, want_slot)?
    };
    match send_once(&up, out, body, request_budget(is_content)).await {
        Ok((resp, ms)) => {
            *info.lock().unwrap() = up.ip.clone();
            pool::cursor_note(host, &up.ip, true, up.slot);
            upstream::note_latency(&up.ip, up.id, ms);
            if is_content {
                pool::CONTENT_BREAKER.clear(host);
            }
            // 复用路径同样要学 302：头像请求几乎总走这里，只挂拨号分支会漏。
            redirect_memo::observe_response(host, out.uri(), resp.status(), resp.headers());
            quiet::note_reuse(log, host, ms);
            Some(Ok(resp))
        }
        Err(why) => {
            upstream::drop_h2_id(&up.ip, up.id);
            (log)(&format!(
                "[MITM] {host} 复用连接已断({}, {why}), 重新建连",
                up.ip
            ));
            // 请求没写出去（连接已死）时，非幂等方法也能换连接重发。
            let replayable = is_simple || (body.is_some() && failed_before_send(&why));
            (!replayable).then(|| Err("POST 等非简单方法不重发(复用连接失效)".to_string()))
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
    let path = path_of(out.uri());
    let want_slot = if is_search_path(&path) { Some(1) } else { None };
    // copilot-proxy 后缀是 githubusercontent.com，会误命中内容域熔断，但它走 edge 白名单族。
    let is_content = pool::route::is_content(host);
    // 查询管线②③：host → 邻接 IP（滤黑边后）。None=不在表；空=全黑走 fallback。
    let targets = match pool::route::dial_targets(host) {
        Some(t) => t,
        None => return Err(format!("域名不在路由表({host})")),
    };
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    if is_content && pool::CONTENT_BREAKER.open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    if let Some(r) = try_cached(log, out, host, &ips, info, is_simple, body).await {
        return r;
    }
    // per-host 拨号单飞：锁只罩拨号等待不罩发送（持锁到发送曾致 129 并发串行 34s FCP）。
    let dial_lock = upstream::host_dial_lock(host);
    let mut guard = Some(dial_lock.lock().await);
    if is_content && pool::CONTENT_BREAKER.open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    // 必须重查：等锁期间别人可能刚建好连接；砍掉这步会让 18 个在途请求排队各自拨号。
    let reusable_in_pool = !(!is_simple && body.is_none())
        && if upstream::prefer_own_channel(host) {
            upstream::cached_h2_own(host, &ips, want_slot).is_some()
        } else {
            upstream::cached_h2_in(&ips, want_slot).is_some()
        };
    if reusable_in_pool {
        guard.take();
        if let Some(r) = try_cached(log, out, host, &ips, info, is_simple, body).await {
            return r;
        }
        guard = Some(dial_lock.lock().await);
    }
    let _dial_guard = guard;
    for attempt in 0..GET_DIRECT_MAX_ATTEMPTS {
        // 每轮重推一次 targets：黑边/候选可能已被别的请求更新。
        let ips: Vec<String> = match pool::route::dial_targets(host) {
            Some(t) if !t.is_empty() => t.into_iter().map(|t| t.ip).collect(),
            _ => return Err(format!("{host} 候选 IP 全部在边冷却中")),
        };
        // 每轮再查一次池子：竞速任务可能已建成，排队者直接复用。
        // 流式请求（body 未缓存）跳过复用：发了就收不回，必须走新拨的连接。
        let cached = if !is_simple && body.is_none() {
            None
        } else if upstream::prefer_own_channel(host) {
            upstream::cached_h2_own(host, &ips, want_slot)
        } else {
            upstream::cached_h2_in(&ips, want_slot)
        };
        let (up, fresh) = match cached {
            Some(up) => (up, false),
            None => match upstream::dial_upstream(
                host,
                log,
                !(!is_simple && body.is_none()),
            )
            .await
            {
                Ok((up, fresh)) => (up, fresh),
                Err(e) => {
                    // 候选被已有通道占满：换候选、再来一轮都是同一句话，直接交兜底。
                    // 这里放过会变成 24 行完全相同的失败日志（实测发生过）。
                    if e.contains(upstream::ERR_NO_FREE_IP) {
                        return Err(e);
                    }
                    // 串发冷却中：重试只是空转（30s 内必再败），立即交兜底（镜像/DNS）。
                    if pool::dial_cool_open(host) {
                        return Err(e);
                    }
                    (log)(&format!(
                        "[MITM] {host} 上游第 {} 次失败({e}), 换下一个 IP",
                        attempt + 1
                    ));
                    // 拨号失败 = 请求体一个字节都没发出去，换候选重拨对任何方法都安全。
                    if is_content {
                        // 候选确实全灭：记熔断，后续请求直接走镜像链。
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
                // 服务端回 421 = 这个 IP 服务不了这个 host：边级长冷却，换下一条。
                if resp.status() == StatusCode::MISDIRECTED_REQUEST {
                    // 边状态按路由键记账（子域请求的 host ≠ 路由键，按 host 记会永远对不上）。
                    if let Some(row) = pool::route::route_for(host) {
                        pool::edges::mark_reject(&up_ip, &row.key);
                    }
                    upstream::drop_h2_id(&up_ip, id);
                    (log)(&format!(
                        "[MITM] {host} <- {up_ip} 被拒(421), 该 IP 冷却 4 小时, 换下一个"
                    ));
                    // 421 = 服务器声明未处理该请求；body 已缓存才能重发（流式已随旧连接消费掉）。
                    if !is_simple && body.is_none() {
                        return Err("421 边缘拒绝(流式请求不可重发)".to_string());
                    }
                    continue;
                }
                *info.lock().unwrap() = up_ip.clone();
                // HTTP 交换完成即回写（是不是风控页这里看不见）；成功只清短冷却，洗不掉风控冷却。
                pool::cursor_note(host, &up_ip, true, up_slot);
                if fresh {
                    // 连接拨完即已入库，这里只负责补第二条（只会落在另一个 IP）。
                    upstream::maybe_spawn_second(host, log);
                } // 竞速路径不补:race 的另一任务就是第二条,补建会与它抢跑
                upstream::note_latency(&up_ip, id, ms); // 新连接也要记账，否则择优池没有它的样本
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
        // 数据层失败才垫底 IP，且只认幂等、无镜像兜底的失败；POST/内容域失败不代表 IP 死。
        if is_simple && !is_content {
            pool::cursor_note(host, &up.ip, false, up.slot);
        }
        // 边级记账：超时/断连短冷却，这个 IP 对这个 host 稍后再说。
        pool::edges::mark_stall(&up.ip, host);
        upstream::drop_h2_id(&up.ip, up.id);
        (log)(&format!(
            "[MITM] {host} 上游第 {} 次失败({e}), 换下一个 IP",
            attempt + 1
        ));
        // 只有"连接没接住请求 + body 还在手里"才允许非幂等方法重发；半路断的不重试。
        if !is_simple && !(body.is_some() && failed_before_send(&e)) {
            return Err(format!("POST 等非简单方法不重发({e})"));
        }
        if is_content {
            // 同上：先熔断再走镜像链，让下一条请求少走一轮必败的拨号。
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
            let up = match upstream::h2_from_dialed(host, conn, &ip, "真名(系统DNS)", 1, log).await
            {
                Ok(u) => u,
                Err(e) => {
                    (log)(&format!("[DNS直连] {host} <- {ip} h2 失败({e})"));
                    continue;
                }
            };
            // 拨完立刻入库：晚一秒都可能让别的 host 对同一 IP 又拨一条。
            upstream::store_h2(&ip, up)
        };
        match send_once(&up, out, body, request_budget(budget_content)).await {
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
