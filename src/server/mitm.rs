//! MITM 路径：池内域名本地终结 TLS 后按 plans.json 串发连上游
//! (boring Chrome 指纹 + 伪装 SNI)，风控拦截页(403 restricted/400 Whoa)
//! 本地识别(ghDefuse)，该 IP 垫底换下一个重试。分流：
//! - core/api/edge：直连（edge 混合池内按 IP 族分形态，见 pool::shape_for_ip）
//! - githubusercontent 内容域（avatars/camo/gist/raw）：直连优先（1s 内 200），
//!   失败回落镜像串行链
//! - codeload / objects / release-assets / github.com 的 releases/download、
//!   archive 路径：镜像 only（禁并发竞速，2026-10-15 裁定），链全灭 502
use super::upstream::{self, mitm_h1_client, BoxBody, Incoming, REQUEST_BUDGET};
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
// ---------- 常量与镜像 ----------
// 镜像腿响应头预算：8s 内必须出响应头，头一到即解除，体不限。
const MIRROR_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// 内容域镜像链限长（2026-10-17 用户要求）：仍然串行逐家试，只是最多前 5
/// 家、每家 5s 超时——把一张坏图标的最坏等待从"11 家 × 各自超时"(实测 16s)
/// 压到 25s 上限内的大概率更早出局。大文件保链全量（各家串行, 不并发）。
const MIRROR_CHAIN_CAP: usize = 5;

/// 内容域小文件（头像/图片/gist/media）的镜像链限长；大文件与 github.com
/// 归档/release 返回 None = 用全链。
/// 注意：**镜像链仍是串行**（与直连 IP 串发同一哲学：一家失败再下一家）。
fn mirror_chain_cap(host: &str) -> Option<usize> {
    (host != "github.com" && !is_big_file_host(host)).then_some(MIRROR_CHAIN_CAP)
}
const GET_DIRECT_MAX_ATTEMPTS: usize = 24;
// ghDefuse 无冷静阈值与尝试上限（用户裁定：试到全表），终止
// 条件只有"拿到正常页"或"串发全灭"。
/// release 附件与源码包路径（/releases/download、/archive）一律走镜像；
/// git 智能协议路径不在此列 —— 镜像不认，必须走 core 池直连（伪装 SNI）。
fn is_release_asset_path(host: &str, path: &str) -> bool {
    if host != "github.com" {
        return false;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        [_owner, _repo, kind, ..] if *kind == "releases" => {
            // releases/download/... （releases 页面本身不拦，只拦下载）
            segs.len() >= 4 && segs[3] == "download"
        }
        [_owner, _repo, kind, ..] if *kind == "archive" => true,
        _ => false,
    }
}
/// 大文件下载域(整域镜像)：codeload=源码包；objects/release-assets=release
/// 附件 302 的落点(新旧两代域名)。
fn is_big_file_host(host: &str) -> bool {
    host == "codeload.github.com"
        || host == "objects.githubusercontent.com"
        || host == "release-assets.githubusercontent.com"
}
/// 池内域名本地终结 TLS。直连白名单域名（objects-origin 等）pool_for 返回空
/// → 上面 is_empty 分支已豁免；把它们改回池属契约变更，由
/// pool::tests::objects_origin_never_pooled 拦，不设运行时护栏。
pub fn mitm_scope(authority: Option<&Arc<Authority>>, host: &str) -> bool {
    if authority.is_none() || !crate::settings::mitm() {
        return false;
    }
    !pool::pool_for(host).is_empty()
}
// ---------- 单连接 MITM 服务 ----------
/// 回 200 后把连接升级为 TLS 服务端，按 ALPN 选择 h2/h1 服务，可承载多条请求。
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
    (srv.log)(&format!("[MITM] {host} 隧道已解密, 按域名路由转发"));
    // axum 0.8 的 Handler 只接受 axum::extract::Request，而本层必须保留原始
    // Incoming body（重放/嗅探），故不用 axum Router，直接 hyper service_fn。
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
// ---------- MITM HTTP 处理 ----------
/// 记录本次实际使用的上游边缘 IP，响应头暴露(X-GitPort-Upstream 排障)。
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
    // host 优先取 URI authority（h2 :authority / 代理形式绝对 URL）；
    // CONNECT 隧道内的 h1 请求是 origin-form（GET /），URI 无 host ——
    // 回退 Host 头（2026-10-13 实测隧道内 502 根因）。
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
    // 遥测/心跳本地短路：collector(埋点)与 alive(心跳)是纯丢弃型 POST,
    // 回 204 不拨号 —— 免掉每笔 8s 预算白烧与无谓新拨(2026-10-15 实锤:
    // 心跳 connection error 刷屏、遥测超时全是白烧)。WebSocket 心跳走
    // CONNECT/upgrade 路径, 不受此影响。
    if host == "collector.github.com" || host == "alive.github.com" {
        return axum::response::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(BoxBody::new(
                http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}),
            ))
            .unwrap();
    }

    // websocket/101: 交给原始双向透传
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
    // 改造成客户端请求：绝对 URL
    let Ok((out, _)) = upstream::upstream_request(&req, &host) else {
        return mitm_unavailable(&req, &host);
    };
    let is_simple = req.method() == Method::GET || req.method() == Method::HEAD;
    let path = path_of(req.uri());
    // 流式直通判定（2026-10-16 方案一落地）：git 智能协议 POST（push/fetch
    // 包传输）或声明体积超限的请求不进有界缓冲 —— 缓冲路径下 >1MB 的请求
    // 一律 502, git push 大包必挂。GET/HEAD 无体不涉及。
    let mut streaming_reason = stream_decision(req.method(), &path, declared_content_len(&req));
    let mut overflow_prefix: Option<Vec<u8>> = None;
    let mut replay: Option<Bytes> = None;
    if streaming_reason.is_none() {
        // 有界请求体缓冲(≤1MB)：建连失败换路重试时可安全重放。
        // 读超限不再 502 —— 已读前缀作为首块, 转流式继续泵送剩余体。
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
    // 镜像 only 域（不直连）：codeload / objects / release-assets 大文件域、
    // github.com 的 releases/download 与 archive 路径（git 智能协议路径除外）。
    // 镜像链全灭 → 直接 502，不回落直连。
    // githubusercontent 内容域不在此列 —— 直连优先（1s 内 200），失败回落镜像链。
    if is_simple && (is_big_file_host(&host) || is_release_asset_path(&host, &path)) {
        if let Ok(resp) = chain_fetch(&log, &out_body, &host).await {
            return write_upstream(resp, "mirror", &info);
        }
        (log)(&format!("[MITM] {host}{path} 镜像链全灭, 不回落直连"));
        return mitm_unavailable(&req, &host);
    }
    let mut resp = match get_direct(&log, &out_body, &host, &info, is_simple, &replay).await {
        Ok(r) => r,
        Err(e) => {
            // 内容域直连优先、失败回落镜像链：直连是 avatars/camo/gist
            // 的常态路径；raw 真名 SNI 被 GFW 黑洞（快速失败），兜底走链。
            if host.ends_with("githubusercontent.com") && is_simple {
                if let Ok(r) = chain_fetch(&log, &out_body, &host).await {
                    return write_upstream(r, "mirror", &info);
                }
                (log)(&format!("[MITM] {host}{path} 直连全灭且镜像链全灭"));
            } else {
                (log)(&format!(
                    "[MITM] {host}{} 上游失败: {e}",
                    path_of(req.uri())
                ));
            }
            // 末路兜底: 系统 DNS 直连腿 —— 池表 IP 漂移(GitHub 边缘迁移,
            // 如 2026-10 assets .154→.215)时按系统解析自愈。仅 GET/HEAD。
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
    // 风控拦截页本地化解：实锤 403 restricted/400 Whoa 后垫底换 IP 直连重试
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
/// 流式直通判定：Some(原因) = 不进缓冲直接流式；None = 有界缓冲(≤1MB)。
/// git 智能协议 POST（push/fetch 包传输端点）与声明超限（含 GB 级 PUT）
/// 必流式；声明未超限但实际超限的在缓冲读满后转流式（不丢请求也不 502）。
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
/// hyper Incoming（错误类型 hyper::Error）→ BoxBody（错误类型 io::Error）。
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
/// 前缀字节 + 尾体拼接（http_body_util 0.1 无 Chain 组合子，手写）：
/// 先吐 prefix 一帧，再透传 rest 的全部帧。缓冲转流式用（已读的 ≤1MB+1
/// 前缀必须原样发给上游，剩余体继续泵送）。
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
/// 纯 502 兜底（非 GET 失败路径；GET 的自动刷新页见 mitm_unavailable）。
fn plain_502() -> axum::response::Response<BoxBody> {
    axum::response::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(BoxBody::new(
            http_body_util::Full::new(Bytes::from_static(b"upstream unavailable"))
                .map_err(|never| std::io::Error::other(never)),
        ))
        .unwrap()
}
/// 流式直通：请求体不进缓冲，边收边泵给上游（h2 背压分片）。单次尝试
/// 语义（同既有"非简单方法不重发"）：预泵段失败 = 连接死且体未动，允许
/// 换新拨重试一次；体泵启动后体已部分消耗，失败只记日志不重试。响应头
/// 一到立即交付客户端（响应优先），泵的非致命错误绝不覆盖真实响应。
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
    // 连接选择：缓存优先（git 场景 info/refs 前置 GET 通常已暖好连接）；
    // 预泵失败允许新拨重试一次（体未触碰, 重放安全）。
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
    // 接住泵句柄：响应头失败/超时路径必须 abort，否则泵滞留不回收
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
/// HTML 实体转义（&<>"'），错误页插值用。
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
/// 嗅探响应体头部判定 GitHub 风控拦截页(HTML + 标志串)。
/// 2026-10-17 起 github.com/api 强制上游 gzip(大页面裸传是"大仓库进页面慢"
/// 主因, 实测仓库页 327KB → 44.5KB): 嗅探改为**边收边解压**判前 4KB 明文,
/// 已消费的**原始压缩帧**原样保留(PeekRaw), 写回时拼到最前 —— 浏览器收到的
/// 字节流与上游完全一致(解压由浏览器负责), 不重压缩、不改 content-length。
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
    // 只认 gzip(上游请求由我们强制) 与 identity; 其他编码放弃嗅探(透明转发,
    // 宁可不判也不误杀)
    if !enc.is_empty() && enc != "identity" && enc != "gzip" {
        return false;
    }
    let gz = enc == "gzip";
    let mut raw: Vec<Bytes> = Vec::new();
    let mut comp: Vec<u8> = Vec::new();
    let mut plain: Vec<u8> = Vec::new();
    let body = resp.body_mut();
    // 帧式读取: 单帧 16KB, 解压后远超 4KB, 一般 1-2 帧即够。上限 8 帧 /
    // 128KB 压缩数据, 防异常响应拖住嗅探; 多读的字节原样保留, 不影响完整性。
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
    // "bad request" 串太宽(任何 400 页正文都可能含) —— 必须叠加状态码=400
    // 才判风控(2026-10-17 安全审计 F-005), 否则正常 400 会触发整池轮换
    chunk.contains("has been restricted")
        || chunk.contains("whoa there")
        || (resp.status() == http::StatusCode::BAD_REQUEST && chunk.contains("bad request"))
}

/// 解压已收到的 gzip 前缀(可能被截断): 尾部"数据不足"错误忽略, 返回已解出部分。
fn gunzip_partial(data: &[u8], max: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(data)
        .take(max as u64)
        .read_to_end(&mut out);
    out
}
/// 嗅探/探测已消费的原始帧：最终写回时拼到响应体前端。
#[derive(Clone)]
struct PeekRaw(Vec<Bytes>);
/// 复用缓存 h2 连接发一次请求。Some(Ok)=成功可直接交付；Some(Err)=POST 等
/// 非简单方法复用失效不重发，直接报错；None=缓存未命中或连接已死，落回串发。
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
    let timed = tokio::time::timeout(
        REQUEST_BUDGET,
        upstream::h2_send(&up, &attempt_req, body),
    );
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
/// 直连串发 = 完整请求逐个试：响应头到手 = 成功连（该 IP 置顶）；超时/
/// 黑洞 = 垫底换下一个；上限 24 防病态；POST 等非简单方法不重发。
/// fresh 语义：每 attempt 新拨号（坏 IP 连接不缓存），
/// 垫底后下一 attempt 必然换 IP —— "垫底换 IP"真实生效。
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
    let is_content = host.ends_with("githubusercontent.com");
    // 内容域直连熔断：GFW 按域黑洞期间每个请求烧满预算才回落 —— 熔断中
    // 直接放弃直连（调用方立即回落镜像链），不再逐条试
    if name == "edge" && is_content && pool::content_direct_open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    // 复用优先：上次完整成功的那条 h2 连接还活着就直接发请求 —— 零拨号
    // 零握手。失败 = 连接已死, 清槽落回串发新拨号（POST 同样只试这一次）。
    if let Some(r) = try_cached(
        log, out, host, info, name, is_simple, is_content, &path, t0, body,
    )
    .await
    {
        return r;
    }
    // per-host 拨号单飞：并发未命中缓存时只放一个进串发拨号，其余排队；
    // 首拨入槽后排队者立即放锁、锁外并发复用。锁只罩"拨号等待"不罩发送
    // —— 2026-10-16 实测：持锁到响应返回会把 129 个并发压成逐个 RTT 串行
    // （34s FCP / 布局跳动的真凶）。
    let dial_lock = upstream::host_dial_lock(host);
    let mut guard = Some(dial_lock.lock().await);
    // 拿到锁后重查熔断：排队期间排在前面的请求可能已把该 host 拨到熔断
    // —— 否则队列里每个成员都会再烧一次 8s 黑洞预算（一波头像逐个 8s）
    if name == "edge" && is_content && pool::content_direct_open(host) {
        return Err("内容域直连熔断中, 直接走镜像链".to_string());
    }
    // 首拨已被前面请求完成：立即放单飞，队列全员锁外并发复用
    if upstream::cached_h2(host).is_some() {
        guard.take();
        if let Some(r) = try_cached(
            log, out, host, info, name, is_simple, is_content, &path, t0, body,
        )
        .await
        {
            return r;
        }
        // 极端竞态：复用连接在查与发之间又死了 —— 重新拿锁落回串发拨号
        guard = Some(dial_lock.lock().await);
    }
    // 串发拨号期间持续持锁（单飞）；所有 return 路径上随函数结束释放
    let _dial_guard = guard;
    for attempt in 0..GET_DIRECT_MAX_ATTEMPTS {
        // 每 attempt 串发拨号 + h2 握手（boring Chrome 指纹 + 伪装/真名 SNI，
        // fresh 语义）：失败 attempt 的连接即弃，坏连接复用不可能发生；
        // 串发表内失败 IP 已由 serial_dial 自动垫底。
        let up = match upstream::dial_h2(name, host, CancellationToken::new(), log).await {
            Ok(up) => up,
            Err(e) => {
                // 拨号全灭/握手失败（serial_dial 内部已对失败 IP 垫底）
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
        let timed = tokio::time::timeout(
            REQUEST_BUDGET,
            upstream::h2_send(&up, &attempt_req, body),
        );
        match timed.await {
            Ok(Ok(resp)) => {
                info.set(&up.ip);
                if !name.is_empty() {
                    pool::serial_note(name, &up.ip, "ok"); // 数据到手 = 真成功, 置顶
                }
                // 首拨成功入连接缓存：后续同 host 请求复用该 h2 连接
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
            Ok(Err(e)) => {
                // 数据层失败(含"握手通但响应黑洞")：本次尝试实际拨到的 IP 垫底，
                // 下一轮自动换候选。垫底只认"幂等且无镜像兜底"的失败：POST(遥
                // 测)失败不代表 IP 死；githubusercontent 族失败多为 GFW 按域干
                // 扰而 IP 本身健康。两者垫底都会让池序被噪声刷着轮换。
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
                    // 一圈即回落，不绕圈等 24 attempts；同时熔断直连 120s，
                    // 后续请求直接走镜像链（成功自动恢复）
                    pool::content_direct_fail(host);
                    return Err(format!("内容域直连全灭({e})"));
                }
                continue; // GET/HEAD: 换下一个候选重发完整请求
            }
            Err(_) => {
                // 响应预算超时（8s 内响应头都没到）：视同数据层失败
                if !name.is_empty() && is_simple && !is_content {
                    pool::serial_note(name, &up.ip, "noreply");
                }
                upstream::drop_h2(host, &up.ip);
                (log)(&format!(
                    "[MITM] {host} 上游第 {} 次尝试失败(响应预算超时), 垫底换候选",
                    attempt + 1
                ));
                if !is_simple {
                    return Err("POST 等非简单方法不重发(响应预算超时)".to_string());
                }
                if is_content {
                    pool::content_direct_fail(host);
                    return Err("内容域直连全灭(响应预算超时)".to_string());
                }
                continue;
            }
        }
    }
    Err("直连串发全灭(完整请求逐个试完)".to_string())
}

/// gh_defuse 终止决策（纯函数，仅为可测性抽出）：同 IP 再现 = 整表已轮完
/// 一圈，全员拦截页 → 终止交付真实响应。调用方必须已完成垫底 + drop_h2
/// （顺序不可换：终止交付时坏连接不能留在复用缓存）。
fn defuse_full_cycle(seen: &mut std::collections::HashSet<String>, ip: &str) -> bool {
    !seen.insert(ip.to_string())
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
    // 不冷静、试到全表(用户裁定) —— 检测出 Whoa 就换 IP 试到底，
    // 串发表每个候选都要试过才算数。终止条件只有两个：重试拿到正常页(交付)、
    // 或串发给不出新连接(全灭 → retry 报错，交回最后响应)。中间任一个候选返回
    // 正常页即交付成功，绝不无谓冷静。
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
            // 复用连接上的拦截页(理论可达：本次没拨号)：直接重试(连接不复用，
            // 重试必有归属)。归属缺失时 seen 无法追踪 —— 计数上限钉死该
            // 理论路径(2026-10-17 代码审查: 防未来改动使其真可达时死循环)
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
        if defuse_full_cycle(&mut seen, &ip) {
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
/// 把上游响应写回浏览器：剔除 hop-by-hop 头，注入 X-GitPort-Route / X-GitPort-Upstream
/// 诊断头；嗅探读出的前缀字节拼回响应体前端。
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
/// 上游失败时的诚实错误页：GET 导航给带自动刷新的提示页，其余方法纯 502。
fn mitm_unavailable(
    req: &hyper::Request<Incoming>,
    host: &str,
) -> axum::response::Response<BoxBody> {
    if req.method() != Method::GET {
        return plain_502();
    }
    let ui_port = config::webui_port();
    // host 来自 CONNECT 目标/Host 头, 进 HTML 前转义(2026-10-17 安全审计
    // F-007: 浏览器路径不可注入, 纯纵深)
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
// ---------- 系统 DNS 直连腿(末路兜底) ----------
/// 串发池全灭且(内容域)镜像链也失败后, 按系统解析的当前 IP 真名 SNI 直拨
/// —— GitHub 边缘 IP 迁移(如 2026-10 assets .154→.215)导致池表过期的自愈
/// 路径: 系统解析拿到的就是当下有效的边缘。仅 GET/HEAD 调用(POST 不重发)。
/// 成功后入连接缓存, 后续同 host 请求自动走复用快路径。
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
        let timed = tokio::time::timeout(
            REQUEST_BUDGET,
            upstream::h2_send(&up, &attempt_req, body),
        );
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
// ---------- 镜像串行链：按链逐个用，禁并发竞速 ----------
/// 镜像串行链：按链序逐个取用，失败/被拒换下一个，链全灭才报错。
/// 2026-10-15 裁定废除并发竞速：N 路并发探测会打爆公共镜像（头像全灭
/// 的推手）。链序 = 内置默认（实测 TTFB）+ UI 校准。
async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
) -> Result<hyper::Response<BoxBody>, String> {
    let chain = pool::mirror_chain(host);
    if chain.is_empty() {
        return Err(format!("{host} 无镜像链"));
    }
    // 全灭熔断：刚整链失败过(60s 内)直接快速失败, 不再逐家重烧 —— 多图
    // 仓库在全灭窗口里每张图都重烧一遍链, spinner 会转几分钟
    if pool::mirror_breaker_open(host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    // 凭据查询串拒绝走镜像(2026-10-17 安全审计 F-001)：签名凭据
    // (token/X-Amz-*/sig 类)等价 bearer, 剥头清单管不到它 —— 私库附件
    // signed URL 交给第三方镜像即外泄。此类请求镜像本也取不回, 直接拒。
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
    // 内容域小文件限长前 5 家（串行逐家, 2026-10-17 用户要求）; 大文件全链。
    let limit = mirror_chain_cap(host).unwrap_or(chain.len()).min(chain.len());
    for (i, m) in chain.iter().take(limit).enumerate() {
        let req = match mirror_request(out, m, &orig_url) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 请求构造失败({e}), 链内下一个"));
                continue;
            }
        };
        match mirror_do(req, m).await {
            Ok(resp) => {
                let skipped = if i == 0 {
                    String::new()
                } else {
                    format!(", 跳过前 {i} 个")
                };
                (log)(&format!(
                    "[镜像] {host}{path} via {m} (链位 {}/{len}{skipped})",
                    i + 1,
                    len = chain.len(),
                ));
                pool::mirror_breaker_clear(host); // 链是活的: 清全灭熔断
                return Ok(resp);
            }
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 失败({e}), 链内下一个"));
            }
        }
    }
    pool::mirror_breaker_set(host); // 整链烧完仍全灭: 熔断 60s, 后续图快速失败
    Err(format!("{host} 镜像链全灭({limit} 个)"))
}
/// 重建请求：头/方法/URI 复制 + 体按 replay 注入（Request<BoxBody> 不可
/// Clone，换 IP/换候选重发时每 attempt 重建一份）。
/// 2026-10-14 修复：旧 simple_request 丢体却保留原头（含 content-length）——
/// GitHub 边缘对"声明 N 字节却永远等不到体"的请求挂起不放，恰是遥测 POST
/// 全灭（30s 响应预算超时）进而失败垫底刷轮换的根源。GET 无体不受影响。
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
/// 镜像腿请求：拼 URL(镜像域名 + 原始 https URL) + 剥身份头
/// (Cookie/Authorization/Host/Referer —— 镜像站不该收到 GitHub 的凭据)。
fn mirror_request(
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
) -> Result<hyper::Request<BoxBody>, String> {
    let url = format!("{mirror}/{orig_url}");
    let mut builder = hyper::Request::builder().method(out.method()).uri(url);
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if low == "cookie" || low == "authorization" || low == "host" || low == "referer" {
            continue;
        }
        builder = builder.header(k, v);
    }
    let body =
        BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(|e| std::io::Error::other(e)));
    builder.body(body).map_err(|e| e.to_string())
}
/// 镜像腿单发：有头预算(8s 内必须出响应头，头一到即解除，体不限) +
/// 假页拒判(≥400 或 text/html = 镜像自身的 SPA 页，不算成绩)。
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
) -> Result<hyper::Response<BoxBody>, String> {
    let client = mitm_h1_client();
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
    // 镜像须直出内容：3xx=甩锅回 GitHub(用户侧被墙，浏览器跟随即断)，
    // HTML=假站/停车场页面，>=400=镜像侧拒绝。实测(2026-10-14 沙箱)11 候选
    // 无一带 3xx，护栏常驻防镜像来日改配。
    let st = resp.status().as_u16();
    if st >= 300 || ct.contains("text/html") {
        return Err(format!("{mirror} 状态 {st}"));
    }
    // hyper Incoming → BoxBody（镜像腿统一响应类型）
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(http_body_util::BodyExt::map_err(
        body,
        std::io::Error::other,
    ));
    Ok(hyper::Response::from_parts(parts, body))
}
/// 镜像腿凭据查询串检测：参数名命中凭据形态即拒（大小写不敏感）。
/// 前缀匹配覆盖 AWS SigV4 全家（x-amz-*），精确名覆盖 gh-proxy 系常见形态。
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
/// 校准模板：每 host 一个内置稳定 URL，校准时经各镜像拉它测 TTFB。
/// 选型原则：十年不腐 —— octocat 官方 gist/头像、torvalds/linux 的
/// README 与 v2.6.11 老 tag、git-lfs 的 release 资产（文件名含 v 前缀，
/// 2026-10-15 实测全镜像 200）。
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
/// 单镜像校准测速：拉模板 URL，响应头达标（<300 且非 HTML）即有效成绩。
/// 拒判口径与 mirror_do 一致 —— 3xx=甩锅、HTML=假站、>=400=拒绝路由。
async fn calibrate_one(mirror: &str, tmpl: &str) -> Result<u16, String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("user-agent", "Mozilla/5.0")
        .header("accept", "*/*")
        .body(BoxBody::new(
            http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
        ))
        .map_err(|e| e.to_string())?;
    let client = mitm_h1_client();
    let timed = tokio::time::timeout(MIRROR_HEAD_TIMEOUT, client.request(req)).await;
    match timed {
        Ok(Ok(r)) => {
            let st = r.status().as_u16();
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if st >= 300 || ct.contains("text/html") {
                Err(format!("状态 {st}"))
            } else {
                Ok(st)
            }
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("响应头预算超时".to_string()),
    }
}
/// 镜像链校准（UI"校准"按钮后端）：对每条链串行实测 TTFB（host 之间并行
/// —— 校准是维护操作，不是流量路径；链内严格串行），按成绩升序重排
/// （失败条目按原相对序排尾），写回 plans.json mirrors 板块。
/// 返回人读报告供 UI 展示。
pub async fn calibrate_chains(log: &LogFn) -> String {
    let chains = pool::mirror_chains_snapshot();
    let mut joins = tokio::task::JoinSet::new();
    for (host, chain) in chains {
        let Some((_, tmpl)) = CALIBRATE_TEMPLATES.iter().find(|(h, _)| *h == host) else {
            continue;
        };
        let tmpl = tmpl.to_string();
        let log = log.clone();
        joins.spawn(async move {
            // rows: (镜像, ms) —— 失败 ms 为负，排序自然沉底
            let mut rows: Vec<(String, i64)> = Vec::new();
            for m in &chain {
                let t0 = Instant::now();
                let res = calibrate_one(m, &tmpl).await;
                let ms = t0.elapsed().as_millis() as i64;
                match res {
                    Ok(st) => {
                        log(&format!("[校准] {host} {m} {ms}ms {st}"));
                        rows.push((m.clone(), ms));
                    }
                    Err(e) => {
                        log(&format!("[校准] {host} {m} 失败({e})"));
                        rows.push((m.clone(), -ms));
                    }
                }
            }
            (host, rows)
        });
    }
    let mut report = String::new();
    while let Some(res) = joins.join_next().await {
        let Ok((host, rows)) = res else { continue };
        let mut ok: Vec<(String, i64)> = rows.iter().filter(|(_, ms)| *ms > 0).cloned().collect();
        ok.sort_by_key(|(_, ms)| *ms);
        let dead: Vec<String> = rows
            .iter()
            .filter(|(_, ms)| *ms <= 0)
            .map(|(m, _)| m.clone())
            .collect();
        let new_chain: Vec<String> = ok
            .iter()
            .map(|(m, _)| m.clone())
            .chain(dead.iter().cloned())
            .collect();
        let summary: Vec<String> = new_chain
            .iter()
            .map(|m| {
                let ms = rows
                    .iter()
                    .find(|(mm, _)| mm == m)
                    .map(|(_, ms)| *ms)
                    .unwrap_or(0);
                if ms > 0 {
                    format!("{}({}ms)", m.trim_start_matches("https://"), ms)
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
// ---------- WebSocket 原始转发 ----------
/// 原始转发(101 升级)：拨通上游后原样写请求，双向透传。
async fn mitm_upgrade(
    log: LogFn,
    req: hyper::Request<Incoming>,
    host: &str,
) -> axum::response::Response<BoxBody> {
    // 取出升级流（hyper 1.x：连接层已标记 upgrade）
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
    // 原样写请求：请求行 + 全头(含 Upgrade/Connection)
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
    // 双向透传：客户端升级流 ↔ 上游（TokioIo 统一 hyper/tokio IO trait）
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
    /// 镜像链限长范围（2026-10-17 用户要求）：内容域小文件限长前 5 家（仍串行），
    /// 大文件与 github.com 归档/release 用全链。
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
    /// gzip 嗅探(2026-10-17): 拦截页必须在"解压后的前 4KB"被判出, 且已消费的
    /// 原始压缩帧必须是压缩流的真前缀 —— 写回时拼回不破坏字节流(浏览器自行解压)。
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
        // 正常页不误判
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
    /// 锁住镜像候选池契约：全部 https、互不重复、全部来自统一 MIRRORS 池
    /// （gh-proxy 系；dh-proxy 无对应服务，域名是本常量数组可改）。
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
        // 默认链契约：每个内容域 host 一条链，链内无重复、全是池内成员
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
        // 校准模板契约：每个内容域 host 都有模板（校准全覆盖）
        for h in pool::CONTENT_HOSTS {
            assert!(
                CALIBRATE_TEMPLATES.iter().any(|(host, _)| host == h),
                "{h} 缺校准模板"
            );
        }
    }
    /// gh_defuse 终止决策契约：首见 IP 继续, 同 IP 再现(整表轮完一圈)终止。
    #[test]
    fn defuse_full_cycle_pins_contract() {
        let mut seen = std::collections::HashSet::new();
        assert!(!defuse_full_cycle(&mut seen, "1.2.3.4"), "首见 = 继续");
        assert!(!defuse_full_cycle(&mut seen, "5.6.7.8"), "另一 IP = 继续");
        assert!(
            defuse_full_cycle(&mut seen, "1.2.3.4"),
            "同 IP 再现 = 整表轮完, 终止"
        );
        assert!(defuse_full_cycle(&mut seen, "1.2.3.4"), "重复终止保持终止");
    }
    /// release/archive 路径判定：只拦下载，不拦 git 智能协议与页面。
    #[test]
    fn release_asset_path_gate() {
        assert!(is_release_asset_path(
            "github.com",
            "/torvalds/linux/archive/refs/tags/v6.6.tar.gz"
        ));
        assert!(is_release_asset_path(
            "github.com",
            "/cli/cli/releases/download/v2.0.0/gh_2.0.0_windows_amd64.zip"
        ));
        // releases 列表页本身不拦（只是页面）
        assert!(!is_release_asset_path(
            "github.com",
            "/torvalds/linux/releases"
        ));
        assert!(!is_release_asset_path(
            "github.com",
            "/torvalds/linux/releases/tag/v6.6"
        ));
        // git 智能协议不拦：必须走 core 池直连
        assert!(!is_release_asset_path(
            "github.com",
            "/torvalds/linux/info/refs?service=git-upload-pack"
        ));
        assert!(!is_release_asset_path(
            "github.com",
            "/torvalds/linux/git-upload-pack"
        ));
        // 只判 github.com
        assert!(!is_release_asset_path(
            "api.github.com",
            "/repos/x/y/releases/assets/1"
        ));
        assert!(!is_release_asset_path(
            "codeload.github.com",
            "/x/y/legacy.tar.gz"
        ));
    }

    /// 流式直通判定契约（2026-10-16 方案一）：git 智能协议 POST 与声明
    /// 超限必流式；GET/HEAD 与常规小体不流式；超限值恰为 MAX_REPLAY_BODY
    /// 时不流式（缓冲路径的合法上界）。
    #[test]
    fn stream_decision_contract() {
        use upstream::MAX_REPLAY_BODY;
        // git 智能协议 POST：必流式
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
        // info/refs 是 GET（无体），不流式
        assert_eq!(
            stream_decision(
                &Method::GET,
                "/fastgh/fgit.git/info/refs?service=git-receive-pack",
                None
            ),
            None
        );
        // 声明超限（含 PUT 大文件场景）：必流式；上界内不流式
        assert_eq!(
            stream_decision(&Method::PUT, "/some/upload", Some(MAX_REPLAY_BODY as u64 + 1)),
            Some("声明超限")
        );
        assert_eq!(
            stream_decision(&Method::POST, "/api/x", Some(MAX_REPLAY_BODY as u64)),
            None
        );
        // 未知体积（chunked）不流式：交给缓冲读满后转流式兜底
        assert_eq!(stream_decision(&Method::POST, "/api/x", None), None);
        // GET/HEAD 永不流式（无体）
        assert_eq!(stream_decision(&Method::GET, "/x", Some(u64::MAX)), None);
        assert_eq!(stream_decision(&Method::HEAD, "/x", Some(u64::MAX)), None);
    }
}
