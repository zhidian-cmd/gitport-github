//! 上游 HTTP 客户端：直连腿 = boring 指纹自管 h2 连接（fresh 语义）；镜像腿 = 标准 TLS + h1 共享池。
use crate::pool::{self, dial::Dialed, LogFn};
use bytes::Bytes;
use h2::client::SendRequest;
use http::Uri;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
pub type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>;
pub type Incoming = hyper::body::Incoming;
/// 每 host 一条自管 h2 连接（不用 legacy 池：体还在转发的连接不回池）。
/// SendRequest 可 Clone，一条连接承载该 host 全部并发；只有完整成功过的连接入槽。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    send: SendRequest<Bytes>,
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
}
static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, H2Upstream>>> =
    std::sync::OnceLock::new();
fn conn_pool() -> &'static Mutex<HashMap<String, H2Upstream>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

static LAST_ACTIVITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ACTIVITY_KICK: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn note_activity() {
    LAST_ACTIVITY.store(now_secs(), std::sync::atomic::Ordering::Relaxed);
    ACTIVITY_KICK.notify_one();
}

/// 启动保活任务：有请求每 PROBE 秒 PING 一次，静默超窗回睡，空闲零唤醒。
pub fn start_keepalive(rt: &tokio::runtime::Runtime) {
    rt.spawn(async move {
        loop {
            ACTIVITY_KICK.notified().await; // 空闲: 纯睡, 零周期唤醒
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(
                    crate::config::KEEPALIVE_PROBE_SECS,
                ))
                .await;
                let idle = now_secs()
                    .saturating_sub(LAST_ACTIVITY.load(std::sync::atomic::Ordering::Relaxed));
                if idle > crate::config::KEEPALIVE_WINDOW_SECS {
                    break; // 静默超窗: 停保活, 回 Notify 睡眠
                }
                keepalive_pass().await;
            }
        }
    });
}

async fn keepalive_pass() {
    let conns: Vec<(String, H2Upstream)> = {
        let g = conn_pool().lock().unwrap();
        g.iter().map(|(h, u)| (h.clone(), u.clone())).collect()
    };
    for (host, up) in conns {
        let Some(pp) = up.ping.clone() else { continue };
        let mut guard = pp.lock().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            guard.ping(h2::Ping::opaque()),
        )
        .await;
        if !matches!(r, Ok(Ok(_))) {
            drop(guard);
            drop_h2(&host, &up.ip); // 对端无答/连接已死: 清槽
        }
    }
}

pub fn cached_h2(host: &str) -> Option<H2Upstream> {
    conn_pool().lock().unwrap().get(host).cloned()
}
pub fn store_h2(host: &str, up: H2Upstream) {
    conn_pool().lock().unwrap().insert(host.to_string(), up);
}
pub fn drop_h2(host: &str, ip: &str) {
    let mut g = conn_pool().lock().unwrap();
    if g.get(host).map(|u| u.ip == ip).unwrap_or(false) {
        g.remove(host);
    }
}
pub async fn h2_from_dialed(
    host: &str,
    conn_io: Dialed,
    ip: &str,
    form: &str,
    log: &LogFn,
) -> Result<H2Upstream, String> {
    // h2 默认窗口 64KB 会把单页 129 并发压成按 RTT 串行（实测 FCP 34s），放大为流 1MB/连接 4MB。
    let mut cb = h2::client::Builder::new();
    cb.initial_window_size(1024 * 1024) // 流级 1MB
        .initial_connection_window_size(4 * 1024 * 1024); // 连接级聚合 4MB
    let (send, mut conn) = cb
        .handshake(conn_io)
        .await
        .map_err(|e| format!("h2 握手失败: {e}"))?;
    let ping = conn
        .ping_pong()
        .map(|p| Arc::new(tokio::sync::Mutex::new(p)));
    tokio::spawn(async move {
        let _ = conn.await; // 连接驱动：帧收发/GOAWAY 处理, 结束即连接死亡
    });
    (log)(&format!(
        "[上游] {host} <- {ip} (boring {form} SNI, h2 握手)"
    ));
    Ok(H2Upstream {
        ip: ip.to_string(),
        send,
        ping,
    })
}
pub async fn dial_h2(
    pool_name: &str,
    host: &str,
    ctx: CancellationToken,
    log: &LogFn,
) -> Result<H2Upstream, String> {
    let (conn_io, ip, shape) = pool::serial_dial(pool_name, host, ctx, true, Some(log))
        .await
        .map_err(|e| e.to_string())?;
    let form = if shape == pool::dial::MODE_SNI {
        "真名"
    } else {
        "伪装"
    };
    h2_from_dialed(host, conn_io, &ip, form, log).await
}
/// 流式直通响应头预算：git push 大包 GitHub 收完包校验才应答（2GB@1MB/s ≈ 35 分钟），给 30 分钟。
pub const STREAM_HEAD_BUDGET_SECS: u64 = 1800;

/// hop-by-hop 头（RFC 7230 §6.1）；mirror_request 与 h2_request_head 单点共用。
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "te"
    )
}

fn h2_request_head(out: &hyper::Request<BoxBody>) -> Result<hyper::Request<()>, String> {
    let mut builder = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri());
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if is_hop_by_hop(&low) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder.body(()).map_err(|e| e.to_string())
}
/// h2 响应头 future → Response；体逐块即时放窗（不 release 会死锁）。
pub async fn h2_recv_response(
    resp_fut: h2::client::ResponseFuture,
) -> Result<hyper::Response<BoxBody>, String> {
    let resp = resp_fut.await.map_err(|e| format!("h2 响应: {e}"))?;
    let (parts, mut recv) = resp.into_parts();
    let body_stream = futures_util::stream::poll_fn(move |cx| match recv.poll_data(cx) {
        std::task::Poll::Ready(Some(Ok(chunk))) => {
            let _ = recv.flow_control().release_capacity(chunk.len());
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))))
        }
        std::task::Poll::Ready(Some(Err(e))) => {
            std::task::Poll::Ready(Some(Err(std::io::Error::other(e))))
        }
        std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
        std::task::Poll::Pending => std::task::Poll::Pending,
    });
    Ok(hyper::Response::from_parts(
        parts,
        BoxBody::new(http_body_util::StreamBody::new(body_stream)),
    ))
}
pub async fn h2_send(
    up: &H2Upstream,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let mut send = up.send.clone();
    send = send.ready().await.map_err(|e| format!("h2 流配额: {e}"))?;
    let request = h2_request_head(out)?;
    let has_body = body.as_ref().map_or(false, |b| !b.is_empty());
    let (resp_fut, mut send_stream) = send
        .send_request(request, !has_body)
        .map_err(|e| format!("h2 发送: {e}"))?;
    if has_body {
        send_stream
            .send_data(body.as_ref().unwrap().clone(), true)
            .map_err(|e| format!("h2 请求体: {e}"))?;
    }
    h2_recv_response(resp_fut).await
}
pub async fn h2_stream_head(
    up: &H2Upstream,
    out: &hyper::Request<BoxBody>,
) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
    let mut send = up.send.clone();
    send = send.ready().await.map_err(|e| format!("h2 流配额: {e}"))?;
    let request = h2_request_head(out)?;
    let (resp_fut, stream) = send
        .send_request(request, false)
        .map_err(|e| format!("h2 发送: {e}"))?;
    Ok((resp_fut, stream))
}
/// 流式直通·请求体泵：按对端窗口分片发送；客户端断开时弃流不补 EOS（pack 尾带校验和）。
/// 返回 JoinHandle 供失败路径 abort（句柄丢弃会让泵滞留不回收）。
pub fn h2_spawn_pump(
    mut send: h2::SendStream<Bytes>,
    mut body: BoxBody,
    log: LogFn,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sent: u64 = 0;
        loop {
            let frame = match body.frame().await {
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    (log)(&format!(
                        "[上游] 请求体泵: 客户端体读取失败(已发 {sent}B), 弃流不补 EOS: {e}"
                    ));
                    return;
                }
                None => break,
            };
            let mut chunk = match frame.into_data() {
                Ok(d) => d,
                Err(_) => break, // 尾帧（trailer 类）：按体结束处理
            };
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(n)) if n > 0 => {
                        let piece = chunk.split_to(n.min(chunk.len()));
                        sent += piece.len() as u64;
                        if let Err(e) = send.send_data(piece, false) {
                            (log)(&format!("[上游] 请求体泵中止(已发 {sent}B): {e}"));
                            return;
                        }
                    }
                    Some(Ok(_)) => {} // 授予 0：继续等下次窗口唤醒
                    Some(Err(e)) => {
                        (log)(&format!("[上游] 请求体泵窗口错误(已发 {sent}B): {e}"));
                        return;
                    }
                    None => {
                        (log)(&format!("[上游] 请求体泵: 上游重置流(已发 {sent}B)"));
                        return;
                    }
                }
            }
        }
        let _ = send.send_data(Bytes::new(), true); // 干净收尾: EOS
        (log)(&format!("[上游] 请求体泵完成: {sent}B"));
    })
}
/// 每 host 拨号单飞闸：并发未命中只放一个进串发拨号（无闸时一波 27 条全新拨号，握手风暴触发边缘限流）。
static HOST_LOCKS: std::sync::OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    std::sync::OnceLock::new();
pub fn host_dial_lock(host: &str) -> Arc<tokio::sync::Mutex<()>> {
    HOST_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .entry(host.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}
#[derive(Clone)]
pub struct MirrorConnector {
    log: LogFn,
}
impl Service<Uri> for MirrorConnector {
    type Response = TokioIo<Dialed>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<TokioIo<Dialed>, std::io::Error>> + Send>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let host = uri.host().unwrap_or("").to_lowercase();
        let log = self.log.clone();
        Box::pin(async move {
            let t0 = std::time::Instant::now();
            let tls = pool::dial::dial_tls_simple(&host).await?;
            let alpn = tls.ssl().selected_alpn_protocol().unwrap_or_default();
            (log)(&format!(
                "[镜像拨号] {host} TLS {}ms alpn={}",
                t0.elapsed().as_millis(),
                String::from_utf8_lossy(alpn)
            ));
            Ok(TokioIo::new(Dialed::Tls(tls)))
        })
    }
}
const MIRROR_POOL_MAX_IDLE: usize = 4;
const MIRROR_POOL_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

static MIRROR_CLIENT: std::sync::OnceLock<LegacyClient<MirrorConnector, BoxBody>> =
    std::sync::OnceLock::new();

/// 镜像腿共享客户端（进程内单例）；首次调用者的 log 被永久持有。
pub fn mirror_client(log: &LogFn) -> &'static LegacyClient<MirrorConnector, BoxBody> {
    MIRROR_CLIENT.get_or_init(|| {
        let mut b = LegacyClient::builder(TokioExecutor::new());
        b.pool_max_idle_per_host(MIRROR_POOL_MAX_IDLE)
            .pool_idle_timeout(MIRROR_POOL_IDLE)
            // pool_idle_timeout 必须配 pool_timer 才生效（hyper-util 内部行为）。
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .retry_canceled_requests(true);
        b.build(MirrorConnector { log: log.clone() })
    })
}
pub const REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);
pub const MAX_REPLAY_BODY: usize = 1024 * 1024;
/// 重写上游请求：绝对 URL 化 + 剥代理头；嗅探型 host 强制 gzip。
pub fn upstream_request<B>(
    req: &hyper::Request<B>,
    host: &str,
) -> Result<(hyper::Request<BoxBody>, String), String> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let uri: Uri = format!("https://{host}{path}")
        .parse()
        .map_err(|_| format!("非法上游 URI: {host}{path}"))?;
    let mut out = hyper::Request::builder().method(method).uri(uri);
    // github.com/api 强制 gzip（大页面裸传是"进页面慢"主因，实测 327KB→44.5KB）；
    // 嗅探边收边解压，原始压缩帧原样转发。其余 host 放行浏览器原生压缩。
    let sniffed = host == "github.com" || host == "api.github.com";
    for (k, v) in req.headers() {
        let low = k.as_str().to_lowercase();
        if (sniffed && low == "accept-encoding")
            || low == "proxy-connection"
            || low == "proxy-authorization"
        {
            continue;
        }
        out = out.header(k, v);
    }
    if sniffed {
        // 只在客户端声明接受 gzip 时才强制（curl/git 无解压能力，无条件强制曾致其解码失败）。
        let accepts_gzip = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("gzip"))
            .unwrap_or(false);
        if accepts_gzip {
            out = out.header("accept-encoding", "gzip");
        }
    }
    let body =
        BoxBody::new(http_body_util::Empty::<bytes::Bytes>::new().map_err(|never| match never {}));
    let out = out.body(body).map_err(|e| e.to_string())?;
    Ok((out, host.to_string()))
}
pub fn prepend_body(prefix: Vec<bytes::Bytes>, tail: BoxBody) -> BoxBody {
    use futures_util::StreamExt;
    let tail_stream = http_body_util::BodyExt::into_data_stream(tail);
    let stream = futures_util::stream::iter(
        prefix
            .into_iter()
            .map(|b| Ok::<_, std::io::Error>(hyper::body::Frame::data(b))),
    )
    .chain(tail_stream.map(|r| r.map(hyper::body::Frame::data)));
    BoxBody::new(http_body_util::StreamBody::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_gzip_gated_on_client_accept() {
        let req = hyper::Request::builder()
            .uri("https://github.com/a")
            .header("accept-encoding", "gzip, deflate, br")
            .body(())
            .unwrap();
        let (out, _) = upstream_request(&req, "github.com").unwrap();
        assert_eq!(
            out.headers().get("accept-encoding").unwrap(),
            "gzip",
            "声明过 gzip 的客户端应被强制 gzip"
        );

        let req2 = hyper::Request::builder()
            .uri("https://github.com/a")
            .body(())
            .unwrap();
        let (out2, _) = upstream_request(&req2, "github.com").unwrap();
        assert!(
            out2.headers().get("accept-encoding").is_none(),
            "未声明的客户端应回身份编码"
        );

        let req3 = hyper::Request::builder()
            .uri("https://raw.githubusercontent.com/a")
            .body(())
            .unwrap();
        let (out3, _) = upstream_request(&req3, "raw.githubusercontent.com").unwrap();
        assert!(
            out3.headers().get("accept-encoding").is_none(),
            "非嗅探 host 不添加"
        );
    }
}
