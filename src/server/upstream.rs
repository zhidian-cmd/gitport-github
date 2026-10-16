//! 上游 HTTP 客户端。
//!
//! 分两条腿：
//! - 池内域名直连腿（core/api/edge）：boring Chrome 指纹 —— GREASE +
//!   Chrome 默认密码套件/扩展顺序 + ALPN h2,http/1.1（等价 utls HelloChrome
//!   的 Rust 落地；Rust 生态无 utls 绑定，warpsock 腿已拆除）。
//!   SNI 按 IP 族定：Fastly 边缘真名，主站边缘含 auth 主机伪装（baidu.com），
//!   证书按目标 host 校验（SNI 与校验名解耦，见 pool/dial.rs）。每请求经串发表
//!   新拨号（fresh 语义，坏连接复用不可能发生）。
//! - 镜像腿（fastly/codeload/release）：标准 TLS + h1 直拨，无表无阶梯。
//!
//! Go 版用 http2.Transport + DialTLSContext 语义一致：连接层完全自定义。
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
// ---------- 自管 h2 连接：拨号、握手、多路复用 ----------
/// 每 host 一条自管 h2 连接。不用 hyper-util legacy 池：它对"响应体还在
/// 流式转发"的连接不回池，页面连续取资源时每秒再拨一条（实测新拨与复用
/// 各半）。自管后 h2 的 SendRequest 可 Clone 且请求体流与连接复用解耦 ——
/// 一条连接承载该 host 全部并发请求（浏览器同款语义），新拨号只在连接
/// 死亡时发生。只有"完整请求成功过"的连接才入槽（fresh 语义保持）。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    send: SendRequest<Bytes>,
}
static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, H2Upstream>>> =
    std::sync::OnceLock::new();
fn conn_pool() -> &'static Mutex<HashMap<String, H2Upstream>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}
/// 取 host 的复用连接。命中 = 上次完整成功的那条链路。
pub fn cached_h2(host: &str) -> Option<H2Upstream> {
    conn_pool().lock().unwrap().get(host).cloned()
}
/// 缓存成功连接（覆盖旧槽）。
pub fn store_h2(host: &str, up: H2Upstream) {
    conn_pool().lock().unwrap().insert(host.to_string(), up);
}
/// 清槽（连接失效时）：仅当槽内还是该 ip 才清，防误删刚写入的新槽。
pub fn drop_h2(host: &str, ip: &str) {
    let mut g = conn_pool().lock().unwrap();
    if g.get(host).map(|u| u.ip == ip).unwrap_or(false) {
        g.remove(host);
    }
}
/// 已拨好的连接(Dialed) → h2 握手。连接驱动 future 必须常驻 —— spawn 到
/// 后台直到连接自然结束。dial_h2(串发腿)与 dns_direct_fetch(系统 DNS 兜底
/// 腿)共用。
pub async fn h2_from_dialed(
    host: &str,
    conn_io: Dialed,
    ip: &str,
    form: &str,
    log: &LogFn,
) -> Result<H2Upstream, String> {
    // 流控窗口（2026-10-16 实测）：h2 默认流级/连接级窗口都是 65535B。一条
    // h2 连接上几十个并发资源流共享这 64KB 连接窗口，每 ~64KB 就要等一次
    // WINDOW_UPDATE 往返（边缘 RTT ~240ms）——单页 129 个资源被串行成 ~34s
    // FCP（实测每请求恰好慢 ~240ms），是"进仓库文件列表先在正中间再跳位"
    // 的最后一层元凶（.215 边缘迁移修复之后的遗留问题）。放大窗口让多流
    // 真正并行。
    let mut cb = h2::client::Builder::new();
    cb.initial_window_size(1024 * 1024) // 流级 1MB
        .initial_connection_window_size(4 * 1024 * 1024); // 连接级聚合 4MB
    let (send, conn) = cb
        .handshake(conn_io)
        .await
        .map_err(|e| format!("h2 握手失败: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await; // 连接驱动：帧收发/GOAWAY 处理, 结束即连接死亡
    });
    (log)(&format!(
        "[上游] {host} <- {ip} (boring {form} SNI, h2 握手)"
    ));
    Ok(H2Upstream {
        ip: ip.to_string(),
        send,
    })
}
/// 串发拨号 + h2 握手（boring 拨号 ALPN 已协商 h2）。
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
/// 流式直通响应头预算（秒）：git push 大包时 GitHub 收完包并解包校验才回
/// 响应头, 2GB@1MB/s ≈ 35 分钟 —— 给足 30 分钟。黑洞上游（收包不应答）由
/// 客户端侧超时/中止兜底。
pub const STREAM_HEAD_BUDGET_SECS: u64 = 1800;
/// 从 out 重建 h2 请求头：剥 h1 hop-by-hop 头 —— 浏览器/git 在隧道内可能
/// 以 http/1.1 发请求, h1 遗留头转发给 h2 会被判 malformed（RFC 7540
/// §8.1.2.2）。
fn h2_request_head(out: &hyper::Request<BoxBody>) -> Result<hyper::Request<()>, String> {
    let mut builder = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri());
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if matches!(
            low.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "te"
        ) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder.body(()).map_err(|e| e.to_string())
}
/// h2 响应头 future → Response<BoxBody>。体 RecvStream 逐块即时放窗
/// （h2 必须显式 release_capacity, 否则大响应死锁）。
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
/// 在自管 h2 连接上发一次请求：请求头从 out 重建, 体按 replay 注入
/// （SendStream 发送, 不阻塞连接复用）。
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
/// 流式直通·预泵段：重建请求头并以 EOS=false 发出，返回 (响应future, 发送流)。
/// 此段失败 = 连接已死且客户端体未被触碰 —— 调用方可安全换新拨重试。
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
/// 流式直通·请求体泵：客户端体帧 → SendStream，按对端授予的发送窗口分片
/// 发送（reserve_capacity/poll_capacity 背压，单次 send_data 严禁超窗口）。
/// 响应头先到时调用方已把响应交付客户端 —— 泵的失败仅记日志，绝不覆盖真实
/// 业务响应（响应优先语义）。客户端体读取出错（中断）时不补 EOS 直接弃流：
/// 上游按 RST 丢弃截断体 —— git pack 尾部带校验和，截断包必须被服务端拒绝，
/// 若补 EOS 反而会让上游把截断包当完整包处理。
pub fn h2_spawn_pump(mut send: h2::SendStream<Bytes>, mut body: BoxBody, log: LogFn) {
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
    });
}
/// 每 host 拨号单飞闸：并发请求同时缓存未命中时，只有一个真正进串发拨号，
/// 其余排队等待 —— 首拨成功入槽后，队列里的请求全部直走复用路径。
/// 实测无闸时一波页面并发 27 条全新拨号（新拨:复用 215:211），握手风暴
/// 还会触发边缘限流把表头翻飞（39s 翻 33 次）。
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
/// 镜像腿：标准 TLS + h1 直拨（非池域名），无表无阶梯。
#[derive(Clone)]
pub struct MirrorConnector;
impl Service<Uri> for MirrorConnector {
    type Response = TokioIo<Dialed>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<TokioIo<Dialed>, std::io::Error>> + Send>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let host = uri.host().unwrap_or("").to_lowercase();
        Box::pin(async move {
            let tls = pool::dial::dial_tls_simple(&host).await?;
            Ok(TokioIo::new(Dialed::Tls(tls)))
        })
    }
}
/// 构建镜像腿 h1 客户端。
pub fn mitm_h1_client() -> LegacyClient<MirrorConnector, BoxBody> {
    let connector = MirrorConnector;
    LegacyClient::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(connector)
}
/// 请求预算：一次上游请求的总预算。
pub const REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);
pub const MAX_REPLAY_BODY: usize = 1024 * 1024;
/// 重写上游请求：绝对 URL 化 + 剥代理头；accept-encoding 仅嗅探型 host
/// （github.com/api）剥离，其余放行压缩（见函数内注释）。返回 (host, 请求)。
pub fn upstream_request(
    req: &hyper::Request<Incoming>,
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
    // accept-encoding 策略（2026-10-15）：gh_defuse 要读明文 HTML 头 4KB 判拦截页，
    // 只有 github.com / api.github.com 强制身份编码（HTML 文档 300~400KB，代价可忍）；
    // 其余 host（assets/内容域/avatars 等从不嗅探响应体）放行浏览器原生压缩。
    // 此前全量裸传是"进仓库慢"主因 —— 实测仓库页 327KB→gzip 44.5KB（7.3x），
    // 31 个 CSS 合计 3.34MB→507KB（6.6x），129 个 JS 同理。
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
    let body =
        BoxBody::new(http_body_util::Empty::<bytes::Bytes>::new().map_err(|never| match never {}));
    let out = out.body(body).map_err(|e| e.to_string())?;
    Ok((out, host.to_string()))
}
/// 重组带缓冲前缀的响应体流（嗅探/探测后拼接回给客户端）。
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
