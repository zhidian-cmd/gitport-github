//! 上游 HTTP 客户端。两条腿：
//! - 池内直连腿：boring Chrome 指纹（GREASE + Chrome 套件/扩展序 + ALPN
//!   h2,http/1.1；Rust 无 utls 绑定，warpsock 腿已拆除）。SNI 按 IP 族定
//!   （Fastly 边缘真名 / 主站与 auth 伪装），证书按目标 host 校验（解耦见
//!   pool/dial.rs）。每请求经串发表新拨号（fresh 语义）。
//! - 镜像腿：标准 TLS + h1 直拨，无表无阶梯。
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
/// 每 host 一条自管 h2 连接（不用 hyper-util legacy 池：响应体还在转发的
/// 连接不回池，页面连续取资源时每秒再拨一条——实测新拨与复用各半）。
/// SendRequest 可 Clone，一条连接承载该 host 全部并发请求；只有"完整请求
/// 成功过"的连接才入槽（fresh 语义保持）。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    send: SendRequest<Bytes>,
    /// h2 PING 句柄（保活用）：连接建立时取出，活跃窗口内发 PING 帧防边缘
    /// 按空闲回收（约 50-60s）导致跨导航冷启动（1.3s 握手）。None = 取不到
    /// （理论上不会），保活跳过该连接。
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
}
static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, H2Upstream>>> =
    std::sync::OnceLock::new();
fn conn_pool() -> &'static Mutex<HashMap<String, H2Upstream>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

// ---------- 活跃窗口内 h2 保活（跨导航复用，2026-10-17） ----------
/// 最近一次代理请求时间（unix 秒）。0 = 从未有请求（任务纯睡）。
static LAST_ACTIVITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// 唤醒保活任务（每次请求踢一下；无请求时任务睡在它上面，零周期唤醒）。
static ACTIVITY_KICK: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 记录一次代理请求：开着保活窗口计时并踢醒任务。
pub fn note_activity() {
    LAST_ACTIVITY.store(now_secs(), std::sync::atomic::Ordering::Relaxed);
    ACTIVITY_KICK.notify_one();
}

/// 启动活跃窗口保活任务（须在 runtime 构建后调用）。
/// 语义：有请求 → 每 PROBE 秒对 core host 的缓存 h2 连接发 PING；静默超过
/// WINDOW 秒 → 回睡眠。**空闲零唤醒不变**：无请求 = 无定时器, 进程纯睡。
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

/// 一轮保活：对所有**已缓存**的连接发 PING（不主动建新连接——只续命真实
/// 请求建立过的连接，符合"不预建通道"约束）。覆盖 core(页面骨架) + api +
/// edge(头像/图片/样式)：2026-10-17 实测只保 core 时，avatars 冷启 741ms、
/// camo 1823ms、assets 753ms，跨导航后图片/样式明显晚到。
/// 失败即清槽（下次请求重新拨，等价无保活行为）。
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
    // h2 默认流级/连接级窗口都是 64KB，单页 129 个并发资源流共享连接窗口
    // 会被压成按 RTT 逐个串行（实测 FCP 34s）——放大为流 1MB/连接 4MB
    // 让多流真并行（2026-10-16）。
    let mut cb = h2::client::Builder::new();
    cb.initial_window_size(1024 * 1024) // 流级 1MB
        .initial_connection_window_size(4 * 1024 * 1024); // 连接级聚合 4MB
    let (send, mut conn) = cb
        .handshake(conn_io)
        .await
        .map_err(|e| format!("h2 握手失败: {e}"))?;
    // PING 句柄必须在驱动前取出（只能取一次）；连接驱动 spawn 后句柄仍可发帧
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
/// 响应头先到时泵失败只记日志，绝不覆盖已交付的响应（响应优先）。
/// 客户端体读取出错时不补 EOS 直接弃流 —— git pack 尾带校验和，截断包必须
/// 被服务端 RST 拒绝，补 EOS 会被当完整包处理。
/// 返回 JoinHandle 供调用方在失败路径 abort —— 句柄丢弃的话，"上游停发
/// 窗口 + 客户端挂连接不关"的组合会让泵滞留在 poll_capacity 上，任务/连接
/// 不回收（2026-10-17 复审裁定）。
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
/// 镜像腿：标准 TLS + 直拨（非池域名），无表无阶梯。
/// ALPN 是 h2,http/1.1：镜像（多为 Cloudflare 前置）常协商 h2，一条连接可
/// 复用多个请求（图片突发/多 Range），h1 镜像退回串行复用。
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
            // 只在真正新建 TLS 时出现 —— 复用命中的请求没有这行, 天然无噪音
            (log)(&format!(
                "[镜像拨号] {host} TLS {}ms alpn={}",
                t0.elapsed().as_millis(),
                String::from_utf8_lossy(alpn)
            ));
            Ok(TokioIo::new(Dialed::Tls(tls)))
        })
    }
}
/// 镜像腿每镜像的空闲连接上限。0 = 关闭连接池（回滚开关，退回"每次新拨"）。
const MIRROR_POOL_MAX_IDLE: usize = 4;
/// 空闲连接保留时长；必须配 pool_timer 才生效（见 mirror_client）。
const MIRROR_POOL_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

static MIRROR_CLIENT: std::sync::OnceLock<LegacyClient<MirrorConnector, BoxBody>> =
    std::sync::OnceLock::new();

/// 镜像腿共享客户端（进程内单例，2026-10-18）。
/// 此前每请求新建 client 且 `pool_max_idle_per_host(0)`，17 张图/多次 Range
/// 各自重付一次 DNS+TCP+TLS；共享后每镜像只拨 1-4 次。
/// 边界：h2 下响应头到手连接即回池（并发小请求可复用）；**单流大文件吞吐
/// 不变**——大文件的速度杠杆是链序置顶（pool::MIRROR_PINS）。
/// 首次调用者的 log 被永久持有；各调用点传的都是同一 Logger 的克隆，无差别。
pub fn mirror_client(log: &LogFn) -> &'static LegacyClient<MirrorConnector, BoxBody> {
    MIRROR_CLIENT.get_or_init(|| {
        let mut b = LegacyClient::builder(TokioExecutor::new());
        b.pool_max_idle_per_host(MIRROR_POOL_MAX_IDLE)
            .pool_idle_timeout(MIRROR_POOL_IDLE)
            // 没有 timer 时 pool_idle_timeout 完全不生效（hyper-util 内部
            // 只在 timer 存在时 spawn 空闲回收任务）
            .pool_timer(hyper_util::rt::TokioTimer::new())
            // 复用了已死连接且请求尚未写出 → 自动重发（镜像请求体恒空，安全）
            .retry_canceled_requests(true);
        b.build(MirrorConnector { log: log.clone() })
    })
}
/// 请求预算：一次上游请求的总预算。
pub const REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);
pub const MAX_REPLAY_BODY: usize = 1024 * 1024;
/// 重写上游请求：绝对 URL 化 + 剥代理头；嗅探型 host（github.com/api）强制
/// gzip 上游压缩（2026-10-17），其余 host 放行浏览器原生压缩。
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
    // accept-encoding 策略（2026-10-17）：gh_defuse 要读拦截页明文，过去对
    // github.com/api 强制身份编码 —— 但大页面裸传是"大仓库进页面慢"主因
    // （实测仓库页 327KB → 44.5KB，7.3x）。现在改为强制 gzip：嗅探在
    // mitm::is_gh_block_page 里做"边收边解压判前 4KB"，已消费的原始压缩帧
    // 原样转发给浏览器，不重压缩。其余 host（assets/内容域/avatars，从不
    // 嗅探响应体）继续放行浏览器原生压缩（br/zstd 由浏览器自己协商）。
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
        // 只认 gzip：代理侧只需一个解压器（flate2），br/zstd 解压要额外依赖。
        // gzip 已拿回 ~5-6 倍压缩比，足够。
        out = out.header("accept-encoding", "gzip");
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
