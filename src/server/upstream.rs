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

/// BoxBody 构造收口：全仓的 Empty/Full + io 错误映射统一走这两个入口。
pub fn empty_body() -> BoxBody {
    BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other))
}

pub fn full_body(b: Bytes) -> BoxBody {
    BoxBody::new(http_body_util::Full::new(b).map_err(std::io::Error::other))
}
/// 每 host 最多两条自管 h2 连接（不用 legacy 池：体还在转发的连接不回池）。
/// 一条连接承载该 host 的全部并发，但服务端对单连接的并发流有上限——实测 40 并发时
/// 两条连接能把 p50 腰斩（2170ms → 1019ms），四条不再改善。只有成功过的连接入槽。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    /// 进程内唯一：同一 IP 的两条连接也要能精确区分，否则 keepalive 会删错。
    pub id: u64,
    /// 游标槽位:1 = 主通道(主键游标),2 = 第二通道(`~2` 游标)。
    /// 数据到手后的置顶/垫底记账跟着连接走,保证各记各的钥匙、互不覆盖。
    pub slot: u8,
    send: SendRequest<Bytes>,
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 它最近的响应耗时（EWMA，毫秒）。同 host 两条连接质量可能差很多，
/// 实测出现过一条 p50 1671ms、另一条 460ms，轮转等于把一半请求喂给慢的。
struct ConnSlot {
    up: H2Upstream,
    ewma: f64,
    n: u32,
}

/// 单 host 的连接组：按耗时择优取用（偶尔轮转做探索）+ 补第二条时防重入。
#[derive(Default)]
struct HostConns {
    conns: Vec<ConnSlot>,
    next: usize,
    filling: bool,
}

static EXPLORE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 值得开两条连接的 host（高频入口）。长尾 host 多一条只是白占 socket。
const DUAL_CONN_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "avatars.githubusercontent.com",
    "github.githubassets.com",
];
const MAX_CONNS_PER_HOST: usize = 2;

static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, HostConns>>> =
    std::sync::OnceLock::new();
fn conn_pool() -> &'static Mutex<HashMap<String, HostConns>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

static LAST_ACTIVITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ACTIVITY_KICK: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn now_secs() -> u64 {
    pool::now_ms() / 1000
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
        let g = pool::lock(conn_pool());
        g.iter()
            .flat_map(|(h, hc)| hc.conns.iter().map(move |c| (h.clone(), c.up.clone())))
            .collect()
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
            drop_h2_id(&host, up.id); // 对端无答/连接已死: 只摘这一条
        }
    }
}

/// 取一条连接：优先近况最快的那条；每 8 次放一次轮转做探索，避免把慢连接饿死
/// 到永远发现不了它变快。
pub fn cached_h2(host: &str) -> Option<H2Upstream> {
    cached_h2_in(host, None)
}

/// 带槽位过滤的取连接:`want_slot = Some(1)` 时只回主通道——搜索接口专用
/// (GitHub blackbird 反爬对同会话跨 IP 敏感,实测会话在两通道间漂移会被
/// 降级成无结果骨架页,2026-10-27 实证)。过滤池为空 = 主通道不在,回 None
/// 交给拨号路径按主键游标重建;非搜索请求传 None 走原有轮转/择优。
pub fn cached_h2_in(host: &str, want_slot: Option<u8>) -> Option<H2Upstream> {
    let mut g = pool::lock(conn_pool());
    let h = g.get_mut(host)?;
    let n = h.conns.len();
    if n == 0 {
        return None;
    }
    if let Some(want) = want_slot {
        // 过滤池:主通道优先,EWMA 最快者胜(样本不足取第一条)。不参与轮转计数。
        let pick = h
            .conns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.up.slot == want && c.n >= 3)
            .min_by(|a, b| a.1.ewma.total_cmp(&b.1.ewma))
            .map(|(i, _)| i)
            .or_else(|| h.conns.iter().position(|c| c.up.slot == want));
        return pick.map(|i| h.conns[i].up.clone());
    }
    let mut idx = h.next % n;
    h.next = idx + 1;
    if n > 1 && !EXPLORE.fetch_add(1, std::sync::atomic::Ordering::Relaxed).is_multiple_of(8) {
        if let Some((i, _)) = h
            .conns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.n >= 3)
            .min_by(|a, b| a.1.ewma.total_cmp(&b.1.ewma))
        {
            idx = i;
        }
    }
    Some(h.conns[idx].up.clone())
}

/// 每次成功发完回填耗时（α=0.3，抗单次抖动）。
pub fn note_latency(host: &str, id: u64, ms: u64) {
    let mut g = pool::lock(conn_pool());
    let Some(h) = g.get_mut(host) else { return };
    let Some(c) = h.conns.iter_mut().find(|c| c.up.id == id) else {
        return;
    };
    let x = ms as f64;
    c.ewma = if c.n == 0 { x } else { c.ewma * 0.7 + x * 0.3 };
    c.n = c.n.saturating_add(1);
}

pub fn store_h2(host: &str, up: H2Upstream) {
    let mut g = pool::lock(conn_pool());
    let h = g.entry(host.to_string()).or_default();
    h.filling = false;
    // 同 IP 也允许并存：服务端并发上限是按连接算的，两条同 IP 的 TCP 同样能摊开。
    if h.conns.len() >= MAX_CONNS_PER_HOST {
        h.conns.remove(0); // 只留最新的两条，避免旧连接占位
    }
    h.conns.push(ConnSlot { up, ewma: 0.0, n: 0 });
}

/// 按连接 id 精确摘除（keepalive / 复用失败都走这里）。
/// 两条同 IP 的连接靠 IP 是分不开的，删错就会把健康的摘掉、坏的留着反复被轮转。
pub fn drop_h2_id(host: &str, id: u64) {
    let mut g = pool::lock(conn_pool());
    let empty = match g.get_mut(host) {
        Some(h) => {
            if let Some(pos) = h.conns.iter().position(|c| c.up.id == id) {
                h.conns.remove(pos);
            }
            h.conns.is_empty()
        }
        None => false,
    };
    if empty {
        g.remove(host);
    }
}

/// 只有 IP 没有句柄时用（gh_defuse 从响应头拿到的是 IP）：查到 id 交 drop_h2_id 摘除。
pub fn drop_h2(host: &str, ip: &str) {
    let id = {
        let g = pool::lock(conn_pool());
        g.get(host)
            .and_then(|h| h.conns.iter().find(|c| c.up.ip == ip))
            .map(|c| c.up.id)
    };
    if let Some(id) = id {
        drop_h2_id(host, id);
    }
}

/// 首条连接建好后，后台补第二条（只对高频 host，失败不影响当前请求）。
/// skip 池中所有活连接占用的 IP;游标用副键(~2),与主通道各记各的。
pub fn maybe_spawn_second(host: &str, log: &LogFn) {
    if !DUAL_CONN_HOSTS.contains(&host) {
        return;
    }
    {
        let mut g = pool::lock(conn_pool());
        let Some(h) = g.get_mut(host) else { return };
        if h.conns.len() >= MAX_CONNS_PER_HOST || h.filling {
            return;
        }
        h.filling = true;
    }
    let skip = occupied_ips(host);
    let host = host.to_string();
    let log = log.clone();
    tokio::spawn(async move {
        let name = crate::config::pool_for(&host);
        match h2_dial_slot(name, &host, &log, &skip, 2, None).await {
            Ok(up) => store_h2(&host, up),
            Err(e) => {
                (log)(&format!("[上游] {host} 第二条连接失败({e}), 保持单连接"));
                if let Some(h) = pool::lock(conn_pool()).get_mut(&host) {
                    h.filling = false;
                }
            }
        }
    });
}
pub async fn h2_from_dialed(
    host: &str,
    conn_io: Dialed,
    ip: &str,
    form: &str,
    slot: u8,
    log: &LogFn,
) -> Result<H2Upstream, String> {
    // h2 默认窗口 64KB 会把单页 129 并发压成按 RTT 串行（实测 FCP 34s），放大为流 1MB/连接 4MB。
    let mut cb = h2::client::Builder::new();
    cb.initial_window_size(1024 * 1024) // 流级 1MB
        .initial_connection_window_size(4 * 1024 * 1024); // 连接级聚合 4MB
    // h2 握手（等对端回 SETTINGS）必须限时：TCP 3s / TLS 3s / 发请求 8s 都有，
    // 唯独这步曾裸等——对端 TLS 通了之后装死，会永久持有 per-host 拨号锁，拖死整个域名。
    let (send, mut conn) = tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::H2_HANDSHAKE_TIMEOUT_SECS),
        cb.handshake(conn_io),
    )
    .await
    .map_err(|_| format!("h2 握手超时({}s): {host}", crate::config::H2_HANDSHAKE_TIMEOUT_SECS))?
    .map_err(|e| format!("h2 握手失败: {e}"))?;
    let ping = conn
        .ping_pong()
        .map(|p| Arc::new(tokio::sync::Mutex::new(p)));
    tokio::spawn(async move {
        let _ = conn.await; // 连接驱动：帧收发/GOAWAY 处理, 结束即连接死亡
    });
    // 第二通道在行尾标出;主通道与单发保持原样,免日志噪音。
    let chan = if slot > 1 { format!(", 通道{slot}") } else { String::new() };
    (log)(&format!(
        "[上游] {host} <- {ip} (boring {form} SNI, h2 握手{chan})"
    ));
    Ok(H2Upstream {
        ip: ip.to_string(),
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        slot,
        send,
        ping,
    })
}
/// 池中该 host 活连接占用的 IP(供拨号 skip:两条通道不落同一地址)。
fn occupied_ips(host: &str) -> Vec<String> {
    pool::lock(conn_pool())
        .get(host)
        .map(|h| h.conns.iter().map(|c| c.up.ip.clone()).collect())
        .unwrap_or_default()
}

/// 单通道拨号:串发选 IP(slot 游标钥匙) → boring 握手 → h2。
/// 白名单域名走 edge 池,但握手由 dial_one 强制真名 + 分片,条目自带的 sni 不生效,
/// 日志按实际形态标注,别被 plans.json 里的 "baidu.com" 骗了。
async fn h2_dial_slot(
    pool_name: &str,
    host: &str,
    log: &LogFn,
    skip_ips: &[String],
    slot: u8,
    crew: Option<&pool::DialCrew>,
) -> Result<H2Upstream, String> {
    let (conn_io, ip, shape) = pool::serial_dial_skip(
        pool::DialSkip {
            pool_name,
            host,
            tls_handshake: true,
            skip_ips,
            passthrough: false,
            slot,
            crew,
        },
        CancellationToken::new(),
        Some(log),
    )
    .await
    .map_err(|e| e.to_string())?;
    let form = if crate::config::is_whitelist(host) {
        "真名(分片)"
    } else if shape.is_empty() {
        "无"
    } else if shape == host {
        "真名"
    } else {
        "伪装"
    };
    h2_from_dialed(host, conn_io, &ip, form, slot, log).await
}

/// 双通道高频站冷启动:两个任务并行竞速建连。
/// - 各领各的游标钥匙(主键 / ~2 副键),成功各记各的,主通道的最优记忆不再被覆盖
/// - SERIAL 表内 in-flight 认领:对方正在试的 IP 自动跳过,两个任务不重复劳动
/// - 先成者立即服务请求;晚成者建完直接入库上岗——拿拨号锁醒来的排队请求
///   会在循环顶部 cached_h2 复用到它,这就是"把排队的塞进自己这里"
/// - 两个全败 = 现有全灭语义(冷却 30s)
async fn dial_h2_race(pool_name: &str, host: &str, log: &LogFn) -> Result<H2Upstream, String> {
    let crew = pool::DialCrew::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<H2Upstream, String>>(4);
    (log)(&format!("[建连] {host} 冷启动竞速发射"));
    for slot in [1u8, 2] {
        let tx = tx.clone();
        let name = pool_name.to_string();
        let host = host.to_string();
        let log = log.clone();
        let crew = crew.clone();
        tokio::spawn(async move {
            match h2_dial_slot(&name, &host, &log, &[], slot, Some(&crew)).await {
                Ok(up) => {
                    store_h2(&host, up.clone());
                    let _ = tx.send(Ok(up)).await;
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await; // 红字由收尾统一接管,不逐任务刷
                }
            }
        });
    }
    drop(tx);
    // 等第一个成功;两个全败则整组失败
    let mut last: Option<String> = None;
    let won = loop {
        match rx.recv().await {
            Some(Ok(up)) => break up,
            Some(Err(e)) => last = Some(e),
            None => return Err(last.unwrap_or_else(|| "并行建连全败".into())),
        }
    };
    // 收尾移交后台:晚成者建成照常入库上岗;失败则补建一次第二通道
    // (skip 池中占用,失败静默降级单通道)。竞速败者的空试不再逐条刷红——
    // 真实的候选超时由串发全灭日志记录。
    // 收尾移交后台:晚成者建成照常入库上岗;失败则走统一的补建入口
    // (maybe_spawn_second 自带 DUAL 名单/filling/满员检查,失败静默降级单通道)。
    // 竞速败者的空试不再逐条刷红——真实的候选超时由串发全灭日志记录。
    let host = host.to_string();
    let log = log.clone();
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            match r {
                Ok(up) => store_h2(&host, up),
                Err(_) => maybe_spawn_second(&host, &log),
            }
        }
    });
    Ok(won)
}

/// 上游建连统一入口:双通道高频站池空走并行竞速,其余单发。
/// 单发也 skip 池中活连接占用的 IP——修掉旧版"主连接断掉重拨时游标已被
/// 第二条记账、又不 skip"导致两条通道撞同一 IP 的暗坑。
pub async fn dial_upstream(
    pool_name: &str,
    host: &str,
    log: &LogFn,
) -> Result<(H2Upstream, bool), String> {
    if DUAL_CONN_HOSTS.contains(&host) && occupied_ips(host).is_empty() {
        let up = dial_h2_race(pool_name, host, log).await?;
        return Ok((up, false)); // 竞速任务内部已入库
    }
    let skip = occupied_ips(host);
    let up = h2_dial_slot(pool_name, host, log, &skip, 1, None).await?;
    Ok((up, true)) // 尚不在池中,发送成功后由调用方入库
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
/// 流前置三步共用（h2_send 与流式直通单点）：等配额 → 剥逐跳头 → 发头帧；
/// eos = 头帧即请求终点（无体请求 true）。
pub async fn h2_open_stream(
    up: &H2Upstream,
    out: &hyper::Request<BoxBody>,
    eos: bool,
) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
    let mut send = up.send.clone();
    send = send.ready().await.map_err(|e| format!("h2 流配额: {e}"))?;
    send.send_request(h2_request_head(out)?, eos)
        .map_err(|e| format!("h2 发送: {e}"))
}

pub async fn h2_send(
    up: &H2Upstream,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let has_body = body.as_ref().is_some_and(|b| !b.is_empty());
    let (resp_fut, mut send_stream) = h2_open_stream(up, out, !has_body).await?;
    if has_body {
        send_stream
            .send_data(body.as_ref().unwrap().clone(), true)
            .map_err(|e| format!("h2 请求体: {e}"))?;
    }
    h2_recv_response(resp_fut).await
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
        .unwrap_or_else(|p| p.into_inner())
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
/// 客户端声明接受 gzip。**唯一判定**：上游要不要强制 gzip、缓存要不要分 `-gz`/`-id` 桶
/// 都调它——两处各写一份时，改一边就会让"压缩体发给没声明 gzip 的客户端"复现。
pub fn accepts_gzip<B>(req: &hyper::Request<B>) -> bool {
    let Some(v) = req
        .headers()
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    for item in v.split(',') {
        // 去空白 + 小写：分号/等号两侧的空白都合法("gzip ; q=0")
        let item: String = item
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let Some(rest) = item.strip_prefix("gzip") else {
            continue;
        };
        if rest.is_empty() {
            return true; // 裸 "gzip" = 默认接受
        }
        let Some(params) = rest.strip_prefix(';') else {
            continue; // "gzipx" 之类前缀误中，跳过
        };
        for kv in params.split(';') {
            if let Some(q) = kv.strip_prefix("q=") {
                // q=0 / 0.0 / 0.000 = 明确拒绝
                let zero = q == "0"
                    || q.strip_prefix("0.")
                        .is_some_and(|rest| rest.chars().all(|c| c == '0'));
                return !zero;
            }
        }
        return true; // 有 gzip 无 q 参数 = 接受
    }
    false
}

/// 重写上游请求：绝对 URL 化 + 剥代理头；嗅探型 host 强制 gzip。
pub fn upstream_request<B>(
    req: &hyper::Request<B>,
    host: &str,
) -> Result<hyper::Request<BoxBody>, String> {
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
    // 只在客户端声明接受 gzip 时才强制（curl/git 无解压能力，无条件强制曾致其解码失败）。
    if sniffed && accepts_gzip(req) {
        out = out.header("accept-encoding", "gzip");
    }
    out.body(empty_body()).map_err(|e| e.to_string())
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
mod conn_slot_tests {
    use super::*;

    /// 造一条合法 H2Upstream:h2 握手用本机 duplex 对拉(无需真网络),
    /// server 端由 h2::server 驱动回 SETTINGS,client 端即完成。
    async fn mk_up(ip: &str, slot: u8) -> H2Upstream {
        let (client_io, server_io) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = h2::server::handshake(server_io).await;
        });
        let (send, conn) = h2::client::handshake(client_io).await.expect("duplex 握手");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        H2Upstream {
            ip: ip.to_string(),
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            slot,
            send,
            ping: None,
        }
    }

    #[tokio::test]
    async fn slot_filter_pins_search_to_primary() {
        let host = "test-slot-filter.github.com";
        store_h2(host, mk_up("9.9.9.2", 2).await); // 第二通道先入池
        store_h2(host, mk_up("9.9.9.1", 1).await); // 主通道后入
        for _ in 0..4 {
            let up = cached_h2_in(host, Some(1)).expect("主通道应在池");
            assert_eq!(up.ip, "9.9.9.1", "Some(1) 永远拿主通道,轮转计数不动");
        }
        // 主通道被摘后:Some(1) -> None(交拨号按主键重建),绝不误用第二通道
        drop_h2_id(host, {
            let g = pool::lock(conn_pool());
            g.get(host).unwrap().conns.iter().find(|c| c.up.slot == 1).unwrap().up.id
        });
        assert!(
            cached_h2_in(host, Some(1)).is_none(),
            "主通道被摘后应回 None 走重建,不得回落第二通道"
        );
        // None = 原语义:池里剩下的第二通道照常服务
        let up = cached_h2_in(host, None).expect("无过滤应命中");
        assert_eq!(up.ip, "9.9.9.2");
        let _ = pool::lock(conn_pool()).remove(host);
    }

    #[tokio::test]
    async fn slot_filter_prefers_fastest_primary() {
        let host = "test-slot-ewma.github.com";
        let slow = mk_up("9.9.8.1", 1).await;
        let fast = mk_up("9.9.8.2", 1).await;
        let (sid, fid) = (slow.id, fast.id);
        store_h2(host, slow);
        store_h2(host, fast);
        // 灌 EWMA 样本(>=3 次才参与择优):慢的 300ms,快的 50ms
        for _ in 0..4 {
            note_latency(host, sid, 300);
            note_latency(host, fid, 50);
        }
        let up = cached_h2_in(host, Some(1)).expect("主通道应在池");
        assert_eq!(up.id, fid, "槽位过滤应在主通道内取 EWMA 最快者");
        let _ = pool::lock(conn_pool()).remove(host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gzip;q=0 是明确拒绝：别再把压缩体塞给手写客户端(浏览器不受影响)。
    #[test]
    fn accepts_gzip_respects_explicit_reject() {
        let mk = |ae: &str| {
            hyper::Request::builder()
                .header("accept-encoding", ae)
                .body(())
                .unwrap()
        };
        assert!(accepts_gzip(&mk("gzip, deflate")));
        assert!(accepts_gzip(&mk("GZIP")));
        assert!(accepts_gzip(&mk("br, gzip;q=1")));
        assert!(!accepts_gzip(&mk("gzip;q=0")));
        assert!(!accepts_gzip(&mk("br")));
        // 分号/等号两侧的空白合法(HTTP OWS)，照样是明确拒绝
        assert!(!accepts_gzip(&mk("gzip; q=0")));
        assert!(!accepts_gzip(&mk("gzip ; q=0")));
        assert!(!accepts_gzip(&mk("br, gzip;q=0")));
    }

    /// 上行泵（git push 的请求体通道）：2MB 体必须一字节不差送到对端。
    /// 这条路径此前没有任何测试——窗口/背压改错不会让别的测试变红，只会让 push 卡住。
    #[tokio::test]
    async fn h2_body_pump_delivers_every_byte() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        // 假上游：h2 服务端，收满请求体后把字节数写回响应体。
        let srv = tokio::spawn(async move {
            let (sock, _) = ln.accept().await.unwrap();
            let svc = hyper::service::service_fn(
                |req: hyper::Request<hyper::body::Incoming>| async move {
                    let n = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes().len())
                        .unwrap_or(0);
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(full_body(
                        Bytes::from(n.to_string()),
                    )))
                },
            );
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (send, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut send = send.ready().await.unwrap();
        let head = http::Request::builder()
            .method("POST")
            .uri("https://example.test/upload")
            .body(())
            .unwrap();
        let (resp_fut, stream) = send.send_request(head, false).unwrap();

        let len = 2 * 1024 * 1024;
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let body = full_body(Bytes::from(payload));
        let log: LogFn = Arc::new(|_: &str| {});
        let pump = h2_spawn_pump(stream, body, log);

        let resp = tokio::time::timeout(std::time::Duration::from_secs(10), resp_fut)
            .await
            .expect("10s 内上游没收到完整请求体（泵卡住了）")
            .unwrap();
        let mut recv = resp.into_body();
        let mut echoed = Vec::new();
        while let Some(chunk) = recv.data().await {
            echoed.extend_from_slice(&chunk.unwrap());
        }
        pump.await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&echoed),
            len.to_string(),
            "上游收到的字节数应与发送量一致"
        );
        srv.abort();
    }

    #[test]
    fn forced_gzip_gated_on_client_accept() {
        let req = hyper::Request::builder()
            .uri("https://github.com/a")
            .header("accept-encoding", "gzip, deflate, br")
            .body(())
            .unwrap();
        let out = upstream_request(&req, "github.com").unwrap();
        assert_eq!(
            out.headers().get("accept-encoding").unwrap(),
            "gzip",
            "声明过 gzip 的客户端应被强制 gzip"
        );

        let req2 = hyper::Request::builder()
            .uri("https://github.com/a")
            .body(())
            .unwrap();
        let out2 = upstream_request(&req2, "github.com").unwrap();
        assert!(
            out2.headers().get("accept-encoding").is_none(),
            "未声明的客户端应回身份编码"
        );

        let req3 = hyper::Request::builder()
            .uri("https://raw.githubusercontent.com/a")
            .body(())
            .unwrap();
        let out3 = upstream_request(&req3, "raw.githubusercontent.com").unwrap();
        assert!(
            out3.headers().get("accept-encoding").is_none(),
            "非嗅探 host 不添加"
        );
    }
}
