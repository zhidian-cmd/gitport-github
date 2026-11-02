//! 上游 HTTP 客户端：直连腿 = boring 指纹自管 h2 连接（fresh 语义）；镜像腿 = 标准 TLS + h1 共享池。
use super::protocol::{empty_body, BoxBody};
use crate::pool::{self, dial::Dialed};
use crate::util::{lock, now_ms, LogFn};
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
use std::time::{Duration, Instant};
use tower_service::Service;
/// 每 host 最多两条自管 h2 连接：一条承载全部并发但受服务端流上限，两条实测能把 p50 腰斩。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    /// 进程内唯一：同一 IP 的两条连接也要能精确区分，否则 keepalive 会删错。
    pub id: u64,
    /// 游标槽位：1 主通道、2 副通道，记账跟着连接走，各记各的钥匙。
    pub slot: u8,
    send: SendRequest<Bytes>,
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 最近响应耗时（EWMA）：同 host 两条连接可能一快一慢，轮转会把请求喂给慢的。
struct ConnSlot {
    up: H2Upstream,
    ewma: f64,
    n: u32,
    /// 借出去、响应体还没走完的流数：挑下一条 donor 靠它摊开，别把并发全堆到一根 TCP。
    borrowed: u32,
    /// 借失败后的冷却：坏的是这一条，同 host 的另一条照常服务。
    borrow_cool: Option<Instant>,
}

/// 借道失败冷却时长；到期自动重新参与挑选。
const BORROW_COOL: Duration = Duration::from_secs(30);

/// 单 host 的连接组：按耗时择优取用（偶尔轮转做探索）+ 补第二条时防重入。
#[derive(Default)]
struct HostConns {
    conns: Vec<ConnSlot>,
    next: usize,
    filling: bool,
}

static EXPLORE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 值得开两条连接的高频 host；长尾 host 多一条只是白占 socket。
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
    now_ms() / 1000
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
        let g = lock(conn_pool());
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

/// 取近况最快的那条，每 8 次放一次轮转做探索。
pub fn cached_h2(host: &str) -> Option<H2Upstream> {
    cached_h2_in(host, None)
}

/// 带槽位过滤取连接：搜索接口只回主通道（会话跨 IP 漂移会被降级成无结果骨架）。
pub fn cached_h2_in(host: &str, want_slot: Option<u8>) -> Option<H2Upstream> {
    let mut g = lock(conn_pool());
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

/// 借道 donor：assets 域已建好的伪装连接。
///
/// 证书只覆盖 `*.githubassets.com`，但 h2 的路由依据是 `:authority` 而不是 SNI——
/// 同一条连接换 `:authority` 就能取内容域（实测 avatars/raw 都是 200 整包）。
///
/// 只返回池里**现成**的连接：新建一条就得选 SNI，真名会暴露目标域，伪装又过不了内容域的证书校验，
/// 两条都是死路。所以这里没有"借不到就建一条"的分支，借不到就返回 None，让调用方走回退。
///
/// 挑法：先看这条连接上还挂着几条借出的流（少的优先），同负载再取 EWMA 快的；
/// 冷却中的直接跳过。借出的计数要由调用方在响应体走完（或失败）时归还，
/// 否则一条连接会越借越"忙"，最后谁也选不中它。
pub fn borrow_donor(exclude_host: &str) -> Option<(String, H2Upstream)> {
    let mut g = lock(conn_pool());
    let now = Instant::now();
    let mut pick: Option<(String, u64, (u32, f64))> = None;
    for (h, hc) in g.iter() {
        if h.as_str() == exclude_host || !h.ends_with("githubassets.com") {
            continue;
        }
        for c in &hc.conns {
            if c.borrow_cool.is_some_and(|t| now < t) {
                continue;
            }
            let key = (c.borrowed, c.ewma);
            let better = match &pick {
                None => true,
                Some((_, _, k)) => key.0 < k.0 || (key.0 == k.0 && key.1 < k.1),
            };
            if better {
                pick = Some((h.clone(), c.up.id, key));
            }
        }
    }
    let (host, id, _) = pick?;
    let c = g
        .get_mut(&host)?
        .conns
        .iter_mut()
        .find(|c| c.up.id == id)?;
    c.borrow_cool = None; // 冷却到期：这次选中即复位
    c.borrowed = c.borrowed.saturating_add(1);
    Some((host, c.up.clone()))
}

/// 借出的流走完了（正常或中途被丢弃）：把配额还回去。
pub fn borrow_done(host: &str, id: u64) {
    let mut g = lock(conn_pool());
    if let Some(c) = g
        .get_mut(host)
        .and_then(|h| h.conns.iter_mut().find(|c| c.up.id == id))
    {
        c.borrowed = c.borrowed.saturating_sub(1);
    }
}

/// 借失败：归还配额并把**这一条**冷藏 30 秒。同 host 的另一条不动——
/// 两条通道的意义就在于一条坏了另一条还能顶上。
pub fn borrow_poison(host: &str, id: u64) {
    let mut g = lock(conn_pool());
    if let Some(c) = g
        .get_mut(host)
        .and_then(|h| h.conns.iter_mut().find(|c| c.up.id == id))
    {
        c.borrowed = c.borrowed.saturating_sub(1);
        c.borrow_cool = Some(Instant::now() + BORROW_COOL);
    }
}

/// 每次成功发完回填耗时（α=0.3，抗单次抖动）。
pub fn note_latency(host: &str, id: u64, ms: u64) {
    let mut g = lock(conn_pool());
    let Some(h) = g.get_mut(host) else { return };
    let Some(c) = h.conns.iter_mut().find(|c| c.up.id == id) else {
        return;
    };
    let x = ms as f64;
    c.ewma = if c.n == 0 { x } else { c.ewma * 0.7 + x * 0.3 };
    c.n = c.n.saturating_add(1);
}

pub fn store_h2(host: &str, up: H2Upstream) {
    let mut g = lock(conn_pool());
    let h = g.entry(host.to_string()).or_default();
    h.filling = false;
    // 同 IP 也允许并存：服务端并发上限是按连接算的，两条同 IP 的 TCP 同样能摊开。
    if h.conns.len() >= MAX_CONNS_PER_HOST {
        h.conns.remove(0); // 只留最新的两条，避免旧连接占位
    }
    h.conns.push(ConnSlot {
        up,
        ewma: 0.0,
        n: 0,
        borrowed: 0,
        borrow_cool: None,
    });
}

/// 按连接 id 精确摘除：同 IP 两条连接靠 IP 分不开，删错会把健康的摘掉。
pub fn drop_h2_id(host: &str, id: u64) {
    let mut g = lock(conn_pool());
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
        let g = lock(conn_pool());
        g.get(host)
            .and_then(|h| h.conns.iter().find(|c| c.up.ip == ip))
            .map(|c| c.up.id)
    };
    if let Some(id) = id {
        drop_h2_id(host, id);
    }
}

/// 首条建好后后台补第二条（只对高频 host）；skip 池中活连接占用的 IP，游标用副键。
pub fn maybe_spawn_second(host: &str, log: &LogFn) {
    if !DUAL_CONN_HOSTS.contains(&host) {
        return;
    }
    {
        let mut g = lock(conn_pool());
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
                if let Some(h) = lock(conn_pool()).get_mut(&host) {
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
    // h2 握手必须限时：对端 TLS 通了之后装死会永久持有 per-host 拨号锁，拖死整个域名。
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
    lock(conn_pool())
        .get(host)
        .map(|h| h.conns.iter().map(|c| c.up.ip.clone()).collect())
        .unwrap_or_default()
}

/// 单通道拨号：串发选 IP → boring 握手 → h2；白名单域名的 sni 由 dial_one 强制真名分片。
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

/// 双通道冷启动并行竞速：各领各的游标、跳过对方正在试的 IP，先成者服务、晚成者入库。
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
    // 收尾移交后台：晚成者建成入库，失败走补建入口；竞速败者的空试不逐条刷红。
    let host = host.to_string();
    let log = log.clone();
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            match r {
                // 晚成者已在它自己的拨号任务里入过库（见上面 store_h2）：
                // 这里再存一次会变成两条同 id 的槽位，把真正的另一条挤掉。
                Ok(_) => {}
                Err(_) => maybe_spawn_second(&host, &log),
            }
        }
    });
    Ok(won)
}

/// 建连统一入口：双通道高频站池空走竞速，其余单发（单发也跳过池中占用的 IP）。
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
/// 流前置三步：等配额 → 剥逐跳头 → 发头帧；eos 表示头帧即请求终点。
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
/// 请求体泵：按对端窗口分片发送，客户端断开时弃流不补 EOS；句柄供失败路径 abort。
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
pub const MAX_REPLAY_BODY: usize = 1024 * 1024;
/// 客户端是否接受 gzip：强制压缩与缓存分桶的唯一判定，两处各写一份必有一边漏改。
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
    // github.com/api 强制 gzip（大页面裸传是进页面慢的主因），边收边解压，原始压缩帧照转。
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
#[path = "../tests/server/upstream_conn_slot_tests.rs"]
mod conn_slot_tests;

#[cfg(test)]
#[path = "../tests/server/upstream.rs"]
mod tests;
