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
use tower_service::Service;
/// 池按 IP 记账：一条连接可被该 IP 服务着的所有路由键共用（v2 复用单元 = IP）。
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

/// 一条连接 + 最近响应耗时（EWMA）：同 IP 两条连接可能一快一慢，轮转会把请求喂给慢的。
struct ConnSlot {
    up: H2Upstream,
    ewma: f64,
    n: u32,
}

/// 单 IP 的连接组：补第二条时防重入。
#[derive(Default)]
struct IpConns {
    conns: Vec<ConnSlot>,
    filling: bool,
}

static EXPLORE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 每 IP 最多两条自管 h2 连接：一条承载全部并发但受服务端流上限，两条实测能把 p50 腰斩。
const MAX_CONNS_PER_IP: usize = 2;

/// 带会话（cookie/auth）的域：只留单通道单 IP。同一会话并发出现在两个 IP 上，
/// 正是 GitHub 风控最容易抓的特征；内容域（图片/静态资源）才吃双通道加速。
fn session_host(host: &str) -> bool {
    matches!(host, "github.com" | "api.github.com")
}

static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, IpConns>>> = std::sync::OnceLock::new();
fn conn_pool() -> &'static Mutex<HashMap<String, IpConns>> {
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
    let conns: Vec<H2Upstream> = {
        let g = lock(conn_pool());
        g.values()
            .flat_map(|hc| hc.conns.iter().map(|c| c.up.clone()))
            .collect()
    };
    for up in conns {
        let Some(pp) = up.ping.clone() else { continue };
        let mut guard = pp.lock().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            guard.ping(h2::Ping::opaque()),
        )
        .await;
        if !matches!(r, Ok(Ok(_))) {
            drop(guard);
            drop_h2_id(&up.ip, up.id); // 对端无答/连接已死: 只摘这一条
        }
    }
}

/// 测试专用：把探索计数器对齐到非探索相位（接下来 7 次取用都走 EWMA 择优，概率不进断言）。
#[cfg(test)]
pub(crate) fn align_explore_to_sampled_phase() {
    let c = EXPLORE.load(std::sync::atomic::Ordering::Relaxed);
    EXPLORE.store(c + (8 - c % 8) + 1, std::sync::atomic::Ordering::Relaxed);
}

/// 在给定 IP 集合里取活连接：跨 IP 按 EWMA 择优（样本不足取首条），每 8 次放一次轮转做探索。
pub fn cached_h2_in(ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    let mut g = lock(conn_pool());
    // 收集候选集合内全部连接（want_slot 过滤后）。
    let mut cands: Vec<(f64, H2Upstream)> = Vec::new();
    for ip in ips {
        let Some(h) = g.get_mut(ip) else { continue };
        for c in &h.conns {
            if let Some(want) = want_slot {
                if c.up.slot != want {
                    continue;
                }
            }
            cands.push((c.ewma, c.up.clone()));
        }
    }
    if cands.is_empty() {
        return None;
    }
    let pick = if want_slot.is_none() {
        // 1/8 探索：按全局计数器在候选里轮转一圈，摊开别全堆一条；其余 7/8 走 EWMA 择优。
        let explore = EXPLORE
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(8);
        if explore {
            // 探索：按全局计数器在候选里轮转一圈，摊开别全堆一条。
            let offset = EXPLORE.load(std::sync::atomic::Ordering::Relaxed) as usize;
            let i = offset % cands.len();
            cands.swap(0, i);
            0
        } else {
            // 择优：样本 >=3 的里挑 EWMA 最小；全都没样本取首条。
            let sampled: Vec<usize> = cands
                .iter()
                .enumerate()
                .filter(|(_, (ewma, _))| *ewma > 0.0)
                .map(|(i, _)| i)
                .collect();
            if sampled.is_empty() {
                0
            } else {
                sampled
                    .into_iter()
                    .min_by(|a, b| cands[*a].0.total_cmp(&cands[*b].0))
                    .unwrap()
            }
        }
    } else {
        // 槽位过滤：EWMA 最快者胜（样本不足取首条）。
        let sampled: Vec<usize> = cands
            .iter()
            .enumerate()
            .filter(|(_, (ewma, _))| *ewma > 0.0)
            .map(|(i, _)| i)
            .collect();
        if sampled.is_empty() {
            0
        } else {
            sampled
                .into_iter()
                .min_by(|a, b| cands[*a].0.total_cmp(&cands[*b].0))
                .unwrap()
        }
    };
    Some(cands.remove(pick).1)
}

/// 每次成功发完回填耗时（α=0.3，抗单次抖动）。
pub fn note_latency(ip: &str, id: u64, ms: u64) {
    let mut g = lock(conn_pool());
    let Some(h) = g.get_mut(ip) else { return };
    let Some(c) = h.conns.iter_mut().find(|c| c.up.id == id) else {
        return;
    };
    let x = ms as f64;
    c.ewma = if c.n == 0 { x } else { c.ewma * 0.7 + x * 0.3 };
    c.n = c.n.saturating_add(1);
}

pub fn store_h2(ip: &str, up: H2Upstream) {
    let mut g = lock(conn_pool());
    let h = g.entry(ip.to_string()).or_default();
    h.filling = false;
    // 同 IP 也允许并存：服务端并发上限是按连接算的，两条同 IP 的 TCP 同样能摊开。
    if h.conns.len() >= MAX_CONNS_PER_IP {
        h.conns.remove(0); // 只留最新的两条，避免旧连接占位
    }
    h.conns.push(ConnSlot {
        up,
        ewma: 0.0,
        n: 0,
    });
}

/// 按连接 id 精确摘除：同 IP 两条连接靠 IP 分不开，删错会把健康的摘掉。
pub fn drop_h2_id(ip: &str, id: u64) {
    let mut g = lock(conn_pool());
    let empty = match g.get_mut(ip) {
        Some(h) => {
            if let Some(pos) = h.conns.iter().position(|c| c.up.id == id) {
                h.conns.remove(pos);
            }
            h.conns.is_empty()
        }
        None => false,
    };
    if empty {
        g.remove(ip);
    }
}

/// 只有 IP 没有句柄时用（gh_defuse 从响应头拿到的是 IP）：查到 id 交 drop_h2_id 摘除。
pub fn drop_h2(ip: &str) {
    let id = {
        let g = lock(conn_pool());
        g.get(ip).and_then(|h| h.conns.first()).map(|c| c.up.id)
    };
    if let Some(id) = id {
        drop_h2_id(ip, id);
    }
}

/// 池中该组 IP 已占用的地址(供拨号 skip:两条通道不落同一地址)。
fn occupied_ips(ips: &[String]) -> Vec<String> {
    let g = lock(conn_pool());
    ips.iter()
        .filter(|ip| g.contains_key(ip.as_str()))
        .cloned()
        .collect()
}

/// 首条建好后后台补第二条：skip 池中活连接占用的 IP，游标用副键。
/// 后台执行时点边状态可能已翻转：全黑（targets 空）直接放弃，绝不能索引越界。
pub fn maybe_spawn_second(host: &str, log: &LogFn) {
    if session_host(host) {
        return; // 会话域单通道：补第二条 = 把同一会话拆到第二个 IP 上
    }
    let Some(targets) = pool::route::dial_targets(host) else {
        return;
    };
    if targets.is_empty() {
        return; // 全黑：补连无从谈起
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    {
        let mut g = lock(conn_pool());
        // 任一候选 IP 已有两条或正在补 → 不动；全部单条/空 → 需要补。
        let full = ips.iter().any(|ip| {
            g.get(ip)
                .is_some_and(|h| h.conns.len() >= MAX_CONNS_PER_IP || h.filling)
        });
        let has_two = ips
            .iter()
            .filter_map(|ip| g.get(ip))
            .map(|h| h.conns.len())
            .sum::<usize>()
            >= MAX_CONNS_PER_IP;
        if full || has_two {
            return;
        }
        // 没有第二个"未占用"的候选 IP 就不补：同一 IP 再开一条只是多一次握手，
        // 慢 IP 上还会把两份超时叠起来（原本单通道等 3s，凑两条等 6s）。
        if !ips.iter().any(|ip| !g.contains_key(ip.as_str())) {
            return;
        }
        // 挑池中已有的那条所在 IP 记 filling（防重入）；全空则记首个。
        let anchor = ips
            .iter()
            .find(|ip| g.contains_key(ip.as_str()))
            .cloned()
            .unwrap_or_else(|| ips[0].clone());
        if let Some(h) = g.get_mut(&anchor) {
            if h.filling {
                return;
            }
            h.filling = true;
        } else {
            g.entry(anchor).or_default().filling = true;
        }
    }
    let skip = occupied_ips(&ips);
    let host = host.to_string();
    let log = log.clone();
    tokio::spawn(async move {
        match h2_dial_slot(&host, &log, &skip, 2, None).await {
            Ok(up) => {
                let ip = up.ip.clone();
                store_h2(&ip, up)
            }
            Err(e) => {
                (log)(&format!("[上游] {host} 第二条连接失败({e}), 保持单连接"));
                let mut g = lock(conn_pool());
                for ip in &ips {
                    if let Some(h) = g.get_mut(ip) {
                        h.filling = false;
                    }
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
    .map_err(|_| {
        format!(
            "h2 握手超时({}s): {host}",
            crate::config::H2_HANDSHAKE_TIMEOUT_SECS
        )
    })?
    .map_err(|e| format!("h2 握手失败: {e}"))?;
    let ping = conn
        .ping_pong()
        .map(|p| Arc::new(tokio::sync::Mutex::new(p)));
    tokio::spawn(async move {
        let _ = conn.await; // 连接驱动：帧收发/GOAWAY 处理, 结束即连接死亡
    });
    // 第二通道在行尾标出;主通道与单发保持原样,免日志噪音。
    let chan = if slot > 1 {
        format!(", 通道{slot}")
    } else {
        String::new()
    };
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

/// 单通道拨号：串发选 IP → boring 握手（SNI 骗墙，证书按锚点校验）→ h2。
async fn h2_dial_slot(
    host: &str,
    log: &LogFn,
    skip_ips: &[String],
    slot: u8,
    crew: Option<&pool::DialCrew>,
) -> Result<H2Upstream, String> {
    let (conn_io, ip, sni) = pool::serial_dial_skip(
        pool::DialSkip {
            host,
            tls_handshake: true,
            skip_ips,
            slot,
            crew,
        },
        Some(log),
    )
    .await
    .map_err(|e| e.to_string())?;
    let form = if sni.is_empty() || sni == host {
        "真名"
    } else {
        "伪装"
    };
    h2_from_dialed(host, conn_io, &ip, form, slot, log).await
}

/// 双通道冷启动并行竞速：各领各的游标、跳过对方正在试的 IP，先成者服务、晚成者入库。
async fn dial_h2_race(host: &str, log: &LogFn) -> Result<H2Upstream, String> {
    let crew = pool::DialCrew::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<H2Upstream, String>>(4);
    // 会话域只发一条（同会话不跨 IP）；内容域要有第二个不同 IP 才发两条。
    // 候选只剩一家时凑双通道 = 同一 IP 握手两次、超时也等两份，比单通道更慢。
    let distinct = pool::route::dial_targets(host).map_or(0, |t| t.len());
    let slots: &[u8] = if session_host(host) || distinct < 2 {
        (log)(&format!("[建连] {host} 单通道(可用候选 {distinct} 家)"));
        &[1]
    } else {
        (log)(&format!("[建连] {host} 冷启动竞速发射"));
        &[1, 2]
    };
    for &slot in slots {
        let tx = tx.clone();
        let host = host.to_string();
        let log = log.clone();
        let crew = crew.clone();
        tokio::spawn(async move {
            match h2_dial_slot(&host, &log, &[], slot, Some(&crew)).await {
                Ok(up) => {
                    store_h2(&up.ip, up.clone());
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
    // 收尾移交后台：晚成者已在拨号任务里自入库；只有「一成一败」才值得补建第二条。
    // 全败时补建必再失败（IP 刚判死），只会白刷一条"第二条连接失败"。
    let host = host.to_string();
    let log = log.clone();
    tokio::spawn(async move {
        let mut any_ok = false;
        let mut any_err = false;
        while let Some(r) = rx.recv().await {
            match r {
                Ok(_) => any_ok = true,
                Err(_) => any_err = true,
            }
        }
        if any_ok && any_err {
            maybe_spawn_second(&host, &log);
        }
    });
    Ok(won)
}

/// 全局"正在拨"登记：IP → 认领时刻。多个 host 的候选组重叠时，后到的等先到的出结果再复用，
/// 而不是各自拨一条——同一会话被拆到多个 IP，是风控最容易抓的破绽。
static INFLIGHT: std::sync::OnceLock<Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::OnceLock::new();
static INFLIGHT_DONE: tokio::sync::Notify = tokio::sync::Notify::const_new();
/// 等别人拨号的上限：对端拨得慢也不能把请求挂住，超时自己拨。
const INFLIGHT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn inflight_map() -> &'static Mutex<HashMap<String, std::time::Instant>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

fn inflight_busy(ips: &[String]) -> bool {
    let g = lock(inflight_map());
    ips.iter().any(|ip| g.contains_key(ip))
}

/// 认领这批 IP 的拨号权；Drop 时注销并叫醒等待者（成功入池、失败退出都走）。
struct DialingGuard {
    ips: Vec<String>,
}

impl DialingGuard {
    fn claim(ips: &[String]) -> Self {
        let now = std::time::Instant::now();
        let mut g = lock(inflight_map());
        for ip in ips {
            g.insert(ip.clone(), now);
        }
        Self { ips: ips.to_vec() }
    }
}

impl Drop for DialingGuard {
    fn drop(&mut self) {
        {
            let mut g = lock(inflight_map());
            for ip in &self.ips {
                g.remove(ip);
            }
        }
        INFLIGHT_DONE.notify_waiters();
    }
}

/// 等这批 IP 上的在拨拨号结束；true = 等过（调用方应回头查池再决定）。
async fn wait_inflight(ips: &[String]) -> bool {
    let deadline = std::time::Instant::now() + INFLIGHT_WAIT;
    let mut waited = false;
    while inflight_busy(ips) {
        waited = true;
        if std::time::Instant::now() >= deadline {
            return waited;
        }
        tokio::select! {
            _ = INFLIGHT_DONE.notified() => {}
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
    }
    waited
}

/// 建连统一入口：候选全空走竞速（两个两个建），其余单发（单发也跳过池中占用的 IP）。
/// 串发全灭冷却中直接快速失败：调用方走兜底（镜像/DNS），绝不空转重试刷屏。
pub async fn dial_upstream(host: &str, log: &LogFn) -> Result<(H2Upstream, bool), String> {
    if pool::dial_cool_open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let targets =
        pool::route::dial_targets(host).ok_or_else(|| format!("域名不在路由表({host})"))?;
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走 fallback"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    // 支路：别的 host 正在拨同组 IP，先等它出结果——成了直接复用，不重复拨。
    if wait_inflight(&ips).await {
        if let Some(up) = cached_h2_in(&ips, None) {
            return Ok((up, false)); // 池中已有（对方入的库），无需再存
        }
    }
    if occupied_ips(&ips).is_empty() {
        let _claim = DialingGuard::claim(&ips);
        let up = dial_h2_race(host, log).await?;
        return Ok((up, false)); // 竞速任务内部已入库
    }
    let skip = occupied_ips(&ips);
    let _claim = DialingGuard::claim(&ips);
    let up = h2_dial_slot(host, log, &skip, 1, None).await?;
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
/// 每路由拨号单飞闸：并发未命中只放一个进串发拨号（无闸时一波 27 条全新拨号，握手风暴触发边缘限流）。
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
