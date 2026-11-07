//! 上游 HTTP 客户端：直连腿 = boring 指纹自管 h2 连接（fresh 语义）；镜像腿 = 标准 TLS + h1 共享池。
//! 通道池的记账、挑选、开流全在本文件：池只有一个口径，选和用不另设管理层。
use super::protocol::{empty_body, BoxBody};
use crate::pool::{self, dial::Dialed};
use crate::util::{lock, now_ms, LogFn};
use bytes::Bytes;
use h2::client::SendRequest;
use http::{Request, Uri};
use http_body_util::BodyExt;
use hyper::Response;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower_service::Service;
/// 池按 IP 记账：一条连接可被该 IP 服务着的所有路由键共用（v2 复用单元 = IP）。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    /// 进程内唯一：同一 IP 若将来有多条连接，摘除时也才能精确到条、不删错。
    /// 连接驱动结束时靠它把自己从池里摘掉（对端回收空闲连接时不留僵尸）。
    pub id: u64,
    /// 游标槽位：1 主通道、2 副通道，记账跟着连接走，各记各的钥匙。
    pub slot: u8,
    /// 建这条连接时用的 host。会话域靠它认出"自己的通道"：优先复用它，
    /// 而不是额度还没建就连别人的公共通道。
    pub owner: Option<String>,
    /// 服务端在 SETTINGS 里下发的并发上限（`MAX_CONCURRENT_STREAMS`）。
    pub max_streams: u32,
    /// 当前在途流数：发请求 +1、流收尾 -1。选路按"占用率 × 延迟"挑最闲且最快的。
    pub inflight: Arc<AtomicU32>,
    /// 会话域按需 ping 的入口：发一个 oneshot 回执端过去，驱动任务 ping 完回 bool。
    /// 内容域通道不做任何健康检查，恒为 None。
    pub ping_tx: Option<tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<bool>>>,
    send: SendRequest<Bytes>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 最近响应耗时（EWMA）：跨 IP 的两条通道可能一快一慢，轮转会把请求喂给慢的。
pub(crate) struct ConnSlot {
    pub(crate) up: H2Upstream,
    pub(crate) ewma: f64,
    n: u32,
    /// 这条连接自己最后一次被使用（开流刷新）；批窗与 ping 闸的空闲期按它算。
    last_used: u64,
}

/// 单 IP 的连接组。
#[derive(Default)]
pub(crate) struct IpConns {
    pub(crate) conns: Vec<ConnSlot>,
}


/// 同一个 IP 永远只允许一条 h2 连接。要开第二条通道只能落在另一个 IP 上。
/// 这是硬约束：无论多少个 host 同时拨到同一个 IP，入库时只留第一条，其余当场丢弃。
const MAX_CONNS_PER_IP: usize = 1;

/// 拨号成功但耗时超过此值 = 撞上 GFW 抖动：延迟表记实测，游标挪窝别黏住慢 IP。
const DIAL_SLOW_MS: u64 = 1500;

/// 这个错误重试没有意义：候选都被已有通道占着，
/// 换候选、再来一轮都是同一句话。上层看到它直接交兜底，别原地刷屏。
pub const ERR_NO_FREE_IP: &str = "候选均已有通道";

/// host 三类：
/// - 内容域：双通道，池里按"空闲且快"选。
/// - 会话域：单通道单 IP，建连优先自己拨一条，不蹭公共通道（带会话，跨 IP 是风控特征）。
/// - 其他（大文件、docs/agent）：单通道，复用现成的优先，自建只是兜底——
///   它们不维护长期会话，没必要占一条专属通道。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HostClass {
    Content,
    Session,
    Other,
}

/// 归「其他」的 github.com 子域：单通道、复用优先，不值得养一条专属通道。
/// 前十个只去 Fastly 边缘、不走主站（docs/CONFIG.md 实测表，2026-11-03 全量测绘），
/// 拿主站 IP 去拨是白试；后两个是超低频入口（上传附件、MCP 调用），
/// 长期吃灰的通道不如直接蹭一条热的。
const REUSE_FIRST_HOSTS: &[&str] = &[
    "docs.github.com",
    "support.github.com",
    "resources.github.com",
    "desktop.github.com",
    "pages.github.com",
    "skills.github.com",
    "archiveprogram.github.com",
    "socialimpact.github.com",
    "raw.github.com",
    "agent.github.com",
    "uploads.github.com",
    "api.mcp.github.com",
];

fn is_other_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    REUSE_FIRST_HOSTS.contains(&h.as_str())
}

pub(crate) fn host_class(host: &str) -> HostClass {
    // 大文件域虽然挂着 content 标记（走镜像链），但不再开第二条腿：
    // 一条长流就能把槽位占满，两条反而互相抢带宽。
    if pool::route::is_big_file_host(host) || is_other_host(host) {
        return HostClass::Other;
    }
    if pool::route::is_content(host) {
        return HostClass::Content;
    }
    // 会话域按风控面划界：拦截页(Whoa)实测只出现在主站族(github.com / api.github.com /
    // *.github.com)，只有它们配长期通道 + ping 闸。其余(githubassets / github.io /
    // githubapp / codeload…)的数据不是主站，一律批窗内容域语义(单通道变体)——
    // 否则 githubassets 的长寿命通道会把 185.199.154/215 这 8 个三类横跨的共享 IP
    // 从内容域的可拨池里长期占走。按路由键判而非域名后缀，codeload.github.com
    // 这类独立行才不会被通配误捞回会话。
    let session_keys = ["github.com", "*.github.com", "api.github.com"];
    let on_risk_surface = pool::route::route_for(host)
        .is_some_and(|row| session_keys.contains(&row.key.as_str()));
    if on_risk_surface {
        HostClass::Session
    } else {
        HostClass::Other
    }
}

/// 是否开双通道（批模型下通道总数上限 = 本批的主副两条腿，不再单独记账）：
/// 双通道把页面的并发流摊到两条连接上——单连接 24 并发实测全部同一时刻返回
/// （p50 1036ms），两条压到 332ms。
fn dual_channel(host: &str) -> bool {
    host_class(host) == HostClass::Content
}

/// 会话域：建连时自建优先，连上了再复用自己那条。
pub(crate) fn prefer_own_channel(host: &str) -> bool {
    host_class(host) == HostClass::Session
}

static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, IpConns>>> = std::sync::OnceLock::new();
pub(crate) fn conn_pool() -> &'static Mutex<HashMap<String, IpConns>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

/// 批窗外通道的就地除名（请求驱动，无定时器）：本 host 候选 IP 里，空闲（无在途流）
/// 且最后使用已过批窗的连接，当场按 id 摘除。「下批重建」的批界由此落地——过窗通道
/// 不先摘掉，`store_h2` 会把新拨的当场作废、把旧通道塞回手里，拨号订单也会被
/// 「已有通道」驳回。会话域自己的通道不在此列（归 ping 闸验活）；睡眠唤醒也不再需要
/// 专门机制：醒来后所有通道都过了窗，第一个请求自然清场。
pub(crate) fn evict_stale(ips: &[String]) {
    let stale: Vec<(String, u64)> = {
        let g = lock(conn_pool());
        ips.iter()
            .filter_map(|ip| {
                let h = g.get(ip.as_str())?;
                h.conns
                    .iter()
                    .find(|c| {
                        // 在途流 > 0 说明正在干活：长下载的 last_used 停在开流时刻，
                        // 不能按空闲论处。会话域通道由 ping 闸负责，批窗摘除永远跳过。
                        c.up.inflight.load(std::sync::atomic::Ordering::Relaxed) == 0
                            && !c.up.owner.as_deref().is_some_and(prefer_own_channel)
                            && now_secs().saturating_sub(c.last_used)
                                > crate::config::REUSE_WINDOW_SECS
                    })
                    .map(|c| (ip.clone(), c.up.id))
            })
            .collect()
    };
    for (ip, id) in stale {
        drop_h2_id(&ip, id);
    }
}

/// 响应头预算超时：上层按它区分"真等超了"和别的失败。
pub const ERR_BUDGET_TIMEOUT: &str = "响应预算超时";

/// 门房公式：在给定 IP 集合里挑活连接——占用率 × 延迟，最闲且最快的胜出。
/// only_owner = 会话域只认自己建的通道；want_slot = 搜索路径固定骑主通道。
pub(crate) fn pick(
    ips: &[String],
    want_slot: Option<u8>,
    only_owner: Option<&str>,
) -> Option<H2Upstream> {
    let mut g = lock(conn_pool());
    // (分数, 是否顶到并发上限, 连接)
    let mut cands: Vec<(f64, bool, H2Upstream)> = Vec::new();
    for ip in ips {
        let Some(h) = g.get_mut(ip) else { continue };
        for c in &h.conns {
            if let Some(want) = want_slot {
                if c.up.slot != want {
                    continue;
                }
            }
            if let Some(owner) = only_owner {
                if c.up.owner.as_deref() != Some(owner) {
                    continue;
                }
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            // 占用率 × 延迟：闲着又快的分最小；都忙时也自然挑"最快腾出槽位"的那条。
            // 还没发过请求的连接 ewma=0，用 1ms 兜底，免得白捡成永远第一。
            let ewma = if c.ewma > 0.0 { c.ewma } else { 1.0 };
            let score = (inflight as f64 + 1.0) / cap as f64 * ewma;
            cands.push((score, inflight >= cap, c.up.clone()));
        }
    }
    if cands.is_empty() {
        return None;
    }
    // 优先没顶到上限的；全满时才按分数排在队首那条（h2 自己会在服务端配额上排队）。
    let any_free = cands.iter().any(|c| !c.1);
    let pick = cands
        .iter()
        .enumerate()
        .filter(|(_, c)| !any_free || !c.1)
        .min_by(|a, b| a.1.0.total_cmp(&b.1.0))
        .map_or(0, |(i, _)| i);
    Some(cands.remove(pick).2)
}

/// 门房开流：把请求递进通道。字节不过这里——hyper 的泵直接在请求体/响应体与
/// socket 之间搬运，本层加一跳都不该加；每次开流顺带刷新这条连接的空闲期。
pub async fn stream_on(
    up: &H2Upstream,
    out: &Request<BoxBody>,
    body: &Option<Bytes>,
    budget: Duration,
) -> Result<(Response<BoxBody>, u64), String> {
    let t0 = Instant::now();
    match tokio::time::timeout(budget, h2_send(up, out, body)).await {
        Ok(r) => r.map(|resp| (resp, t0.elapsed().as_millis() as u64)),
        Err(_) => Err(ERR_BUDGET_TIMEOUT.to_string()),
    }
}

/// 会话域取用闸：闲置超过阈值的通道先 ping 验活——活着直接复用（同 IP 保住会话，
/// 风控面不漂移），死了当场摘掉返回 None，调用方走拨号（游标钉着原 IP，重拨落回原家）。
/// ping 由连接驱动任务代答（PingPong 只有 poll conn 的人能驱动），本侧另设兜底超时：
/// 驱动已死/卡死时通道同样判死，绝不挂住取用路径。
pub(crate) async fn session_pick(
    host: &str,
    ips: &[String],
    want_slot: Option<u8>,
) -> Option<H2Upstream> {
    let up = pick(ips, want_slot, Some(host))?;
    let idle = conn_idle_secs(&up.ip, up.id).unwrap_or(u64::MAX);
    if idle < crate::config::SESSION_PING_GATE_SECS {
        return Some(up); // 刚用过的连接：零额外延迟，直接信
    }
    let Some(tx) = &up.ping_tx else {
        return Some(up); // 无 ping 端（理论不可达）：按旧语义放行，失败由请求路径兜底
    };
    let (rtx, rrx) = tokio::sync::oneshot::channel();
    let alive = if tx.send(rtx).await.is_err() {
        false // 驱动任务已不在：通道必死
    } else {
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(crate::config::SESSION_PING_TIMEOUT_SECS + 1),
                rrx,
            )
            .await,
            Ok(Ok(true))
        )
    };
    if alive {
        Some(up)
    } else {
        drop_h2_id(&up.ip, up.id);
        None
    }
}

/// 在给定 IP 集合里取活连接：按「占用率 × 延迟」挑最闲且最快的那条（公式在 keeper 层）。
pub fn cached_h2_in(ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, None)
}

/// 会话域取用：**只认这个 host 自己建的通道**。没有就返回 None，让调用方去自建。
/// 自建不出来时的兜底复用放在拨号链路末尾（`cached_h2_in`），不在入口抢跑——
/// 自己拨一条并不慢，但一上来就蹭公共通道会跟一堆 host 抢同一条 h2 的流窗口。
pub fn cached_h2_own(host: &str, ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, Some(host))
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

/// 新连接入库的唯一入口：同一把锁里保证每个 IP 只有一条通道。
/// 该 IP 已有连接时，新拨的这条当场作废（句柄 drop 即关掉那条 TCP），返回池里现成的那条。
/// 调用方必须改用返回的连接发请求——继续用自己手里那条，就等于绕过约束并存两条。
pub fn store_h2(ip: &str, up: H2Upstream) -> H2Upstream {
    let mut g = lock(conn_pool());
    let h = g.entry(ip.to_string()).or_default();
    if h.conns.len() >= MAX_CONNS_PER_IP {
        return h.conns[0].up.clone();
    }
    let keep = up.clone();
    h.conns.push(ConnSlot {
        up,
        ewma: 0.0,
        n: 0,
        last_used: now_secs(),
    });
    keep
}

/// 按连接 id 精确摘除：同 IP 两条连接靠 IP 分不开，删错会把健康的摘掉。
pub fn drop_h2_id(ip: &str, id: u64) {
    let mut g = lock(conn_pool());
    match g.get_mut(ip) {
        Some(h) => {
            if let Some(pos) = h.conns.iter().position(|c| c.up.id == id) {
                h.conns.remove(pos);
            }
            if h.conns.is_empty() {
                g.remove(ip);
            }
        }
        None => {}
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

/// 池中该组 IP 里**已经有活连接**的地址(供拨号 skip:同一个 IP 不再拨第二次)。
/// 全仓"这个 IP 有没有通道"的唯一口径：拨号预检与双通道 skip 都从这里取。
pub(crate) fn occupied_ips(ips: &[String]) -> Vec<String> {
    let g = lock(conn_pool());
    ips.iter()
        .filter(|ip| g.get(ip.as_str()).is_some_and(|h| !h.conns.is_empty()))
        .cloned()
        .collect()
}

/// 这条连接还在池里吗？在 → 返回它自己的空闲秒数（会话域 ping 闸按它决定要不要验活）。
fn conn_idle_secs(ip: &str, id: u64) -> Option<u64> {
    let g = lock(conn_pool());
    g.get(ip)?
        .conns
        .iter()
        .find(|c| c.up.id == id)
        .map(|c| now_secs().saturating_sub(c.last_used))
}

/// 一条连接 = 一个任务。它只干两件事：持续 poll conn 让 h2 帧收发活着（这是 h2 协议
/// 的硬要求，不是保活），以及连接结束时把自己从池里摘掉。
///
/// 通道不再是需要续命的资产：内容域没有定时器、没有 PING——死没死由请求结果说了算，
/// 批窗外的通道由 `evict_stale` 在取用时惰性清场，还挂在池里的由边缘 50-65s 空闲回收
/// 收尾（对端关连接时 conn.await 返回，这里自摘）。会话域额外挂一个按需 ping 的应答
/// 端：取用闸要验活时发一个 oneshot 过来，这里代答。所有出口都按 id 自摘并撤销
/// 「已有通道」登记；不做任何补拨——通道重建是下一批请求自己的事。
struct ConnDriver<T> {
    ip: String,
    id: u64,
    conn: h2::client::Connection<T, Bytes>,
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
    /// 会话域才有：取用闸的 ping 请求队列；全部发送端释放后退化为纯 conn 模式。
    ping_rx: Option<tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<bool>>>,
    log: LogFn,
}

fn spawn_conn_driver<T>(d: ConnDriver<T>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ConnDriver {
        ip,
        id,
        conn,
        ping,
        mut ping_rx,
        log,
    } = d;
    tokio::spawn(async move {
        let mut conn = Box::pin(conn);
        let why: &str = 'keep: loop {
            // 先把 ping 端从 Option 里取出来再等：recv 到 None（全部 H2Upstream 句柄
            // 已释放）就不再放回，下一轮退化为纯 conn 模式；代答完再原样还回去。
            // 取出/还回都发生在 select 之外，避开「future 借着 rx 时移动 rx」的借用冲突。
            let mut rx = match ping_rx.take() {
                Some(rx) => rx,
                None => {
                    let _ = (&mut conn).await;
                    break 'keep "对端关闭";
                }
            };
            enum Step {
                ConnEnd,
                Ping(Option<tokio::sync::oneshot::Sender<bool>>),
            }
            let step = tokio::select! {
                _ = &mut conn => Step::ConnEnd,
                req = rx.recv() => Step::Ping(req),
            };
            match step {
                Step::ConnEnd => break 'keep "对端关闭",
                Step::Ping(None) => continue, // ping 端已空：下一轮走纯 conn
                Step::Ping(Some(reply)) => {
                    let Some(pp) = &ping else {
                        let _ = reply.send(false);
                        ping_rx = Some(rx);
                        continue;
                    };
                    // PONG 靠 conn 被 poll 才收得到，所以等 PONG 时 conn 仍要在同一个
                    // select 里跑；连接恰在此刻断开就当场收摊（reply 随 drop 关闭，
                    // 取用闸按「通道已死」处理）。
                    let pong = async {
                        let mut guard = pp.lock().await;
                        tokio::time::timeout(
                            std::time::Duration::from_secs(
                                crate::config::SESSION_PING_TIMEOUT_SECS,
                            ),
                            guard.ping(h2::Ping::opaque()),
                        )
                        .await
                    };
                    let ponged = tokio::select! {
                        _ = &mut conn => None,
                        r = pong => Some(r),
                    };
                    match ponged {
                        None => break 'keep "对端关闭",
                        Some(r) => {
                            let _ = reply.send(matches!(r, Ok(Ok(_))));
                            ping_rx = Some(rx); // 还回去，下一轮继续听
                        }
                    }
                }
            }
        };
        // 唯一出口：连接结束（对端关闭/回收/错误）。把自己从池里摘掉；
        // 已被 evict_stale 先摘过的，这里 no-op。不做任何补拨——通道重建是
        // 下一批请求自己的事。
        drop_h2_id(&ip, id);
        log(&format!("[通道] {ip}#{id} 断开出池({why})"));
    });
}

pub async fn h2_from_dialed(
    host: &str,
    conn_io: Dialed,
    ip: &str,
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
    // 会话域才有按需 ping：内容域通道不做任何健康检查，PingPong 和应答端整个省掉。
    let session = host_class(host) == HostClass::Session;
    let ping = if session {
        conn.ping_pong()
            .map(|p| Arc::new(tokio::sync::Mutex::new(p)))
    } else {
        None
    };
    // 服务端在 SETTINGS 里说了它一条连接能接多少流，照着用，不替它猜数字。
    let max_streams = conn.max_concurrent_send_streams().max(1) as u32;
    // id 建连时就定下：驱动任务带着它，连接一断就能精确摘自己那一条。
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (ping_tx, ping_rx) = if session {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    // 从此这条连接归它自己的任务管：驱动帧收发、按需代答 ping、断开自摘。
    spawn_conn_driver(ConnDriver {
        ip: ip.to_string(),
        id,
        conn,
        ping,
        ping_rx,
        log: log.clone(),
    });
    Ok(H2Upstream {
        ip: ip.to_string(),
        id,
        slot,
        owner: Some(host.to_string()),
        max_streams,
        inflight: Arc::new(AtomicU32::new(0)),
        ping_tx,
        send,
    })
}

/// 单通道拨号：串发选 IP → boring 握手（SNI 骗墙，证书按锚点校验）→ h2。
pub(crate) async fn h2_dial_slot(
    host: &str,
    log: &LogFn,
    skip_ips: &[String],
    slot: u8,
    crew: Option<&pool::DialCrew>,
    prefer_shared: Option<bool>,
) -> Result<H2Upstream, String> {
    let t_dial = std::time::Instant::now();
    let (conn_io, ip, sni) = pool::serial_dial_skip(
        pool::DialSkip {
            host,
            tls_handshake: true,
            skip_ips,
            slot,
            crew,
            prefer_shared,
        },
        Some(log),
    )
    .await
    .map_err(|e| e.to_string())?;
    let dial_ms = t_dial.elapsed().as_millis();
    // 运行时延迟回流：实测建连用时进排序表（内存态），慢 IP 自动沉底；
    // 撞上 GFW 抖动（慢成功）时游标挪窝，别让"上次成功"把一页请求都黏在慢 IP 上。
    pool::latency::note(&ip, dial_ms as u64);
    if dial_ms as u64 >= DIAL_SLOW_MS {
        pool::cursor_note(host, &ip, false, slot);
    }
    let form = if sni.is_empty() || sni == host {
        "真名"
    } else {
        "伪装"
    };
    let t_h2 = std::time::Instant::now();
    // h2 谈不成（TCP+TLS 都过、SETTINGS 不回）也是"这个 IP 现在建不成通道"：
    // 进全局死亡退避，别 host 的串发直接跳过，不再对着同一个 IP 重复付 5s。
    let up = h2_from_dialed(host, conn_io, &ip, slot, log)
        .await
        .map_err(|e| {
            pool::note_dead(&ip);
            e
        })?;
    let h2_ms = t_h2.elapsed().as_millis();
    // 顺序不能反：先让池里出现这 IP 唯一的一条连接，调用方拿到手的就是池里那条。
    // 若期间别人已经建好同一个 IP，这里丢弃刚拨的、返回池里那条现成的。
    let up = store_h2(&ip, up);
    // 分段计时落一行：慢在拨号(TCP+TLS)还是 h2 握手，一眼可辨。
    let chan = if slot > 1 {
        format!(", 通道{slot}")
    } else {
        String::new()
    };
    (log)(&format!(
        "[上游] {host} <- {ip} ({form}SNI 直连, h2{chan}, 拨{dial_ms}ms+握手{h2_ms}ms)"
    ));
    Ok(up)
}

/// 单通道的原因：会话域/大文件是规则（候选再多也不开第二条），候选不足是没得选。
/// 分开写是为了不出现「26 家候选却单通道」这种看不懂的日志。
fn single_channel_reason(class: HostClass, _distinct: usize, free: usize) -> String {
    match class {
        HostClass::Session => "会话域固定同一 IP, 不开第二条(防风控)".to_string(),
        HostClass::Other => "大文件/文档站: 单通道, 复用优先".to_string(),
        HostClass::Content => format!("可用候选仅 {free} 家, 不够开第二条"),
    }
}

/// 这一轮发哪几条腿：主通道只管开新坑，副通道多一步「先看有没有现成的可捡」。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegPlan {
    /// 主通道：还有没被已有通道占用的 IP 就发，串发新建。
    pub primary: bool,
    /// 副通道拨号：没有现成通道可捡、且还剩两个以上空 IP 才发。
    pub vice_dial: bool,
    /// 副通道复用：本 host 候选里已有现成通道，直接拿来用，不拨号。
    pub vice_reuse: bool,
}

/// 纯计算，把「主副分工」钉死：
/// - 会话域不设副通道（同会话跨 IP 是风控特征）；
/// - 有空 IP 才发主通道；
/// - 副通道优先复用；没有现成的、且空 IP 够两家，才再发一条去拨。
pub(crate) fn plan_legs(session: bool, free: usize, reusable: bool) -> LegPlan {
    LegPlan {
        primary: free > 0,
        vice_dial: !session && !reusable && free >= 2,
        vice_reuse: !session && reusable,
    }
}

/// 双通道建连：主通道串发开新 IP，副通道起跑前先查「本 host 候选 ∩ 已有通道」，
/// 有现成的直接复用（请求不用等握手），没有才跟主通道一样串发。
/// 两条腿共享 crew：同一个 IP 只由一条腿试，绝不重复。
/// 返回的 bool：这条连接是不是**池里现成的**（而不是本轮刚拨出来的）。
/// 上层要靠它区分「旧连接死了」和「这个 IP 不行」，两者处置完全不同。
async fn dial_h2_race(
    host: &str,
    log: &LogFn,
    occupied: &[String],
    allow_reuse: bool,
) -> Result<(H2Upstream, bool), String> {
    let crew = pool::DialCrew::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<(H2Upstream, bool), String>>(4);
    let targets = pool::route::dial_targets(host).unwrap_or_default();
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    let distinct = ips.len();
    // 已有通道占掉的 IP 不再拨：主副两条腿都跳过，这是「更严格的主副通道」的底线。
    let free = distinct.saturating_sub(occupied.len());
    // 单通道判定：内容域之外都是。即使只剩一家，原因也按规则算，不误报成「候选不足」。
    let single = !dual_channel(host);
    // 副通道的「先查表」：只在这个 host 自己的候选里找现成通道；
    // 别的 host 能用、但不在本 host 候选里的，不算数。
    // 流式请求（allow_reuse=false）不许捡：body 发出去就收不回，只能走确定属于它的新连接。
    let reusable = if single || !allow_reuse {
        None
    } else {
        cached_h2_in(&ips, None)
    };
    let legs = plan_legs(single, free, reusable.is_some());

    let mut launched = 0usize;
    // 一条腿 = 一个拨号任务：串发选 IP → h2 握手 → 入库，结果回执 tx。
    let dial_leg = |slot: u8, prefer_shared: Option<bool>, tx: tokio::sync::mpsc::Sender<Result<(H2Upstream, bool), String>>| {
        let host = host.to_string();
        let log2 = log.clone();
        let skip = occupied.to_vec();
        let crew2 = crew.clone();
        tokio::spawn(async move {
            let r = h2_dial_slot(&host, &log2, &skip, slot, Some(&crew2), prefer_shared)
                .await
                .map(|up| (up, true));
            let _ = tx.send(r).await;
        });
    };
    if legs.vice_reuse {
        if let Some(up) = reusable {
            // 先把现成的交上去：调用方立刻能发请求，主通道在后台慢慢拨。
            let _ = tx.send(Ok((up, true))).await;
            (log)(&format!(
                "[建连] {host} 复用现成通道{}",
                if legs.primary {
                    ", 主通道另起一条"
                } else {
                    ""
                }
            ));
            launched += 1;
        }
    }
    if legs.primary {
        // 主通道：独占档在前（独占用尽才轮到共享），游标用主键。
        dial_leg(1, Some(false), tx.clone());
        launched += 1;
    }
    if legs.vice_dial {
        // 副通道：共享档在前（没得捡才自己拨），游标用 _vice 副键。
        dial_leg(2, Some(true), tx.clone());
        launched += 1;
    }
    if launched == 0 {
        // 一条腿都发不出去：可能空 IP 用完了，也可能会话域本来就不设副通道。
        // 这时池里若已有本 host 候选的连接就直接用——把"已有通道"判成失败，
        // 上层只会拿同一句话重试到死（实测 api.github.com 连刷 24 行）。
        if allow_reuse {
            if let Some(up) = cached_h2_in(&ips, None) {
                return Ok((up, true));
            }
        }
        return Err(format!("{host} {ERR_NO_FREE_IP}, 请重查连接池"));
    }
    drop(tx);
    // 两条腿同时拨 = 一次等待把两条容量通道都建好；只发主通道时说清为什么单通道。
    if legs.primary && legs.vice_dial {
        (log)(&format!("[建连] {host} 主副双通道同时开建"));
    } else if legs.primary && !legs.vice_reuse {
        (log)(&format!(
            "[建连] {host} 单通道({})",
            single_channel_reason(host_class(host), distinct, free)
        ));
    }
    // 等第一个成功;两个全败则整组失败
    let mut last: Option<String> = None;
    let won = loop {
        match rx.recv().await {
            Some(Ok(up)) => break up,
            Some(Err(e)) => last = Some(e),
            None => {
                // 候选全试完才看现成的：会话域宁可自己拨，也不要一上来就蹭公共通道；
                // 但真拨不出来时，有一条能用的总比整组失败好。
                if allow_reuse {
                    if let Some(up) = cached_h2_in(&ips, None) {
                        return Ok((up, true));
                    }
                }
                return Err(last.unwrap_or_else(|| "并行建连全败".into()));
            }
        }
    };
    // 晚成腿的收尾：连接已在拨号任务内自入库（store_h2），这里不再等待也不再补建——
    // 批模型下通道重建是下一批请求自己的事，一成一败就本批单通道跑。
    // rx 就地丢弃：dialer 的回执发送对已关闭的通道是 no-op（let _ = tx.send），无副作用。
    drop(rx);
    Ok(won)
}

/// 建连统一入口：主通道串发开新 IP，副通道先查交集、能复用就复用。
/// 两条腿都跳过本 host 候选里已有通道的 IP，所以永远落在不同 IP 上。
/// 串发全灭冷却中直接快速失败：调用方走兜底（镜像/DNS），绝不空转重试刷屏。
pub async fn dial_upstream(
    host: &str,
    log: &LogFn,
    allow_reuse: bool,
) -> Result<(H2Upstream, bool), String> {
    if pool::dial_cool_open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let targets =
        pool::route::dial_targets(host).ok_or_else(|| format!("域名不在路由表({host})"))?;
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走 fallback"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    // 本 host 候选里已经被通道占掉的 IP：主副两条腿都跳过，绝不为这个 host 再拨一条。
    // 同 IP 并发拨不设仲裁：两条都建，入库时 store_h2 按"每 IP 一条"去重，
    // 输家的握手是接受的代价；别的 host 已建好的那家由 skip_ips 绕开。
    let occupied = occupied_ips(&ips);
    let (up, reused) = dial_h2_race(host, log, &occupied, allow_reuse).await?;
    // 两腿都在这一轮处理完了（副腿可能直接复用了现成通道），调用方不必再补第二条。
    // reused 如实交代来源：池里现成的连接失败只能说明它自己死了，不能据此判 IP 不行。
    Ok((up, reused))
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
/// 一条 h2 流的在途计数凭据：建流时 +1，响应体读完或客户端丢弃 body 时 -1。
/// 跟着 body 的生命周期走，异常、取消、提前断开都不会漏归还槽位。
pub struct StreamGuard {
    inflight: Arc<AtomicU32>,
}

impl StreamGuard {
    fn new(inflight: Arc<AtomicU32>) -> Self {
        inflight.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { inflight }
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.inflight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// h2 响应头 future → Response；体逐块即时放窗（不 release 会死锁）。
pub async fn h2_recv_response(
    resp_fut: h2::client::ResponseFuture,
    guard: StreamGuard,
) -> Result<hyper::Response<BoxBody>, String> {
    let resp = resp_fut.await.map_err(|e| format!("h2 响应: {e}"))?;
    let (parts, mut recv) = resp.into_parts();
    let body_stream = futures_util::stream::poll_fn(move |cx| {
        // guard 跟着这条 body 一起活；body 被读完或丢弃时才归还并发槽位。
        let _keep = &guard;
        match recv.poll_data(cx) {
        std::task::Poll::Ready(Some(Ok(chunk))) => {
            let _ = recv.flow_control().release_capacity(chunk.len());
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))))
        }
        std::task::Poll::Ready(Some(Err(e))) => {
            std::task::Poll::Ready(Some(Err(std::io::Error::other(e))))
        }
        std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
        std::task::Poll::Pending => std::task::Poll::Pending,
        }
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
) -> Result<
    (
        h2::client::ResponseFuture,
        h2::SendStream<Bytes>,
        StreamGuard,
    ),
    String,
> {
    // 每次开流刷新这条连接自己的空闲期：批窗与 ping 闸的空闲期按它算。
    {
        let mut g = lock(conn_pool());
        if let Some(h) = g.get_mut(&up.ip) {
            if let Some(c) = h.conns.iter_mut().find(|c| c.up.id == up.id) {
                c.last_used = now_secs();
            }
        }
    }
    let mut send = up.send.clone();
    send = send.ready().await.map_err(|e| format!("h2 流配额: {e}"))?;
    let (fut, stream) = send
        .send_request(h2_request_head(out)?, eos)
        .map_err(|e| format!("h2 发送: {e}"))?;
    // 流真正建出来才计入在途；ready() 之前卡住的配额等待不该占槽位。
    Ok((fut, stream, StreamGuard::new(up.inflight.clone())))
}

pub async fn h2_send(
    up: &H2Upstream,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let has_body = body.as_ref().is_some_and(|b| !b.is_empty());
    let (resp_fut, mut send_stream, guard) = h2_open_stream(up, out, !has_body).await?;
    if has_body {
        send_stream
            .send_data(body.as_ref().unwrap().clone(), true)
            .map_err(|e| format!("h2 请求体: {e}"))?;
    }
    h2_recv_response(resp_fut, guard).await
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
                        "[上游] 请求体转发中止(已发 {sent}B): 客户端读取失败 {e}"
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
                            (log)(&format!("[上游] 请求体转发中止(已发 {sent}B): {e}"));
                            return;
                        }
                    }
                    Some(Ok(_)) => {} // 授予 0：继续等下次窗口唤醒
                    Some(Err(e)) => {
                        (log)(&format!(
                            "[上游] 请求体转发流控窗口错误(已发 {sent}B): {e}"
                        ));
                        return;
                    }
                    None => {
                        (log)(&format!("[上游] 请求体转发: 上游重置流(已发 {sent}B)"));
                        return;
                    }
                }
            }
        }
        let _ = send.send_data(Bytes::new(), true); // 干净收尾: EOS
        (log)(&format!("[上游] 请求体转发完成: {sent}B"));
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
