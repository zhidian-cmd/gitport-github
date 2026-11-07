//! 上游 HTTP 客户端：直连腿 = boring 指纹自管 h2 连接（fresh 语义）；镜像腿 = 标准 TLS + h1 共享池。
//! 通道的记账、挑选、探活、开流全在本文件；取用统一入口是 `pool::get_or_build`
//! （骑池 → 建造 → 溢出，一层管完），请求路径不再各管一段。
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
    /// 溢出临时通道标记：句柄只归触发那次溢出的调用方，pick/通道清单不再外发；
    /// 驱动在它空闲（在途流归零）后的第一个探活拍单方面掐断——用完即焚。
    pub overflow: bool,
    send: SendRequest<Bytes>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 最近响应耗时（EWMA）：跨 IP 的两条通道可能一快一慢，轮转会把请求喂给慢的。
pub(crate) struct ConnSlot {
    pub(crate) up: H2Upstream,
    pub(crate) ewma: f64,
    n: u32,
    /// 这条连接自己最后一次被使用（开流刷新）；探活计时器的闲置期按它算。
    last_used: u64,
}

/// 单 IP 的连接组。
#[derive(Default)]
pub(crate) struct IpConns {
    pub(crate) conns: Vec<ConnSlot>,
}


/// 同 IP 通道上限：会话域恒 1 条（风控面不漂移，全忙骑现有连接排队）；
/// 内容域/其他 3 条——常态 2 条（主副双腿），两条顶满才同 IP 溢出补。
pub(crate) fn max_conns_per_ip(class: HostClass) -> usize {
    match class {
        HostClass::Session => crate::config::MAX_CONNS_SESSION,
        _ => crate::config::MAX_CONNS_CONTENT,
    }
}

/// 拨号成功但耗时超过此值 = 撞上 GFW 抖动：延迟表记实测，游标挪窝别黏住慢 IP。
const DIAL_SLOW_MS: u64 = 1500;

/// host 三类：
/// - 内容域：多通道并存，池里按"空闲且快"选。
/// - 会话域：单通道单 IP，建连优先自己拨一条，不蹭公共通道（带会话，跨 IP 是风控特征）。
/// - 其他（大文件、docs/agent）：单通道，批窗临时通道。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HostClass {
    Content,
    Session,
    Other,
}

/// host 三类全部由 routes.json/seeds.json 的 hosts 标志决定（数据，改类别不用重编译）：
/// - content 标记：内容域（双通道，池里按"空闲且快"选）。
/// - big 标记：大文件域（单通道——一条长流占满槽位，两条互相抢带宽；大镜像链）。
/// - session 标记：会话域（单通道单 IP 长期资产 + ping 闸，只标实测出拦截页的主站族）。
/// - 三个都不标：「其他」——单通道、批窗临时通道，不值得养专属资产。
pub(crate) fn host_class(host: &str) -> HostClass {
    if pool::route::is_big_file_host(host) {
        return HostClass::Other;
    }
    if pool::route::is_content(host) {
        return HostClass::Content;
    }
    // 会话域按风控面划界：拦截页(Whoa)实测只出现在主站族，只有它们配长期通道 + ping 闸。
    // 类别是数据：routes.json/seeds.json 的 hosts 标志 `session` 决定，改类别不用重编译。
    // 内容型的子域不做通配排除——写进 ips 节点的 hosts（写完整即豁免，具体键最长匹配
    // 天然压过通配）。githubassets/github.io/githubapp/codeload 等不标 session——
    // 数据不是主站，批窗内容域语义；否则 githubassets 的长寿命通道会把
    // 185.199.154/215 这 8 个三类横跨的共享 IP 占走。
    let on_risk_surface = pool::route::route_for(host).is_some_and(|row| row.flags.session);
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
            // 溢出临时通道不外发句柄：它只归触发那次溢出的调用方用。
            if c.up.overflow {
                continue;
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

/// 在给定 IP 集合里取活连接：按「占用率 × 延迟」挑最闲且最快的那条（公式在 keeper 层）。
pub fn cached_h2_in(ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, None)
}

/// 会话域取用：**只认这个 host 自己建的通道**。没有就返回 None，让调用方去自建——
/// 一上来就蹭公共通道，等于带会话的请求骑在别人建的连接上，风控面直接漂移。
pub fn cached_h2_own(host: &str, ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, Some(host))
}

/// 候选 IP 集合内**全部**可用通道，按「占用率 × 延迟」升序；溢出临时通道不在列
/// （即取即用的一次品，句柄不再外发）。摊段/批量取通道的调用方用这个。
pub(crate) fn channels_for(ips: &[String]) -> Vec<H2Upstream> {
    let g = lock(conn_pool());
    let mut cands: Vec<(f64, H2Upstream)> = Vec::new();
    for ip in ips {
        let Some(h) = g.get(ip.as_str()) else { continue };
        for c in &h.conns {
            if c.up.overflow {
                continue;
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            let ewma = if c.ewma > 0.0 { c.ewma } else { 1.0 };
            cands.push(((inflight as f64 + 1.0) / cap as f64 * ewma, c.up.clone()));
        }
    }
    cands.sort_by(|a, b| a.0.total_cmp(&b.0));
    cands.into_iter().map(|(_, up)| up).collect()
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

/// 新连接入库的唯一入口。会话域同 IP 去重；内容域/其他并存（赌 IP 能扛多通道）。
/// 会话域该 IP 已有连接时，新拨的当场作废，返回池里现成的那条。
pub fn store_h2(ip: &str, up: H2Upstream) -> H2Upstream {
    let mut g = lock(conn_pool());
    let h = g.entry(ip.to_string()).or_default();
    let cap = up.owner.as_deref()
        .map(|owner| max_conns_per_ip(host_class(owner)))
        .unwrap_or(usize::MAX);
    if h.conns.len() >= cap {
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

/// 该 IP 当前在池里的通道条数（溢出闸按它判"同 IP 还能不能再开"）。
pub(crate) fn conn_count_on_ip(ip: &str) -> usize {
    lock(conn_pool()).get(ip).map(|h| h.conns.len()).unwrap_or(0)
}

/// 驱动探活用：这条连接的 (闲置秒数, 在途流数, 是否溢出临时通道)。不在池里 = (0, 0, false)。
fn conn_probe_state(ip: &str, id: u64) -> (u64, u32, bool) {
    let g = lock(conn_pool());
    match g.get(ip).and_then(|h| h.conns.iter().find(|c| c.up.id == id)) {
        Some(c) => (
            now_secs().saturating_sub(c.last_used),
            c.up.inflight.load(std::sync::atomic::Ordering::Relaxed),
            c.up.overflow,
        ),
        None => (0, 0, false),
    }
}

/// 内容域/其他探活的单次实现：在现有 h2 连接上开 stream 发 GET Range:bytes=0-0，
/// `PROBE_TIMEOUT_SECS` 内等到响应头 = 通道活着（响应体随 stream 一起丢弃，h2 自动
/// 发 RST_STREAM 收尾）。PING 帧被 GFW 放行但数据被丢，探不了黑洞；1 字节 Range 是
/// 正常 HTTP 请求，与真实流量无异。单独拎成函数：驱动循环里跑，单测里对本地假上游跑。
pub(crate) async fn probe_liveness(send: &SendRequest<Bytes>, owner: &str) -> bool {
    let probe = async {
        let send = send.clone();
        let mut ready = send.ready().await.ok()?;
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!("https://{owner}/"))
            .header("range", "bytes=0-0")
            .body(())
            .ok()?;
        let (resp, _stream) = ready.send_request(req, true).ok()?;
        resp.await.ok()?;
        Some(())
    };
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(crate::config::PROBE_TIMEOUT_SECS),
            probe,
        )
        .await,
        Ok(Some(()))
    )
}

/// 一条连接 = 一个任务。它只干三件事：持续 poll conn 让 h2 帧收发活着（这是 h2 协议
/// 的硬要求，不是保活）、按类探活、连接结束时把自己从池里摘掉。
///
/// 通道持续存在（无批窗），健康由探活保证——驱动自己的 select 里挂一个计时器，闲置的
/// 通道按类验活：内容域/其他发极小请求（[`probe_liveness`]），会话域发 PING。
/// 超时无响应 = 连接已黑洞 → 当场自摘出池，不再等下一个请求骑上去 4-8s 才发现。
/// 所有出口都按 id 自摘出池；不做任何补拨——通道重建是下一个请求自己的事。
/// 断开日志只给会话域：内容域的连接断掉是家常便饭（边缘回收在预期内），记了全是噪音。
struct ConnDriver<T> {
    ip: String,
    id: u64,
    conn: h2::client::Connection<T, Bytes>,
    session: bool,
    /// 会话域才有：PING 探活用（内容域/其他恒 None，探活走极小请求）。
    ping: Option<Arc<tokio::sync::Mutex<h2::PingPong>>>,
    /// 内容域/其他探活用：驱动自己持有的 send clone，在现有连接上开流。
    send: SendRequest<Bytes>,
    /// 探活请求的 :authority（建这条连接时用的 host）。
    owner: String,
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
        session,
        ping,
        send,
        owner,
        log,
    } = d;
    tokio::spawn(async move {
        let mut conn = Box::pin(conn);
        let probe_every = if session {
            crate::config::SESSION_PROBE_INTERVAL_SECS
        } else {
            crate::config::PROBE_INTERVAL_SECS
        };
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(probe_every));
        tick.tick().await; // interval 首拍立即完成，吞掉
        let why: &str = 'keep: loop {
            enum Step {
                ConnEnd,
                Probe,
            }
            let step = tokio::select! {
                _ = &mut conn => Step::ConnEnd,
                _ = tick.tick() => Step::Probe,
            };
            match step {
                Step::ConnEnd => break 'keep "对端关闭",
                Step::Probe => {
                    // 溢出通道是临时工：在途流归零就单方面掐断出池（句柄已不再外发），
                    // 最多滞后一个探活拍——用完即焚。
                    let (idle, inflight, overflow) = conn_probe_state(&ip, id);
                    if overflow && inflight == 0 {
                        break 'keep "溢出通道用毕回收";
                    }
                    // 刚用过的通道不必探；探的是闲置期黑洞。
                    if idle < probe_every {
                        continue;
                    }
                    let alive = if session {
                        let Some(pp) = &ping else { continue };
                        // PONG 靠 conn 被 poll 才收得到，所以等 PONG 时 conn 仍要在
                        // 同一个 select 里跑；连接恰在此刻断开就当场收摊。
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
                        matches!(
                            tokio::select! {
                                _ = &mut conn => None,
                                r = pong => Some(r),
                            },
                            Some(Ok(Ok(_)))
                        )
                    } else {
                        probe_liveness(&send, &owner).await
                    };
                    if !alive {
                        break 'keep "探活失败(黑洞)";
                    }
                }
            }
        };
        // 唯一出口：连接结束（对端关闭/回收/错误）或探活判死。把自己从池里摘掉；
        // 已被先摘过的，这里 no-op。不做任何补拨——通道重建是下一个请求自己的事。
        drop_h2_id(&ip, id);
        if session {
            // 只有会话域的断开值得记：长寿命资产没了，下一个会话请求会重拨落回原家。
            log(&format!("[会话通道] {ip}#{id} 断开出池({why}), 下次会话请求重拨"));
        }
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
    // 会话域才有 PING 探活（PingPong 归驱动自用）；内容域/其他探活走极小请求，
    // 驱动自持 send clone 即可，PingPong 整个省掉。
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
    // 从此这条连接归它自己的任务管：驱动帧收发、按类探活、断开自摘。
    spawn_conn_driver(ConnDriver {
        ip: ip.to_string(),
        id,
        conn,
        session,
        ping,
        send: send.clone(),
        owner: host.to_string(),
        log: log.clone(),
    });
    Ok(H2Upstream {
        ip: ip.to_string(),
        id,
        slot,
        owner: Some(host.to_string()),
        max_streams,
        inflight: Arc::new(AtomicU32::new(0)),
        overflow: false,
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
    /// 副通道拨号：还剩两个以上空 IP 才发（复用归池子的骑池，这里只拨新）。
    pub vice_dial: bool,
}

/// 纯计算，把「主副分工」钉死：
/// - 会话域不设副通道（同会话跨 IP 是风控特征）；
/// - 有空 IP 才发主通道；
/// - 空 IP 够两家才发副腿去拨。
pub(crate) fn plan_legs(session: bool, free: usize) -> LegPlan {
    LegPlan {
        primary: free > 0,
        vice_dial: !session && free >= 2,
    }
}

/// 双腿建连：主副各拨各的新连接（串发选 IP → h2 握手 → 入库），
/// 两条腿共享 crew：同一个 IP 只由一条腿试，绝不重复。
/// 返回的连接必是本轮新拨的——骑池里现成通道归 `pool::get_or_build` 的骑池步骤，不归这里。
async fn dial_h2_race(
    host: &str,
    log: &LogFn,
    occupied: &[String],
) -> Result<H2Upstream, String> {
    let crew = pool::DialCrew::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<H2Upstream, String>>(4);
    let targets = pool::route::dial_targets(host).unwrap_or_default();
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    let distinct = ips.len();
    // 会话域：已有通道的 IP 不再拨（同 IP 只留一条，风控面不漂移）。
    // 内容域/其他：不管已有通道——同 IP 并发拨出来的都保留（赌 IP 能扛多通道），
    // store_h2 按类处置（会话域去重，内容域并存）。
    let session = host_class(host) == HostClass::Session;
    let free = if session {
        distinct.saturating_sub(occupied.len())
    } else {
        distinct
    };
    // 单通道判定：内容域之外都是。即使只剩一家，原因也按规则算，不误报成「候选不足」。
    let single = !dual_channel(host);
    let legs = plan_legs(single, free);

    let mut launched = 0usize;
    // 一条腿 = 一个拨号任务：串发选 IP → h2 握手 → 入库，结果回执 tx。
    let dial_leg = |slot: u8, prefer_shared: Option<bool>, tx: tokio::sync::mpsc::Sender<Result<H2Upstream, String>>| {
        let host = host.to_string();
        let log2 = log.clone();
        let skip = occupied.to_vec();
        let crew2 = crew.clone();
        tokio::spawn(async move {
            let r = h2_dial_slot(&host, &log2, &skip, slot, Some(&crew2), prefer_shared).await;
            let _ = tx.send(r).await;
        });
    };
    if legs.primary {
        // 主通道：独占档在前（独占用尽才轮到共享），游标用主键。
        dial_leg(1, Some(false), tx.clone());
        launched += 1;
    }
    if legs.vice_dial {
        // 副通道：共享档在前，游标用 _vice 副键。
        dial_leg(2, Some(true), tx.clone());
        launched += 1;
    }
    if launched == 0 {
        // 一条腿都发不出去：会话域的候选全被已有通道占住——重拨只能落在同批 IP 上
        // 再被 store_h2 作废，这句话重试到死没有意义（实测 api.github.com 连刷 24 行），
        // 立即交上层走兜底。
        return Err(format!("{host} 候选均已有通道, 请重查连接池"));
    }
    drop(tx);
    // 两条腿同时拨 = 一次等待把两条容量通道都建好；只发主通道时说清为什么单通道。
    if legs.primary && legs.vice_dial {
        (log)(&format!("[建连] {host} 主副双通道同时开建"));
    } else if legs.primary {
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
            None => return Err(last.unwrap_or_else(|| "并行建连全败".into())),
        }
    };
    // 晚成腿的收尾：连接已在拨号任务内自入库（store_h2），这里不再等待也不再补建——
    // 通道重建是下一个请求自己的事，一成一败就本轮单通道跑。
    // rx 就地丢弃：dialer 的回执发送对已关闭的通道是 no-op（let _ = tx.send），无副作用。
    drop(rx);
    Ok(won)
}

/// 建连统一入口：双腿各拨各的新连接（会话域跳过已有通道的 IP，内容域/其他不管）。
/// 串发全灭冷却中直接快速失败：调用方走兜底（镜像/DNS），绝不空转重试刷屏。
pub async fn dial_upstream(host: &str, log: &LogFn) -> Result<H2Upstream, String> {
    if pool::dial_cool_open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let targets =
        pool::route::dial_targets(host).ok_or_else(|| format!("域名不在路由表({host})"))?;
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走 fallback"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    // 会话域：已有通道的 IP 不再拨（同 IP 只留一条，风控面不漂移）。
    // 内容域/其他：不管已有通道——同 IP 并发拨出来的都保留（赌 IP 能扛多通道），
    // skip_ips 传空让串发试全部候选。
    let occupied = if host_class(host) == HostClass::Session {
        occupied_ips(&ips)
    } else {
        Vec::new()
    };
    dial_h2_race(host, log, &occupied).await
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
    // 每次开流刷新这条连接自己的空闲期：探活计时器的闲置期按它算。
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
