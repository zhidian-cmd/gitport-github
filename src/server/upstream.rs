//! 上游 HTTP 客户端：直连腿 = boring 指纹自管 h2 连接（fresh 语义）；镜像腿 = 标准 TLS + h1 共享池。
//! 通道的记账、挑选、开流全在本文件；取用统一入口是 `pool::get_or_build`
//! （取 → 溢出 → 建，一层管完），请求路径不再各管一段。
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
    /// 当前在途流数：发请求 +1、流收尾 -1。选路按"占用率 × 吞吐倒数"挑最闲且最快的。
    pub inflight: Arc<AtomicU32>,
    /// 溢出临时通道：句柄不再外发，空闲（在途归零）即被驱动掐断出池。
    pub overflow: bool,
    /// 主动关闭信号：竞速落败的腿靠它立刻断开，不等闲置超时。
    pub close: Arc<tokio::sync::Notify>,
    send: SendRequest<Bytes>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 最近使用时刻。
pub(crate) struct ConnSlot {
    pub(crate) up: H2Upstream,
    /// 这条连接自己最后一次被使用（开流刷新）；闲置焚毁计时按它算。
    last_used: u64,
}

/// 同 IP 通道上限：会话域/内容域/其他恒 1——多通道一律换 IP 另起（同 IP 溢出例外）。
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
/// - session 标记：会话域（单通道单 IP 单通道单 IP，只标实测出拦截页的主站族）。
/// - 三个都不标：「其他」——单通道、批窗临时通道，不值得养专属资产。
pub(crate) fn host_class(host: &str) -> HostClass {
    if pool::route::is_big_file_host(host) {
        return HostClass::Other;
    }
    if pool::route::is_content(host) {
        return HostClass::Content;
    }
    // 会话域按风控面划界：拦截页(Whoa)实测只出现在主站族，只有它们配专属通道。
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

static CONN_POOL: std::sync::OnceLock<Mutex<HashMap<String, Vec<ConnSlot>>>> = std::sync::OnceLock::new();
pub(crate) fn conn_pool() -> &'static Mutex<HashMap<String, Vec<ConnSlot>>> {
    CONN_POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

/// 响应头预算超时：上层按它区分"真等超了"和别的失败。
pub const ERR_BUDGET_TIMEOUT: &str = "响应预算超时";

/// 门房公式：在给定 IP 集合里挑活连接——占用率 × 吞吐倒数，最闲且最快的胜出。
/// only_owner = 会话域只认自己建的通道；want_slot = 搜索路径固定骑主通道。
pub(crate) fn pick(
    ips: &[String],
    want_slot: Option<u8>,
    only_owner: Option<&str>,
) -> Option<H2Upstream> {
    let mut g = lock(conn_pool());
    // 暂缓（低于够用线）的 IP 先不发；全暂缓时 usable 原样返回，不让请求饿死。
    let usable = pool::speed::usable(ips);
    // (分数, 是否顶到并发上限, 连接)
    let mut cands: Vec<(f64, bool, H2Upstream)> = Vec::new();
    for ip in &usable {
        let Some(h) = g.get_mut(ip) else { continue };
        for c in h.iter() {
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
            // 溢出临时通道：句柄只归触发者，不外发。
            if c.up.overflow {
                continue;
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            let score = channel_score(ip, inflight, cap);
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

/// 在给定 IP 集合里取活连接：按「占用率 × 吞吐倒数」挑最闲且最快的那条。
pub fn cached_h2_in(ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, None)
}

/// 会话域只认自己建的通道；没有就返回 None 让调用方自建——蹭公共通道 = 风控漂移。
pub fn cached_h2_own(host: &str, ips: &[String], want_slot: Option<u8>) -> Option<H2Upstream> {
    pick(ips, want_slot, Some(host))
}

/// 通道选路打分（pick 与 channels_for 共用）：占用率 × 吞吐倒数，闲着又快的分最小。
/// 快慢只认池子那张实测吞吐表，握手耗时留在建造机器人自己的拨号排序里，不进选路。
fn channel_score(ip: &str, inflight: u32, cap: u32) -> f64 {
    let kbps = pool::speed::kbps_of(ip).unwrap_or(pool::speed::TARGET_KBPS);
    (inflight as f64 + 1.0) / cap as f64 * (pool::speed::TARGET_KBPS / kbps.max(1.0))
}

/// 候选内全部可用通道（不含溢出临时通道），按「占用率 × 吞吐倒数」升序。
pub(crate) fn channels_for(ips: &[String]) -> Vec<H2Upstream> {
    let g = lock(conn_pool());
    let usable = pool::speed::usable(ips);
    let mut cands: Vec<(f64, H2Upstream)> = Vec::new();
    for ip in &usable {
        let Some(h) = g.get(ip.as_str()) else { continue };
        for c in h.iter() {
            if c.up.overflow {
                continue;
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            cands.push((channel_score(ip, inflight, cap), c.up.clone()));
        }
    }
    cands.sort_by(|a, b| a.0.total_cmp(&b.0));
    cands.into_iter().map(|(_, up)| up).collect()
}

/// 新连接入库唯一入口：同 IP 只留一条（一 IP 一通道），后到作废返现成的。
pub fn store_h2(ip: &str, up: H2Upstream) -> H2Upstream {
    let mut g = lock(conn_pool());
    let h = g.entry(ip.to_string()).or_default();
    let cap = up.owner.as_deref()
        .map(|owner| max_conns_per_ip(host_class(owner)))
        .unwrap_or(usize::MAX);
    // 常驻名额按非溢出通道算：溢出是拥挤时的临时工，不占"一 IP 一通道"的名额。
    let normal_cnt = h.iter().filter(|c| !c.up.overflow).count();
    if !up.overflow && normal_cnt >= cap {
        // 常编满员：落选连接当场关闭。调用方拿到的是池里现成那条，新拨的这条
        // 若只是丢弃，驱动任务会在池外养到对端回收（泄漏）。Notify 无等待者也存许可，必达。
        up.close.notify_one();
        return h[0].up.clone();
    }
    if up.overflow && h.iter().any(|c| c.up.overflow) {
        // 每 IP 至多一条溢出：再来的关掉，把正编（若有）递回去——溢出通道本身
        // 还在驮上一个请求时，后来的拥挤请求骑它排队，总好过再拨。
        up.close.notify_one();
        return h
            .iter()
            .find(|c| !c.up.overflow)
            .map(|c| c.up.clone())
            .unwrap_or_else(|| h[0].up.clone());
    }
    let keep = up.clone();
    h.push(ConnSlot {
        up,
        last_used: now_secs(),
    });
    keep
}

/// 按连接 id 精确摘除：同 IP 两条连接靠 IP 分不开，删错会把健康的摘掉。
pub fn drop_h2_id(ip: &str, id: u64) {
    let mut g = lock(conn_pool());
    match g.get_mut(ip) {
        Some(h) => {
            if let Some(pos) = h.iter().position(|c| c.up.id == id) {
                h.remove(pos);
            }
            if h.is_empty() {
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
        g.get(ip).and_then(|h| h.first()).map(|c| c.up.id)
    };
    if let Some(id) = id {
        drop_h2_id(ip, id);
    }
}

/// 状态行快照：池内全部通道按 owner（建连时的 host）归组。
/// 返回 (host, [(ip, 在途流, 流上限, 空闲秒)])，host 键稳定排序。
pub(crate) fn channels_snapshot() -> Vec<(String, Vec<(String, u32, u32, u64)>)> {
    let mut groups: std::collections::HashMap<String, Vec<(String, u32, u32, u64)>> =
        std::collections::HashMap::new();
    {
        let g = lock(conn_pool());
        for (ip, h) in g.iter() {
            for c in h.iter() {
                let host = c.up.owner.clone().unwrap_or_else(|| ip.clone());
                let idle = now_secs().saturating_sub(c.last_used);
                let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
                groups
                    .entry(host)
                    .or_default()
                    .push((ip.clone(), inflight, c.up.max_streams.max(1), idle));
            }
        }
    }
    let mut out: Vec<(String, Vec<(String, u32, u32, u64)>)> = groups.into_iter().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// 池中该组 IP 里**已经有活连接**的地址(供拨号 skip:同一个 IP 不再拨第二次)。
/// 全仓"这个 IP 有没有通道"的唯一口径：拨号预检与双通道 skip 都从这里取。
pub(crate) fn occupied_ips(ips: &[String]) -> Vec<String> {
    let g = lock(conn_pool());
    ips.iter()
        .filter(|ip| g.get(ip.as_str()).is_some_and(|h| !h.is_empty()))
        .cloned()
        .collect()
}

/// 该 IP 当前在池里的通道条数（溢出闸按它判"同 IP 还能不能再开"）。
pub(crate) fn conn_count_on_ip(ip: &str) -> usize {
    lock(conn_pool()).get(ip).map(|h| h.len()).unwrap_or(0)
}

/// 该 IP 上正编通道的（在途流, 流上限）；无正编 = None。溢出临时通道不算。
/// 拥挤判定用：溢出的前提是"正编满载且速度不慢"，不是"随便加一条"。
pub(crate) fn channel_load(ip: &str) -> Option<(u32, u32)> {
    let g = lock(conn_pool());
    let h = g.get(ip)?;
    let c = h.iter().find(|c| !c.up.overflow)?;
    Some((
        c.up.inflight.load(std::sync::atomic::Ordering::Relaxed),
        c.up.max_streams.max(1),
    ))
}

/// 摘除并关闭该 IP 的正编通道（cap=1 时即唯一一条）——替换黑通道/会话换血用。
/// 只 notify：驱动走 close 分支退出并自摘出池，连接随任务收尾关闭。
pub(crate) fn cull_channel(ip: &str) {
    let close = {
        let g = lock(conn_pool());
        g.get(ip)
            .and_then(|h| h.first())
            .map(|c| c.up.close.clone())
    };
    if let Some(c) = close {
        c.notify_one();
    }
}

/// 驱动清扫用：这条连接的 (闲置秒数, 在途流数, 是否溢出临时通道)。不在池里 = (0, 0, false)。
fn conn_probe_state(ip: &str, id: u64) -> (u64, u32, bool) {
    let g = lock(conn_pool());
    match g.get(ip).and_then(|h| h.iter().find(|c| c.up.id == id)) {
        Some(c) => (
            now_secs().saturating_sub(c.last_used),
            c.up.inflight.load(std::sync::atomic::Ordering::Relaxed),
            c.up.overflow,
        ),
        None => (0, 0, false),
    }
}

/// 一条连接 = 一个任务：持续 poll conn（协议硬要求）、收到关闭信号或闲置超限即焚。
/// 即用即建、用完就丢：通道不再长期持有——闲置寿命（10s）远短于对端/中间设备的
/// 静默掐死窗口（60~90s），「领到僵尸通道」在结构上不可能发生。
/// 断开日志只给会话域——内容域断连是家常便饭，记了全是噪音。
struct ConnDriver<T> {
    ip: String,
    id: u64,
    conn: h2::client::Connection<T, Bytes>,
    session: bool,
    /// 竞速落败的腿：收到即断开，不必等闲置超时。
    close: Arc<tokio::sync::Notify>,
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
        close,
        log,
    } = d;
    tokio::spawn(async move {
        let mut conn = Box::pin(conn);
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.tick().await; // interval 首拍立即完成，吞掉
        let why: &str = 'keep: loop {
            enum Step {
                ConnEnd,
                Close,
                Sweep,
            }
            let step = tokio::select! {
                _ = &mut conn => Step::ConnEnd,
                _ = close.notified() => Step::Close,
                _ = tick.tick() => Step::Sweep,
            };
            match step {
                Step::ConnEnd => break 'keep "对端关闭",
                Step::Close => break 'keep "主动关闭",
                Step::Sweep => {
                    // 用完就丢：溢出通道在途归零即刻焚；普通通道闲置超限（在途流
                    // 不为零不算闲置——长下载的 last_used 停在开流时刻）即焚。
                    // 重拨是下一个请求自己的事（即用即建）。
                    let (idle, inflight, overflow) = conn_probe_state(&ip, id);
                    if overflow && inflight == 0 {
                        break 'keep "溢出通道用毕回收";
                    }
                    if inflight == 0 && idle >= crate::config::CONN_IDLE_RETIRE_SECS {
                        break 'keep "闲置用毕丢弃";
                    }
                }
            }
        };
        // 唯一出口：断开/判焚/主动关闭，按 id 自摘（已被摘过则 no-op）。
        drop_h2_id(&ip, id);
        if session {
            // 会话域的断开值得记一行，内容域是噪音。
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
    let (send, conn) = tokio::time::timeout(
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
    let session = host_class(host) == HostClass::Session;
    // 服务端在 SETTINGS 里说了它一条连接能接多少流，照着用，不替它猜数字。
    // 服务端不设上限时 h2 回 u32::MAX——评分按 (在途+1)/上限 算，(MAX) 会让它
    // 永远显得最闲；钳到 100 与 Fastly 实际下发值同量级。
    let max_streams = conn.max_concurrent_send_streams().max(1).min(100) as u32;
    // id 建连时就定下：驱动任务带着它，连接一断就能精确摘自己那一条。
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let close = Arc::new(tokio::sync::Notify::new());
    // 从此这条连接归它自己的任务管：驱动帧收发、闲置焚毁、断开自摘。
    spawn_conn_driver(ConnDriver {
        ip: ip.to_string(),
        id,
        conn,
        session,
        close: close.clone(),
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
        close,
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
    let form = if sni.is_empty() {
        "无"
    } else if sni == host {
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

/// 单通道原因：会话域/大文件是规则，候选不足是没得选——日志要能看懂。
fn single_channel_reason(class: HostClass, _distinct: usize, free: usize) -> String {
    match class {
        HostClass::Session => "会话域固定同一 IP, 不开第二条(防风控)".to_string(),
        HostClass::Other => "大文件/文档站: 单通道".to_string(),
        HostClass::Content => format!("可用候选仅 {free} 家, 不够开第二条"),
    }
}

/// 这一轮发哪几条腿：主通道只管开新坑，副通道多一步「先看有没有现成的可捡」。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegPlan {
    /// 主通道：还有没被已有通道占用的 IP 就发，串发新建。
    pub primary: bool,
    /// 副通道拨号：空 IP 够两家才发。
    pub vice_dial: bool,
}

/// 主副分工：会话域不设副腿（跨 IP 是风控特征），其余空 IP 够两家才拨副腿。
pub(crate) fn plan_legs(session: bool, free: usize) -> LegPlan {
    LegPlan {
        primary: free > 0,
        vice_dial: !session && free >= 2,
    }
}

/// 竞速腿的结果：拨号耗时（TCP+TLS+h2）与实测吞吐（500ms 探针）。
#[derive(Clone)]
pub(crate) struct RaceLeg {
    pub ip: String,
    pub dial_ms: u64,
    up: H2Upstream,
}

/// 竞速排名（纯函数）：拨号耗时升序——通道即用即建几乎全新，
/// 拨号快慢就是当前可得的唯一速度先验；传输快慢由真实请求记账兜底。
pub(crate) fn rank_legs(mut legs: Vec<RaceLeg>) -> Vec<RaceLeg> {
    legs.sort_by_key(|l| l.dial_ms);
    legs
}

/// 内容域竞速建连：该 host 的**全部**候选 IP 一 IP 一条腿并发拨（数量随域的 IP 组走），
/// 按拨号耗时取最快的两条入池，其余当场关闭。建连机器人返回最快那条。
const RACE_WINDOW_SECS: u64 = 8;

async fn race_build(host: &str, _probe_path: &str, log: &LogFn) -> Result<H2Upstream, String> {
    let targets = pool::route::dial_targets(host).unwrap_or_default();
    // 跳过死亡冷却与暂缓；全被排除就用回全部（软排除，不能把候选打空）。
    let alive: Vec<crate::pool::route::NodeIp> = targets
        .iter()
        .filter(|t| !pool::dial_cooling(&t.ip, &t.sni))
        .cloned()
        .collect();
    let alive = if alive.is_empty() { targets.clone() } else { alive };
    let ips: Vec<String> = alive.iter().map(|t| t.ip.clone()).collect();
    let keep_ips = pool::speed::usable(&ips);
    let cands: Vec<crate::pool::route::NodeIp> = alive
        .into_iter()
        .filter(|t| keep_ips.iter().any(|ip| ip == &t.ip))
        .collect();
    if cands.len() < 2 {
        // 候选不足两条没法赛：退回单腿串发（跟旧路径一致）。
        return h2_dial_slot(host, log, &[], 1, None, None).await;
    }
    (log)(&format!("[建连] {host} {} 路竞速(错峰 50ms)", cands.len()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<RaceLeg, String>>(cands.len());
    for (li, node) in cands.into_iter().enumerate() {
        let host2 = host.to_string();
        let log2 = log.clone();
        let tx2 = tx.clone();
        tokio::spawn(async move {
            // 错峰起跑：12 条腿同时砸向同一批新连接，Fastly 对新连接首请求
            // 会排队（实测 12 路全零字节、真实流量随即正常），错开 50ms 避开突发。
            tokio::time::sleep(Duration::from_millis(li as u64 * 50)).await;
            let t0 = Instant::now();
            let conn = match pool::dial::dial_one(&node.ip, &node.sni, &node.verify, true).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx2.send(Err(format!("{} 拨号失败({e})", node.ip))).await;
                    return;
                }
            };
            let dial_ms = t0.elapsed().as_millis() as u64;
            pool::latency::note(&node.ip, dial_ms);
            let up = match h2_from_dialed(&host2, conn, &node.ip, 1, &log2).await {
                Ok(u) => u,
                Err(e) => {
                    pool::note_dead(&node.ip);
                    let _ = tx2.send(Err(format!("{} h2 失败({e})", node.ip))).await;
                    return;
                }
            };
            let _ = tx2
                .send(Ok(RaceLeg {
                    ip: node.ip.clone(),
                    dial_ms,
                    up,
                }))
                .await;
        });
    }
    drop(tx);
    // 收腿：窗口到就用手上的排名，不等磨蹭的腿。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(RACE_WINDOW_SECS);
    let mut got: Vec<RaceLeg> = Vec::new();
    let mut last: Option<String> = None;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Ok(leg))) => got.push(leg),
            Ok(Some(Err(e))) => last = Some(e),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if got.is_empty() {
        return Err(last.unwrap_or_else(|| format!("{host} 竞速全败")));
    }
    // 迟到腿：后台收尸——已建成但没被选中的连接必须关，否则会在池外白养到闲置超时。
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            if let Ok(leg) = r {
                leg.up.close.notify_one();
            }
        }
    });
    let mut ranked = rank_legs(got);
    // 按拨号耗时取最快的两条，落败腿关闭；传输快慢由真实请求记账与
    // 触发链兜底（黑洞 30s 看门狗 / settle 触发链），竞速不再做测速预判。
    let keep = ranked.len().min(2);
    let winners: Vec<RaceLeg> = ranked.drain(..keep).collect();
    // 落败腿：主动关闭，不入池。
    for leg in ranked {
        leg.up.close.notify_one();
    }
    // 先留排名摘要：入池后 leg 被拆开，日志还要说清谁快。
    let summary: Vec<String> = winners
        .iter()
        .map(|l| format!("{}(拨{}ms)", l.ip, l.dial_ms))
        .collect();
    let mut kept: Vec<H2Upstream> = Vec::new();
    for (i, mut leg) in winners.into_iter().enumerate() {
        // 第二名按副通道记账（游标键分开），第一名仍是主通道。
        if i == 1 {
            leg.up.slot = 2;
        }
        kept.push(store_h2(&leg.ip, leg.up));
    }
    (log)(&format!("[建连] {host} 竞速取前二: {}", summary.join(" / ")));
    Ok(kept.remove(0))
}

/// 双腿建连：主副各拨各的新连接，crew 互斥保证同一个 IP 只由一条腿试。
/// 只建新的、不查池——查池归 get_or_build。
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
    // 会话域跳过已有通道的 IP；内容域/其他不管——store_h2 按类处置。
    let session = host_class(host) == HostClass::Session;
    let free = if session {
        distinct.saturating_sub(occupied.len())
    } else {
        distinct
    };
    // 单通道判定：内容域之外都是。
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
        // 会话域候选全被占：重拨必被 store_h2 作废，立即交兜底。
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
    // 晚成腿已自入库，不等不补——重建是下一个请求自己的事。
    drop(rx);
    Ok(won)
}

/// 建连统一入口：双腿各拨各的新连接；串发全灭冷却中快速失败，调用方走兜底。
pub async fn dial_upstream(host: &str, probe_path: &str, log: &LogFn) -> Result<H2Upstream, String> {
    if pool::SERIAL_COOL.open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let targets =
        pool::route::dial_targets(host).ok_or_else(|| format!("域名不在路由表({host})"))?;
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走 fallback"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    // 会话域跳过已有通道的 IP；内容域/其他传空让串发试全部候选。
    let occupied = if host_class(host) == HostClass::Session {
        occupied_ips(&ips)
    } else {
        Vec::new()
    };
    // 内容域：多路竞速 + 首包排名，取最快两条（机器人交付最快那条）。
    if host_class(host) == HostClass::Content {
        return race_build(host, probe_path, log).await;
    }
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

/// 纯 CDN 域：只伺候公开静态资源，永远不需要凭据——Cookie/Authorization 剥掉，
/// 免得会话痕迹跟着资产请求落到 CDN 边缘。
/// 只圈纯静态两家：githubusercontent 家族不在此列——私有仓库的 raw/头像/codeload
/// 压缩包靠 Cookie 鉴权，剥了会把私有内容直接掐死。
pub fn strip_credentials(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "githubassets.com"
        || h.ends_with(".githubassets.com")
        || h == "github.io"
        || h.ends_with(".github.io")
}

fn h2_request_head(out: &hyper::Request<BoxBody>) -> Result<hyper::Request<()>, String> {
    // :authority 是真实目标域名（伪装只发生在 TLS 握手的 SNI 上），按它判要不要剥凭据。
    let strip = out
        .uri()
        .authority()
        .map(|a| strip_credentials(a.host()))
        .unwrap_or(false);
    let mut builder = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri());
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if is_hop_by_hop(&low) {
            continue;
        }
        if strip && matches!(low.as_str(), "cookie" | "authorization") {
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
    // 每次开流刷新这条连接自己的空闲期：闲置焚毁计时按它算。
    {
        let mut g = lock(conn_pool());
        if let Some(h) = g.get_mut(&up.ip) {
            if let Some(c) = h.iter_mut().find(|c| c.up.id == up.id) {
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
 
