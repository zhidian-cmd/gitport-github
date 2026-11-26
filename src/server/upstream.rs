//! 上游 HTTP 客户端：直连腿 boring 自管 h2（fresh 语义），镜像腿 标准 TLS + h1 共享池；取用统一走 pool::get_or_build。
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
/// 池按 IP 记账：一条连接供该 IP 所有路由键共用（v2 复用单元 = IP）。
#[derive(Clone)]
pub struct H2Upstream {
    pub ip: String,
    /// 进程内唯一 ID：驱动结束时按它自摘出池。
    pub id: u64,
    /// 建连 host：会话域靠它认自建通道。
    pub owner: Option<String>,
    /// 服务端在 SETTINGS 里下发的并发上限（`MAX_CONCURRENT_STREAMS`）。
    pub max_streams: u32,
    /// 在途流数：发请求 +1、流收尾 -1；选路按占用率挑最闲的。
    pub inflight: Arc<AtomicU32>,
    /// 溢出临时通道：句柄不外发，在途归零即被驱动掐断。
    pub overflow: bool,
    /// 主动关闭信号：竞速落败腿靠它立刻断开。
    pub close: Arc<tokio::sync::Notify>,
    send: SendRequest<Bytes>,
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 一条连接 + 最近使用时刻。
pub(crate) struct ConnSlot {
    pub(crate) up: H2Upstream,
    /// 该连接最后使用时刻（开流刷新），闲置焚毁计时按它算。
    last_used: u64,
}

/// 拨号耗时超过此值 = GFW 抖动：记实测延迟，游标挪窝别黏慢 IP。
const DIAL_SLOW_MS: u64 = 1500;

/// 编译期断言：TCP+TLS 拨号合计 > DIAL_SLOW_MS，否则慢成功检测失效。
const _: () = assert!(
    crate::config::TCP_CONNECT_TIMEOUT_MS + crate::config::TLS_HANDSHAKE_TIMEOUT_MS > DIAL_SLOW_MS,
    "TCP+TLS 拨号合计必须 > DIAL_SLOW_MS(1500), 否则慢成功检测窗失效"
);

/// host 三类：内容域竞速取最速；会话域单通道单 IP；其他单通道即用即建。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HostClass {
    Content,
    Session,
    Other,
}

/// 类别由 hosts 标志决定（数据驱动）：content 竞速短预算；big 单通道+大镜像链；session 单通道单 IP；未标即其他。
pub(crate) fn host_class(host: &str) -> HostClass {
    if pool::route::is_big_file_host(host) {
        return HostClass::Other;
    }
    if pool::route::is_content(host) {
        return HostClass::Content;
    }
    // 仅主站族标 session；内容型子域写进 ips 节点的 hosts 即豁免通配。
    let on_risk_surface = pool::route::route_for(host).is_some_and(|row| row.flags.session);
    if on_risk_surface {
        HostClass::Session
    } else {
        HostClass::Other
    }
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

/// 响应头预算超时错误码。
pub const ERR_BUDGET_TIMEOUT: &str = "响应预算超时";

/// 候选全被其他 host 认领：调用方稍候重查池；真拨失败不走此码。
pub const ERR_ALL_CLAIMED: &str = "建连候选全被其他 host 认领";

/// 门房：在给定 IP 里按占用率挑最闲的；only_owner = 会话域只认自建通道。
pub(crate) fn pick(ips: &[String], only_owner: Option<&str>) -> Option<H2Upstream> {
    let mut g = lock(conn_pool());
    // 暂缓的 IP 先不发；全暂缓时 usable 原样返回。
    let usable = pool::speed::usable(ips);
    // (分数, 是否顶到并发上限, 连接)
    let mut cands: Vec<(f64, bool, H2Upstream)> = Vec::new();
    for ip in &usable {
        let Some(h) = g.get_mut(ip) else { continue };
        for c in h.iter() {
            if let Some(owner) = only_owner {
                if c.up.owner.as_deref() != Some(owner) {
                    continue;
                }
            }
            // 溢出临时通道句柄只归触发者，不外发。
            if c.up.overflow {
                continue;
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            let score = channel_score(inflight, cap);
            cands.push((score, inflight >= cap, c.up.clone()));
        }
    }
    if cands.is_empty() {
        return None;
    }
    // 优先未顶上限者；全满时按分数取队首（h2 会在服务端配额上排队）。
    let any_free = cands.iter().any(|c| !c.1);
    let pick = cands
        .iter()
        .enumerate()
        .filter(|(_, c)| !any_free || !c.1)
        .min_by(|a, b| a.1.0.total_cmp(&b.1.0))
        .map_or(0, |(i, _)| i);
    Some(cands.remove(pick).2)
}

/// 门房开流：字节由 hyper 直接搬运，本层不加跳；顺带刷新连接空闲期。
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

/// 在给定 IP 集合里取活连接：按占用率挑最闲的那条。
pub fn cached_h2_in(ips: &[String]) -> Option<H2Upstream> {
    pick(ips, None)
}

/// 会话域只认自建通道，没有就返回 None 让调用方自建。
pub fn cached_h2_own(host: &str, ips: &[String]) -> Option<H2Upstream> {
    pick(ips, Some(host))
}

/// 通道打分（pick/channels_for 共用）：占用率最小者胜；调用方须已持 conn_pool 锁。
fn channel_score(inflight: u32, cap: u32) -> f64 {
    (inflight as f64 + 1.0) / cap as f64
}

/// 候选内全部可用通道（不含溢出临时通道），按占用率升序。
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
            cands.push((channel_score(inflight, cap), c.up.clone()));
        }
    }
    cands.sort_by(|a, b| a.0.total_cmp(&b.0));
    cands.into_iter().map(|(_, up)| up).collect()
}

/// 该 IP 池内现成常编通道（竞速并集排名参赛用）；溢出通道不算。
fn pooled_normal(ip: &str) -> Option<H2Upstream> {
    let g = lock(conn_pool());
    g.get(ip)?
        .iter()
        .find(|c| !c.up.overflow)
        .map(|c| c.up.clone())
}

/// 新连接入库唯一入口：同 IP 只留一条，后到作废返现成的。
pub fn store_h2(ip: &str, up: H2Upstream) -> H2Upstream {
    let mut g = lock(conn_pool());
    let h = g.entry(ip.to_string()).or_default();
    // 同 IP 通道上限恒 1（同 IP 溢出例外）。
    let cap = 1usize;
    // 常驻名额按非溢出通道算，溢出不占名额。
    let normal_cnt = h.iter().filter(|c| !c.up.overflow).count();
    if !up.overflow && normal_cnt >= cap {
        // 满员落选连接当场关闭，调用方拿池里现成那条；Notify 许可必达。
        up.close.notify_one();
        // 找正编通道而非列表头（头可能是溢出的）。
        if let Some(c) = h.iter().find(|c| !c.up.overflow) {
            return c.up.clone();
        }
        // 理论不可达：真到了就扶正新连接。
        let keep = up.clone();
        h.push(ConnSlot { up, last_used: now_secs() });
        return keep;
    }
    if up.overflow && h.iter().any(|c| c.up.overflow) {
        // 每 IP 至多一条溢出：再来的关掉、递回正编。
        if let Some(c) = h.iter().find(|c| !c.up.overflow) {
            up.close.notify_one();
            return c.up.clone();
        }
        // 正编被摘光只剩溢出：扶正新连接、关旧溢出。
        for c in h.iter().filter(|c| c.up.overflow) {
            c.up.close.notify_one();
        }
        h.retain(|c| !c.up.overflow);
        let mut normal = up.clone();
        normal.overflow = false;
        let keep = normal.clone();
        h.push(ConnSlot { up: normal, last_used: now_secs() });
        return keep;
    }
    let keep = up.clone();
    h.push(ConnSlot {
        up,
        last_used: now_secs(),
    });
    keep
}

/// 按连接 id 精确摘除，摘后必须 notify 驱动自退出（重复 notify 无害）。
pub fn drop_h2_id(ip: &str, id: u64) {
    let close = {
        let mut g = lock(conn_pool());
        let mut found = None;
        if let Some(h) = g.get_mut(ip) {
            if let Some(pos) = h.iter().position(|c| c.up.id == id) {
                found = Some(h.remove(pos).up.close.clone());
            }
            if h.is_empty() {
                g.remove(ip);
            }
        }
        found
    };
    if let Some(c) = close {
        c.notify_one();
    }
}

/// 只有 IP 无句柄时用：查到 id 交 drop_h2_id 摘除。
pub fn drop_h2(ip: &str) {
    let id = {
        let g = lock(conn_pool());
        g.get(ip).and_then(|h| h.first()).map(|c| c.up.id)
    };
    if let Some(id) = id {
        drop_h2_id(ip, id);
    }
}

/// 状态行快照：池内通道按 owner 归组，返回 (host, [(ip, 在途流, 流上限, 空闲秒)])，host 稳定排序。
pub(crate) fn channels_snapshot() -> Vec<(String, Vec<(String, u32, u32, u64)>)> {    let mut groups: std::collections::HashMap<String, Vec<(String, u32, u32, u64)>> =
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

/// 池中已有活连接的 IP（拨号 skip 用），"有无通道"的唯一口径。
pub(crate) fn occupied_ips(ips: &[String]) -> Vec<String> {
    let g = lock(conn_pool());
    ips.iter()
        .filter(|ip| g.get(ip.as_str()).is_some_and(|h| !h.is_empty()))
        .cloned()
        .collect()
}

/// 该 IP 在池中的通道条数（溢出闸据此判能否再开）。
pub(crate) fn conn_count_on_ip(ip: &str) -> usize {
    lock(conn_pool()).get(ip).map(|h| h.len()).unwrap_or(0)
}

/// 黑洞处置（会话域）：notify 该 IP 首条通道关闭信号，驱动自摘出池。
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

/// 驱动清扫用：(闲置秒数, 在途流数, 是否溢出)；不在池里 = (0,0,false)。
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

/// 一条连接 = 一个任务：持续 poll conn，关闭信号或闲置 10s 即焚；断开日志只给会话域。
struct ConnDriver<T> {
    ip: String,
    id: u64,
    conn: h2::client::Connection<T, Bytes>,
    session: bool,
    /// 竞速落败腿：收到即断开，不等闲置超时。
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
                    // 溢出在途归零即焚，普通通道闲置 10s 即焚（在途非零不算闲置）。
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
        // 唯一出口：按 id 自摘（已被摘过则 no-op）。
        drop_h2_id(&ip, id);
        if session {
            // 仅会话域记断开日志。
            log(&format!("[会话通道] {ip}#{id} 断开出池({why}), 下次会话请求重拨"));
        }
    });
}

pub async fn h2_from_dialed(
    host: &str,
    conn_io: Dialed,
    ip: &str,
    log: &LogFn,
) -> Result<H2Upstream, String> {
    // h2 窗口顶到 2^31−1（默认 64KB 太窄）：仅是在途额度、不预分配内存，背压靠 release_capacity，连接级须一次给足。
    let h2_window = i32::MAX as u32; // 2147483647 = h2 MAX_WINDOW_SIZE，三个 builder 的 assert 均通过
    let mut cb = h2::client::Builder::new();
    cb.initial_window_size(h2_window) // 流级顶格
        .initial_connection_window_size(h2_window); // 连接级顶格（所有流共享）
                                                          // h2 握手限时，防对端装死持有 per-host 拨号锁。
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
    // 流上限用 SETTINGS 下发值，钳到 100（防 h2 回 u32::MAX 使评分失真）。
    let max_streams = conn.max_concurrent_send_streams().max(1).min(100) as u32;
    // id 建连时定下，驱动据此精确自摘。
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let close = Arc::new(tokio::sync::Notify::new());
    // 连接交给自己的任务管：帧收发、闲置焚毁、断开自摘。
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
        owner: Some(host.to_string()),
        max_streams,
        inflight: Arc::new(AtomicU32::new(0)),
        overflow: false,
        close,
        send,
    })
}

/// 单通道拨号：串发选 IP → boring 握手（SNI 骗墙，证书按锚点校验）→ h2。
pub(crate) async fn h2_dial(
    host: &str,
    log: &LogFn,
    skip_ips: &[String],
) -> Result<H2Upstream, String> {
    let t_dial = std::time::Instant::now();
    let (conn_io, ip, sni) = pool::serial_dial_skip(
        pool::DialSkip {
            host,
            tls_handshake: true,
            skip_ips,
        },
        Some(log),
    )
    .await
    .map_err(|e| e.to_string())?;
    let dial_ms = t_dial.elapsed().as_millis();
    // 拨号慢的 IP 游标挪窝（排序基线由设置页 IP 测速刷新）。
    if dial_ms as u64 >= DIAL_SLOW_MS {
        pool::cursor_note(host, &ip, false);
    }
    let form = if sni.is_empty() {
        "无"
    } else if sni == host {
        "真名"
    } else {
        "伪装"
    };
    let t_h2 = std::time::Instant::now();
    // h2 谈不成 = IP 建不成通道，进全局死亡退避。
    let up = h2_from_dialed(host, conn_io, &ip, log)
        .await
        .map_err(|e| {
            pool::note_dead(&ip);
            e
        })?;
    let h2_ms = t_h2.elapsed().as_millis();
    // 先入库再交付：调用方拿到池里那条；别人已建好则丢弃自己拨的。
    let up = store_h2(&ip, up);
    // 分段计时落一行（拨号 vs h2 握手）。
    (log)(&format!(
        "[上游] {host} <- {ip} ({form}SNI 直连, h2, 拨{dial_ms}ms+握手{h2_ms}ms)"
    ));
    Ok(up)
}

/// 单通道原因文案。
fn single_channel_reason(class: HostClass, free: usize) -> String {
    match class {
        HostClass::Session => "会话域固定同一 IP, 不开第二条(防风控)".to_string(),
        HostClass::Other => "大文件/文档站: 单通道".to_string(),
        HostClass::Content => format!("可用候选仅 {free} 家, 不够开第二条"),
    }
}

/// 竞速腿带实测 dial_ms；池内现成通道也参赛（pooled=true、耗时读延迟表）。
#[derive(Clone)]
pub(crate) struct RaceLeg {
    pub ip: String,
    pub dial_ms: u64,
    up: H2Upstream,
    pooled: bool,
}

/// 竞速排名按拨号耗时升序；传输快慢由真实请求记账兜底。
pub(crate) fn rank_legs(mut legs: Vec<RaceLeg>) -> Vec<RaceLeg> {
    legs.sort_by_key(|l| l.dial_ms);
    legs
}

/// 内容域竞速：全部候选 IP 一 IP 一腿并发拨，取最快一条入池，其余当场关闭。
const RACE_WINDOW_SECS: u64 = 8;

async fn race_build(host: &str, log: &LogFn) -> Result<H2Upstream, String> {
    let cands = pool::dial_candidates(host);
    if cands.len() < 2 {
        // 候选不足两条：退回单腿串发。
        return h2_dial(host, log, &[]).await;
    }
    (log)(&format!("[建连] {host} {} 路竞速(错峰 50ms)", cands.len()));
    // 参赛名单快照：收尾并集排名据此认领池内现成通道。
    let raced: Vec<String> = cands.iter().map(|t| t.ip.clone()).collect();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<RaceLeg, String>>(cands.len());
    for (li, node) in cands.into_iter().enumerate() {
        let host2 = host.to_string();
        let log2 = log.clone();
        let tx2 = tx.clone();
        tokio::spawn(async move {
            // 错峰起跑 50ms。
            tokio::time::sleep(Duration::from_millis(li as u64 * 50)).await;
            // 全局认领：同 IP 别的腿在拨则本腿不出场（attempted 不计）。
            if !pool::claim_dial(&node.ip) {
                return;
            }
            let t0 = Instant::now();
            let conn = match pool::dial::dial_one(&node.ip, &node.sni, &node.verify, true).await {
                Ok(c) => c,
                Err(e) => {
                    pool::release_dial(&node.ip);
                    let _ = tx2.send(Err(format!("{} 拨号失败({e})", node.ip))).await;
                    return;
                }
            };
            let dial_ms = t0.elapsed().as_millis() as u64;
            let up = match h2_from_dialed(&host2, conn, &node.ip, &log2).await {
                Ok(u) => u,
                Err(e) => {
                    pool::release_dial(&node.ip);
                    pool::note_dead(&node.ip);
                    let _ = tx2.send(Err(format!("{} h2 失败({e})", node.ip))).await;
                    return;
                }
            };
            // 拨完即释放认领；入库/关闭由收尾裁决。
            pool::release_dial(&node.ip);
            let _ = tx2
                .send(Ok(RaceLeg {
                    ip: node.ip.clone(),
                    dial_ms,
                    up,
                    pooled: false,
                }))
                .await;
        });
    }
    drop(tx);
    // 收腿：窗口到用手上排名，不等磨蹭腿；每条消息 = 一次真实尝试。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(RACE_WINDOW_SECS);
    let mut got: Vec<RaceLeg> = Vec::new();
    let mut last: Option<String> = None;
    let mut attempted = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Ok(leg))) => {
                attempted += 1;
                got.push(leg);
            }
            Ok(Some(Err(e))) => {
                attempted += 1;
                last = Some(e);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    // 并集排名：池内现成通道也参赛，耗时读延迟表；同 IP 以自己腿为准。
    for ip in &raced {
        if got.iter().any(|l| &l.ip == ip) {
            continue;
        }
        if let Some(up) = pooled_normal(ip) {
            let ms = { let v = pool::route::latency_of(ip); if v == 0 { u64::MAX } else { v } };
            got.push(RaceLeg {
                ip: ip.clone(),
                dial_ms: ms,
                up,
                pooled: true,
            });
        }
    }
    if got.is_empty() {
        if attempted == 0 {
            // 一条都没轮到拨 = 候选全被认领：哨兵让调用方稍候重查池。
            return Err(ERR_ALL_CLAIMED.to_string());
        }
        // 真失败：照旧报错，冷却表已记账。
        return Err(last.unwrap_or_else(|| format!("{host} 竞速全败")));
    }
    // 迟到腿后台收尸：未选中的连接必须关。
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            if let Ok(leg) = r {
                leg.up.close.notify_one();
            }
        }
    });
    let mut ranked = rank_legs(got);
    // 按拨号耗时取最快一条，落败腿关闭。
    let keep = ranked.len().min(1);
    let winners: Vec<RaceLeg> = ranked.drain(..keep).collect();
    // 落败腿：自己的主动关闭不入池；池内的不动。
    for leg in ranked {
        if !leg.pooled {
            leg.up.close.notify_one();
        }
    }
    // 入池前先留排名摘要。
    let summary: Vec<String> = winners
        .iter()
        .map(|l| {
            if l.pooled {
                format!("池·{}({}ms)", l.ip, l.dial_ms)
            } else {
                format!("{}(拨{}ms)", l.ip, l.dial_ms)
            }
        })
        .collect();
    let mut kept: Vec<H2Upstream> = Vec::new();
    for leg in winners.into_iter() {
        if leg.pooled {
            // 现成通道已在池里，直接交付不重复入库。
            kept.push(leg.up);
        } else {
            kept.push(store_h2(&leg.ip, leg.up));
        }
    }
    (log)(&format!(
        "[建连] {host} 竞速取最速: {}",
        summary.join(" / ")
    ));
    Ok(kept.remove(0))
}

/// 串发建连（会话域/低频域恒单腿）：全局认领保证同 IP 同时只一条腿；只建新的不查池。
async fn dial_h2_race(
    host: &str,
    log: &LogFn,
    occupied: &[String],
) -> Result<H2Upstream, String> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<H2Upstream, String>>(4);
    let targets = pool::route::dial_targets(host).unwrap_or_default();
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    let distinct = ips.len();
    // 会话域跳过已有通道的 IP；内容域/其他不管。
    let session = host_class(host) == HostClass::Session;
    let free = if session {
        distinct.saturating_sub(occupied.len())
    } else {
        distinct
    };
    if free == 0 {
        // 会话域候选全被占：立即交兜底。
        return Err(format!("{host} 候选均已有通道, 请重查连接池"));
    }
    // 单腿串发：候选按游标+延迟序逐个试。
    tokio::spawn({
        let host = host.to_string();
        let log2 = log.clone();
        let skip = occupied.to_vec();
        async move {
            let r = h2_dial(&host, &log2, &skip).await;
            let _ = tx.send(r).await;
        }
    });
    (log)(&format!(
        "[建连] {host} 单通道({})",
        single_channel_reason(host_class(host), free)
    ));
    // 等串发结果用绝对硬窗（同 BUILD_WAIT_SECS）；串发独立跑，超窗只影响本请求。
    let dl = tokio::time::Instant::now() + Duration::from_secs(pool::BUILD_WAIT_SECS);
    let mut last: Option<String> = None;
    let won = loop {
        match tokio::time::timeout_at(dl, rx.recv()).await {
            Err(_) => {
                return Err(format!("串发建连硬窗({}s)耗尽, 走兜底", pool::BUILD_WAIT_SECS))
            }
            Ok(Some(Ok(up))) => break up,
            Ok(Some(Err(e))) => last = Some(e),
            Ok(None) => return Err(last.unwrap_or_else(|| "串发建连全败".into())),
        }
    };
    // 晚成腿已自入库，不等不补。
    drop(rx);
    Ok(won)
}

/// 建连统一入口：串发全灭冷却中快速失败，调用方走兜底。
pub async fn dial_upstream(host: &str, log: &LogFn) -> Result<H2Upstream, String> {
    if pool::SERIAL_COOL.open(host) {
        return Err("串发冷却中(全灭后 30s 内), 走兜底".to_string());
    }
    let targets =
        pool::route::dial_targets(host).ok_or_else(|| format!("域名不在路由表({host})"))?;
    if targets.is_empty() {
        return Err(format!("{host} 候选 IP 全部在边冷却中, 走 fallback"));
    }
    let ips: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
    // 会话域跳过已有通道的 IP；内容域/其他传空试全部候选。
    let occupied = if host_class(host) == HostClass::Session {
        occupied_ips(&ips)
    } else {
        Vec::new()
    };
    // 内容域：多路竞速 + 首包排名，只留最快一条入池。
    if host_class(host) == HostClass::Content {
        return race_build(host, log).await;
    }
    dial_h2_race(host, log, &occupied).await
}
/// 流式直通响应头预算 1800s（30 分钟）：git push 大包收完校验才应答。
pub const STREAM_HEAD_BUDGET_SECS: u64 = 1800;

/// 镜像/后台拉取恒定浏览器 UA（CF 系镜像拦非浏览器 UA），全仓唯一一份。
pub const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// hop-by-hop 头（RFC 7230 §6.1）；mirror_request 与 h2_request_head 单点共用。
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "te"
    )
}

/// 纯 CDN 域（githubassets.com / github.io）剥 Cookie/Authorization，其余不剥。
pub fn strip_credentials(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "githubassets.com"
        || h.ends_with(".githubassets.com")
        || h == "github.io"
        || h.ends_with(".github.io")
}

fn h2_request_head(out: &hyper::Request<BoxBody>) -> Result<hyper::Request<()>, String> {
    // 按 :authority（真实目标域名）判是否剥凭据。
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
/// 在途计数凭据：建流 +1，body 结束/丢弃 -1（随 body 生命周期）。
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

/// h2 响应头 future → Response；体逐块即时 release_capacity。
pub async fn h2_recv_response(
    resp_fut: h2::client::ResponseFuture,
    guard: StreamGuard,
) -> Result<hyper::Response<BoxBody>, String> {
    let resp = resp_fut.await.map_err(|e| format!("h2 响应: {e}"))?;
    let (parts, mut recv) = resp.into_parts();
    let body_stream = futures_util::stream::poll_fn(move |cx| {
        // guard 随 body 存活，body 结束/丢弃时归还槽位。
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
    // 每次开流刷新连接空闲期。
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
    // 流真正建出才计入在途；ready() 前的配额等待不占槽位。
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
/// 请求体泵：按对端窗口分片发送，客户端断开弃流不补 EOS。
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

/// 镜像腿共享客户端（进程内单例）：ALPN 出 h2 时 legacy 自动切 h2 驱动，连接多路复用。
pub fn mirror_client(log: &LogFn) -> &'static LegacyClient<MirrorConnector, BoxBody> {
    MIRROR_CLIENT.get_or_init(|| {
        let mut b = LegacyClient::builder(TokioExecutor::new());
        b.pool_max_idle_per_host(MIRROR_POOL_MAX_IDLE)
            .pool_idle_timeout(MIRROR_POOL_IDLE)
            // pool_idle_timeout 须配 pool_timer 才生效。
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .retry_canceled_requests(true)
            // h2 窗口顶到 2^31−1（默认 64KB 太窄）：新流一次灌满，窗口不预分配内存、背压靠 release_capacity。
            .http2_initial_stream_window_size(i32::MAX as u32)
            .http2_initial_connection_window_size(i32::MAX as u32);
        b.build(MirrorConnector { log: log.clone() })
    })
}
pub const MAX_REPLAY_BODY: usize = 1024 * 1024;
/// 客户端是否接受指定压缩编码：裸 token = 默认接受；q=0/0.0/0.000 = 明确拒绝。
fn accepts_token<B>(req: &hyper::Request<B>, token: &str) -> bool {
    let Some(v) = req
        .headers()
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    for item in v.split(',') {
        // 去空白 + 小写（"gzip ; q=0" 合法）。
        let item: String = item
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let Some(rest) = item.strip_prefix(token) else {
            continue;
        };
        if rest.is_empty() {
            return true; // 裸 token = 默认接受
        }
        let Some(params) = rest.strip_prefix(';') else {
            continue; // 前缀误中（"gzipx" 之于 "gzip"），跳过
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
        return true; // 有 token 无 q 参数 = 接受
    }
    false
}

/// 客户端是否接受 gzip：缓存分桶与强制压缩的判定之一。
pub fn accepts_gzip<B>(req: &hyper::Request<B>) -> bool {
    accepts_token(req, "gzip")
}

/// 客户端是否接受 br（Brotli，比 gzip 小约 16%）。
pub fn accepts_brotli<B>(req: &hyper::Request<B>) -> bool {
    accepts_token(req, "br")
}

/// 编码档：br 优先、gzip 兜底、否则 identity；强制编码与缓存解析同源。
pub fn encoding_bucket<B>(req: &hyper::Request<B>) -> &'static str {
    if accepts_brotli(req) {
        "br"
    } else if accepts_gzip(req) {
        "gzip"
    } else {
        "identity"
    }
}

/// 重写上游请求：绝对 URL 化 + 剥代理头；嗅探型 host 强制压缩协商。
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
    // 嗅探型 host（github.com/api.github.com）强制压缩协商。
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
    // 仅客户端声明接受时强制双档 br,gzip（curl/git 无解压能力）。
    if sniffed {
        let forced = if accepts_brotli(req) && accepts_gzip(req) {
            Some("br, gzip")
        } else if accepts_brotli(req) {
            Some("br")
        } else if accepts_gzip(req) {
            Some("gzip")
        } else {
            None
        };
        if let Some(enc) = forced {
            out = out.header("accept-encoding", enc);
        }
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
 
