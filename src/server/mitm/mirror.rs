//! 镜像链：内容域回落 + 图片链 TTFB 校准 + 凭据防护；派发走 ECT，清场断流交客户端重发。
use super::merge::{self, MergeBody};
use super::path_of;
use super::quiet;
use crate::pool;
use crate::server::protocol::{self, BoxBody};
use crate::server::upstream;
use crate::util::{now_ms, LogFn};
use bytes::Bytes;
use http::Method;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

const MIRROR_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// 直连分段的响应头预算：好 IP 建连 0.6s、首包再 1s；超过 2s 基本是坏 IP，
/// 等它只会把整条下载拖住，不如立刻记坏、改走镜像。
const DIRECT_SEG_HEAD: Duration = Duration::from_secs(2);
const MIRROR_CHAIN_CAP: usize = 5;
/// 失败降权窗；全体都在窗内则放开过滤。
const MIRROR_FAIL_WINDOW_MS: u64 = 45_000;
/// 开放区间/无 Range 的体积假设，仅影响派发权重。
const ASSUMED_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
/// 评估缓存的最低存活门槛：流活满这么久才值得记一条样本。
const SAMPLE_TIME_FLOOR_MS: u64 = 100;
/// 预热：响应头到达后先跑这么久，让慢启动过去，这段不计入速度。
const WARMUP_MS: u64 = 100;
/// 测量窗口：预热结束后取这么长的吞吐当分数。100ms 分不出 6MB/s 和 300KB/s——
/// 那测的是首包反应；500ms 窗口慢家也有 150KB 样本，快家有 3MB，排序不会错。
const MEASURE_MS: u64 = 500;

/// 运行期窗口：有流在跑时，每这么久按「本镜像全流合计字节 ÷ 实际耗时」更新一次分数。
/// 接的活越多分数越贴近真实总吞吐，ECT 才会跟着涨——否则快的那家被压到几百 KB/s，
/// 分数还停在单流峰值，补发会一直往它身上堆。
const RATE_WINDOW_MS: u64 = 500;

/// 每面镜像的记账：在途字节/流数、速度分(0=未交卷)、失败与采样时刻、清场纪元。
#[derive(Default)]
pub(super) struct MirrorLoad {
    pub(super) in_flight_bytes: AtomicU64,
    pub(super) in_flight_streams: AtomicU64,
    /// 这家的吞吐：有流在跑时按窗口跟着实测走，没有流就停在最后一次。
    pub(super) speed_ewma: AtomicU64,
    /// 大文件交付字节的镜像级累计（所有流合并），窗口速率的分子。
    bytes_total: AtomicU64,
    /// 窗口基线：(字节, 时刻)。`win_base_ms == 0` = 当前没有流在跑，下一帧重新起算。
    win_base_bytes: AtomicU64,
    win_base_ms: AtomicU64,
    pub(super) last_fail_ms: AtomicU64,
    pub(super) last_sample_ms: AtomicU64,
    pub(super) cull_epoch: AtomicU64,
    /// 镜像 URL(评估缓存键; mirror_load 创建时填)。
    url: String,
}

static MIRROR_LOAD: LazyLock<Mutex<HashMap<String, Arc<MirrorLoad>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn mirror_load(mirror: &str) -> Arc<MirrorLoad> {
    let mut g = MIRROR_LOAD.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(mirror.to_string())
        .or_insert_with(|| {
            Arc::new(MirrorLoad {
                url: mirror.to_string(),
                ..Default::default()
            })
        })
        .clone()
}

/// 供直连腿(mod.rs)记账：直连候选与镜像共用同一张负载表。
pub(super) fn mirror_load_for(mirror: &str) -> Arc<MirrorLoad> {
    mirror_load(mirror)
}

/// 直连候选的记账键(mod.rs 组装 DirectLeg 前后共用)。
pub(super) fn direct_load_key(chain_host: &str) -> String {
    format!("direct/{chain_host}")
}

/// 运行期窗口结算：有流在跑就按「本窗全镜像交付字节 ÷ 实际耗时」更新分数。
/// 一个窗口只让一条流结算（CAS 抢占），重复调用直接返回。
/// 没有帧就不会走到这里——待机镜像的分数自然停在最后一次，不需要额外冻结逻辑。
fn settle_window(load: &MirrorLoad) {
    let now = now_ms();
    let base = load.win_base_ms.load(Ordering::Relaxed);
    if base == 0 {
        // 待机转忙：从第一帧起算，拨号和待机时长都不进分母。
        if load
            .win_base_ms
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            load.win_base_bytes
                .store(load.bytes_total.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        return;
    }
    let dt = now.saturating_sub(base);
    if dt < RATE_WINDOW_MS {
        return;
    }
    if load
        .win_base_ms
        .compare_exchange(base, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return; // 这一窗刚被别的流结算过
    }
    let total = load.bytes_total.load(Ordering::Relaxed);
    let prev = load.win_base_bytes.load(Ordering::Relaxed);
    load.win_base_bytes.store(total, Ordering::Relaxed);
    let bytes = total.saturating_sub(prev);
    if bytes == 0 {
        return; // 这一窗没数据：保留上次分数，不写成 0
    }
    load.speed_ewma.store(
        (bytes.saturating_mul(1000) / dt.max(1)).max(1),
        Ordering::Relaxed,
    );
    load.last_sample_ms.store(now, Ordering::Relaxed);
}

/// 按 head_at 起算的全片均速落分；返回分数供评估缓存记账。
fn store_probe_score(load: &MirrorLoad, bytes: u64, us: u64) -> u64 {
    if bytes == 0 || us == 0 {
        return 0;
    }
    let score = (bytes * 1_000_000 / us).max(1);
    load.speed_ewma.store(score, Ordering::Relaxed);
    load.last_sample_ms.store(now_ms(), Ordering::Relaxed);
    // 链序按速度重排落盘: 链头恒为实测最快(IDM 首片/非下载器直接受益)。
    resort_throttled(&load.url);
    score
}

/// 按速度降序重排链；无分/失败窗者保持原相对顺序缀尾（稳定排序，幂等）。
fn speed_sorted_chain(chain: &[String], speed_of: &dyn Fn(&str) -> u64) -> Vec<String> {
    let mut idx: Vec<usize> = (0..chain.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(speed_of(&chain[i])));
    idx.into_iter().map(|i| chain[i].clone()).collect()
}

/// 取出含该镜像的全部大文件链（一个镜像同挂三条，漏一条就永不更新）。
fn big_chains_with<'a>(
    chains: &'a HashMap<String, Vec<String>>,
    url: &str,
) -> Vec<(&'a String, &'a Vec<String>)> {
    chains
        .iter()
        .filter(|(h, c)| pool::route::is_big_file_host(h.as_str()) && c.iter().any(|m| m == url))
        .collect()
}

/// 重排节流：链序只影响探测顺序、并列轮转和失败兜底，晚一秒无代价；每帧重排却要复制整张链表。
const RESORT_MIN_INTERVAL_MS: u64 = 1000;
static LAST_RESORT_MS: AtomicU64 = AtomicU64::new(0);

fn resort_throttled(scored_url: &str) {
    let now = now_ms();
    let last = LAST_RESORT_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < RESORT_MIN_INTERVAL_MS {
        return;
    }
    // 抢占: 并发写分时只有一个线程进重排, 其余直接返回。
    if LAST_RESORT_MS
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    resort_chain_by_speed(scored_url);
}

/// 按最新速度重排该镜像所属的大文件链并落盘；小文件链序归校准管，这里不碰。
fn resort_chain_by_speed(scored_url: &str) {
    let chains = pool::mirror_chains_snapshot();
    let targets = big_chains_with(&chains, scored_url);
    if targets.is_empty() {
        return;
    }
    let now = now_ms();
    let speed_of = |m: &str| -> u64 {
        let ld = mirror_load(m);
        let lf = ld.last_fail_ms.load(Ordering::Relaxed);
        let failed = lf != 0 && now.saturating_sub(lf) < MIRROR_FAIL_WINDOW_MS;
        if failed {
            0
        } else {
            ld.speed_ewma.load(Ordering::Relaxed)
        }
    };
    for (host, chain) in targets {
        let new_chain = speed_sorted_chain(chain, &speed_of);
        pool::set_mirror_chain(host, &new_chain, "测速");
    }
}

/// 记账守卫：派发记在途、逐帧归还、Drop 清残余；归还封顶于记账额，采样走原始字节。
pub(super) struct LoadGuard {
    load: Arc<MirrorLoad>,
    /// 大文件机器标记: false = 小文件流, 与速度分/在途/失败窗/评估缓存零接触。
    big: bool,
    charged: u64,
    delivered: u64,
    raw_delivered: u64,
    /// head_at 时的 raw_delivered 基准(全片均速的字节分母起点)。
    head_bytes: u64,
    /// 体流起点(响应头到达)：探测判分用全片体速率, 不随区间采样重置。
    head_at: Instant,
    /// 大文件链且镜像尚无速度样本 = 本流是探测片(小文件流恒 false)。
    pub(super) is_probe: bool,
    /// 测量窗口起点：(时刻, 起点字节)。满 WARMUP_MS 时记一次。
    measure_from: Option<(Instant, u64)>,
    /// 已交卷：分数只写一次，之后冻结。
    measured: bool,
    /// 切片段传输起点（收到 206 的时刻，不含建连）：段结束时据此打实测吞吐。
    seg_start: Option<Instant>,
    /// 首包时刻：首包与收尾的差值能分清"握手慢"和"传输慢"。
    seg_first: Option<Instant>,
}

impl LoadGuard {
    /// big=false = 小文件流: 零充值零归还零采样, 与大文件机器绝对解耦。
    pub(super) fn charge(load: Arc<MirrorLoad>, new_bytes: u64, big: bool) -> Self {
        let charged = if big { new_bytes } else { 0 };
        if big {
            load.in_flight_bytes.fetch_add(charged, Ordering::Relaxed);
            load.in_flight_streams.fetch_add(1, Ordering::Relaxed);
        }
        let is_probe = big && load.speed_ewma.load(Ordering::Relaxed) == 0;
        LoadGuard {
            load,
            big,
            charged,
            delivered: 0,
            raw_delivered: 0,
            head_bytes: 0,
            head_at: Instant::now(),
            is_probe,
            measure_from: None,
            measured: false,
            seg_start: None,
            seg_first: None,
        }
    }

    /// 切片段：记下传输起点（响应头到达的时刻），段结束据此打吞吐。
    pub(super) fn segment_from(mut self, t: Instant) -> Self {
        self.seg_start = Some(t);
        self
    }

    /// 交付一帧：按记账额归还(封顶防下溢)，原始字节照常累计；满 100ms 即按全片均速落分。
    pub(super) fn on_frame(&mut self, n: u64) {
        if n > 0 && self.seg_first.is_none() {
            self.seg_first = Some(Instant::now());
        }
        let credit = n.min(self.charged.saturating_sub(self.delivered));
        self.delivered += credit;
        self.raw_delivered += n;
        if credit > 0 {
            self.load
                .in_flight_bytes
                .fetch_sub(credit, Ordering::Relaxed);
        }
        if !self.big {
            return;
        }
        // 镜像级累计：ECT 的分母是这家的总吞吐，不是某一条流自己的均速。
        self.load.bytes_total.fetch_add(n, Ordering::Relaxed);
        settle_window(&self.load);
        // 探测流只负责冷启动的初值；之后的分数由窗口在运行中持续更新。
        if !self.is_probe || self.measured {
            return;
        }
        // 预热：先跑满 WARMUP_MS，这段是慢启动，不计入速度。
        let Some((t0, b0)) = self.measure_from else {
            if self.head_at.elapsed() >= Duration::from_millis(WARMUP_MS) {
                self.measure_from = Some((Instant::now(), self.raw_delivered));
            }
            return;
        };
        // 窗口满才交卷：取这 MEASURE_MS 内的吞吐，不看首包反应。
        if t0.elapsed() < Duration::from_millis(MEASURE_MS) {
            return;
        }
        let bytes = self.raw_delivered.saturating_sub(b0);
        if bytes == 0 {
            self.measured = true; // 窗口内一个字节都没有：不记分，等下次
            return;
        }
        store_probe_score(&self.load, bytes, MEASURE_MS * 1000);
        self.measured = true;
    }

    /// 响应头到达时重置测速时钟：建连等待只算墙钟，不进速度样本（否则快镜像被稀释得更狠）。
    pub(super) fn restart_mark(&mut self) {
        self.head_at = Instant::now();
        self.head_bytes = self.raw_delivered;
    }
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        if !self.big {
            return; // 小文件流: 零充值零归还, 与大文件机器零接触。
        }
        // 探测片终值：全片均速定稿，被清场提前断流的也在此记分；活不满 100ms 的不记。
        if self.is_probe && !self.measured {
            let since_bytes = self.raw_delivered - self.head_bytes;
            let since_us = self.head_at.elapsed().as_micros() as u64;
            if since_us >= SAMPLE_TIME_FLOOR_MS * 1000 && since_bytes > 0 {
                let score = store_probe_score(&self.load, since_bytes, since_us);
                // 评估缓存只吃终值：首帧的慢启动读数只用于当次派发，不能用来判镜像去留。
                pool::mirror_stats::record(&self.load.url, score);
            }
        }
        let residual = self.charged.saturating_sub(self.delivered);
        if residual > 0 {
            self.load
                .in_flight_bytes
                .fetch_sub(residual, Ordering::Relaxed);
        }
        // 流数随流终结归位(正常读完/客户端断开/清场断流全走这里)。
        // 最后一条流关闭窗口：待机期间不累计时间，下个忙期从第一帧重新起算。
        if self.load.in_flight_streams.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.load.win_base_ms.store(0, Ordering::Relaxed);
        }
    }
}

/// ECT 绝对最小者胜，无容差；完全相等才看流数、再相等才轮转。失败窗内的跳过，全在窗内则放开。
fn pick_mirror(chain: &[String], new_bytes: u64) -> usize {
    let now = now_ms();
    let loads: Vec<Arc<MirrorLoad>> = chain.iter().map(|m| mirror_load(m)).collect();
    // ECT 取毫秒；.max(1) 是防御：零样本的候选 ECT 无穷大，稳定态里垫底。
    let ect_of = |ld: &MirrorLoad| -> u64 {
        let speed = ld.speed_ewma.load(Ordering::Relaxed).max(1);
        ld.in_flight_bytes
            .load(Ordering::Relaxed)
            .saturating_add(new_bytes)
            * 1000
            / speed
    };

    let healthy = |ld: &MirrorLoad, allow_recent_failures: bool| -> bool {
        allow_recent_failures || {
            let lf = ld.last_fail_ms.load(Ordering::Relaxed);
            lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS
        }
    };
    for allow_recent_failures in [false, true] {
        let elig: Vec<usize> = (0..loads.len())
            .filter(|&i| healthy(&loads[i], allow_recent_failures))
            .collect();
        if elig.is_empty() {
            continue;
        }
        // 绝对最小; 完全相等才二级判据。
        let best = elig
            .iter()
            .map(|&i| ect_of(&loads[i]))
            .min()
            .unwrap_or(u64::MAX);
        let tied: Vec<usize> = elig
            .into_iter()
            .filter(|&i| ect_of(&loads[i]) == best)
            .collect();
        if tied.len() == 1 {
            return tied[0];
        }
        // 完全相等: 在途流数最少者胜; 流数也相同才轮转均摊。
        let min_streams = tied
            .iter()
            .map(|&i| loads[i].in_flight_streams.load(Ordering::Relaxed))
            .min()
            .unwrap_or(0);
        let fewest: Vec<usize> = tied
            .into_iter()
            .filter(|&i| loads[i].in_flight_streams.load(Ordering::Relaxed) == min_streams)
            .collect();
        if fewest.len() == 1 {
            return fewest[0];
        }
        let n = TIE_ROTATOR.fetch_add(1, Ordering::Relaxed);
        return fewest[(n % fewest.len() as u64) as usize];
    }
    0
}

/// 轮转计数器：并列候选间均摊。
static TIE_ROTATOR: AtomicU64 = AtomicU64::new(0);

/// 探测轮游标：并发派发下连续领取必命中不同候选(连续整数 mod n 两两不同)。
static PROBE_CURSOR: AtomicU64 = AtomicU64::new(0);

/// 探测轮选家：未交卷且健康的候选按原子游标轮转领取，并发分片天然一片一家；没有则交回 ECT。
fn probe_pick(candidates: &[String]) -> Option<usize> {
    let now = now_ms();
    let unprobed: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            let ld = mirror_load(m);
            ld.last_sample_ms.load(Ordering::Relaxed) == 0 && {
                let lf = ld.last_fail_ms.load(Ordering::Relaxed);
                lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS
            }
        })
        .map(|(i, _)| i)
        .collect();
    if unprobed.is_empty() {
        return None;
    }
    let n = PROBE_CURSOR.fetch_add(1, Ordering::Relaxed);
    Some(unprobed[(n % unprobed.len() as u64) as usize])
}

fn walk_order(chain_len: usize, start: usize, limit: usize) -> Vec<usize> {
    if chain_len == 0 {
        return Vec::new();
    }
    (0..chain_len)
        .map(|i| (start + i) % chain_len)
        .take(limit)
        .collect()
}
/// cap 窗口没轮到直连时把它追加为最后一棒；已在列表或刚失败的不追加。
fn append_direct_if_missed(
    order: &mut Vec<usize>,
    direct_idx: usize,
    last_fail_ms: u64,
    now_ms: u64,
) {
    if order.contains(&direct_idx) {
        return;
    }
    if last_fail_ms != 0 && now_ms.saturating_sub(last_fail_ms) < MIRROR_FAIL_WINDOW_MS {
        return;
    }
    order.push(direct_idx);
}

/// bytes=a-b → b-a+1；开放区间/无头/畸形按假设值。派发记账与直连腿共用。
pub(super) fn range_bytes(range: Option<&str>) -> u64 {
    let Some(spec) = range.and_then(|r| r.trim().strip_prefix("bytes=")) else {
        return ASSUMED_REQUEST_BYTES;
    };
    let first = spec.split(',').next().unwrap_or("").trim();
    match first.split_once('-') {
        Some((a, b)) => match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
            (Ok(lo), Ok(hi)) if hi >= lo => hi - lo + 1,
            _ => ASSUMED_REQUEST_BYTES,
        },
        None => ASSUMED_REQUEST_BYTES,
    }
}

/// 非 3xx、非 HTML；带 Range 必须 206；304 无正文放行。
/// `allow_full`：探测轮专用——上游忽略 Range 回 200 全量时放行，body 由调用方当单流接管。
fn validate_mirror_response(
    had_range: bool,
    status: u16,
    content_type: &str,
    allow_full: bool,
) -> Result<(), String> {
    if status == 304 {
        return Ok(());
    }
    let ct = content_type.to_lowercase();
    if had_range && status != 206 && !(allow_full && status == 200) {
        return Err(format!("状态 {status}(请求带 Range, 未回 206)"));
    }
    if status >= 300 || ct.contains("text/html") {
        return Err(format!("状态 {status}"));
    }
    Ok(())
}

// ---- 清场：探测交卷后严劣于链内最快者让位, 在途断流交客户端重发 ----

struct CullState {
    body: BoxBody,
    guard: LoadGuard,
    load: Arc<MirrorLoad>,
    peers: Vec<Arc<MirrorLoad>>,
    my_epoch: u64,
    culled: bool,
    label: String,
    mirror: String,
    log: LogFn,
}

/// 段收尾一行：多少字节 / 多少毫秒 / 合多少 MB/s。
/// 日志此前只有“谁胜出”没有“跑多快”，判不出直连是真快还是只是抢到了位置。
fn log_seg_line(guard: &mut LoadGuard, label: &str, mirror: &str, log: &LogFn, note: &str) {
    let Some(t0) = guard.seg_start.take() else {
        return;
    };
    // 建连耗时 = 打点时刻 − charge 时刻（charge 在发请求之前，段路径不重置表）。
    let dial = t0.saturating_duration_since(guard.head_at).as_millis();
    let ms = t0.elapsed().as_millis().max(1);
    let mb = guard.raw_delivered as f64 / 1_048_576.0;
    // 首包 = 拿到响应头之后多久见到第一块数据；没有首包就打 0。
    let first = guard
        .seg_first
        .map(|t| t.saturating_duration_since(t0).as_millis())
        .unwrap_or(0);
    (log)(&format!(
        "[段] {label} {mirror} {mb:.1}MB / {ms}ms = {:.2}MB/s (建连 {dial}ms, 首包 {first}ms){note}",
        mb * 1000.0 / ms as f64
    ));
}

fn log_seg_end(st: &mut CullState, note: &str) {
    log_seg_line(&mut st.guard, &st.label, &st.mirror, &st.log, note);
}

/// 切片段只记账、只打吞吐，不判掐：慢段由合并层缩边界让位，掐了就是个洞。
fn account_seg(
    body: BoxBody,
    guard: LoadGuard,
    label: String,
    mirror: String,
    log: LogFn,
) -> BoxBody {
    let st = (body, guard, label, mirror, log);
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        match http_body_util::BodyExt::frame(&mut st.0).await {
            Some(Ok(frame)) => {
                let n = frame.data_ref().map(|d| d.len() as u64).unwrap_or(0);
                st.1.on_frame(n);
                Some((Ok(frame), st))
            }
            Some(Err(e)) => {
                log_seg_line(&mut st.1, &st.2, &st.3, &st.4, " (上游断流)");
                Some((Err(e), st))
            }
            None => {
                log_seg_line(&mut st.1, &st.2, &st.3, &st.4, "");
                None
            }
        }
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}

/// 清场监视(仅带 Range 的流)：本镜像被盖纪元即断流；探测流交分后严劣于链内最快者时盖纪元。
fn cull_watched_body(
    body: BoxBody,
    guard: LoadGuard,
    load: Arc<MirrorLoad>,
    peers: Vec<Arc<MirrorLoad>>,
    label: String,
    mirror: String,
    log: LogFn,
) -> BoxBody {
    let my_epoch = load.cull_epoch.load(Ordering::Relaxed);
    let st = CullState {
        body,
        guard,
        load,
        peers,
        my_epoch,
        culled: false,
        label,
        mirror,
        log,
    };
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        // 纪元不匹配: 本镜像已被清场(含本流上一帧触发的让位), 断流重发。
        if st.load.cull_epoch.load(Ordering::Relaxed) != st.my_epoch {
            log_seg_end(&mut st, " (清场断流)");
            return Some((
                Err(std::io::Error::other("镜像已清场让位, 断流交客户端重发")),
                st,
            ));
        }
        match http_body_util::BodyExt::frame(&mut st.body).await {
            Some(Ok(frame)) => {
                let n = frame.data_ref().map(|d| d.len() as u64).unwrap_or(0);
                st.guard.on_frame(n);
                // 探测交分自检: 本镜像速度严格小于链内已交卷最大者 → 让位。
                if !st.culled && st.guard.is_probe {
                    let my = st.load.speed_ewma.load(Ordering::Relaxed);
                    let top = st
                        .peers
                        .iter()
                        .map(|p| p.speed_ewma.load(Ordering::Relaxed))
                        .max()
                        .unwrap_or(0);
                    if my > 0 && top > my {
                        st.culled = true;
                        st.load.cull_epoch.fetch_add(1, Ordering::Relaxed);
                        (st.log)(&format!(
                            "[清场] {} {} 探测交分 {}KB/s 严劣于链内最快 {}KB/s, 在途让位重发",
                            st.label,
                            st.mirror,
                            my / 1024,
                            top / 1024
                        ));
                    }
                }
                Some((Ok(frame), st))
            }
            Some(Err(e)) => {
                log_seg_end(&mut st, " (上游断流)");
                Some((Err(e), st))
            }
            None => {
                log_seg_end(&mut st, "");
                None
            }
        }
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}

/// 小文件链限前 5 家，大文件全链。
fn mirror_chain_cap(host: &str) -> Option<usize> {
    (!pool::route::is_big_file_host(host)).then_some(MIRROR_CHAIN_CAP)
}

/// 直连腿的注入接口：拨号与记账由 mod.rs 组装，这里只管 ECT 派发与失败降权。
pub(super) struct DirectLeg<'a> {
    pub fetch: std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<hyper::Response<BoxBody>, String>> + Send + 'a>,
    >,
}

pub(super) async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    direct: DirectLeg<'_>,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    // 凭据查询串等价 bearer，交第三方镜像即外泄——标记后剥空镜像，仅派直连。
    let cred_locked = out.uri().query().is_some_and(has_credential_query);
    let orig_url = format!(
        "https://{host}{}",
        out.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default()
    );
    let path = path_of(out.uri());
    // release 附件走专属链；URL 仍用原 host（镜像自己跟随 302 落点）。
    let chain_host = pool::route::mirror_chain_host(host, &path);
    if chain_host != host && quiet::first_time("chain", host) {
        (log)(&format!(
            "[镜像] {host}{path} 归属链 {chain_host}（不用 {host} 自己的链）"
        ));
    }
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let cond = out
        .headers()
        .get("if-none-match")
        .or_else(|| out.headers().get("if-modified-since"))
        .and_then(|v| v.to_str().ok());
    if let Some(r) = range.filter(|_| quiet::first_time("range", host)) {
        (log)(&format!("[镜像] {host}{path} 客户端 Range: {r}"));
    }
    if let Some(c) = cond {
        (log)(&format!("[镜像] {host}{path} 客户端条件请求: {c}"));
    }
    // 凭据串请求：签名 URL 不落第三方，除非镜像被标记为可信；全不可信则剥空仅直连。
    let chain = if cred_locked {
        let trusted_set = crate::settings::trusted_mirrors();
        let trusted: Vec<String> = pool::mirror_chain(chain_host)
            .into_iter()
            .filter(|m| trusted_set.iter().any(|t| same_origin(m, t)))
            .collect();
        if trusted.is_empty() {
            (log)(&format!(
                "[镜像] {host}{path} 凭据查询串, 剥空镜像仅直连(防外泄; 可在工作台标记镜像「信任」以放行)"
            ));
            Vec::new()
        } else {
            (log)(&format!(
                "[镜像] {host}{path} 凭据查询串放行 {} 个可信镜像(签名将随 URL 交予第三方, 用户已授权)",
                trusted.len()
            ));
            trusted
        }
    } else {
        pool::mirror_chain(chain_host)
    };
    // 直连同台：直连以 direct/{host} 的身份参与 ECT；502 只在镜像与直连全灭时发生。
    let direct_key = format!("direct/{chain_host}");
    let mut candidates: Vec<String> = chain.clone();
    candidates.push(direct_key.clone());
    // 熔断只拦有镜像候选的请求: 凭据串剥空/零镜像时直连独走, 别连坐。
    if !chain.is_empty() && pool::MIRROR_BREAKER.open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(candidates.len())
        .min(candidates.len());
    let new_bytes = range_bytes(out.headers().get("range").and_then(|v| v.to_str().ok()));
    // 探测轮优先：有未交卷候选就一片一家实测，全员交卷后回 ECT；小文件不参与，只按链序从头试。
    // 单字节探片是下载器探路，按小文件走：链头直通，不探测、不记账、不切分。
    let big = pool::route::is_big_file_host(chain_host) && !merge::is_probe_range(range);
    // 镜像有富余时切片并发拉；条件不满足(探片/开区间/不支持 Range/无空闲镜像)交回单流。
    if big {
        match split_download(log, out, &orig_url, host, &candidates, info, replay).await {
            Ok(Some(resp)) => return Ok(resp),
            Ok(None) => {}
            Err(e) => (log)(&format!("[切片] {host}{path} 放弃切片({e}), 回单流")),
        }
    }
    let start = if big {
        match probe_pick(&candidates) {
            Some(i) => {
                (log)(&format!(
                    "[探测] {host}{path} 探测轮领取 {} (候选 {}/{}), 交卷后回 ECT",
                    candidates[i],
                    i + 1,
                    candidates.len()
                ));
                i
            }
            None => pick_mirror(&candidates, new_bytes),
        }
    } else {
        0
    };
    let mut direct = direct;
    let mut order = walk_order(candidates.len(), start, limit);
    append_direct_if_missed(
        &mut order,
        candidates.len() - 1,
        if big {
            mirror_load(&direct_key)
                .last_fail_ms
                .load(Ordering::Relaxed)
        } else {
            0
        },
        now_ms(),
    );
    for i in order {
        let m = candidates[i].as_str();
        // 直连候选：拨号/游标/连接池/记账包装全在 fetch future 内(mod.rs 组装)。
        if m == direct_key {
            let t0 = Instant::now();
            match direct.fetch.as_mut().await {
                Ok(mut resp) => {
                    resp.extensions_mut().insert("direct");
                    if big {
                        mirror_load(&direct_key)
                            .last_fail_ms
                            .store(0, Ordering::Relaxed);
                    }
                    (log)(&format!(
                        "[直连] {host}{path} {}({}ms), 候选 {}/{}",
                        if big { "ECT 胜出" } else { "链序首位" },
                        t0.elapsed().as_millis(),
                        i + 1,
                        candidates.len()
                    ));
                    pool::MIRROR_BREAKER.clear(chain_host);
                    return Ok(resp);
                }
                Err(e) => {
                    if big {
                        mirror_load(&direct_key)
                            .last_fail_ms
                            .store(now_ms(), Ordering::Relaxed);
                    }
                    (log)(&format!(
                        "[直连] {host}{path} 失败({e}, {}ms), 链内下一个",
                        t0.elapsed().as_millis()
                    ));
                    continue;
                }
            }
        }
        let req = match mirror_request(out, m, &orig_url) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 请求构造失败({e}), 链内下一个"));
                continue;
            }
        };
        let mut guard = LoadGuard::charge(mirror_load(m), new_bytes, big);
        let t0 = Instant::now();
        match mirror_do(req, m, log).await {
            Ok(resp) => {
                // 头已到：码表重跑，建连/等待耗时留在墙钟不进速度样本。
                guard.restart_mark();
                if big {
                    mirror_load(m).last_fail_ms.store(0, Ordering::Relaxed);
                }
                // 只在「首次用这家 / 换链 / 头过慢」时出声：正常派发不再每请求一条。
                let first = quiet::first_time("mirror", m);
                let rotated = quiet::mirror_rotated(chain_host, m);
                let ms = t0.elapsed().as_millis();
                if first || rotated || ms > 800 {
                    (log)(&format!(
                        "[镜像] {host}{path} via {m} (链位 {}/{len}, {} #{}, 头 {ms}ms)",
                        i + 1,
                        if big { "ECT起点" } else { "链序起点" },
                        start + 1,
                        len = chain.len(),
                    ));
                }
                pool::MIRROR_BREAKER.clear(chain_host);
                // 带 Range 挂清场监视(纪元核对+探测让位)；无 Range 只记账(浏览器断流是用户可见失败)。
                let (mut parts, body) = resp.into_parts();
                parts.extensions.insert("mirror");
                let body = if range.is_some() && big {
                    let peers: Vec<Arc<MirrorLoad>> = chain
                        .iter()
                        .filter(|x| x.as_str() != m)
                        .map(|x| mirror_load(x))
                        .collect();
                    cull_watched_body(
                        body,
                        guard,
                        mirror_load(m),
                        peers,
                        format!("{host}{path}"),
                        m.to_string(),
                        log.clone(),
                    )
                } else {
                    let body = http_body_util::BodyExt::map_frame(body, move |frame| {
                        if let Some(n) = frame.data_ref().map(|d| d.len() as u64) {
                            guard.on_frame(n);
                        }
                        frame
                    });
                    BoxBody::new(body)
                };
                return Ok(hyper::Response::from_parts(parts, body));
            }
            Err(e) => {
                if big {
                    mirror_load(m)
                        .last_fail_ms
                        .store(now_ms(), Ordering::Relaxed);
                }
                (log)(&format!(
                    "[镜像] {host} {m} 失败({e}, {}ms), 链内下一个",
                    t0.elapsed().as_millis()
                ));
            }
        }
    }
    // 纯直连耗尽(零镜像/凭据串剥空)不给链上熔断——镜像没参与，别连坐。
    if !chain.is_empty() {
        pool::MIRROR_BREAKER.set(chain_host);
    }
    let why = if cred_locked {
        "凭据串仅直连, 直连失败"
    } else {
        "镜像链全灭"
    };
    Err(format!("{host} {why}({chain_host} 候选 {limit} 个)"))
}
/// 无 Range 时探测文件总长：发 1 字节 Range，从 Content-Range 取分母。
enum Probe {
    /// 上游回了 206 + Content-Range：拿到了总长，可以切。
    Total(u64),
    /// 上游忽略 Range 直接回 200 全量：body 就是整份文件，直接当单流交出去，别丢。
    NotSliceable(hyper::Response<BoxBody>),
}

async fn probe_total(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<Probe, String> {
    let tag = if mirror.starts_with("direct/") {
        "direct"
    } else {
        "mirror"
    };
    let mut resp = if mirror.starts_with("direct/") {
        segment_direct(log, out, host, info, replay, 0, 1).await?
    } else {
        let mut req = mirror_request(out, mirror, orig_url)?;
        req.headers_mut().insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-0"),
        );
        mirror_do_probe(req, mirror, log).await?
    };
    if let Some(t) = merge::content_range_total(
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
    ) {
        return Ok(Probe::Total(t));
    }
    if resp.status() == http::StatusCode::OK {
        resp.extensions_mut().insert(tag);
        return Ok(Probe::NotSliceable(resp));
    }
    Err(format!(
        "{mirror} 未给 Content-Range 总长(回 {})",
        resp.status()
    ))
}

/// 不可切片标记：host+path → 时刻。10 分钟内同一 URL 不再为探测白跑一趟。
const UNSLICEABLE_TTL: Duration = Duration::from_secs(600);
static UNSLICEABLE: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

fn marked_unsliceable(key: &str) -> bool {
    UNSLICEABLE
        .lock()
        .unwrap()
        .get(key)
        .is_some_and(|t| t.elapsed() < UNSLICEABLE_TTL)
}

fn mark_unsliceable(key: String) {
    let mut g = UNSLICEABLE.lock().unwrap();
    if g.len() >= 256 {
        g.retain(|_, t| t.elapsed() < UNSLICEABLE_TTL);
    }
    g.insert(key, Instant::now());
}

/// 直连段请求：克隆原请求头换成本段 Range，再走直连腿。
/// release 的下载地址本身不放文件，会 302 到 release-assets——跟一跳，
/// 把 Range 带过去。跳转目标的 IP 与原 host 无关，用独立记账。
async fn segment_direct(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    s: u64,
    e: u64,
) -> Result<hyper::Response<BoxBody>, String> {
    let range = http::HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
        .map_err(|err| err.to_string())?;
    let mut req = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri())
        .body(protocol::empty_body())
        .map_err(|err| err.to_string())?;
    *req.headers_mut() = out.headers().clone();
    req.headers_mut().insert(http::header::RANGE, range.clone());
    strip_body_headers(&mut req);
    let mut resp = super::get_direct(log, &req, host, info, true, replay).await?;

    // 3xx：内容在别处。最多跟两跳（release 实测一跳到位）。
    let mut hops = 0;
    while resp.status().is_redirection() && hops < 2 {
        let Some(loc) = resp
            .headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        else {
            break;
        };
        let Ok(uri) = loc.parse::<http::Uri>() else {
            break;
        };
        let Some(next_host) = uri.host().map(str::to_string) else {
            break;
        };
        hops += 1;
        (log)(&format!("[切片] 直连 {host} 跳转到 {next_host}"));
        let mut req2 = hyper::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(protocol::empty_body())
            .map_err(|err| err.to_string())?;
        for (k, v) in req.headers() {
            if k.as_str().eq_ignore_ascii_case("host") {
                continue;
            }
            req2.headers_mut().insert(k.clone(), v.clone());
        }
        req2.headers_mut()
            .insert(http::header::RANGE, range.clone());
        let fresh = super::UpstreamInfo::default();
        resp = super::get_direct(log, &req2, &next_host, &fresh, true, replay).await?;
        (log)(&format!("[切片] 直连 {next_host} 回 {}", resp.status()));
    }
    Ok(resp)
}

/// 分段请求统一剥掉这两类头：压缩会把每段各压一遍拼起来就是坏数据，
/// 条件请求会让上游回 304 而段请求要的是实体。
fn strip_body_headers(req: &mut hyper::Request<BoxBody>) {
    for h in [
        http::header::ACCEPT_ENCODING,
        http::header::IF_NONE_MATCH,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_RANGE,
    ] {
        req.headers_mut().remove(h);
    }
}

/// 切片下载：一条请求按镜像数平均切段、并发拉，按边界合并回单条字节流。
/// 段数 = 空闲镜像数（候选 − 在途）；少于 2 段不切，交回单流派发。
/// 探片、开区间 Range、上游不支持 Range 一律退回单流。
async fn split_download(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    orig_url: &str,
    host: &str,
    candidates: &[String],
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<Option<hyper::Response<BoxBody>>, String> {
    if out.method() != http::Method::GET {
        return Ok(None); // HEAD/其他方法没有体可切
    }
    let path = out.uri().path().to_string();
    // 刚探过、上游明确不给 Range 的 URL：10 分钟内不再探测，直接走单流。
    let slice_key = format!("{host}{path}");
    if marked_unsliceable(&slice_key) {
        return Ok(None);
    }
    let now = now_ms();
    let healthy: Vec<&str> = candidates
        .iter()
        .filter(|m| {
            let lf = mirror_load(m).last_fail_ms.load(Ordering::Relaxed);
            lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS
        })
        .map(|m| m.as_str())
        .collect();
    // 空闲 = 此刻零在途的镜像数（不是流数总和：一家跑三条流也只算占一家）。
    let busy = healthy
        .iter()
        .filter(|m| mirror_load(m).in_flight_streams.load(Ordering::Relaxed) > 0)
        .count();
    let want = healthy.len().saturating_sub(busy);
    if want < 2 {
        return Ok(None); // 镜像已占满或本来就没几家：切了只是抢自己的份额
    }
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let (base, len, known_total) = match range {
        // 开区间/多区间/畸形：长度未知或语义不同，不切
        Some(_) => match merge::parse_range(range) {
            Some((a, Some(b))) if b >= a => (a, b - a + 1, None),
            _ => return Ok(None),
        },
        None => match probe_total(log, out, healthy[0], orig_url, host, info, replay).await {
            Ok(Probe::Total(t)) if t > 0 => (0, t, Some(t)),
            Ok(Probe::Total(_)) => return Ok(None),
            // 上游忽略 Range(回 200 全量)：探测那次的 body 就是整份文件，直接交出去，
            // 省掉「丢掉 + 重发单流」的一次完整往返（codeload 大归档正是这条路径）。
            Ok(Probe::NotSliceable(resp)) => {
                mark_unsliceable(slice_key.clone());
                (log)(&format!(
                    "[切片] {host}{path} 上游忽略 Range(回 200), 探测响应直接按单流交出"
                ));
                return Ok(Some(resp));
            }
            Err(e) => {
                (log)(&format!("[切片] {host}{path} 探测总长失败({e}), 回单流"));
                return Ok(None);
            }
        },
    };
    let segs = merge::split_even(base, len, want);
    if segs.len() < 2 {
        return Ok(None);
    }
    (log)(&format!(
        "[切片] {host}{path} 切 {} 段(候选 {} 家, 空闲 {want}), 并发拉取",
        segs.len(),
        healthy.len()
    ));
    // 段优先派给最空闲的镜像；同负载时保持链序（稳定排序）。否则会全压在最快的几家人身上，
    // 闲置的镜像照样闲着，切片就白切了。
    let mut pick: Vec<&str> = healthy.clone();
    pick.sort_by_key(|m| mirror_load(m).in_flight_streams.load(Ordering::Relaxed));
    // 有镜像兜底才给直连设 2s 预算；没有镜像（用户没配 / 链全灭）时直连是唯一的路，
    // 这时不能掐它，交给它按 IP 表自己换、自己等。
    let has_mirror = healthy.iter().any(|m| !m.starts_with("direct/"));
    let futs = segs.iter().enumerate().map(|(i, &(s, e))| {
        let m = pick[i % pick.len()];
        async move {
            let guard = LoadGuard::charge(mirror_load(m), e - s, true);
            let is_direct = m.starts_with("direct/");
            let got = if is_direct {
                // 直连分段：有兜底时 2s 拿不到响应头就当这条路是死的——好 IP 建连 0.6s、
                // 首包再 1s，超过 2s 基本是坏 IP，等它只会拖住整条下载。
                let attempt = segment_direct(log, out, host, info, replay, s, e);
                if has_mirror {
                    match tokio::time::timeout(DIRECT_SEG_HEAD, attempt).await {
                        Ok(r) => r,
                        Err(_) => Err("直连 2s 内没给响应头".to_string()),
                    }
                } else {
                    attempt.await
                }
            } else {
                match mirror_request(out, m, orig_url) {
                    Ok(mut req) => {
                        let hv = http::HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
                            .map_err(|err| err.to_string())?;
                        req.headers_mut().insert(http::header::RANGE, hv);
                        strip_body_headers(&mut req);
                        mirror_do(req, m, log).await
                    }
                    Err(err) => Err(err),
                }
            };
            // 直连没打出 206（超时/4xx/连不上）：这个 IP 记一次失败，ECT 下次绕开它。
            if is_direct
                && !matches!(got.as_ref(), Ok(r) if r.status() == http::StatusCode::PARTIAL_CONTENT)
            {
                mirror_load(m)
                    .last_fail_ms
                    .store(now_ms(), Ordering::Relaxed);
            }
            match got {
                Ok(resp) if resp.status() == http::StatusCode::PARTIAL_CONTENT => {
                    let at = Instant::now();
                    Ok((guard.segment_from(at), at, resp))
                }
                Ok(resp) => {
                    // 4xx 时把正文前 200 字节带上：GitHub/Azure 会把原因写在正文里。
                    let status = resp.status();
                    let mut hint = String::new();
                    if status.is_client_error() {
                        let mut body = resp.into_body();
                        let mut got: Vec<u8> = Vec::new();
                        while got.len() < 200 {
                            match http_body_util::BodyExt::frame(&mut body).await {
                                Some(Ok(f)) => {
                                    if let Some(d) = f.data_ref() {
                                        got.extend_from_slice(d);
                                    }
                                }
                                _ => break,
                            }
                        }
                        hint = format!(
                            ": {}",
                            String::from_utf8_lossy(&got).replace(['\r', '\n'], " ")
                        );
                    }
                    Err(format!("{m} 不支持分段(回 {status}{hint})"))
                }
                Err(err) => Err(err),
            }
        }
    });
    let results = futures_util::future::join_all(futs).await;
    // 段响应里除逐跳头/分段头之外的头统一搬过来：content-disposition 决定保存的文件名，
    // etag/last-modified 决定缓存语义，少了客户端行为会变。
    let mut extra: Option<Vec<(http::HeaderName, http::HeaderValue)>> = None;
    let mut total = known_total;
    let mut bodies: Vec<(u64, u64, Instant, BoxBody)> = Vec::with_capacity(segs.len());
    let mut dead = 0usize;
    let mut failed: Vec<(u64, u64)> = Vec::new();
    for (i, r) in results.into_iter().enumerate() {
        let (s, e) = segs[i];
        let end = e - base;
        match r {
            Ok((guard, at, resp)) => {
                if extra.is_none() {
                    extra = Some(
                        resp.headers()
                            .iter()
                            .filter(|(k, _)| {
                                !matches!(
                                    k.as_str(),
                                    "content-range"
                                        | "content-length"
                                        | "transfer-encoding"
                                        | "connection"
                                        | "content-encoding"
                                )
                            })
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    );
                    total = total.or_else(|| {
                        merge::content_range_total(
                            resp.headers()
                                .get("content-range")
                                .and_then(|v| v.to_str().ok()),
                        )
                    });
                }
                let m = pick[i % pick.len()];
                let body = account_seg(
                    resp.into_body(),
                    guard,
                    format!("{host}{path}"),
                    m.to_string(),
                    log.clone(),
                );
                bodies.push((s - base, end, at, body));
            }
            Err(err) => {
                dead += 1;
                (log)(&format!(
                    "[切片] {host}{path} 段 [{s}..{e}) 失败({err}), 立刻补发"
                ));
                bodies.push((s - base, end, Instant::now(), protocol::empty_body()));
                failed.push((s - base, end));
            }
        }
    }
    if dead == segs.len() {
        return Ok(None); // 全灭：退回单流，别让一次切片失败毁掉整个请求
    }
    let total_hdr = total
        .map(|t| t.to_string())
        .unwrap_or_else(|| "*".to_string());
    let mut builder = hyper::Response::builder();
    builder = if range.is_some() {
        builder.status(http::StatusCode::PARTIAL_CONTENT).header(
            http::header::CONTENT_RANGE,
            format!("bytes {}-{}/{total_hdr}", base, base + len - 1),
        )
    } else {
        builder.status(http::StatusCode::OK)
    };
    if let Some(hs) = extra {
        for (k, v) in hs {
            builder = builder.header(k, v);
        }
    }
    builder = builder.header(http::header::CONTENT_LENGTH, len);
    // 起流收口成闭包：驱动只管"要 [from,to)"，怎么发由这里决定，也便于单测替换。
    let chain: Vec<String> = healthy.iter().map(|m| m.to_string()).collect();
    let (orig, host_s, log_s) = (orig_url.to_string(), host.to_string(), log.clone());
    let fetch: Fetch = Arc::new(move |from: u64, to: u64| {
        let (chain, orig, host_s, log_s) =
            (chain.clone(), orig.clone(), host_s.clone(), log_s.clone());
        Box::pin(async move { split_fetch(&chain, &orig, &host_s, base, from, to, &log_s).await })
    });
    let ctx = SplitCtx {
        fetch,
        host: host.to_string(),
        log: log.clone(),
    };
    let mut mb = MergeBody::new(bodies, len);
    // 开场就失败的段立刻排队补发：不等交付线走到它——那块往往在末尾，干等就是几秒。
    for (a, b) in failed {
        mb.queue_fill(a, b);
    }
    let body = drive_split(mb, ctx);
    builder.body(body).map(Some).map_err(|e| e.to_string())
}

/// 起一条拉 [from, to) 的新流。偏移相对区间起点，发出去要加 base。
async fn split_fetch(
    chain: &[String],
    orig_url: &str,
    host: &str,
    base: u64,
    from: u64,
    to: u64,
    log: &LogFn,
) -> Result<BoxBody, String> {
    // 按 ECT（在途字节 ÷ 实测速度）挑最小者。不能挑"最空闲"：
    // 刚断流的那家负载归零，正是最空闲的那个，补回去就是原地打转。
    let mirrors: Vec<String> = chain
        .iter()
        .filter(|m| !m.starts_with("direct/"))
        .cloned()
        .collect();
    if mirrors.is_empty() {
        return Err("无可用补发镜像".to_string());
    }
    let m = &mirrors[pick_mirror(&mirrors, to - from)];
    // 只有 GET 会走到切片（split_download 早退挡掉其它方法），补发一律 GET。
    let req = hyper::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{m}/{orig_url}"))
        .header(http::header::USER_AGENT, MIRROR_UA)
        .header(
            http::header::RANGE,
            format!("bytes={}-{}", base + from, base + to - 1),
        )
        .body(protocol::empty_body())
        .map_err(|e| e.to_string())?;
    let resp = mirror_do(req, m, log).await?;
    if resp.status() != http::StatusCode::PARTIAL_CONTENT {
        return Err(format!(
            "{m} 补发回 {} 而非 206 (host {host})",
            resp.status()
        ));
    }
    Ok(resp.into_body())
}

/// 起流函数的返回：一条从 from 拉到 to 的流。
type FetchFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<BoxBody, String>> + Send + Sync>>;
type Fetch = Arc<dyn Fn(u64, u64) -> FetchFuture + Send + Sync>;

/// 切片调度上下文：缺口、让位尾巴都往这里要新流。
struct SplitCtx {
    fetch: Fetch,
    host: String,
    log: LogFn,
}

/// 体检间隔：停滞是 5s 判据，500ms 看一眼足够，又不至于空转。
const SPLIT_TICK: Duration = Duration::from_millis(500);
/// 起流失败后的重试间隔：立刻重打同一家只会连撞同一堵墙。
const RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// 旁路起流的结果：成功就接上这条流，失败就排队重发。
enum Fetched {
    Ok {
        from: u64,
        to: u64,
        body: BoxBody,
    },
    /// ms = 这次起流本身花了多久（不含排队），用来分清"等排队"和"对方慢"。
    Err {
        from: u64,
        to: u64,
        err: String,
        ms: u128,
    },
}

/// 驱动循环被谁叫醒。
enum Wake {
    Fetched(Fetched),
    Frame(Option<Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>>),
    Tick,
}

fn apply_fetched(mb: &mut MergeBody, ctx: &SplitCtx, msg: Fetched) {
    match msg {
        Fetched::Ok { from, to, body } => {
            (ctx.log)(&format!(
                "[切片] {} [{from}..{to}) 起新流 ({}KB)",
                ctx.host,
                (to - from) / 1024
            ));
            mb.feed(from, to, Instant::now(), body);
        }
        Fetched::Err { from, to, err, ms } => {
            (ctx.log)(&format!(
                "[切片] {} [{from}..{to}) 起流失败({err}, {ms}ms)",
                ctx.host
            ));
            mb.retry_fill(from, to);
        }
    }
}

/// 切片驱动：发缺口、收停滞、让位慢段，其余时间只泵数据。
/// 起流走旁路任务：建连/等首包再久，也不挡泵数据、不挡下一次让位。
/// 补发没有全局次数上限——只要还在往前走就一直续，卡死才有上限。
fn drive_split(mb: MergeBody, ctx: SplitCtx) -> BoxBody {
    let (tx, rx) = tokio::sync::mpsc::channel::<Fetched>(8);
    // tx 每个状态机实例克隆一份：unfold 的闭包是 FnMut，不能把 tx 移出去。
    let stream = futures_util::stream::unfold(
        (mb, ctx, rx, Instant::now(), false),
        move |(mut mb, ctx, mut rx, t0, mut first)| {
            let tx = tx.clone();
            async move {
                loop {
                    if mb.exhausted() {
                        (ctx.log)(&format!(
                            "[切片] {} 连续 {} 次补发一个字节都没下到, 放弃",
                            ctx.host,
                            merge::MAX_DEAD_FILLS
                        ));
                        return Some((
                            Err(std::io::Error::other("切片补发连续失败")),
                            (mb, ctx, rx, t0, first),
                        ));
                    }
                    // 先收旁路回来的流，接上就能继续泵。
                    while let Ok(msg) = rx.try_recv() {
                        apply_fetched(&mut mb, &ctx, msg);
                    }
                    // 有活就派出去（不等）：起流多久都不影响下面的泵和体检。
                    while let Some((from, to)) = mb.take_fill() {
                        let fetch = ctx.fetch.clone();
                        let tx = tx.clone();
                        (ctx.log)(&format!(
                            "[切片] {} 派发补发 [{from}..{to}) ({}KB)",
                            ctx.host,
                            (to - from) / 1024
                        ));
                        tokio::spawn(async move {
                            let t = Instant::now();
                            let msg =
                                match tokio::time::timeout(MIRROR_HEAD_TIMEOUT, fetch(from, to))
                                    .await
                                {
                                    Ok(Ok(body)) => Fetched::Ok { from, to, body },
                                    Ok(Err(e)) => Fetched::Err {
                                        from,
                                        to,
                                        err: e,
                                        ms: t.elapsed().as_millis(),
                                    },
                                    Err(_) => Fetched::Err {
                                        from,
                                        to,
                                        err: "起流超时".to_string(),
                                        ms: t.elapsed().as_millis(),
                                    },
                                };
                            if matches!(msg, Fetched::Err { .. }) {
                                tokio::time::sleep(RETRY_BACKOFF).await;
                            }
                            let _ = tx.send(msg).await;
                        });
                    }
                    // 体检：停滞收尸、抢慢段。数据一直在流也要做——涓流不触发超时。
                    if mb.tick_due(Instant::now()) {
                        let now = Instant::now();
                        if mb.reap_stalled(now) {
                            (ctx.log)(&format!("[切片] {} 有段停滞, 尾巴转补发", ctx.host));
                            continue;
                        }
                        if let Some((from, to)) = mb.plan_cut(now) {
                            (ctx.log)(&format!(
                                "[切片] {} 慢段让位 [{from}..{to}) 交闲连接 ({}KB)",
                                ctx.host,
                                (to - from) / 1024
                            ));
                            continue;
                        }
                    }
                    // 盯数据，顺带定时醒来收旁路结果、做体检。
                    let wake = tokio::select! {
                        Some(msg) = rx.recv() => Wake::Fetched(msg),
                        r = tokio::time::timeout(SPLIT_TICK, std::future::poll_fn(|cx| {
                            hyper::body::Body::poll_frame(std::pin::Pin::new(&mut mb), cx)
                        })) => match r {
                            Ok(polled) => Wake::Frame(polled),
                            Err(_) => Wake::Tick,
                        },
                    };
                    match wake {
                        Wake::Fetched(msg) => {
                            apply_fetched(&mut mb, &ctx, msg);
                        }
                        Wake::Frame(Some(Ok(f))) => {
                            if !first && mb.sent() > 0 {
                                first = true;
                                (ctx.log)(&format!(
                                    "[切片] {} 首字节 {}ms (已交付 {}/{})",
                                    ctx.host,
                                    t0.elapsed().as_millis(),
                                    mb.sent(),
                                    mb.total()
                                ));
                            }
                            return Some((Ok(f), (mb, ctx, rx, t0, first)));
                        }
                        Wake::Frame(Some(Err(e))) => {
                            return Some((Err(e), (mb, ctx, rx, t0, first)))
                        }
                        Wake::Frame(None) => {
                            if mb.sent() >= mb.total() {
                                (ctx.log)(&format!(
                                    "[切片] {} 交付完成 {}ms",
                                    ctx.host,
                                    t0.elapsed().as_millis()
                                ));
                                return None;
                            }
                        }
                        Wake::Tick => {}
                    }
                }
            }
        },
    );
    BoxBody::new(http_body_util::StreamBody::new(stream))
}

fn mirror_request(
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
) -> Result<hyper::Request<BoxBody>, String> {
    let url = format!("{mirror}/{orig_url}");
    let mut builder = hyper::Request::builder().method(out.method()).uri(url);
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if upstream::is_hop_by_hop(&low)
            || matches!(
                low.as_str(),
                "cookie"
                    | "authorization"
                    | "proxy-authorization"
                    | "host"
                    | "referer"
                    | "user-agent"
            )
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    // CF 系镜像拦非浏览器 UA；剥原 UA 统一注入，防 builder 追加出两个 UA。
    builder = builder.header(
        http::header::USER_AGENT,
        http::HeaderValue::from_static(MIRROR_UA),
    );
    builder
        .body(protocol::empty_body())
        .map_err(|e| e.to_string())
}
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    mirror_do_inner(req, mirror, log, false).await
}

/// 探测专用：允许上游忽略 Range 回 200，把整份 body 交还调用方当单流用。
async fn mirror_do_probe(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    mirror_do_inner(req, mirror, log, true).await
}

async fn mirror_do_inner(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
    allow_full: bool,
) -> Result<hyper::Response<BoxBody>, String> {
    let had_range = req.headers().get("range").is_some();
    let client = upstream::mirror_client(log);
    let timed = tokio::time::timeout(MIRROR_HEAD_TIMEOUT, client.request(req));
    let resp = match timed.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("镜像响应头预算超时".to_string()),
    };
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    validate_mirror_response(had_range, resp.status().as_u16(), ct, allow_full)
        .map_err(|e| format!("{mirror} {e}"))?;
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(http_body_util::BodyExt::map_err(
        body,
        std::io::Error::other,
    ));
    Ok(hyper::Response::from_parts(parts, body))
}

/// 3xx/4xx = 镜像拒绝（不支持），超时/连接错误 = 失败；日志措辞要分清。
fn calib_fail_label(e: &str) -> &'static str {
    if e.contains("状态 ") {
        "不支持"
    } else {
        "失败"
    }
}

/// 同源判定：忽略大小写与尾斜杠后全等；前缀匹配会把 gh-proxy.org.evil.tld 当成自己人。
fn same_origin(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        s.trim().trim_end_matches('/').to_ascii_lowercase()
    }
    norm(a) == norm(b)
}

fn has_credential_query(query: &str) -> bool {
    query.split('&').any(|kv| {
        let name = kv.split('=').next().unwrap_or("").to_lowercase();
        name == "token"
            || name == "sig"
            || name == "signature"
            || name == "jwt"
            || name == "auth"
            || name == "access_token"
            || name == "session_token"
            || name == "awsaccesskeyid"
            || name == "key"
            || name == "api_key"
            || name == "apikey"
            || name == "secret"
            || name == "password"
            || name.starts_with("x-amz-")
    })
}

/// 仅小文件域。模板失效会让镜像全判"不支持"，改前先手测直连 200。
pub const CALIBRATE_TEMPLATES: &[(&str, &str)] = &[
    (
        "raw.githubusercontent.com",
        "https://raw.githubusercontent.com/torvalds/linux/master/README",
    ),
    (
        "gist.githubusercontent.com",
        "https://gist.githubusercontent.com/octocat/6cad326836d38bd3a7ae/raw/db9c55113504e46fa076e7df3a04ce592e2e86d8/hello_world.rb",
    ),
    (
        "avatars.githubusercontent.com",
        "https://avatars.githubusercontent.com/u/1?v=4&size=64",
    ),
    (
        "user-images.githubusercontent.com",
        "https://user-images.githubusercontent.com/3098702/171232313-daa606f1-8fd6-4b0f-a20b-2cb93c43d19b.png",
    ),
    (
        "media.githubusercontent.com",
        "https://media.githubusercontent.com/media/blooop/bencher/7e3a628e0e2768acb16c9d14630dd389075323bd/docs/evidence_animation_options/a_morph_differences.svg",
    ),
];
pub static CALIB_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static CALIB_REPORT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn last_calibrate_report() -> String {
    CALIB_REPORT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

pub fn set_calibrate_report(r: Option<String>) {
    if let Ok(mut g) = CALIB_REPORT.lock() {
        *g = r;
    }
}

/// CF 系镜像拦非浏览器 UA（裸 Mozilla/5.0 一律 403），镜像腿恒定浏览器 UA。
const MIRROR_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

fn mirror_get(uri: http::Uri) -> Result<hyper::Request<BoxBody>, String> {
    hyper::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("user-agent", MIRROR_UA)
        .header("accept", "*/*")
        .body(protocol::empty_body())
        .map_err(|e| e.to_string())
}

async fn calibrate_one(mirror: &str, tmpl: &str, log: &LogFn) -> Result<u16, String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let resp = mirror_do(mirror_get(uri)?, mirror, log).await?;
    Ok(resp.status().as_u16())
}

/// 毫秒小者优；失败项负数沉底。
fn rank_by_ttfb(rows: &mut [(String, i64)]) {
    rows.sort_by_key(|(_, ms)| (*ms < 0, ms.unsigned_abs()));
}

/// 逐 host 串行（同镜像服务多条链，跨链并发互相污染测量）。
pub async fn calibrate_chains(log: &LogFn) -> String {
    let chains = pool::mirror_chains_snapshot();
    let mut report = String::new();
    for (host, chain) in chains {
        if pool::route::is_big_file_host(&host) {
            continue; // 大文件域由 ECT 实时接管，不做合成测速
        }
        let Some((_, tmpl)) = CALIBRATE_TEMPLATES.iter().find(|(h, _)| *h == host) else {
            continue;
        };
        let mut rows: Vec<(String, i64)> = Vec::new();
        for m in &chain {
            let t0 = Instant::now();
            let res = calibrate_one(m, tmpl, log).await;
            let ms = t0.elapsed().as_millis() as i64;
            match res {
                Ok(st) => {
                    (log)(&format!("[校准] {host} {m} {ms}ms {st}"));
                    rows.push((m.clone(), ms));
                }
                Err(e) => {
                    (log)(&format!("[校准] {host} {m} {}({e})", calib_fail_label(&e)));
                    rows.push((m.clone(), -(ms.max(1))));
                }
            }
        }
        rank_by_ttfb(&mut rows);
        let new_chain: Vec<String> = rows.iter().map(|(m, _)| m.clone()).collect();
        let summary: Vec<String> = rows
            .iter()
            .map(|(m, v)| {
                if *v >= 0 {
                    format!("{}({}ms)", m.trim_start_matches("https://"), v)
                } else {
                    format!("{}(失败)", m.trim_start_matches("https://"))
                }
            })
            .collect();
        report.push_str(&format!("{host}\n  {}\n", summary.join(" -> ")));
        pool::set_mirror_chain(&host, &new_chain, "校准");
    }
    if report.is_empty() {
        "无可校准的镜像链".to_string()
    } else {
        report
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/mirror.rs"]
mod tests;
