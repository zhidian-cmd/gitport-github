//! 镜像链：内容域回落 + 图片链 TTFB 校准 + 凭据防护。
//! 大文件竞速：按候选数均分切段（测速只来自代理自己分的段）、慢段让位、补发按 ECT 挑家直到不再改善，故障/变慢无缝衔接。
use super::merge::{self, MergeBody};
use super::path_of;
use super::quiet;
use crate::config;
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
/// 直连按跳记响应头预算（每跳 2s，不罩整段）：release 要跟 302 两跳，罩全程会把好腿掐死。
const DIRECT_HOP_HEAD: Duration = Duration::from_secs(2);
/// 直连整段预算：≤2 跳 × 每跳 2s。没有镜像兜底时不设预算（直连是唯一的路）。
const DIRECT_SEG_TOTAL: Duration = Duration::from_secs(4);
const MIRROR_CHAIN_CAP: usize = 5;
/// 硬错误(拒连/RST/回包坏)的失败降权窗；全体都在窗内则放开过滤。
const MIRROR_FAIL_WINDOW_MS: u64 = 45_000;
/// 超时类失败的降权窗：慢不等于死，一次抖动别把腿踢出局太久。
const TIMEOUT_FAIL_WINDOW_MS: u64 = 15_000;
/// 开放区间/无 Range 的体积假设，仅影响派发权重。
const ASSUMED_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
/// 帧间空档超过此值视为「这面镜像全体没人读」，从窗口时长扣除——交付线帧距毫秒级、背压停顿秒级，分得开。
const FRAME_GAP_MS: u64 = 300;
/// 测量窗口：有流在跑时每这么久按「本镜像全流合计字节 ÷ 实际活跃时长」更新一次分数。
/// 活越多越贴近真实总吞吐、ECT 才跟着涨——否则快家被压到几百 KB/s、分数停在单流峰值，补发一直往它堆。
const RATE_WINDOW_MS: u64 = 500;

/// 每面镜像的记账：在途字节/流数、速度分(0=未交卷)、失败窗与采样时刻。
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
    /// 最近一帧到达时刻：窗口结算据此扣除「全体没人读」的空档。
    last_frame_ms: AtomicU64,
    /// 失败降权到期时刻(纪元 ms)。0 = 健康；超时类失败写短窗，硬错误写长窗。
    pub(super) fail_until: AtomicU64,
    pub(super) last_sample_ms: AtomicU64,
}

static MIRROR_LOAD: LazyLock<Mutex<HashMap<String, Arc<MirrorLoad>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 硬错误降权 45s；超时类(拨号/首包/起流超时)降权 15s——慢不等于死。
fn mark_fail(load: &MirrorLoad, timeout_only: bool) {
    let win = if timeout_only {
        TIMEOUT_FAIL_WINDOW_MS
    } else {
        MIRROR_FAIL_WINDOW_MS
    };
    load.fail_until
        .store(now_ms().saturating_add(win), Ordering::Relaxed);
}

fn fail_window_active(load: &MirrorLoad, now: u64) -> bool {
    let until = load.fail_until.load(Ordering::Relaxed);
    until != 0 && now < until
}

/// 超时类识别：拨号/首包/预算超时都是「慢」不是「死」；`kind: TimedOut` 是 io::Error 调试形态，免解析 OS 码。
fn is_timeout_err(e: &str) -> bool {
    e.contains("超时")
        || e.contains("timeout")
        || e.contains("TimedOut")
        || e.to_lowercase().contains("timed out")
}

fn mirror_load(mirror: &str) -> Arc<MirrorLoad> {
    let mut g = MIRROR_LOAD.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(mirror.to_string())
        .or_insert_with(|| Arc::new(MirrorLoad::default()))
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

/// 帧到达记账：把「全体没人读」的空档从窗口时长扣除——交付线堵住（合并层缓冲顶格）时镜像一字节不产，墙钟照走会稀释成假慢。
fn mark_frame(load: &MirrorLoad, now: u64) {
    let last = load.last_frame_ms.swap(now, Ordering::Relaxed);
    if last != 0 && load.win_base_ms.load(Ordering::Relaxed) != 0 {
        let gap = now.saturating_sub(last);
        if gap > FRAME_GAP_MS {
            // 平移窗口基线：等效于这段空档没发生。
            load.win_base_ms
                .fetch_add(gap - FRAME_GAP_MS, Ordering::Relaxed);
        }
    }
}

/// 真 EWMA(α=0.3) + 单窗突变钳制：新样本越过旧值 3 倍边界只走一半差距。
/// 旧实现直接存 500ms 原始窗口率，一个抖动窗就带偏派发，流在源间来回跳、每跳重新慢启动，聚合速率抖着掉。
fn ewma_next(old: u64, rate: u64) -> u64 {
    if old == 0 {
        return rate.max(1);
    }
    let blended = (old * 7 + rate * 3) / 10;
    let clamped = if rate > old * 3 {
        (old + blended) / 2
    } else if rate * 3 < old {
        (old + blended) / 2
    } else {
        blended
    };
    clamped.max(1)
}

/// 运行期窗口结算：有流在跑就按「本窗全镜像交付字节 ÷ 实际活跃时长」更新分数；一窗只让一条流结算（CAS 抢占），重复调用直接返回。
/// 无帧不会走到这里——待机镜像分数自然停在最后一次，无需冻结逻辑。
fn settle_window(load: &MirrorLoad, now: u64) {
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
    let rate = bytes.saturating_mul(1000) / dt.max(1);
    let next = ewma_next(load.speed_ewma.load(Ordering::Relaxed), rate);
    load.speed_ewma.store(next, Ordering::Relaxed);
    load.last_sample_ms.store(now, Ordering::Relaxed);
}

/// 记账守卫：派发记在途、逐帧归还、Drop 清残余；归还封顶于记账额，采样走原始字节。
pub(super) struct LoadGuard {
    load: Arc<MirrorLoad>,
    /// 大文件机器标记: false = 小文件流, 与速度分/在途/失败窗零接触。
    big: bool,
    charged: u64,
    delivered: u64,
    raw_delivered: u64,
    /// head_at 时的 raw_delivered 基准(全片均速的字节分母起点)。
    head_bytes: u64,
    /// 体流起点(响应头到达)：建连耗时打点与段速率分母都从这里起算。
    head_at: Instant,
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
        LoadGuard {
            load,
            big,
            charged,
            delivered: 0,
            raw_delivered: 0,
            head_bytes: 0,
            head_at: Instant::now(),
            seg_start: None,
            seg_first: None,
        }
    }

    /// 切片段：记下传输起点（响应头到达的时刻），段结束据此打吞吐。
    pub(super) fn segment_from(mut self, t: Instant) -> Self {
        self.seg_start = Some(t);
        self
    }

    /// 交付一帧：按记账额归还(封顶防下溢)，原始字节照常累计；大文件流顺带喂窗口采样。
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
        let now = now_ms();
        self.load.bytes_total.fetch_add(n, Ordering::Relaxed);
        mark_frame(&self.load, now);
        settle_window(&self.load, now);
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
        let residual = self.charged.saturating_sub(self.delivered);
        if residual > 0 {
            self.load
                .in_flight_bytes
                .fetch_sub(residual, Ordering::Relaxed);
        }
        // 流数随流终结归位(正常读完/断开都走这里)；最后一条流关窗：待机不累计时间，下个忙期从第一帧重新起算。
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
        allow_recent_failures || !fail_window_active(ld, now)
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

fn walk_order(chain_len: usize, start: usize, limit: usize) -> Vec<usize> {
    if chain_len == 0 {
        return Vec::new();
    }
    (0..chain_len)
        .map(|i| (start + i) % chain_len)
        .take(limit)
        .collect()
}
/// cap 窗口没轮到直连时把它追加为最后一棒；已在列表或失败窗未过的 不追加。
fn append_direct_if_missed(order: &mut Vec<usize>, direct_idx: usize, fail_until: u64, now_ms: u64) {
    if order.contains(&direct_idx) {
        return;
    }
    if fail_until != 0 && now_ms < fail_until {
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

/// 非 3xx、非 HTML；带 Range 必须 206，304 放行；`allow_full` 仅总长探测——上游无视 Range 回 200 全量时放行，body 由调用方当单流接管。
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

// ---- 段日志：只记账、只打吞吐，慢段由合并层缩边界让位，掐了就是个洞 ----

/// 段收尾一行：字节/毫秒/MB/s——此前日志只有“谁胜出”没有“跑多快”，判不出直连是真快还是只抢到了位置。
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
    // 直连优先域（codeload）：direct 提到队首，失败再按校准链序逐家。
    if config::is_direct_first(chain_host) {
        let n = candidates.len();
        candidates.rotate_left(n - 1);
    }
    // 熔断只拦有镜像候选的请求: 凭据串剥空/零镜像时直连独走, 别连坐。
    if !chain.is_empty() && pool::MIRROR_BREAKER.open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(candidates.len())
        .min(candidates.len());
    let new_bytes = range_bytes(out.headers().get("range").and_then(|v| v.to_str().ok()));
    // 单字节探片是下载器探路，按小文件走：链头直通，不切分、不记账。
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
        pick_mirror(&candidates, new_bytes)
    } else {
        0
    };
    let mut direct = direct;
    let mut order = walk_order(candidates.len(), start, limit);
    append_direct_if_missed(
        &mut order,
        candidates.len() - 1,
        if big {
            mirror_load(&direct_key).fail_until.load(Ordering::Relaxed)
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
                            .fail_until
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
                        // 超时(慢)与硬错误(死)分开降权：一次抖动别把好腿踢太久。
                        mark_fail(&mirror_load(&direct_key), is_timeout_err(&e));
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
                    mirror_load(m).fail_until.store(0, Ordering::Relaxed);
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
                let (mut parts, body) = resp.into_parts();
                parts.extensions.insert("mirror");
                let body = if big {
                    account_seg(
                        body,
                        guard,
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
                    mark_fail(&mirror_load(m), is_timeout_err(&e));
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
/// 直连段请求模板：原请求的方法/URI/头。补发起流跑在旁路任务里，原请求不能跨任务借用——克隆一次，各自拼 Range。
#[derive(Clone)]
pub(super) struct DirectTpl {
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
}

fn direct_tpl(out: &hyper::Request<BoxBody>) -> DirectTpl {
    DirectTpl {
        method: out.method().clone(),
        uri: out.uri().clone(),
        headers: out.headers().clone(),
    }
}

/// 总长记忆：探测是真实请求，结果记 10 分钟——同 URL 下一条无 Range 请求不必再白跑探测；只存 206 Content-Range 的权威总长。
static TOTAL_MEMO: LazyLock<Mutex<HashMap<String, (u64, Instant)>>> =
    LazyLock::new(Default::default);

fn total_memo_get(key: &str) -> Option<u64> {
    let mut g = TOTAL_MEMO.lock().unwrap();
    if g.len() >= 256 {
        g.retain(|_, (_, at)| at.elapsed() < UNSLICEABLE_TTL);
    }
    g.get(key)
        .filter(|(_, at)| at.elapsed() < UNSLICEABLE_TTL)
        .map(|(t, _)| *t)
}

fn total_memo_put(key: &str, total: u64) {
    let mut g = TOTAL_MEMO.lock().unwrap();
    g.insert(key.to_string(), (total, Instant::now()));
}

/// 无 Range 时发 1 字节 Range 探测总长，从 Content-Range 取分母。
/// 旧实现单点押注链头，链头挂了每个下载先白付一轮探测超时；现在头两家各试一次（真实请求、不合成测速），谁先给总长用谁。
enum Probe {
    /// 上游回了 206 + Content-Range：拿到了总长，可以切。
    Total(u64),
    /// 上游忽略 Range 直接回 200 全量：body 就是整份文件，直接当单流交出去，别丢。
    NotSliceable(hyper::Response<BoxBody>),
}

async fn probe_total(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    cands: &[&str],
    orig_url: &str,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    tpl: &DirectTpl,
) -> Result<Probe, String> {
    let mut last = "无健康候选".to_string();
    for m in cands {
        match probe_total_one(log, out, m, orig_url, host, info, replay, tpl).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                (log)(&format!("[切片] {host} 探测总长 {m} 失败({e}), 换下一家"));
                last = e;
            }
        }
    }
    Err(last)
}

async fn probe_total_one(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    tpl: &DirectTpl,
) -> Result<Probe, String> {
    let tag = if mirror.starts_with("direct/") {
        "direct"
    } else {
        "mirror"
    };
    let mut resp = if mirror.starts_with("direct/") {
        segment_direct(log, tpl, host, info, replay, Some(http::HeaderValue::from_static("bytes=0-0")), None).await?
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

/// 直连段请求：模板克隆原请求头换本段 Range 走直连腿；release 下载地址 302 到 release-assets，跟一跳把 Range 带过去，跳转目标 IP 与原 host 无关、用独立记账。
/// 预算按跳记：有镜像兜底时每跳 2s 拿不到响应头即死路（好 IP 建连 0.6s、首包再 1s）；没镜像（用户没配/链全灭）时不设预算。
async fn segment_direct(
    log: &LogFn,
    tpl: &DirectTpl,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    range: Option<http::HeaderValue>,
    hop_budget: Option<Duration>,
) -> Result<hyper::Response<BoxBody>, String> {
    let mut req = hyper::Request::builder()
        .method(tpl.method.clone())
        .uri(tpl.uri.clone())
        .body(protocol::empty_body())
        .map_err(|err| err.to_string())?;
    *req.headers_mut() = tpl.headers.clone();
    if let Some(range) = &range {
        req.headers_mut().insert(http::header::RANGE, range.clone());
    }
    strip_body_headers(&mut req);
    let mut resp = match hop_budget {
        Some(b) => tokio::time::timeout(b, super::get_direct(log, &req, host, info, true, replay))
            .await
            .map_err(|_| format!("直连首包超时({}ms)", b.as_millis()))??,
        None => super::get_direct(log, &req, host, info, true, replay).await?,
    };

    // 3xx：内容在别处。最多跟两跳（release 实测一跳到位），每跳各付各的预算。
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
        if let Some(range) = &range {
            req2.headers_mut().insert(http::header::RANGE, range.clone());
        }
        let fresh = super::UpstreamInfo::default();
        resp = match hop_budget {
            Some(b) => {
                tokio::time::timeout(b, super::get_direct(log, &req2, &next_host, &fresh, true, replay))
                    .await
                    .map_err(|_| format!("直连跳转首包超时({}ms)", b.as_millis()))??
            }
            None => super::get_direct(log, &req2, &next_host, &fresh, true, replay).await?,
        };
        (log)(&format!("[切片] 直连 {next_host} 回 {}", resp.status()));
    }
    Ok(resp)
}

/// 分段请求统一剥掉这两类头：压缩每段各压一遍拼起来是坏数据；条件请求让上游回 304，而段请求要的是实体。
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

/// 切片下载：一条请求按镜像数平均切段并发拉，按边界合并回单条字节流；段数=空闲镜像数（候选 − 在途），少于 2 段不切、交回单流。
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
        .filter(|m| !fail_window_active(&mirror_load(m), now))
        .map(|m| m.as_str())
        .collect();
    // 空闲优先：切段只分给零在途的源（链序内稳定序）——旧实现按链序取前 want 家，忙链头凭位置蹭段、链尾闲源落选，白浪费一路带宽。
    let idle: Vec<&str> = healthy
        .iter()
        .filter(|m| mirror_load(m).in_flight_streams.load(Ordering::Relaxed) == 0)
        .copied()
        .collect();
    if idle.len() < 2 {
        return Ok(None); // 镜像已占满或本来就没几家：切了只是抢自己的份额
    }
    // 直连段模板：补发起流跑在旁路任务里，原请求不能跨任务借用。
    let tpl = direct_tpl(out);
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let (base, len, known_total) = match range {
        // 开区间/多区间/畸形：长度未知或语义不同，不切
        Some(_) => match merge::parse_range(range) {
            Some((a, Some(b))) if b >= a => (a, b - a + 1, None),
            _ => return Ok(None),
        },
        None => match total_memo_get(&slice_key) {
            // 总长记忆命中：省掉探测往返（探测本身是真实请求，结果只记 10 分钟）。
            Some(t) => (0, t, Some(t)),
            None => {
                // 探测候选按 ECT 择优、不按链序：大文件域若不支持 Range，整包从探测腿单流出，链头盲选会把大下载砸在慢镜像上；冷启动 ECT 全零时稳定排序退化回链序。
                let mut probe_cands: Vec<&str> = healthy.clone();
                probe_cands.sort_by_key(|m| {
                    let ld = mirror_load(m);
                    ld.in_flight_bytes.load(Ordering::Relaxed) * 1000
                        / ld.speed_ewma.load(Ordering::Relaxed).max(1)
                });
                probe_cands.truncate(2);
                match probe_total(log, out, &probe_cands, orig_url, host, info, replay, &tpl).await
                {
                    Ok(Probe::Total(t)) if t > 0 => {
                        total_memo_put(&slice_key, t);
                        (0, t, Some(t))
                    }
                    Ok(Probe::Total(_)) => return Ok(None),
                    // 上游忽略 Range(回 200 全量)：探测的 body 就是整份文件，直接按单流交出。
                    Ok(Probe::NotSliceable(resp)) => {
                        mark_unsliceable(slice_key.clone());
                        return Ok(Some(resp));
                    }
                    Err(e) => {
                        (log)(&format!("[切片] {host}{path} 探测总长失败({e}), 回单流"));
                        return Ok(None);
                    }
                }
            }
        },
    };
    // 段数按可用字节收缩：len 不够分时少切几段，派发表与段表保持对齐。
    let want = ((idle.len() as u64).min(len)).max(1) as usize;
    let idle = &idle[..want];
    // 竞速切段：每家同等材料，快慢由段自己说话；慢段让位、补发走 ECT。
    let segs = merge::split_even(base, len, want);
    if segs.len() < 2 {
        return Ok(None);
    }
    (log)(&format!(
        "[切片] {host}{path} 切 {} 段(候选 {} 家, 空闲 {want}), 并发拉取",
        segs.len(),
        healthy.len()
    ));
    // 有镜像兜底才给直连设按跳预算；没镜像（用户没配/链全灭）时直连是唯一的路，不能掐，交给它按 IP 表自己换、自己等。
    let has_mirror = healthy.iter().any(|m| !m.starts_with("direct/"));
    let futs = segs.iter().enumerate().map(|(i, &(s, e))| {
        let m = idle[i % idle.len()];
        let host = host.to_string();
        let tpl = tpl.clone();
        async move {
            let guard = LoadGuard::charge(mirror_load(m), e - s, true);
            let is_direct = m.starts_with("direct/");
            let got = if is_direct {
                // 直连分段：预算按跳记（每跳 2s）、整段 ≤2 跳——拿 2s 罩两跳两拨会掐死好腿，release 要跟 302，旧实现正是这样丢速率的。
                let range = http::HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
                    .map_err(|err| err.to_string())?;
                let attempt = segment_direct(
                    log,
                    &tpl,
                    &host,
                    info,
                    replay,
                    Some(range),
                    has_mirror.then_some(DIRECT_HOP_HEAD),
                );
                if has_mirror {
                    match tokio::time::timeout(DIRECT_SEG_TOTAL, attempt).await {
                        Ok(r) => r,
                        Err(_) => Err("直连整段预算耗尽(含 302 跳)".to_string()),
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
            // 直连没打出 206（超时/4xx/连不上）记一次失败，ECT 下次绕开；超时(慢)与硬错误(死)分开降权，别把慢腿踢太久。
            if is_direct
                && !matches!(got.as_ref(), Ok(r) if r.status() == http::StatusCode::PARTIAL_CONTENT)
            {
                let timeout_only = matches!(got.as_ref(), Err(e) if is_timeout_err(e));
                mark_fail(&mirror_load(m), timeout_only);
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
    // 段响应除逐跳头/分段头外的头统一搬过来：content-disposition 定保存文件名，etag/last-modified 定缓存语义，少了客户端行为会变。
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
                let m = idle[i % idle.len()];
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
    // 起流收口成闭包：驱动只管"要 [from,to)"、怎么发由这里决定，也便于单测替换；模板/上游信息/重放体一并捕获——补发两条路都走（ECT 挑）。
    let chain: Vec<String> = healthy.iter().map(|m| m.to_string()).collect();
    let (orig, host_s, log_s) = (orig_url.to_string(), host.to_string(), log.clone());
    let tpl2 = std::sync::Arc::new(tpl);
    let (info2, replay2) = (info.clone(), replay.clone());
    let fetch: Fetch = Arc::new(move |from: u64, to: u64| {
        let (chain, orig, host_s, log_s, tpl, info, replay) = (
            chain.clone(),
            orig.clone(),
            host_s.clone(),
            log_s.clone(),
            tpl2.clone(),
            info2.clone(),
            replay2.clone(),
        );
        Box::pin(async move {
            split_fetch(
                &chain,
                &orig,
                &host_s,
                base,
                from,
                to,
                &log_s,
                &tpl,
                &info,
                &replay,
            )
            .await
        })
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

/// 起一条拉 [from, to) 的新流，偏移相对区间起点、发出去要加 base；候选=镜像+直连（健康时），ECT 挑最小者，两条路都 charge 记账、都采样。
/// 旧实现补发裸奔：ECT 看不见补发的在途字节会过量堆活，直连被永久排除在补发外。
async fn split_fetch(
    chain: &[String],
    orig_url: &str,
    host: &str,
    base: u64,
    from: u64,
    to: u64,
    log: &LogFn,
    tpl: &DirectTpl,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<BoxBody, String> {
    // 按 ECT（在途字节 ÷ 实测速度）挑最小者，不能挑"最空闲"——刚断流那家负载归零恰是最空闲，补回去就是原地打转。
    let mut cands: Vec<String> = chain
        .iter()
        .filter(|m| !m.starts_with("direct/"))
        .cloned()
        .collect();
    if let Some(d) = chain.iter().find(|m| m.starts_with("direct/")) {
        cands.push(d.clone());
    }
    if cands.is_empty() {
        return Err("无可用补发源".to_string());
    }
    let m = cands[pick_mirror(&cands, to - from)].clone();
    let (s, e) = (base + from, base + to - 1);
    if m.starts_with("direct/") {
        let guard = LoadGuard::charge(mirror_load(&m), to - from, true);
        let has_mirror = cands.len() > 1;
        let range = http::HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
            .map_err(|err| err.to_string())?;
        let attempt = segment_direct(
            log,
            tpl,
            host,
            info,
            replay,
            Some(range),
            has_mirror.then_some(DIRECT_HOP_HEAD),
        );
        let got = if has_mirror {
            match tokio::time::timeout(DIRECT_SEG_TOTAL, attempt).await {
                Ok(r) => r,
                Err(_) => Err("直连整段预算耗尽(含 302 跳)".to_string()),
            }
        } else {
            attempt.await
        };
        if !matches!(got.as_ref(), Ok(r) if r.status() == http::StatusCode::PARTIAL_CONTENT) {
            mark_fail(
                &mirror_load(&m),
                matches!(got.as_ref(), Err(err) if is_timeout_err(err)),
            );
        }
        match got {
            Ok(resp) if resp.status() == http::StatusCode::PARTIAL_CONTENT => {
                let at = Instant::now();
                let guard = guard.segment_from(at);
                Ok(account_seg(
                    resp.into_body(),
                    guard,
                    format!("{host} 补发"),
                    m,
                    log.clone(),
                ))
            }
            Ok(resp) => Err(format!(
                "{m} 补发回 {} 而非 206 (host {host})",
                resp.status()
            )),
            Err(err) => Err(err),
        }
    } else {
        let guard = LoadGuard::charge(mirror_load(&m), to - from, true);
        // 只有 GET 会走到切片（split_download 早退挡掉其它方法），补发一律 GET。
        let req = hyper::Request::builder()
            .method(http::Method::GET)
            .uri(format!("{m}/{orig_url}"))
            .header(http::header::USER_AGENT, MIRROR_UA)
            .header(
                http::header::RANGE,
                format!("bytes={s}-{}", base + to - 1),
            )
            .body(protocol::empty_body())
            .map_err(|e| e.to_string())?;
        match mirror_do(req, &m, log).await {
            Ok(resp) if resp.status() == http::StatusCode::PARTIAL_CONTENT => {
                let at = Instant::now();
                let guard = guard.segment_from(at);
                Ok(account_seg(
                    resp.into_body(),
                    guard,
                    format!("{host} 补发"),
                    m,
                    log.clone(),
                ))
            }
            Ok(resp) => Err(format!(
                "{m} 补发回 {} 而非 206 (host {host})",
                resp.status()
            )),
            Err(err) => Err(err),
        }
    }
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

/// 切片驱动：发缺口、收停滞、让位慢段，其余只泵数据；起流走旁路任务，建连/等首包再久也不挡泵数据与让位。
/// 补发没有全局次数上限——还在往前走就一直续，卡死才有上限。
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
        "codeload.github.com",
        "https://codeload.github.com/octocat/Hello-World/tar.gz/refs/heads/master",
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
