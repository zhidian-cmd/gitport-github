//! 镜像链：回落兜底 + 图片链 TTFB 校准 + 凭据防护。
//! 请求级派发：ECT=(在途字节+新请求字节)/速度选起点，失败沿链顺延；不内切不缓冲。
//! 掐断：带 Range 的流慢于同伴中位数/20 即断流，交客户端重发。
use super::{path_of, BoxBody};
use crate::pool::{self, LogFn};
use crate::server::upstream;
use http::Method;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

const MIRROR_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const MIRROR_CHAIN_CAP: usize = 5;
/// 无样本时的基准速率；pick_mirror 按链位注入 -5%/家的梯度(封底 75%)。
const DEFAULT_MIRROR_SPEED: u64 = 2 * 1024 * 1024;
/// 失败降权窗；全体都在窗内则放开过滤。
const MIRROR_FAIL_WINDOW_MS: u64 = 45_000;
/// 开放区间/无 Range 的体积假设，仅影响派发权重。
const ASSUMED_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
const SPEED_SAMPLE_BYTES: u64 = 512 * 1024;
const SPEED_SAMPLE_MIN_BYTES: u64 = 128 * 1024;

/// 在途字节 / 在途流数 / 速度 EWMA(0=无样本) / 失败时刻(0=从未) / 最近采样时刻(0=从未)。
/// 流数用于 ECT 并列组的第二级判据：组内选在途流最少者，负载摊开少误掐。
#[derive(Default)]
pub(super) struct MirrorLoad {
    pub(super) in_flight_bytes: AtomicU64,
    pub(super) in_flight_streams: AtomicU64,
    pub(super) speed_ewma: AtomicU64,
    pub(super) last_fail_ms: AtomicU64,
    pub(super) last_sample_ms: AtomicU64,
}

static MIRROR_LOAD: LazyLock<Mutex<HashMap<String, Arc<MirrorLoad>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn mirror_load(mirror: &str) -> Arc<MirrorLoad> {
    let mut g = MIRROR_LOAD.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(mirror.to_string()).or_default().clone()
}

/// 供直连腿(mod.rs)记账：直连候选与镜像共用同一张负载表。
pub(super) fn mirror_load_for(mirror: &str) -> Arc<MirrorLoad> {
    mirror_load(mirror)
}

/// 直连候选的记账键(mod.rs 组装 DirectLeg 前后共用)。
pub(super) fn direct_load_key(chain_host: &str) -> String {
    format!("direct/{chain_host}")
}

/// 从 Range 头估请求体积(mod.rs 组装直连腿的 charge 用)。
pub(super) fn range_bytes_of(range: Option<&str>) -> u64 {
    range_bytes(range)
}

fn ewma_update(load: &MirrorLoad, bytes: u64, elapsed: Duration) {
    let ms = elapsed.as_millis() as u64;
    if bytes < SPEED_SAMPLE_MIN_BYTES || ms == 0 {
        return;
    }
    let sample = bytes * 1000 / ms;
    let old = load.speed_ewma.load(Ordering::Relaxed);
    let next = if old == 0 {
        sample
    } else {
        (old * 7 + sample * 3) / 10
    };
    load.speed_ewma.store(next.max(1), Ordering::Relaxed);
    load.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
}

/// 掐断采样：直接覆盖，不做历史混合——混样要 8 轮才能压下塌方镜像的旧印象；
/// 60s 失败窗过后正常流量样本自然抬回，暂时抽风不误伤。
fn force_ewma(load: &MirrorLoad, bytes: u64, elapsed: Duration) {
    let ms = elapsed.as_millis() as u64;
    if bytes == 0 || ms == 0 {
        return;
    }
    load.speed_ewma
        .store((bytes * 1000 / ms).max(1), Ordering::Relaxed);
    load.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
}

/// 记账守卫：派发时记在途，交付逐帧归还，Drop 清残余。
/// 记账封顶于记账额防下溢；采样走原始字节，开放区间超记账额后采样不停。
pub(super) struct LoadGuard {
    load: Arc<MirrorLoad>,
    charged: u64,
    delivered: u64,
    raw_delivered: u64,
    mark_at: Instant,
    mark_bytes: u64,
    /// 构造时镜像尚无速度样本 = 本流是探测片(首个真实样本)。
    pub(super) is_probe: bool,
}

impl LoadGuard {
    pub(super) fn charge(load: Arc<MirrorLoad>, new_bytes: u64) -> Self {
        load.in_flight_bytes.fetch_add(new_bytes, Ordering::Relaxed);
        load.in_flight_streams.fetch_add(1, Ordering::Relaxed);
        let is_probe = load.speed_ewma.load(Ordering::Relaxed) == 0;
        LoadGuard {
            load,
            charged: new_bytes,
            delivered: 0,
            raw_delivered: 0,
            mark_at: Instant::now(),
            mark_bytes: 0,
            is_probe,
        }
    }


    /// 交付一帧：记账按记账额归还(封顶于 charged，防镜像无视 Range 回全量把
    /// 计数打成负)；原始累计照走。满一个采样间隔刷新一次速率。
    pub(super) fn on_frame(&mut self, n: u64) {
        let credit = n.min(self.charged.saturating_sub(self.delivered));
        self.delivered += credit;
        self.raw_delivered += n;
        if credit > 0 {
            self.load.in_flight_bytes.fetch_sub(credit, Ordering::Relaxed);
        }
        let since_mark = self.raw_delivered - self.mark_bytes;
        if since_mark >= SPEED_SAMPLE_BYTES {
            ewma_update(&self.load, since_mark, self.mark_at.elapsed());
            self.mark_at = Instant::now();
            self.mark_bytes = self.raw_delivered;
        }
    }
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        ewma_update(
            &self.load,
            self.raw_delivered - self.mark_bytes,
            self.mark_at.elapsed(),
        );
        let residual = self.charged.saturating_sub(self.delivered);
        if residual > 0 {
            self.load.in_flight_bytes.fetch_sub(residual, Ordering::Relaxed);
        }
        // 流数随流终结归位(正常读完/客户端断开/掐断全走这里)。
        self.load
            .in_flight_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// 探测轮末位淘汰(纯函数)：镜像首个样本的速率 vs 有样本同伴中位数。
/// 低于一半 → 探测判定"体质差"，45s 降权。小片熬不到掐断的 1.2s 窗口，
/// 靠这里把探测结论变成账本事实。
fn probe_outlier(own: u64, peer_median: Option<u64>) -> bool {
    peer_median.is_some_and(|m| own < m / 2)
}

/// ECT 最小者胜；并列(相差 ≤5%, ect*100 ≤ best*105 无地板比较)组内二级判据：
/// 选在途流数最少者(负载摊开，少误掐)，流数也相同才轮转均摊。
/// 失败窗内的镜像跳过，全军都在窗内则放开。
fn pick_mirror(chain: &[String], new_bytes: u64) -> usize {
    let now = pool::now_ms();
    let loads: Vec<Arc<MirrorLoad>> = chain.iter().map(|m| mirror_load(m)).collect();
    // 单点实现：速度(冷启动按链位 -4%/家, 封底 80%) 与 ECT 毫秒。
    // 梯度必须 <5% 容差：-5%/家会使 ECT 差 +5.26% 越线，铺开失效。
    let ect_of = |ld: &MirrorLoad, i: usize| -> u64 {
        let speed = {
            let s = ld.speed_ewma.load(Ordering::Relaxed);
            if s == 0 {
                DEFAULT_MIRROR_SPEED - DEFAULT_MIRROR_SPEED / 25 * (i as u64).min(5)
            } else {
                s
            }
        };
        ld.in_flight_bytes.load(Ordering::Relaxed).saturating_add(new_bytes) * 1000 / speed
    };
    let healthy = |ld: &MirrorLoad, allow_recent_failures: bool| -> bool {
        allow_recent_failures || {
            let lf = ld.last_fail_ms.load(Ordering::Relaxed);
            lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS
        }
    };
    for allow_recent_failures in [false, true] {
        let mut best_ect = u64::MAX;
        for (i, ld) in loads.iter().enumerate() {
            if healthy(ld, allow_recent_failures) {
                best_ect = best_ect.min(ect_of(ld, i));
            }
        }
        // 容差内全部入围；真差距(>5%)仍严格选快者。
        let tied: Vec<usize> = (0..loads.len())
            .filter(|&i| healthy(&loads[i], allow_recent_failures))
            .filter(|&i| ect_of(&loads[i], i) * 100 <= best_ect * 105)
            .collect();
        if let Some(&first) = tied.first() {
            if tied.len() == 1 {
                return first;
            }
            // 二级判据：在途流数最少者胜(避免往高压镜像继续堆片，减少误掐)；
            // 流数也并列才轮转均摊。
            let min_streams = tied
                .iter()
                .map(|&i| loads[i].in_flight_streams.load(Ordering::Relaxed))
                .min()
                .unwrap_or(0);
            let fewest: Vec<usize> = tied
                .into_iter()
                .filter(|&i| {
                    loads[i].in_flight_streams.load(Ordering::Relaxed) == min_streams
                })
                .collect();
            if fewest.len() == 1 {
                return fewest[0];
            }
            let n = TIE_ROTATOR.fetch_add(1, Ordering::Relaxed);
            return fewest[(n % fewest.len() as u64) as usize];
        }
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
/// cap 窗口吃掉直连位时的末位兜底：直连已在窗内不动；刚失败(失败窗内)不追加
/// (别急着重拨)；否则追加为最后一棒——镜像 cap 之外仍有本地腿。
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


/// bytes=a-b → b-a+1；开放区间/无头/畸形按假设值。
fn range_bytes(range: Option<&str>) -> u64 {
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
fn validate_mirror_response(had_range: bool, status: u16, content_type: &str) -> Result<(), String> {
    if status == 304 {
        return Ok(());
    }
    let ct = content_type.to_lowercase();
    if had_range && status != 206 {
        return Err(format!("状态 {status}(请求带 Range, 未回 206)"));
    }
    if status >= 300 || ct.contains("text/html") {
        return Err(format!("状态 {status}"));
    }
    Ok(())
}

// ---- 慢镜像掐断：相对差值检验，全军低速零误杀 ----

const CUT_CHECKPOINT_BYTES: u64 = 96 * 1024;

const CUT_MIN_WINDOW_MS: u64 = 1_200;
const CUT_PEER_FRESH_MS: u64 = 30_000;
/// 流速度 < 同伴中位数 / 该值 = 显著离群。
const CUT_SIGNIFICANCE_DIVISOR: u64 = 20;
const CUT_MIN_PEERS: usize = 3;
/// 每链每窗上限：掐满放行爬行，宁可慢不可自残。
const CUT_LIMIT_PER_WINDOW: u32 = 4;
const CUT_LIMIT_WINDOW_MS: u64 = 60_000;

fn peer_median(peer_rates: &[u64]) -> Option<u64> {
    if peer_rates.len() < CUT_MIN_PEERS {
        return None;
    }
    let mut sorted = peer_rates.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
}

fn should_cut(own_rate: u64, median: Option<u64>) -> bool {
    median.is_some_and(|m| own_rate < m / CUT_SIGNIFICANCE_DIVISOR)
}

static CUT_LIMITER: LazyLock<Mutex<HashMap<String, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cut_allowed(chain_host: &str) -> bool {
    let mut g = CUT_LIMITER.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    let e = g.entry(chain_host.to_string()).or_insert((now, 0));
    if now.duration_since(e.0).as_millis() as u64 >= CUT_LIMIT_WINDOW_MS {
        *e = (now, 0);
    }
    if e.1 >= CUT_LIMIT_PER_WINDOW {
        return false;
    }
    e.1 += 1;
    true
}

struct CutState {
    body: BoxBody,
    guard: LoadGuard,
    load: Arc<MirrorLoad>,
    peers: Vec<Arc<MirrorLoad>>,
    chain_host: String,
    mirror: String,
    label: String,
    log: LogFn,
    since_cp: u64,
    cp_at: Instant,
}

struct CutMeta {
    chain_host: String,
    mirror: String,
    label: String,
}

/// 显著慢于同伴即 Err 终止流，客户端重发重进派发；无 Range 的流不经过这里。
fn cutoff_watched_body(
    body: BoxBody,
    guard: LoadGuard,
    load: Arc<MirrorLoad>,
    peers: Vec<Arc<MirrorLoad>>,
    meta: CutMeta,
    log: LogFn,
) -> BoxBody {
    let CutMeta {
        chain_host,
        mirror,
        label,
    } = &meta;
    let st = CutState {
        body,
        guard,
        load,
        peers,
        chain_host: chain_host.clone(),
        mirror: mirror.clone(),
        label: label.clone(),
        log,
        since_cp: 0,
        cp_at: Instant::now(),
    };
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        match http_body_util::BodyExt::frame(&mut st.body).await {
            Some(Ok(frame)) => {
                let n = frame.data_ref().map(|d| d.len() as u64).unwrap_or(0);
                st.guard.on_frame(n);
                st.since_cp += n;
                if st.since_cp >= CUT_CHECKPOINT_BYTES {
                    let elapsed = st.cp_at.elapsed();
                    if elapsed.as_millis() as u64 >= CUT_MIN_WINDOW_MS {
                        let now_ms = pool::now_ms();
                        let fresh: Vec<u64> = st
                            .peers
                            .iter()
                            .filter(|p| {
                                let s = p.last_sample_ms.load(Ordering::Relaxed);
                                s != 0 && now_ms.saturating_sub(s) < CUT_PEER_FRESH_MS
                            })
                            .map(|p| p.speed_ewma.load(Ordering::Relaxed))
                            .filter(|s| *s > 0)
                            .collect();
                        let median = peer_median(&fresh);
                        let own = st.since_cp * 1000 / elapsed.as_millis().max(1) as u64;
                        if should_cut(own, median) && cut_allowed(&st.chain_host) {
                            force_ewma(&st.load, st.since_cp, elapsed);
                            st.load.last_fail_ms.store(now_ms, Ordering::Relaxed);
                            let base = median.unwrap_or(0) / 1024;
                            (st.log)(&format!(
                                "[镜像] {} {} 速率 {}KB/s 显著低于同伴(基准 {base}KB/s), 掐断断流, 交由客户端重发",
                                st.label, st.mirror, own / 1024
                            ));
                            return Some((
                                Err(std::io::Error::other("镜像显著慢于同伴, 已掐断")),
                                st,
                            ));
                        }
                    }
                    st.since_cp = 0;
                    st.cp_at = Instant::now();
                }
                Some((Ok(frame), st))
            }
            Some(Err(e)) => Some((Err(e), st)),
            None => {
                // EOS = 流正常读完。探测轮末位淘汰：本流是该镜像首个速度样本
                // (探测片)，速率低于同伴基准一半 → 记 45s 降权。
                // 小片熬不到掐断的 1.2s 窗口，探测结论在这里落账本。
                // 基准两级：有新鲜样本同伴用其中位数；全员无样本(首批并发，
                // 谁都没考过)用冷启动先验兜底——但只在至少一家交出"达到先验
                // 70%"成绩时才启用先验判罚，全员都慢(链路本身差)则免检不乱杀。
                let was_probe =
                    st.guard.is_probe && st.guard.delivered >= SPEED_SAMPLE_MIN_BYTES;
                let now_ms = pool::now_ms();
                let fresh: Vec<u64> = st
                    .peers
                    .iter()
                    .filter(|p| {
                        let s = p.last_sample_ms.load(Ordering::Relaxed);
                        s != 0 && now_ms.saturating_sub(s) < CUT_PEER_FRESH_MS
                    })
                    .map(|p| p.speed_ewma.load(Ordering::Relaxed))
                    .filter(|s| *s > 0)
                    .collect();
                let median = peer_median(&fresh);
                let median = median.or_else(|| {
                    let floor = DEFAULT_MIRROR_SPEED - DEFAULT_MIRROR_SPEED / 25 * 5;
                    // 至少一家跑出先验七成才算"链路正常，有人真慢"。
                    if fresh.is_empty()
                        && st.peers.iter().any(|p| {
                            let s = p.speed_ewma.load(Ordering::Relaxed);
                            s * 10 >= floor * 7
                        })
                    {
                        Some(floor)
                    } else {
                        None
                    }
                });
                let own = st.guard.delivered * 1000
                    / st.guard.mark_at.elapsed().as_millis().max(1) as u64;
                if was_probe && probe_outlier(own, median) {
                    st.load.last_fail_ms.store(now_ms, Ordering::Relaxed);
                    let base = median.unwrap_or(0) / 1024;
                    (st.log)(&format!(
                        "[镜像] {} {} 探测片速率 {}KB/s 低于同伴一半(基准 {base}KB/s), 探测出局(45s)",
                        st.label, st.mirror, own / 1024
                    ));
                }
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

/// 直连腿的注入接口：mod.rs 组装完整 future(拨号+记账+掐断包装已含)，
/// mirror.rs 只管 ECT 派发与失败降权——不感知拨号细节。
pub(super) struct DirectLeg<'a> {
    pub fetch: std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<hyper::Response<BoxBody>, String>>
                + Send
                + 'a,
        >,
    >,
}

pub(super) async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    direct: DirectLeg<'_>,
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
    if chain_host != host {
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
    if let Some(r) = range {
        (log)(&format!("[镜像] {host}{path} 客户端 Range: {r}"));
    }
    if let Some(c) = cond {
        (log)(&format!("[镜像] {host}{path} 客户端条件请求: {c}"));
    }
    // 凭据串请求：镜像候选剥空，签名 URL 不落任何第三方。
    let chain = if cred_locked {
        (log)(&format!("[镜像] {host}{path} 凭据查询串, 剥空镜像仅直连(防外泄)"));
        Vec::new()
    } else {
        pool::mirror_chain(chain_host)
    };
    // 直连同台：直连是候选池里的普通选手(键 direct/{host})，ECT 一视同仁；
    // 零镜像时候选=仅直连，502 只在"镜像+直连全灭"时发生。
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
    let start = pick_mirror(&candidates, new_bytes);
    let mut direct = direct;
    let mut order = walk_order(candidates.len(), start, limit);
    append_direct_if_missed(
        &mut order,
        candidates.len() - 1,
        mirror_load(&direct_key).last_fail_ms.load(Ordering::Relaxed),
        pool::now_ms(),
    );
    for i in order {
        let m = candidates[i].as_str();
        // 直连候选：拨号/游标/连接池/记账包装全在 fetch future 内(mod.rs 组装)。
        if m == direct_key {
            let t0 = Instant::now();
            match direct.fetch.as_mut().await {
                Ok(mut resp) => {
                    resp.extensions_mut().insert("direct");
                    mirror_load(&direct_key).last_fail_ms.store(0, Ordering::Relaxed);
                    (log)(&format!(
                        "[直连] {host}{path} ECT 胜出({}ms), 候选 {}/{}",
                        t0.elapsed().as_millis(),
                        i + 1,
                        candidates.len()
                    ));
                    pool::MIRROR_BREAKER.clear(chain_host);
                    return Ok(resp);
                }
                Err(e) => {
                    mirror_load(&direct_key)
                        .last_fail_ms
                        .store(pool::now_ms(), Ordering::Relaxed);
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
        let mut guard = LoadGuard::charge(mirror_load(m), new_bytes);
        let t0 = Instant::now();
        match mirror_do(req, m, log).await {
            Ok(resp) => {
                mirror_load(m).last_fail_ms.store(0, Ordering::Relaxed);
                (log)(&format!(
                    "[镜像] {host}{path} via {m} (链位 {}/{len}, ECT起点 #{}, 头 {ms}ms)",
                    i + 1,
                    start + 1,
                    len = chain.len(),
                    ms = t0.elapsed().as_millis()
                ));
                pool::MIRROR_BREAKER.clear(chain_host);
                // 带 Range 挂掐断监视；无 Range 只记账不掐（浏览器下载掐了是用户可见失败）。
                let (mut parts, body) = resp.into_parts();
                parts.extensions.insert("mirror");
                let body = if range.is_some() {
                    let peers: Vec<Arc<MirrorLoad>> = chain
                        .iter()
                        .filter(|x| x.as_str() != m)
                        .map(|x| mirror_load(x))
                        .collect();
                    cutoff_watched_body(
                        body,
                        guard,
                        mirror_load(m),
                        peers,
                        CutMeta {
                            chain_host: chain_host.to_string(),
                            mirror: m.to_string(),
                            label: format!("{host}{path}"),
                        },
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
                mirror_load(m)
                    .last_fail_ms
                    .store(pool::now_ms(), Ordering::Relaxed);
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
    builder = builder.header(http::header::USER_AGENT, http::HeaderValue::from_static(MIRROR_UA));
    builder.body(upstream::empty_body()).map_err(|e| e.to_string())
}
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
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
    validate_mirror_response(had_range, resp.status().as_u16(), ct)
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
        .body(upstream::empty_body())
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
                    (log)(&format!(
                        "[校准] {host} {m} {}({e})",
                        calib_fail_label(&e)
                    ));
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
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn mirror_chain_cap_scope() {
        for h in [
            "raw.githubusercontent.com",
            "camo.githubusercontent.com",
            "avatars.githubusercontent.com",
            "user-images.githubusercontent.com",
            "media.githubusercontent.com",
            "gist.githubusercontent.com",
        ] {
            assert_eq!(mirror_chain_cap(h), Some(5), "{h} 应限长 5 家");
        }
        for h in [
            "codeload.github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ] {
            assert_eq!(mirror_chain_cap(h), None, "{h} 应用全链");
        }
    }

    #[test]
    fn mirror_request_strips_identity_and_hop_by_hop() {
        let out = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://raw.githubusercontent.com/a/b")
            .header("cookie", "logged_in=yes")
            .header("authorization", "Bearer tok")
            .header("connection", "close")
            .header("keep-alive", "timeout=5")
            .header("upgrade", "websocket")
            .header("te", "trailers")
            .header("range", "bytes=0-1023")
            .header("accept-encoding", "gzip")
            .header("user-agent", "UA/1.0")
            .body(upstream::empty_body())
            .unwrap();
        let req = mirror_request(
            &out,
            "https://gh-proxy.com",
            "https://raw.githubusercontent.com/a/b",
        )
        .unwrap();
        let h = req.headers();
        for gone in [
            "cookie",
            "authorization",
            "host",
            "referer",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
        ] {
            assert!(h.get(gone).is_none(), "{gone} 应被剥除");
        }
        assert_eq!(h.get("range").unwrap(), "bytes=0-1023", "业务头必须保留");
        assert_eq!(h.get("accept-encoding").unwrap(), "gzip");
        assert_eq!(h.get("user-agent").unwrap(), MIRROR_UA);
        let uri = req.uri().to_string();
        assert!(
            uri.starts_with("https://gh-proxy.com/https://raw.githubusercontent.com/"),
            "拼 URL 形态: {uri}"
        );
    }

    #[test]
    fn calibrate_templates_cover_small_hosts_only() {
        for h in pool::CONTENT_HOSTS {
            let covered = CALIBRATE_TEMPLATES.iter().any(|(host, _)| host == h);
            if pool::route::is_big_file_host(h) {
                assert!(!covered, "{h} 大文件域不校准, 不应有模板");
            } else {
                assert!(covered, "{h} 小文件域缺 TTFB 校准模板");
            }
        }
        assert!(
            !CALIBRATE_TEMPLATES.iter().any(|(h, _)| *h == "github.com"),
            "github.com 链已除名, 不应有模板"
        );
    }

    #[test]
    fn credential_query_detection() {
        for q in [
            "token=abc",
            "sig=1",
            "signature=1",
            "jwt=1",
            "auth=1",
            "access_token=x",
            "session_token=1",
            "AWSAccessKeyId=k",
            "X-Amz-Signature=abc",
            "x-amz-credential=1",
            "a=1&access_token=x",
        ] {
            assert!(has_credential_query(q), "{q} 应判含凭据");
        }
        for q in ["", "foo=token", "page=2&q=tokenize", "tokens=1"] {
            assert!(!has_credential_query(q), "{q} 不该误判（名字才参与，值不算）");
        }
    }

    #[test]
    fn ttfb_rank_fastest_first_failures_last() {
        let mut rows = vec![
            ("slow".to_string(), 900),
            ("fast".to_string(), 120),
            ("mid".to_string(), 300),
            ("dead".to_string(), -50),
        ];
        rank_by_ttfb(&mut rows);
        let order: Vec<&str> = rows.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(order, ["fast", "mid", "slow", "dead"], "{rows:?}");
    }

    #[tokio::test]
    async fn chain_fetch_cred_locks_to_direct() {
        let lines: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = lines.clone();
        let log: LogFn = Arc::new(move |s: &str| sink.lock().unwrap().push(s.to_string()));
        let req = hyper::Request::builder()
            .uri("https://raw.githubusercontent.com/o/r/f?sig=abc")
            .body(upstream::empty_body())
            .unwrap();
        let err = chain_fetch(
            &log,
            &req,
            "raw.githubusercontent.com",
            mirror_test_direct_leg(),
        )
        .await
        .unwrap_err();
        assert!(err.contains("仅直连"), "凭据串应剥空镜像仅直连: {err}");
        let got = lines.lock().unwrap();
        assert!(
            got.iter().any(|l| l.contains("仅直连(防外泄)")),
            "应记录剥空镜像决策: {got:?}"
        );
        assert!(
            !got.iter().any(|l| l.contains(" via ")),
            "签名 URL 不得交给第三方镜像: {got:?}"
        );
    }

    /// 纯直连耗尽(零镜像/凭据串剥空)不给镜像链上熔断——链没参与，别连坐。
    #[tokio::test]
    async fn direct_only_exhaustion_spares_chain_breaker() {
        let log: LogFn = Arc::new(|_: &str| {});
        let host = "cred-brk.test";
        pool::MIRROR_BREAKER.clear(host);
        let req = hyper::Request::builder()
            .uri("https://cred-brk.test/f?sig=abc")
            .body(upstream::empty_body())
            .unwrap();
        let err = chain_fetch(&log, &req, host, mirror_test_direct_leg())
            .await
            .unwrap_err();
        assert!(err.contains("仅直连"), "凭据串请求应仅派直连: {err}");
        assert!(
            !pool::MIRROR_BREAKER.open(host),
            "直连独走耗尽不得触发镜像链熔断"
        );
    }

    /// 审计 #3 回归: 熔断只拦有镜像候选的请求——凭据串剥空镜像后直连独走,
    /// 不得撞为镜像设的熔断(哪怕熔断正开着)。
    #[tokio::test]
    async fn breaker_spares_direct_only_requests() {
        let log: LogFn = Arc::new(|_: &str| {});
        let host = "brk-cred.test";
        pool::MIRROR_BREAKER.clear(host);
        pool::MIRROR_BREAKER.set(host);
        let req = hyper::Request::builder()
            .uri("https://brk-cred.test/f?sig=abc")
            .body(upstream::empty_body())
            .unwrap();
        let err = chain_fetch(&log, &req, host, mirror_test_direct_leg())
            .await
            .unwrap_err();
        assert!(!err.contains("熔断"), "直连独走不得撞镜像熔断: {err}");
        assert!(err.contains("仅直连"), "应照常仅派直连: {err}");
        pool::MIRROR_BREAKER.clear(host);
    }

    /// 审计 #2 回归: cap 窗口吃掉直连位时——健康直连追加为末位; 刚失败的不追加;
    /// 已在窗内不重复。
    #[test]
    fn append_direct_gated_by_health_and_presence() {
        let mut order = vec![0usize, 1, 2, 3, 4];
        append_direct_if_missed(&mut order, 8, 0, 1_000);
        assert_eq!(order.last(), Some(&8), "健康直连在窗外应追加为末位");
        let mut order = vec![0usize, 1, 2, 3, 4];
        append_direct_if_missed(&mut order, 8, 1_000, 1_500);
        assert!(!order.contains(&8), "刚失败(失败窗内)不追加, 别急着重拨");
        let mut order = vec![0usize, 4, 8];
        append_direct_if_missed(&mut order, 8, 0, 1_000);
        assert_eq!(order, vec![0, 4, 8], "已在窗内不重复追加");
    }

    /// EOS 探测的先验基准：全员无新鲜样本时，只要有同伴达先验七成即以先验
    /// 为基准判罚(首轮大逃杀)；全员都慢(链路差)则免检不乱杀。
    #[tokio::test]
    async fn probe_prior_baseline_fires_when_link_is_normal() {
        let fast = mirror_load("probe-prior-fast.test");
        fast.speed_ewma
            .store(2 * 1024 * 1024, Ordering::Relaxed); // 达先验，但 last_sample_ms=0(无新鲜样本)
        let me = mirror_load("probe-prior-me.test");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.last_fail_ms.store(0, Ordering::Relaxed);
        let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
                Bytes::from(vec![0u8; SPEED_SAMPLE_MIN_BYTES as usize]),
            ))]),
        ));
        let guard = LoadGuard::charge(me.clone(), SPEED_SAMPLE_MIN_BYTES);
        let mut wrapped = cutoff_watched_body(
            body,
            guard,
            me.clone(),
            vec![fast],
            CutMeta {
                chain_host: "probe-prior.test".into(),
                mirror: "probe-prior-me.test".into(),
                label: "h/p".into(),
            },
            Arc::new(|_: &str| {}),
        );
        // own ≈ 128KB / 0.2s ≈ 640KB/s < 先验 1.6MB/s 的一半 → 探测出局。
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // 数据帧
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // EOS
        drop(wrapped);
        assert_ne!(
            me.last_fail_ms.load(Ordering::Relaxed),
            0,
            "先验基准应判罚首轮慢探测片"
        );
    }

    #[tokio::test]
    async fn probe_prior_baseline_spares_all_slow_links() {
        let slow = mirror_load("probe-prior-slow.test");
        slow.speed_ewma.store(100 * 1024, Ordering::Relaxed); // 远低于先验七成
        let me = mirror_load("probe-prior-me2.test");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.last_fail_ms.store(0, Ordering::Relaxed);
        let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
                Bytes::from(vec![0u8; SPEED_SAMPLE_MIN_BYTES as usize]),
            ))]),
        ));
        let guard = LoadGuard::charge(me.clone(), SPEED_SAMPLE_MIN_BYTES);
        let mut wrapped = cutoff_watched_body(
            body,
            guard,
            me.clone(),
            vec![slow],
            CutMeta {
                chain_host: "probe-prior2.test".into(),
                mirror: "probe-prior-me2.test".into(),
                label: "h/p".into(),
            },
            Arc::new(|_: &str| {}),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await;
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await;
        drop(wrapped);
        assert_eq!(
            me.last_fail_ms.load(Ordering::Relaxed),
            0,
            "全员都慢(链路本身差)不得按先验误杀"
        );
    }

    /// 测试用直连腿：恒失败(不拨真网)，用于驱动候选循环与失败降权路径。
    fn mirror_test_direct_leg() -> DirectLeg<'static> {
        DirectLeg {
            fetch: Box::pin(async {
                Err::<hyper::Response<BoxBody>, String>("test: direct unavailable".into())
            }),
        }
    }

    /// 直连同台：candidates = 镜像 + direct/{host}，ECT 统一派发。
    #[test]
    fn direct_competes_as_candidate() {
        let chain = vec!["cand-m.test".to_string()];
        let cands = [
            chain.as_slice(),
            &[direct_load_key("cand-host.test")][..],
        ];
        let all: Vec<String> = cands.concat();
        // 直连快(EWMA 高) 镜像无样本(默认 2MB/s): ECT 直连小 → 选直连键。
        let d = mirror_load_for(&direct_load_key("cand-host.test"));
        d.speed_ewma.store(8 * 1024 * 1024, Ordering::Relaxed);
        let pick = pick_mirror(&all, 8 * 1024 * 1024);
        assert_eq!(all[pick], direct_load_key("cand-host.test"), "直连快时应胜出");
        // 直连失败降权后 → 轮到镜像。
        d.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        let pick = pick_mirror(&all, 8 * 1024 * 1024);
        assert_eq!(all[pick], "cand-m.test", "直连降权后应选镜像");
        d.speed_ewma.store(0, Ordering::Relaxed);
        d.last_fail_ms.store(0, Ordering::Relaxed);
        // 零镜像: candidates 只有直连, pick 恒 0(直连键)。
        let only_direct = vec![direct_load_key("cand-host.test")];
        assert_eq!(all.len(), 2, "镜像+直连=2 候选");
        assert_eq!(pick_mirror(&only_direct, 1024), 0, "零镜像时候选=仅直连");
    }

    /// 忙而快的胜过闲而慢的；快镜像在途过深则公式自纠改选空闲者。
    #[test]
    fn ect_prefers_busy_fast_over_idle_slow() {
        let a = mirror_load("ect-a.test");
        let b = mirror_load("ect-b.test");
        a.in_flight_bytes.store(512 * 1024, Ordering::Relaxed);
        a.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        b.speed_ewma.store(512 * 1024, Ordering::Relaxed);
        let chain = vec!["ect-a.test".to_string(), "ect-b.test".to_string()];
        // A (0.5+10)/5 ≈ 2s < B 10/0.5 = 20s → A。
        assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 0);
        // A (100+10)/5 = 22 > B 20 → B。
        a.in_flight_bytes.store(100 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 1);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 无样本 → 梯度速率下按在途字节分 → 全零时轮转均摊不塞链头。
    #[test]
    fn cold_start_falls_back_to_chain_order() {
        let a = mirror_load("cold-a.test");
        let b = mirror_load("cold-b.test");
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["cold-a.test".to_string(), "cold-b.test".to_string()];
        // 梯度(-4%/家): a=2MB/s(位0), b=1.92MB/s(位1) → a 的 ECT 差 +4.17% < 5% 容差 → 轮转。
        a.in_flight_streams.store(0, Ordering::Relaxed);
        b.in_flight_streams.store(0, Ordering::Relaxed);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            seen.insert(pick_mirror(&chain, 1024));
        }
        assert!(
            seen.contains(&0) && seen.contains(&1),
            "冷启动全空应在容差内轮转均摊, 不塞链头: {seen:?}"
        );
        // 在途拉开(超容差) → 严格选闲者。
        a.in_flight_bytes.store(8 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 1, "梯度速率下按在途字节分");
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        a.in_flight_streams.store(0, Ordering::Relaxed);
        b.in_flight_streams.store(0, Ordering::Relaxed);
    }

    /// 二级判据：ECT 并列组内选在途流最少者；流数也相同才轮转。
    /// 高压镜像(流多)不再被继续堆片，从源头减少掐断误判。
    #[test]
    fn tie_prefers_fewer_inflight_streams() {
        let a = mirror_load("streams-a.test");
        let b = mirror_load("streams-b.test");
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        a.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
        b.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
        a.in_flight_streams.store(0, Ordering::Relaxed);
        b.in_flight_streams.store(0, Ordering::Relaxed);
        let chain = vec!["streams-a.test".to_string(), "streams-b.test".to_string()];
        // ECT 并列(同速同在途字节)、A 已压 3 流 B 空闲 → 恒选 B。
        a.in_flight_streams.store(3, Ordering::Relaxed);
        for _ in 0..10 {
            assert_eq!(pick_mirror(&chain, 1024), 1, "流少的 B 应胜出");
        }
        // B 也压上 3 流 → 流数并列 → 轮转两家都出。
        b.in_flight_streams.store(3, Ordering::Relaxed);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            seen.insert(pick_mirror(&chain, 1024));
        }
        assert!(
            seen.contains(&0) && seen.contains(&1),
            "流数并列应轮转: {seen:?}"
        );
        // 清场。
        a.in_flight_streams.store(0, Ordering::Relaxed);
        b.in_flight_streams.store(0, Ordering::Relaxed);
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// ECT 相差 ≤5% 轮转均摊，>5% 严格选快者(ECT 核心语义不被稀释)。
    #[test]
    fn ect_tie_rotates_within_tolerance_only() {
        let a = mirror_load("tie-a.test");
        let b = mirror_load("tie-b.test");
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["tie-a.test".to_string(), "tie-b.test".to_string()];
        // 速度差 4%(容差内) + 在途全零 → ECT 并列 → 轮转两家都出。
        a.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
        b.speed_ewma.store(2088 * 1024, Ordering::Relaxed); // +4%
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            seen.insert(pick_mirror(&chain, 8 * 1024 * 1024));
        }
        assert!(
            seen.contains(&0) && seen.contains(&1),
            "5% 内并列应轮转: {seen:?}"
        );
        // 速度差 30%(超容差) → 恒选快者 b。
        b.speed_ewma.store(26 * 1024 * 1024 / 10, Ordering::Relaxed); // 2.6MB/s
        for _ in 0..10 {
            assert_eq!(pick_mirror(&chain, 8 * 1024 * 1024), 1, "真差距必须严格选快");
        }
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
    }

    #[test]
    fn recent_failure_deprioritized() {
        let a = mirror_load("fail-a.test");
        let b = mirror_load("fail-b.test");
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["fail-a.test".to_string(), "fail-b.test".to_string()];
        a.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 1);
        // 全体都在窗内：放开过滤回链序。
        b.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 0);
        a.last_fail_ms.store(0, Ordering::Relaxed);
        b.last_fail_ms.store(0, Ordering::Relaxed);
    }

    #[test]
    fn rotate_walk_respects_limit() {
        assert_eq!(walk_order(8, 0, 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(walk_order(8, 6, 5), vec![6, 7, 0, 1, 2]);
        assert_eq!(walk_order(3, 0, 8), vec![0, 1, 2], "limit 大于链长：全链");
        assert_eq!(walk_order(1, 0, 5), vec![0], "单镜像：不切分，行为同旧");
    }

    #[test]
    fn range_size_parsing() {
        assert_eq!(range_bytes(Some("bytes=0-1048575")), 1048576);
        assert_eq!(range_bytes(Some("bytes=100-199")), 100);
        assert_eq!(range_bytes(Some("bytes=1048576-")), ASSUMED_REQUEST_BYTES);
        assert_eq!(range_bytes(Some("bytes=abc")), ASSUMED_REQUEST_BYTES);
        assert_eq!(range_bytes(None), ASSUMED_REQUEST_BYTES);
        assert_eq!(
            range_bytes(Some("bytes=200-100")),
            ASSUMED_REQUEST_BYTES,
            "逆区间：畸形按假设"
        );
        assert_eq!(range_bytes(Some("bytes=0-99,200-299")), 100, "多区间取第一段");
    }

    #[test]
    fn mirror_response_validation() {
        assert!(validate_mirror_response(true, 206, "application/octet-stream").is_ok());
        assert!(validate_mirror_response(true, 304, "text/html").is_ok());
        assert!(validate_mirror_response(false, 304, "").is_ok());
        assert!(validate_mirror_response(false, 200, "application/octet-stream").is_ok());
        assert!(
            validate_mirror_response(true, 200, "application/octet-stream").is_err(),
            "带 Range 回 200：镜像不认 Range, 必须换家"
        );
        assert!(validate_mirror_response(true, 403, "text/html").is_err());
        assert!(validate_mirror_response(false, 302, "text/html").is_err());
        assert!(validate_mirror_response(false, 200, "text/html; charset=utf-8").is_err());
    }

    /// 派发加、逐帧归还、Drop 清残余；超额交付封顶不下溢。
    #[test]
    fn byte_accounting_lifecycle() {
        let ld = mirror_load("acct.test");
        ld.in_flight_bytes.store(0, Ordering::Relaxed);
        {
            let mut g = LoadGuard::charge(ld.clone(), 1000);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 1000);
            g.on_frame(400);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 600);
            g.on_frame(400);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 200);
        } // drop：残余归还
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "Drop 必须清残余");
        {
            let mut g = LoadGuard::charge(ld.clone(), 100);
            g.on_frame(500);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "交付封顶于记账");
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
        {
            let _g = LoadGuard::charge(ld.clone(), 4096);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 4096);
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
    }

    /// 首样本直取，后续 α=0.3 平滑；小样本忽略。
    #[test]
    fn speed_ewma_smoothing() {
        let ld = mirror_load("ewma.test");
        ld.speed_ewma.store(0, Ordering::Relaxed);
        ewma_update(&ld, 256 * 1024, Duration::from_secs(1));
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), 256 * 1024);
        ewma_update(&ld, 1024 * 1024, Duration::from_secs(1));
        let expect = (256 * 1024 * 7 + 1024 * 1024 * 3) / 10;
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), expect);
        ewma_update(&ld, 128, Duration::from_millis(1));
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), expect);
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 开放区间超记账额后：in_flight 停在 0 不下溢，采样照走。
    /// 帧间真实睡眠：ewma_update 要求窗口耗时 >0 毫秒。
    #[tokio::test]
    async fn on_frame_sampling_outlives_charge_cap() {
        let ld = mirror_load("raw-sampling.test");
        ld.in_flight_bytes.store(0, Ordering::Relaxed);
        ld.speed_ewma.store(0, Ordering::Relaxed);
        let mut g = LoadGuard::charge(ld.clone(), 8 * 1024 * 1024);
        let frame = 1024 * 1024u64;
        for _ in 0..10 {
            g.on_frame(frame);
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        assert_eq!(
            ld.in_flight_bytes.load(Ordering::Relaxed),
            0,
            "记账封顶后 in_flight 必须停在 0, 不得下溢"
        );
        assert!(
            ld.speed_ewma.load(Ordering::Relaxed) > 0,
            "超记账额后 EWMA 采样必须继续"
        );
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 掐断采样覆盖旧印象，不做 α=0.3 混合。
    #[test]
    fn force_ewma_overrides_stale_high_impression() {
        let ld = mirror_load("force-override.test");
        ld.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
        force_ewma(&ld, CUT_CHECKPOINT_BYTES, Duration::from_millis(2_600));
        let expect = CUT_CHECKPOINT_BYTES * 1000 / 2_600;
        assert_eq!(
            ld.speed_ewma.load(Ordering::Relaxed),
            expect,
            "掐断采样必须覆盖旧印象"
        );
        assert!(expect < 5 * 1024 * 1024 / 20, "实测值应远低于快基准/20");
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 相对差值检验：全军低速零误杀，一快多慢慢鼠照样暴露；同伴不足不评。
    #[test]
    fn cutoff_significance_median_of_fresh_peers() {
        let m = |rates: &[u64]| peer_median(rates);
        assert!(should_cut(2 * 1024, m(&[100 * 1024, 100 * 1024, 120 * 1024])));
        assert!(!should_cut(50 * 1024, m(&[50 * 1024, 50 * 1024, 60 * 1024])));
        assert!(should_cut(
            2 * 1024,
            m(&[100 * 1024, 90 * 1024, 110 * 1024, 95 * 1024])
        ));
        assert!(!should_cut(0, m(&[100 * 1024, 100 * 1024])));
        assert!(!should_cut(0, m(&[])));
    }

    #[test]
    fn cut_limiter_caps_per_window() {
        let key = "cut-limit.test";
        for _ in 0..CUT_LIMIT_PER_WINDOW {
            assert!(cut_allowed(key), "窗口内前 {CUT_LIMIT_PER_WINDOW} 次应放行");
        }
        assert!(
            !cut_allowed(key),
            "窗口内第 {} 次应拒绝",
            CUT_LIMIT_PER_WINDOW + 1
        );
    }

    /// 显著慢流在 checkpoint 处 Err 终止；守卫全额归还、last_fail 与慢速率入表。
    #[tokio::test]
    async fn cutoff_body_aborts_significantly_slow_stream() {
        let peers: Vec<Arc<MirrorLoad>> = (0..3)
            .map(|i| {
                let p = mirror_load(&format!("cut-peer{i}.test"));
                p.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
                p.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
                p
            })
            .collect();
        let me = mirror_load("cut-me.test");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.last_fail_ms.store(0, Ordering::Relaxed);
        me.in_flight_bytes.store(0, Ordering::Relaxed);
        // 两帧 96KB，帧间 1.4s：own ≈ 68KB/s < 250KB/s(基准/20) → 掐。
        let chunks = vec![
            Bytes::from(vec![0u8; CUT_CHECKPOINT_BYTES as usize]);
            2
        ];
        let stream = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|b| Ok::<_, std::io::Error>(hyper::body::Frame::data(b))),
        );
        let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(stream));
        let guard = LoadGuard::charge(me.clone(), 2 * CUT_CHECKPOINT_BYTES);
        let mut wrapped = cutoff_watched_body(
            body,
            guard,
            me.clone(),
            peers,
            CutMeta {
                chain_host: "cut-host.test".into(),
                mirror: "cut-mirror.test".into(),
                label: "h/p".into(),
            },
            Arc::new(|_: &str| {}),
        );
        let mut got_err = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(tokio::time::Instant::now() < deadline, "掐断测试超时");
            match http_body_util::BodyExt::frame(&mut wrapped).await {
                Some(Ok(_)) => tokio::time::sleep(Duration::from_millis(1400)).await,
                Some(Err(_)) => {
                    got_err = true;
                    break;
                }
                None => break,
            }
        }
        drop(wrapped);
        assert!(got_err, "显著慢流应在 checkpoint 处被掐断");
        assert_eq!(
            me.in_flight_bytes.load(Ordering::Relaxed),
            0,
            "掐断后守卫必须全额归还"
        );
        assert_ne!(
            me.last_fail_ms.load(Ordering::Relaxed),
            0,
            "掐断必须记 last_fail"
        );
        assert!(
            me.speed_ewma.load(Ordering::Relaxed) > 0,
            "掐断必须强制采样慢速率入 EWMA"
        );
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.last_fail_ms.store(0, Ordering::Relaxed);
    }
}
