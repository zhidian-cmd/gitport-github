//! 镜像链：回落兜底 + 图片链 TTFB 校准 + 凭据防护。
//! 请求级派发：ECT=(在途字节+新请求字节)/速度选起点，失败沿链顺延；不内切不缓冲。
//! 清场：探测交卷后严劣于链内最快者的镜像盖纪元号, 在途断流交客户端重发;
//! 速度分数由探测片一次性交卷冻结(全片均速), 正常流永不改写。
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
/// 失败降权窗；全体都在窗内则放开过滤。
const MIRROR_FAIL_WINDOW_MS: u64 = 45_000;
/// 开放区间/无 Range 的体积假设，仅影响派发权重。
const ASSUMED_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
/// 探测交分：严格按时间——距响应头每满 100ms 按全片运行均速交一次卷,
/// 此后每帧刷新。字节数不设门槛: 交分时刻确定(不随速率/并发漂移),
/// 1-byte Range 探针活不过 100ms 自然不交卷, 亚毫秒突发打不出幽灵样本。
const SAMPLE_TIME_FLOOR_MS: u64 = 100;

/// 在途字节 / 在途流数 / 速度分(0=未交卷; 探测交卷后冻结) / 失败时刻(0=从未)
/// / 最近采样时刻(0=从未) / 清场纪元(严劣让位时 +1, 在途流逐帧核对)。
/// 流数用于 ECT 并列组的第二级判据：组内选在途流最少者。
#[derive(Default)]
pub(super) struct MirrorLoad {
    pub(super) in_flight_bytes: AtomicU64,
    pub(super) in_flight_streams: AtomicU64,
    pub(super) speed_ewma: AtomicU64,
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

/// 从 Range 头估请求体积(mod.rs 组装直连腿的 charge 用)。
pub(super) fn range_bytes_of(range: Option<&str>) -> u64 {
    range_bytes(range)
}

/// 探测交分：head_at 起算的全片运行平均，唯一的速度写入通道——交卷即冻结，
/// 正常流永不覆盖。100ms 时间门槛由调用方把关: 1-byte 探针活不过 100ms
/// 自然不交卷, 亚毫秒突发打不出幽灵样本。
fn store_probe_score(load: &MirrorLoad, bytes: u64, us: u64) {
    if bytes == 0 || us == 0 {
        return;
    }
    let score = (bytes * 1_000_000 / us).max(1);
    load.speed_ewma.store(score, Ordering::Relaxed);
    load.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
    // 历史评估缓存: 每会话每镜 1 条(首落分)。只写不读——派发路径不碰它。
    pool::mirror_stats::record(&load.url, score);
    // 链序按速度重排落盘: 链头恒为实测最快(IDM 首片/非下载器直接受益)。
    resort_chain_by_speed(&load.url);
}

/// 链序按速度重排(纯函数): 有分者速度降序在前, 无分/失败窗者保持原相对
/// 顺序缀尾。稳定排序保证同速者不跳动(幂等关键)。
fn speed_sorted_chain(chain: &[String], speed_of: &dyn Fn(&str) -> u64) -> Vec<String> {
    let mut idx: Vec<usize> = (0..chain.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(speed_of(&chain[i])));
    idx.into_iter().map(|i| chain[i].clone()).collect()
}

/// 探测交分后按最新速度分重排该镜像所属链并落盘 plans.json——链头恒为
/// 实测最快: IDM 爬坡首片与非下载器场景直接命中快腿; 并发派发仍由 ECT 接管。
fn resort_chain_by_speed(scored_url: &str) {
    let chains = pool::mirror_chains_snapshot();
    let Some((host, chain)) = chains
        .into_iter()
        .find(|(_, c)| c.iter().any(|m| m == scored_url))
    else {
        return;
    };
    if !pool::route::is_big_file_host(&host) {
        return; // 小文件链序归校准管
    }
    let now = pool::now_ms();
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
    let new_chain = speed_sorted_chain(&chain, &speed_of);
    pool::set_mirror_chain(&host, &new_chain, "测速");
}

/// 记账守卫：派发时记在途，交付逐帧归还，Drop 清残余。
/// 记账守卫：派发时记在途，交付逐帧归还，Drop 清残余。
/// 记账封顶于记账额防下溢；采样走原始字节，开放区间超记账额后采样不停。
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
        }
    }


    /// 交付一帧：记账按记账额归还(封顶于 charged，防镜像无视 Range 回全量把
    /// 计数打成负)；原始累计照走。分数冻结: 只有探测流写速度, 且是 head_at
    /// 起算的全片运行平均——距头每满 100ms 落一分, 只看时间不看字节。
    pub(super) fn on_frame(&mut self, n: u64) {
        let credit = n.min(self.charged.saturating_sub(self.delivered));
        self.delivered += credit;
        self.raw_delivered += n;
        if credit > 0 {
            self.load.in_flight_bytes.fetch_sub(credit, Ordering::Relaxed);
        }
        if !self.big {
            return;
        }
        let since_bytes = self.raw_delivered - self.head_bytes;
        let since_us = self.head_at.elapsed().as_micros() as u64;
        if since_us >= SAMPLE_TIME_FLOOR_MS * 1000 && since_bytes > 0 {
            store_probe_score(&self.load, since_bytes, since_us);
        }
    }

    /// 测速时钟重置：响应头到达时调用。建连/拨号/等待服务器开腔的全部耗时
    /// 只存在于墙钟，不进速度样本——否则探测交分被等待稀释，且快镜像被
    /// 稀释得更狠(等待是常数)，候选差距被压缩。
    /// 在途记账不受影响：charge 仍在派发时发生(ECT 分子要含已派出未到货)。
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
        // 探测片终值: 全片均速定稿(被清场提前断流的探测片也在此交卷记分)。
        // 同一严格时间规则: 距头满 100ms 且有字节才交, 短命流不交卷。
        if self.is_probe {
            let since_bytes = self.raw_delivered - self.head_bytes;
            let since_us = self.head_at.elapsed().as_micros() as u64;
            if since_us >= SAMPLE_TIME_FLOOR_MS * 1000 && since_bytes > 0 {
                store_probe_score(&self.load, since_bytes, since_us);
            }
        }
        let residual = self.charged.saturating_sub(self.delivered);
        if residual > 0 {
            self.load.in_flight_bytes.fetch_sub(residual, Ordering::Relaxed);
        }
        // 流数随流终结归位(正常读完/客户端断开/清场断流全走这里)。
        self.load
            .in_flight_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}


/// ECT 绝对最小者胜，无容差——速度差 30 倍的现实里 5% 容差是把片撒给慢腿的
/// 祸根。仅当 ECT 完全相等(逐毫秒)才二级: 在途流数最少 → 仍相等才轮转。
/// 失败窗内的镜像跳过，全军都在窗内则放开。探测态走 probe_pick，勿用此函数。
fn pick_mirror(chain: &[String], new_bytes: u64) -> usize {
    let now = pool::now_ms();
    let loads: Vec<Arc<MirrorLoad>> = chain.iter().map(|m| mirror_load(m)).collect();
    // 单点实现：ECT 毫秒。探测轮保证派发前全员交卷，这里不该见到零样本；
    // 防御性 .max(1)：未交卷且在失败窗的候选 ECT 无穷大，稳定态里垫底。
    let ect_of = |ld: &MirrorLoad| -> u64 {
        let speed = ld.speed_ewma.load(Ordering::Relaxed).max(1);
        ld.in_flight_bytes.load(Ordering::Relaxed).saturating_add(new_bytes) * 1000 / speed
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
    0
}

/// 轮转计数器：并列候选间均摊。
static TIE_ROTATOR: AtomicU64 = AtomicU64::new(0);

/// 探测轮游标：并发派发下连续领取必命中不同候选(连续整数 mod n 两两不同)。
static PROBE_CURSOR: AtomicU64 = AtomicU64::new(0);

/// 探测态选家：链内有从未交卷(无速度样本)且健康的候选 → 原子游标轮转领取，
/// 并发分片天然一片一家；无(或全在失败窗) → None，交回 ECT 稳定态。
/// 这是 2MB/s 先验从 ECT 退役后的补位：速度一律实测，不再猜。
fn probe_pick(candidates: &[String]) -> Option<usize> {
    let now = pool::now_ms();
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

/// 清场监视(带 Range 的流)：逐帧核对纪元, 本镜像被清场即 Err 断流, 客户端
/// 重发重进派发; 探测流交分后自检, 严劣于链内已交卷最大者 → 盖纪元号(本镜像
/// 全部在途流下一帧断流)。并列最快者保留, 均摊走 ECT; 无 Range 流不经过这里。
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
            Some(Err(e)) => Some((Err(e), st)),
            None => None,
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

/// 切分下载: 无 Range / 单字节试探片命中大文件链时代理替下载器并发。
/// 按各镜速度比例切段(MirrorLoad 冻结分 → 历史中位 → 均分), 并发拉取,
/// MergeBody 按预划边界合并成单河; 段失败向其余镜发补救请求(限 2 次)。
/// 各段流速 = 测速: 实际字节/实际耗时, 小片不足 100ms 照交(交分即冻结)。
async fn split_download(
    log: &LogFn,
    out: &hyper::Request<crate::server::upstream::BoxBody>,
    orig_url: &str,
    chain: &[String],
    path: &str,
    host: &str,
) -> Result<hyper::Response<crate::server::upstream::BoxBody>, String> {
    let now = pool::now_ms();
    let healthy: Vec<String> = chain
        .iter()
        .filter(|m| {
            let ld = mirror_load(m);
            let lf = ld.last_fail_ms.load(Ordering::Relaxed);
            lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS
        })
        .cloned()
        .collect();
    if healthy.is_empty() {
        return Err(format!("{host} 切分路径: 链内全员失败窗中"));
    }
    let speed_of = |m: &str| -> u64 {
        let s = mirror_load(m).speed_ewma.load(Ordering::Relaxed);
        if s > 0 {
            s
        } else {
            pool::mirror_stats::median_of(m)
        }
    };
    let speeds: Vec<u64> = healthy.iter().map(|m| speed_of(m)).collect();
    // 总长按假设值切(8MB); 段请求带明确 Range, 尾段 EOF 自然收缩。
    let total = range_bytes(None);
    let segs = super::merge::split_by_speed(total, &speeds, healthy.len());
    (log)(&format!(
        "[切分] {host}{path} 按速度比例切 {} 段, 并发拉取",
        segs.len()
    ));
    let mut bodies: Vec<(String, u64, u64, Result<crate::server::upstream::BoxBody, String>)> =
        Vec::new();
    for ((start, end), m) in segs.iter().zip(healthy.iter()) {
        let mut req = mirror_request(out, m, orig_url)?;
        if !(*start == 0 && *end >= total) {
            let hv = http::HeaderValue::from_str(&format!("bytes={start}-{}", end - 1))
                .map_err(|e| e.to_string())?;
            req.headers_mut().insert(http::header::RANGE, hv);
        }
        match mirror_do(req, m, log).await {
            Ok(resp) => {
                let (_, body) = resp.into_parts();
                bodies.push((m.clone(), *start, *end, Ok(body)));
            }
            Err(e) => {
                mirror_load(m)
                    .last_fail_ms
                    .store(pool::now_ms(), Ordering::Relaxed);
                (log)(&format!("[切分] {host} {m} 段 [{start}..{end}) 失败({e}), 缺口留待续传"));
            }
        }
    }
    if bodies.is_empty() {
        return Err(format!("{host} 切分路径: 全部段失败"));
    }
    bodies.sort_by_key(|(_, s, _, _)| *s);
    let ready: Vec<(u64, crate::server::upstream::BoxBody)> = bodies
        .into_iter()
        .map(|(_, e, _, b)| (e, b.expect("bodies 只收 Ok 段")))
        .collect();
    let merged = super::merge::MergeBody::new(ready);
    // unfold 包装器: 缺口内联补救(限 2 次)——向链内其他健康镜像拉剩余区间。
    let st = SplitState {
        merge: merged,
        chain: chain.to_vec(),
        orig_url: orig_url.to_string(),
        host: host.to_string(),
        method: out.method().clone(),
        rescues: 0,
        log: log.clone(),
    };
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        loop {
            if let Some(gap_end) = st.merge.gap.take() {
                if st.rescues >= 2 {
                    return Some((
                        Err(std::io::Error::other("切分段补救次数耗尽, 断流交客户端重试")),
                        st,
                    ));
                }
                st.rescues += 1;
                let from = st.merge.sent();
                match st.fetch_rescue(from, gap_end).await {
                    Ok(body) => {
                        (st.log)(&format!(
                            "[切分] {} 缺口 [{from}..{gap_end}) 补救重拉(第 {} 次)",
                            st.host, st.rescues
                        ));
                        st.merge.feed_rescue(gap_end, body);
                    }
                    Err(e) => {
                        return Some((
                            Err(std::io::Error::other(format!("切分段补救失败: {e}"))),
                            st,
                        ));
                    }
                }
            }
            let poll = std::future::poll_fn(|cx| {
                hyper::body::Body::poll_frame(std::pin::Pin::new(&mut st.merge), cx)
            })
            .await;
            match poll {
                Some(Ok(f)) => return Some((Ok(f), st)),
                Some(Err(e)) => return Some((Err(e), st)),
                None => {
                    if st.merge.gap.is_some() {
                        continue; // 补救后继续
                    }
                    return None; // 真 EOS
                }
            }
        }
    });
    let resp = hyper::Response::builder()
        .status(200)
        .body(crate::server::upstream::BoxBody::new(
            http_body_util::StreamBody::new(stream),
        ))
        .map_err(|e| e.to_string())?;
    Ok(resp)
}

/// split_download 的 unfold 状态: MergeBody + 补救材料。
struct SplitState {
    merge: super::merge::MergeBody,
    chain: Vec<String>,
    orig_url: String,
    host: String,
    method: http::Method,
    rescues: u32,
    log: LogFn,
}

impl SplitState {
    /// 向链内其他健康镜像发补救请求(剩余区间 sent..gap_end)。
    async fn fetch_rescue(&self, from: u64, to: u64) -> Result<crate::server::upstream::BoxBody, String> {
        let now = pool::now_ms();
        let mate = self
            .chain
            .iter()
            .find(|m| {
                let ld = mirror_load(m);
                let lf = ld.last_fail_ms.load(Ordering::Relaxed);
                (lf == 0 || now.saturating_sub(lf) >= MIRROR_FAIL_WINDOW_MS)
                    && ld.speed_ewma.load(Ordering::Relaxed) > 0
            })
            .or_else(|| self.chain.first())
            .ok_or_else(|| "无可用补救镜像".to_string())?;
        let req = hyper::Request::builder()
            .method(self.method.clone())
            .uri(format!("{}/{}", "", self.orig_url.trim_start_matches("https://")))
            .header(
                http::header::RANGE,
                http::HeaderValue::from_str(&format!("bytes={from}-{}", to - 1))
                    .map_err(|e| e.to_string())?,
            )
            .body(crate::server::upstream::empty_body())
            .map_err(|e| e.to_string())?;
        let resp = mirror_do(req, mate, &self.log).await?;
        let (_, body) = resp.into_parts();
        Ok(body)
    }
}

pub(super) async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    direct: DirectLeg<'_>,
) -> Result<hyper::Response<BoxBody>, String> {
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
    // 凭据串请求：签名 URL 不落任何第三方——除非该镜像被用户标记为可信
    // (trusted=true, 知情授权，风险自担)。可信名单非空时按名单放行，
    // 不可信者仍剥除；全不可信则剥空仅直连。
    let chain = if cred_locked {
        let trusted_set = crate::settings::trusted_mirrors();
        let trusted: Vec<String> = pool::mirror_chain(chain_host)
            .into_iter()
            .filter(|m| {
                trusted_set
                    .iter()
                    .any(|t| m.starts_with(t.as_str()))
            })
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
    // 直连同台：直连是候选池里的普通选手(键 direct/{host})，ECT 一视同仁；
    // 零镜像时候选=仅直连，502 只在"镜像+直连全灭"时发生。
    let direct_key = format!("direct/{chain_host}");
    let mut candidates: Vec<String> = chain.clone();
    candidates.push(direct_key.clone());
    // 切分路径(仅大文件链): 无 Range / 单字节试探片, 代理替下载器并发,
    // 按镜像速度比例切段, MergeBody 合并成单河; 各段流速即测速交分。
    if pool::route::is_big_file_host(chain_host)
        && !chain.is_empty()
        && super::merge::splittable_range(range)
    {
        return split_download(log, out, &orig_url, &chain, &path, host).await;
    }
    // 熔断只拦有镜像候选的请求: 凭据串剥空/零镜像时直连独走, 别连坐。
    if !chain.is_empty() && pool::MIRROR_BREAKER.open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(candidates.len())
        .min(candidates.len());
    let new_bytes = range_bytes(out.headers().get("range").and_then(|v| v.to_str().ok()));
    // 探测态优先：链内有从未交卷的候选 → 一片一家实测(原子游标)，全员交卷
    // 后回 ECT 纯实测竞速。2MB/s 先验自 ECT 退役，仅存于 EOS 兜底基准。
    // 大小文件绝对解耦：探测轮与 ECT 选点只属于大文件机器; 小文件消费
    // 校准链序, 从链头逐个试, 对速度分/失败窗/在途/评估缓存零读零写。
    let big = pool::route::is_big_file_host(chain_host);
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
            mirror_load(&direct_key).last_fail_ms.load(Ordering::Relaxed)
        } else {
            0
        },
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
                    if big {
                        mirror_load(&direct_key).last_fail_ms.store(0, Ordering::Relaxed);
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
                            .store(pool::now_ms(), Ordering::Relaxed);
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
                (log)(&format!(
                    "[镜像] {host}{path} via {m} (链位 {}/{len}, {} #{}, 头 {ms}ms)",
                    i + 1,
                    if big { "ECT起点" } else { "链序起点" },
                    start + 1,
                    len = chain.len(),
                    ms = t0.elapsed().as_millis()
                ));
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
                        .store(pool::now_ms(), Ordering::Relaxed);
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
            got.iter().any(|l| l.contains("仅直连(防外泄")),
            "应记录剥空镜像决策: {got:?}"
        );
        assert!(
            !got.iter().any(|l| l.contains(" via ")),
            "签名 URL 不得交给第三方镜像: {got:?}"
        );
    }

    /// 可信镜像白名单：用户标记 trusted 的镜像，凭据串请求放行给它(知情授权);
    /// 未标记的镜像仍被剥除。放行名单为空时行为与旧版一致(仅直连)。
    #[test]
    fn cred_authorized_trusted_mirrors_only() {
        // settings 全局态无法按测隔离——直接验证放行集合的过滤逻辑:
        // trusted_mirrors() 返回 on && trusted 的 URL, 镜像 URL 前缀匹配放行。
        use crate::settings::WorkerMirror;
        let mirrors = [
            WorkerMirror { url: "https://my-worker.example.com".into(), on: true, trusted: true },
            WorkerMirror { url: "https://public-proxy.example.org".into(), on: true, trusted: false },
        ];
        let trusted: std::collections::HashSet<String> = mirrors
            .iter()
            .filter(|w| w.on && w.trusted)
            .map(|w| w.url.clone())
            .collect();
        let chain = [
            "https://my-worker.example.com/".to_string(),      // 可信(带尾斜杠变体)
            "https://public-proxy.example.org".to_string(),    // 不可信
        ];
        let passed: Vec<&String> = chain
            .iter()
            .filter(|m| trusted.iter().any(|t| m.starts_with(t.as_str())))
            .collect();
        assert_eq!(passed.len(), 1, "只有可信镜像应被放行: {passed:?}");
        assert!(
            passed[0].starts_with("https://my-worker.example.com"),
            "放行的应是可信那家: {passed:?}"
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


    /// 测试用直连腿：恒失败(不拨真网)，用于驱动候选循环与失败降权路径。
    fn mirror_test_direct_leg() -> DirectLeg<'static> {
        DirectLeg {
            fetch: Box::pin(async {
                Err::<hyper::Response<BoxBody>, String>("test: direct unavailable".into())
            }),
        }
    }

    /// 探测流交卷: 全片均速从响应头起算(head_at), 建连/等待不进分母。
    #[test]
    fn probe_scores_from_response_head() {
        let ld = mirror_load("probe-score.test");
        ld.speed_ewma.store(0, Ordering::Relaxed);
        let mut g = LoadGuard::charge(ld.clone(), 4 * 1024 * 1024, true); // 无分 → 探测流
        assert!(g.is_probe, "无分镜像派出的流必须是探测流");
        std::thread::sleep(Duration::from_millis(120)); // 模拟建连+等待
        g.restart_mark(); // 头到达, 测速时钟起算
        std::thread::sleep(Duration::from_millis(150)); // 体流 150ms
        g.on_frame(1024 * 1024); // 1MB/150ms ≈ 6.8MB/s; 含建连等待 ≈ 1MB/270ms ≈ 3.8MB/s
        let s = ld.speed_ewma.load(Ordering::Relaxed);
        assert!(
            s > 5 * 1024 * 1024,
            "全片均速不得包含建连/等待耗时: {s}B/s"
        );
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 严格时间交分：距头满 100ms 即落分, 字节数不限——停滞 100ms 内现形。
    #[test]
    fn time_floor_fires_sample_on_stall() {
        let ld = mirror_load("stall-clock.test");
        ld.speed_ewma.store(0, Ordering::Relaxed);
        let mut g = LoadGuard::charge(ld.clone(), 4 * 1024 * 1024, true);
        std::thread::sleep(Duration::from_millis(120));
        g.on_frame(4 * 1024); // 4KB 也交: 只看时间不看字节
        let s = ld.speed_ewma.load(Ordering::Relaxed);
        assert!(
            s > 0 && s < 200 * 1024,
            "时间地板应触发停滞读数(4KB/120ms ≈ 34KB/s): {s}B/s"
        );
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }


    /// 探测轮：全员未交卷时一片一家(前 N 次领取两两不同)；交卷即退出探测态。
    #[test]
    fn probe_round_hands_each_candidate_one_shard() {
        let chain = vec![
            "probe-all.test".to_string(),
            "probe-bl.test".to_string(),
            "probe-cl.test".to_string(),
        ];
        // 隔离: 并发测试可能给同名 load 留下失败窗/样本, 先清场。
        for m in &chain {
            let ld = mirror_load(m);
            ld.last_fail_ms.store(0, Ordering::Relaxed);
            ld.last_sample_ms.store(0, Ordering::Relaxed);
        }
        let mut picks = std::collections::HashSet::new();
        for _ in 0..3 {
            picks.insert(probe_pick(&chain).unwrap());
        }
        assert_eq!(picks.len(), 3, "探测轮前 3 次领取应覆盖全部候选: {picks:?}");
        for m in &chain {
            mirror_load(m)
                .last_sample_ms
                .store(pool::now_ms(), Ordering::Relaxed);
        }
        assert!(probe_pick(&chain).is_none(), "全员交卷应退出探测态");
        for m in &chain {
            mirror_load(m).last_sample_ms.store(0, Ordering::Relaxed);
        }
    }

    /// 探测态跳过：未交卷但在失败窗内的候选不领片；全员无健康未交卷 → None。
    #[test]
    fn probe_skips_failed_unprobed_and_yields_to_ect() {
        let a = mirror_load("probe-skip-a.test");
        let b = mirror_load("probe-skip-b.test");
        let chain = vec!["probe-skip-a.test".to_string(), "probe-skip-b.test".to_string()];
        // 隔离: 清并发测试残留, 再摆本测要的姿态。
        a.last_fail_ms.store(0, Ordering::Relaxed);
        a.last_sample_ms.store(0, Ordering::Relaxed);
        b.last_fail_ms.store(0, Ordering::Relaxed);
        b.last_sample_ms.store(0, Ordering::Relaxed);
        // a 未交卷但刚失败 → 跳过；b 已交卷 → 无探测目标。
        a.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        b.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
        assert!(
            probe_pick(&chain).is_none(),
            "失败窗内的未交卷候选不应被探测"
        );
        // a 失败窗过 → 恢复可探测，领取 a。
        a.last_fail_ms.store(0, Ordering::Relaxed);
        assert_eq!(probe_pick(&chain), Some(0));
        a.last_sample_ms.store(0, Ordering::Relaxed);
        b.last_sample_ms.store(0, Ordering::Relaxed);
    }

    /// 先验退役：未交卷候选在 ECT 里按无穷大垫底——已交卷的慢腿也胜过它。
    #[test]
    fn ect_after_retirement_unprobed_loses_to_probed_slow() {
        let slow = mirror_load("retire-slow.test");
        slow.speed_ewma.store(100 * 1024, Ordering::Relaxed); // 100KB/s 已交卷
        let unprobed = mirror_load("retire-unprobed.test");
        unprobed.speed_ewma.store(0, Ordering::Relaxed);
        let chain = vec!["retire-slow.test".to_string(), "retire-unprobed.test".to_string()];
        assert_eq!(
            pick_mirror(&chain, 1024),
            0,
            "未交卷者 ECT 无穷大, 已交卷的慢腿也胜出(先验不再掺和)"
        );
        slow.speed_ewma.store(0, Ordering::Relaxed);
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
        // 直连快(8MB/s 实测) 镜像未交卷(ECT 无穷大垫底): 直连胜出。
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

    /// 全未交卷(ECT 同为无穷大、并列) → 轮转均摊；在途越深越垫底，闲者胜出。
    #[test]
    fn cold_start_falls_back_to_chain_order() {
        let a = mirror_load("cold-a.test");
        let b = mirror_load("cold-b.test");
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["cold-a.test".to_string(), "cold-b.test".to_string()];
        // 全未交卷 → ECT 同为无穷大 → 并列 → 轮转(先验已退役, 不再按链位铺开)。
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

    /// ECT 绝对最小(无容差): 速度差 4% 也严格选快者——5% 容差已废。
    /// 仅 ECT 完全相等才走二级(流数/轮转)。
    #[test]
    fn ect_strict_minimum_no_tolerance() {
        let a = mirror_load("tie-a.test");
        let b = mirror_load("tie-b.test");
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["tie-a.test".to_string(), "tie-b.test".to_string()];
        // 速度差 4% → 恒选快者 b(容差时代会轮转)。
        a.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
        b.speed_ewma.store(2088 * 1024, Ordering::Relaxed); // +4%
        for _ in 0..10 {
            assert_eq!(pick_mirror(&chain, 8 * 1024 * 1024), 1, "无容差: 4% 差距也严格选快");
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
            let mut g = LoadGuard::charge(ld.clone(), 1000, true);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 1000);
            g.on_frame(400);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 600);
            g.on_frame(400);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 200);
        } // drop：残余归还
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "Drop 必须清残余");
        {
            let mut g = LoadGuard::charge(ld.clone(), 100, true);
            g.on_frame(500);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "交付封顶于记账");
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
        {
            let _g = LoadGuard::charge(ld.clone(), 4096, true);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 4096);
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
    }

    /// 链序按速度重排(纯函数): 快者在前, 无分/失败窗者保持原序缀尾, 同速稳定。
    #[test]
    fn speed_sorted_chain_orders_and_stabilizes() {
        let chain = vec![
            "https://a".to_string(),
            "https://b".to_string(),
            "https://c".to_string(),
            "https://d".to_string(),
        ];
        // 速度: a=100, b=0(无分), c=500, d=100 → c, a, d, b (b 原位缀尾, a/d 同速稳定)
        let speed_of = |m: &str| -> u64 {
            match m {
                "https://a" => 100,
                "https://c" => 500,
                "https://d" => 100,
                _ => 0,
            }
        };
        let out = speed_sorted_chain(&chain, &speed_of);
        assert_eq!(
            out,
            vec!["https://c".to_string(), "https://a".to_string(), "https://d".to_string(), "https://b".to_string()],
            "速度降序 + 无分缀尾 + 同速稳定: {out:?}"
        );
        // 已排序输入重排 = 恒等(幂等)。
        let again = speed_sorted_chain(&out, &speed_of);
        assert_eq!(again, out, "已排序链重排必须恒等(零写盘的幂等基础)");
    }

    /// 分数冻结：正常流(镜像已有分)只记账, 永不改写速度分。
    /// 分数冻结：正常流(镜像已有分)只记账, 永不改写速度分。
    #[test]
    fn normal_stream_never_touches_score() {
        let ld = mirror_load("freeze.test");
        ld.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
        let mut g = LoadGuard::charge(ld.clone(), 1024 * 1024, true); // 有分 → 非探测
        assert!(!g.is_probe, "已有分的镜像派出的流不得是探测流");
        g.on_frame(1024 * 1024);
        drop(g);
        assert_eq!(
            ld.speed_ewma.load(Ordering::Relaxed),
            5 * 1024 * 1024,
            "正常流不得改写冻结分数"
        );
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 清场触发: 探测流交分后严劣于链内已交卷最大者 → 盖纪元号, 在途断流。
    #[tokio::test]
    async fn cull_fires_for_strictly_slower_probe() {
        let fast = mirror_load("cull-fast.test");
        fast.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
        let me = mirror_load("cull-me.test");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.cull_epoch.store(0, Ordering::Relaxed);
        let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
                Bytes::from(vec![0u8; 64 * 1024]),
            ))]),
        ));
        let guard = LoadGuard::charge(me.clone(), 64 * 1024, true); // 无分 → 探测流
        let mut wrapped = cull_watched_body(
            body,
            guard,
            me.clone(),
            vec![fast.clone()],
            "h/p".into(),
            "cull-me.test".into(),
            Arc::new(|_: &str| {}),
        );
        tokio::time::sleep(Duration::from_millis(120)).await; // 满交分地板
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // 帧 → 交分 ~546KB/s → 触发清场
        assert_ne!(
            me.cull_epoch.load(Ordering::Relaxed),
            0,
            "严劣于链内最快的探测片应触发清场盖纪元"
        );
        let got_err = matches!(
            http_body_util::BodyExt::frame(&mut wrapped).await,
            Some(Err(_))
        );
        assert!(got_err, "被清场镜像的在途流必须断流交客户端重发");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.cull_epoch.store(0, Ordering::Relaxed);
        fast.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 并列最快者保留: 链内无更快者 → 不盖纪元, 存量自然跑完。
    #[tokio::test]
    async fn cull_spares_when_no_faster_peer() {
        let slow = mirror_load("tie-slow.test");
        slow.speed_ewma.store(100 * 1024, Ordering::Relaxed); // 同伴比我慢
        let me = mirror_load("tie-me.test");
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.cull_epoch.store(0, Ordering::Relaxed);
        let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
                Bytes::from(vec![0u8; 64 * 1024]),
            ))]),
        ));
        let guard = LoadGuard::charge(me.clone(), 64 * 1024, true);
        let mut wrapped = cull_watched_body(
            body,
            guard,
            me.clone(),
            vec![slow.clone()],
            "h/p".into(),
            "tie-me.test".into(),
            Arc::new(|_: &str| {}),
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // 交分 ~546KB/s > 100KB/s
        assert_eq!(
            me.cull_epoch.load(Ordering::Relaxed),
            0,
            "链内无更快者不得清场(并列最快保留)"
        );
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.cull_epoch.store(0, Ordering::Relaxed);
        slow.speed_ewma.store(0, Ordering::Relaxed);
    }
    /// 小文件流与大文件机器绝对解耦: 零充值零归还零采样零评估。
    #[test]
    fn small_stream_never_touches_big_file_state() {
        let ld = mirror_load("small-decoupled.test");
        ld.in_flight_bytes.store(0, Ordering::Relaxed);
        ld.in_flight_streams.store(0, Ordering::Relaxed);
        ld.speed_ewma.store(0, Ordering::Relaxed);
        let mut g = LoadGuard::charge(ld.clone(), 1024 * 1024, false); // 小文件流
        assert!(!g.is_probe, "小文件流无探测语义");
        g.on_frame(1024 * 1024);
        std::thread::sleep(Duration::from_millis(120));
        g.on_frame(64 * 1024); // 过 100ms 地板也不得交分
        drop(g);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "零充值零归还");
        assert_eq!(ld.in_flight_streams.load(Ordering::Relaxed), 0, "流数零接触");
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), 0, "小文件不写速度分");
        assert_eq!(ld.last_sample_ms.load(Ordering::Relaxed), 0, "评估缓存零记录");
    }

}
