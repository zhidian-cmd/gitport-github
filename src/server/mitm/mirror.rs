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
/// 自然不交卷, 亚毫秒突发打不出幽灵样本。返回本次分数(调用方按需落评估账)。
fn store_probe_score(load: &MirrorLoad, bytes: u64, us: u64) -> u64 {
    if bytes == 0 || us == 0 {
        return 0;
    }
    let score = (bytes * 1_000_000 / us).max(1);
    load.speed_ewma.store(score, Ordering::Relaxed);
    load.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
    // 链序按速度重排落盘: 链头恒为实测最快(IDM 首片/非下载器直接受益)。
    resort_chain_by_speed(&load.url);
    score
}

/// 链序按速度重排(纯函数): 有分者速度降序在前, 无分/失败窗者保持原相对
/// 顺序缀尾。稳定排序保证同速者不跳动(幂等关键)。
fn speed_sorted_chain(chain: &[String], speed_of: &dyn Fn(&str) -> u64) -> Vec<String> {
    let mut idx: Vec<usize> = (0..chain.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(speed_of(&chain[i])));
    idx.into_iter().map(|i| chain[i].clone()).collect()
}

/// 需要按速度重排的链: 只挑大文件链, 且链里确实有这个镜像。
/// 一个镜像同挂三条大文件链, 必须全部命中——只排一条等于另两条永不更新。
fn big_chains_with<'a>(
    chains: &'a HashMap<String, Vec<String>>,
    url: &str,
) -> Vec<(&'a String, &'a Vec<String>)> {
    chains
        .iter()
        .filter(|(h, c)| pool::route::is_big_file_host(h.as_str()) && c.iter().any(|m| m == url))
        .collect()
}

/// 探测交分后按最新速度分重排该镜像所属链并落盘 plans.json——链头恒为
/// 实测最快: IDM 爬坡首片与非下载器场景直接命中快腿; 并发派发仍由 ECT 接管。
/// 小文件链序归校准管, 这里一条都不碰。
fn resort_chain_by_speed(scored_url: &str) {
    let chains = pool::mirror_chains_snapshot();
    let targets = big_chains_with(&chains, scored_url);
    if targets.is_empty() {
        return;
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
    for (host, chain) in targets {
        let new_chain = speed_sorted_chain(chain, &speed_of);
        pool::set_mirror_chain(host, &new_chain, "测速");
    }
}

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
                let score = store_probe_score(&self.load, since_bytes, since_us);
                // 评估缓存只吃终值(全片均速): 首帧那 100ms 的慢启动读数只用于
                // 当次派发与链序, 不能拿去判"这家镜像值不值得留"。
                pool::mirror_stats::record(&self.load.url, score);
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
mod tests;
