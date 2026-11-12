//! 镜像链：内容域回落 + 图片链 TTFB 校准 + 凭据防护。
//! 大文件竞速：按候选数均分切段（测速只来自代理自己分的段）、慢段让位、补发按 ECT 挑家直到不再改善，故障/变慢无缝衔接。
use super::merge::{self, MergeBody};
use super::direct_split::Tpl;
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
/// ECT 时间槽：每这么久把「本窗实收字节」快照给派发器并清零重开，分数 = 债务 ÷ 上一窗字节。
const ECT_WINDOW_MS: u64 = 500;

/// 每面镜像的记账：在途字节/流数、ECT 时间槽（本窗实收 + 上一窗快照）、失败降权窗。
#[derive(Default)]
pub(super) struct MirrorLoad {
    pub(super) in_flight_bytes: AtomicU64,
    pub(super) in_flight_streams: AtomicU64,
    /// 本时间槽实收字节：on_frame 累加，ect_sweep 每 ECT_WINDOW_MS 快照进 window_prev 后清零。
    window_bytes: AtomicU64,
    /// 上一时间槽实收（派发器的吞吐分母）；0=零历史，按 +∞ 垫底。
    /// 快照：有字节换新值；零收有债=卡死清零；零收无债=空闲沿用。
    pub(super) window_prev: AtomicU64,
    /// 失败降权到期时刻(纪元 ms)。0 = 健康；超时类失败写短窗，硬错误写长窗。
    pub(super) fail_until: AtomicU64,
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

/// 供直连腿(mod.rs)记账：直连候选与镜像共用同一张负载表。
pub(super) fn mirror_load(mirror: &str) -> Arc<MirrorLoad> {
    let mut g = MIRROR_LOAD.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(mirror.to_string())
        .or_insert_with(|| Arc::new(MirrorLoad::default()))
        .clone()
}

/// 直连候选的记账键(mod.rs 组装直连腿前后共用)。
pub(super) fn direct_load_key(chain_host: &str) -> String {
    format!("direct/{chain_host}")
}

/// ECT 时间槽结算：本窗实收快照进 `window_prev` 后清零；零收有债=卡死清零，无债=空闲沿用。
fn ect_sweep() {
    let g = crate::util::lock(&MIRROR_LOAD);
    for ld in g.values() {
        let w = ld.window_bytes.swap(0, Ordering::Relaxed);
        if w > 0 {
            ld.window_prev.store(w, Ordering::Relaxed);
        } else if ld.in_flight_bytes.load(Ordering::Relaxed) > 0 {
            ld.window_prev.store(0, Ordering::Relaxed);
        }
    }
}

/// 启动 ECT 时间槽定时器：独立线程 500ms 一拍，零锁争用（快照只碰各镜像自己的原子量）。
pub(crate) fn start_ect_ticker() {
    crate::logger::spawn("ect-tick", || loop {
        std::thread::sleep(Duration::from_millis(ECT_WINDOW_MS));
        ect_sweep();
    });
}

/// 记账守卫：派发记在途、逐帧归还、Drop 清残余；归还封顶于记账额，采样走原始字节。
pub(super) struct LoadGuard {
    load: Arc<MirrorLoad>,
    /// 大文件机器标记: false = 小文件流, 与速度分/在途/失败窗零接触。
    big: bool,
    charged: u64,
    delivered: u64,
    raw_delivered: u64,
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
        // 镜像级累计：ECT 的分母是这家的总吞吐（整窗实收），不是某一条流自己的均速。
        self.load.window_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// 响应头到达时重置测速时钟：建连等待只算墙钟，不进速度样本（否则快镜像被稀释得更狠）。
    pub(super) fn restart_mark(&mut self) {
        self.head_at = Instant::now();
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
        // 流数随流终结归位(正常读完/断开都走这里)。
        if self.load.in_flight_streams.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.load.window_bytes.store(0, Ordering::Relaxed);
        }
    }
}

/// ECT 派发：score=(在途+新增)÷上一窗实收，即还需几个时间槽，最小者胜、无容差。
/// 零历史按 +∞ 垫底；失败窗内跳过，全在窗内则放开。
fn pick_mirror(chain: &[String], new_bytes: u64) -> usize {
    let now = now_ms();
    let loads: Vec<Arc<MirrorLoad>> = chain.iter().map(|m| mirror_load(m)).collect();
    let ect_of = |ld: &MirrorLoad| -> u64 {
        let w = ld.window_prev.load(Ordering::Relaxed);
        if w == 0 {
            // 零历史：整体 +∞ 垫底，档内按在途字节排梯度（闲者先试），仍高于任何有历史者。
            return u64::MAX / 2 + ld.in_flight_bytes.load(Ordering::Relaxed);
        }
        ld.in_flight_bytes
            .load(Ordering::Relaxed)
            .saturating_add(new_bytes)
            * 1024
            / w
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
fn append_direct_if_missed(
    order: &mut Vec<usize>,
    direct_idx: usize,
    fail_until: u64,
    now_ms: u64,
) {
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

/// 非 3xx、非 HTML；带 Range 必须 206，304 放行；`allow_full` 仅总长探测放行 200 全量。
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
pub(super) type DirectLeg<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<hyper::Response<BoxBody>, String>> + Send + 'a>,
>;

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
        let trusted: Vec<String> = pool::mirror_chain(&chain_host)
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
        pool::mirror_chain(&chain_host)
    };
    // 直连同台：直连以 direct/{host} 的身份参与 ECT；502 只在镜像与直连全灭时发生。
        let direct_key = direct_load_key(&chain_host);
    let mut candidates: Vec<String> = chain.clone();
    candidates.push(direct_key.clone());
    // 熔断只拦有镜像候选的请求: 凭据串剥空/零镜像时直连独走, 别连坐。
    if !chain.is_empty() && pool::MIRROR_BREAKER.open(&chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(&chain_host)
        .unwrap_or(candidates.len())
        .min(candidates.len());
    let new_bytes = range_bytes(out.headers().get("range").and_then(|v| v.to_str().ok()));
    // 单字节探片是下载器探路，按小文件走：链头直通，不切分、不记账。
    let big = pool::route::is_big_file_host(&chain_host) && !merge::is_probe_range(range);
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
            match direct.as_mut().await {
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
                    pool::MIRROR_BREAKER.clear(&chain_host);
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
                let rotated = quiet::mirror_rotated(&chain_host, m);
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
                pool::MIRROR_BREAKER.clear(&chain_host);
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
        pool::MIRROR_BREAKER.set(&chain_host);
    }
    let why = if cred_locked {
        "凭据串仅直连, 直连失败"
    } else {
        "镜像链全灭"
    };
    Err(format!("{host} {why}({chain_host} 候选 {limit} 个)"))
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

/// 无 Range 时发 1 字节 Range 探测总长；头两家各试一次（真实请求），谁先给总长用谁。
enum Probe {
    /// 上游回了 206 + Content-Range：拿到了总长，可以切。
    Total(u64),
    /// 上游忽略 Range 回 200 全量：body 就是整份文件，当单流交出。
    NotSliceable(hyper::Response<BoxBody>),
}

// 参数都是同一请求链路的借用；拆结构体只是把解构搬到调用点，收益不抵改动面。
#[allow(clippy::too_many_arguments)]
async fn probe_total(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    cands: &[&str],
    orig_url: &str,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    tpl: &Tpl,
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

#[allow(clippy::too_many_arguments)]
async fn probe_total_one(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    tpl: &Tpl,
) -> Result<Probe, String> {
    let tag = if mirror.starts_with("direct/") {
        "direct"
    } else {
        "mirror"
    };
    let mut resp = if mirror.starts_with("direct/") {
        segment_direct(
            log,
            tpl,
            host,
            info,
            replay,
            Some(http::HeaderValue::from_static("bytes=0-0")),
            None,
        )
        .await?
    } else {
        let mut req = mirror_request(out, mirror, orig_url)?;
        req.headers_mut().insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-0"),
        );
        // 探测专用：允许上游忽略 Range 回 200，把整份 body 交还调用方当单流用。
        mirror_do_inner(req, mirror, log, true).await?
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

/// 直连段请求：克隆模板头、换本段 Range；release 302 到 release-assets 时跟一跳并带 Range。
/// 预算按跳记：有镜像兜底时每跳 2s 等响应头，无兜底不设预算。
async fn segment_direct(
    log: &LogFn,
    tpl: &Tpl,
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
        Some(b) => tokio::time::timeout(b, super::get_direct(log, &req, host, info, replay))
            .await
            .map_err(|_| format!("直连首包超时({}ms)", b.as_millis()))??,
        None => super::get_direct(log, &req, host, info, replay).await?,
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
            req2.headers_mut()
                .insert(http::header::RANGE, range.clone());
        }
        let fresh = super::UpstreamInfo::default();
        resp = match hop_budget {
            Some(b) => tokio::time::timeout(
                b,
                super::get_direct(log, &req2, &next_host, &fresh, replay),
            )
            .await
            .map_err(|_| format!("直连跳转首包超时({}ms)", b.as_millis()))??,
            None => super::get_direct(log, &req2, &next_host, &fresh, replay).await?,
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

/// 段请求的 Range 头：end 是闭区间末端（含）。
/// 主切片的 (s,e) 是半开区间要传 e-1，补发的 e 已经是闭区间末端直接传 e——
/// 统一走这里，免得再出现「末端又减一次 1」那种少一字节的笔误。
fn segment_range(s: u64, end: u64) -> Result<http::HeaderValue, String> {
    http::HeaderValue::from_str(&format!("bytes={s}-{end}")).map_err(|err| err.to_string())
}

/* ---------- 同 URL 并发区间请求的段位分配 ----------
   下载器常对一个文件同时发好几个 Range 请求；每个请求各自切满所有镜像，
   叠加起来就是把 7 家镜像同时按几十路打（日志里 4 秒内 4 次「切 N 段」）。
   段大小改成按"这个 URL 上在途区间的总字节 ÷ 段位总数(镜像+2)"现算：
   大区间先占段位，小区间只拿 1 段，总并发不超段位。 */

/// 在途区间：请求进来登记，响应体释放时注销。
struct RangePlan {
    id: u64,
    len: u64,
    at: Instant,
}

static RANGE_PLANS: LazyLock<Mutex<HashMap<String, Vec<RangePlan>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static RANGE_PLAN_SEQ: AtomicU64 = AtomicU64::new(1);
/// 兜底：响应体没被正常丢弃时，登记最多留这么久，免得拖死后续分配。
const RANGE_PLAN_TTL: Duration = Duration::from_secs(180);

/// 注销登记：挂在响应体上，body drop 即释放。
struct RangePlanGuard {
    key: String,
    id: u64,
}

impl Drop for RangePlanGuard {
    fn drop(&mut self) {
        let mut map = RANGE_PLANS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(list) = map.get_mut(&self.key) {
            list.retain(|p| p.id != self.id);
            if list.is_empty() {
                map.remove(&self.key);
            }
        }
    }
}

struct RangePlanOutcome {
    want: usize,
    pending: u64,
    seg: u64,
    guard: RangePlanGuard,
}

/// 段位分配（纯函数，便于测试）：段大小 = 在途总字节 ÷ 段位总数；
/// 按区间从大到小依次占位，每个请求至少留 1 段。返回本区间该切几段。
fn plan_quota(
    pending: &[(u64, u64)],
    my_id: u64,
    my_len: u64,
    capacity: usize,
    slots: usize,
) -> usize {
    let total: u64 = pending.iter().map(|(l, _)| *l).sum();
    let seg = total.div_ceil(capacity.max(1) as u64).max(1);
    let mut order: Vec<(u64, u64)> = pending.to_vec();
    order.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut remaining = slots.max(1);
    let mut mine = 1usize;
    for (i, (l, id)) in order.iter().enumerate() {
        // 后面还有几个请求，各留 1 段，别让大区间把段位吃光。
        let left = order.len() - i - 1;
        let room = remaining.saturating_sub(left).max(1);
        let take = ((*l).div_ceil(seg).max(1) as usize).min(room);
        remaining = remaining.saturating_sub(take);
        if *id == my_id {
            mine = take;
        }
    }
    mine.clamp(1, my_len.max(1) as usize)
}

/// 登记本次区间并给出段数。key 用 host+path，同一资源的不同签名查询串归到一起。
fn plan_range_segments(
    key: &str,
    len: u64,
    capacity: usize,
    slots: usize,
) -> RangePlanOutcome {
    let id = RANGE_PLAN_SEQ.fetch_add(1, Ordering::Relaxed);
    let now = Instant::now();
    let (pending, total) = {
        let mut map = RANGE_PLANS.lock().unwrap_or_else(|p| p.into_inner());
        let list = map.entry(key.to_string()).or_default();
        list.retain(|p| now.saturating_duration_since(p.at) < RANGE_PLAN_TTL);
        list.push(RangePlan { id, len, at: now });
        let pending: Vec<(u64, u64)> = list.iter().map(|p| (p.len, p.id)).collect();
        let total: u64 = pending.iter().map(|(l, _)| *l).sum();
        (pending, total)
    };
    let want = plan_quota(&pending, id, len, capacity, slots);
    // 日志用的每段字节：总量 ÷ 段位总数，与配额同一把尺子。
    let seg = total.div_ceil(capacity.max(1) as u64).max(1);
    RangePlanOutcome {
        want,
        pending: total / 1024,
        seg: seg / 1024,
        guard: RangePlanGuard {
            key: key.to_string(),
            id,
        },
    }
}

/// 切片下载：按空闲镜像数切段并发拉，按边界合成单条流；不足 2 段、探片或上游不支持 Range 则退回单流。
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
    let idle_src: Vec<&str> = healthy
        .iter()
        .filter(|m| mirror_load(m).in_flight_streams.load(Ordering::Relaxed) == 0)
        .copied()
        .collect();
    if idle_src.len() < 2 {
        return Ok(None); // 镜像已占满或本来就没几家：切了只是抢自己的份额
    }
    // 段位分配：镜像一家 3 份（细切，慢段让位快段接），直连双通道各 1 份共 2 份——
    // 段多了在黑洞窗集体空转，直连两段一通道一段更稳。两份共享同一份负载记账。
    let mut idle: Vec<&str> = Vec::with_capacity(idle_src.len() * 3 + 2);
    for m in &idle_src {
        if m.starts_with("direct/") {
            idle.push(*m);
            idle.push(*m);
        } else {
            for _ in 0..3 {
                idle.push(*m);
            }
        }
    }
    // 直连段模板：补发起流跑在旁路任务里，原请求不能跨任务借用；与直连切片共用同一个 Tpl（direct_split.rs）。
    let tpl = Tpl::of(out);
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let (base, len, known_total) = match range {
        // 开区间/多区间/畸形：长度未知或语义不同，不切
        Some(_) => match merge::parse_range(range) {
            Some((a, Some(b))) if b >= a => {
                let len = b - a + 1;
                // 小区间单流直发：切段纯白建连接（曾把 1394B 的文件切出 23 段）。
                if len < crate::server::mitm::direct_split::MIN_SPLIT_BYTES {
                    return Ok(None);
                }
                (a, len, None)
            }
            _ => return Ok(None),
        },
        None => match total_memo_get(&slice_key) {
            // 总长记忆命中：省掉探测往返（探测本身是真实请求，结果只记 10 分钟）。
            Some(t) => (0, t, Some(t)),
            None => {
                // 探测候选按 ECT 择优、不按链序——整包单流时链头盲选会把大下载砸在慢镜像上；冷启动全零则退化回链序。
                let mut probe_cands: Vec<&str> = healthy.clone();
                probe_cands.sort_by_key(|m| {
                    let ld = mirror_load(m);
                    ld.in_flight_bytes.load(Ordering::Relaxed) * 1024
                        / ld.window_prev.load(Ordering::Relaxed).max(1)
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
    // 段数：非 Range 按空闲段位平均分；Range 按同 URL 在途总字节现算段大小，
    // 大区间先占段位、小区间只拿 1 段——下载器开 N 条连接时不会每家各切满一份。
    let (want, plan) = match range {
        Some(_) => {
            let mirrors = healthy.iter().filter(|m| !m.starts_with("direct/")).count();
            // 段位总数 = 镜像数×3 + 直连 2 份（双通道各 1）：镜像一家 3 份细切。
            let plan = plan_range_segments(&slice_key, len, mirrors * 3 + 2, idle.len());
            (plan.want, Some(plan))
        }
        None => (
            ((idle.len() as u64).min(len)).max(1) as usize,
            None,
        ),
    };
    let want = want.min(idle.len()).min(len as usize).max(1);
    let idle = &idle[..want];
    // 竞速切段：每家同等材料，快慢由段自己说话；慢段让位、补发走 ECT。
    let segs = merge::split_even(base, len, want);
    if segs.len() < 2 {
        return Ok(None);
    }
    (log)(&format!(
        "[切片] {host}{path} 切 {} 段(候选 {} 家, 空闲 {want}{}), 并发拉取",
        segs.len(),
        healthy.len(),
        match &plan {
            Some(p) => format!(", 在途 {}KB 每段 {}KB", p.pending, p.seg),
            None => String::new(),
        }
    ));
    // 有镜像兜底才给直连设按跳预算；没镜像（用户没配/链全灭）时直连是唯一的路，不能掐，交给它按 IP 表自己换、自己等。
    let has_mirror = healthy.iter().any(|m| !m.starts_with("direct/"));
    let futs = segs.iter().enumerate().map(|(i, &(s, e))| {
        let m = idle[i % idle.len()];
        let host = host.to_string();
        let tpl = tpl.clone();
        async move {
            let is_direct = m.starts_with("direct/");
            // 直连腿公共体在 fetch_segment_direct（与补发同路：预算按跳记、失败降权）；
            // 镜像腿 charge 后直接打镜像请求。两腿统一回 (guard, resp) 再做 206 校验。
            let got: Result<(LoadGuard, hyper::Response<BoxBody>), String> = if is_direct {
                // 直连分段：预算按跳记（每跳 2s）、整段 ≤2 跳——拿 2s 罩两跳两拨会掐死好腿，release 要跟 302，旧实现正是这样丢速率的。
                fetch_segment_direct(log, &tpl, &host, info, replay, m, s, e, has_mirror).await
            } else {
                let guard = LoadGuard::charge(mirror_load(m), e - s, true);
                let resp = match mirror_request(out, m, orig_url) {
                    Ok(mut req) => {
                        let hv = http::HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
                            .map_err(|err| err.to_string())?;
                        req.headers_mut().insert(http::header::RANGE, hv);
                        strip_body_headers(&mut req);
                        mirror_do(req, m, log).await
                    }
                    Err(err) => Err(err),
                }?;
                Ok((guard, resp))
            };
            match got {
                Ok((guard, resp)) if resp.status() == http::StatusCode::PARTIAL_CONTENT => {
                    merge::check_segment_start(
                    resp.headers()
                        .get("content-range")
                        .and_then(|v| v.to_str().ok()),
                    s,
                )?;
                    let at = Instant::now();
                    Ok((guard.segment_from(at), at, resp))
                }
                Ok((_, resp)) => {
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
                    // 与直连切片同一张跳过清单（direct_split::skip_response_header）
                    extra = Some(
                        resp.headers()
                            .iter()
                            .filter(|(k, _)| {
                                !super::direct_split::skip_response_header(k.as_str())
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
                &chain, &orig, &host_s, base, from, to, &log_s, &tpl, &info, &replay,
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
    // 区间登记跟着响应体走：body drop（播完/客户端断开）即注销，后续请求才算得准在途量。
    if let Some(p) = plan {
        mb = mb.hold(Box::new(p.guard));
    }
    // 开场就失败的段立刻排队补发：不等交付线走到它——那块往往在末尾，干等就是几秒。
    for (a, b) in failed {
        mb.queue_fill(a, b);
    }
    let body = drive_split(mb, ctx);
    builder.body(body).map(Some).map_err(|e| e.to_string())
}

/// 为 [from,to) 起新流（发出时加 base）；候选=镜像+健康直连，ECT 挑最小，两边都记账采样。
/// 旧实现补发不进 ECT，直连会被永久排除。
#[allow(clippy::too_many_arguments)]
async fn split_fetch(
    chain: &[String],
    orig_url: &str,
    host: &str,
    base: u64,
    from: u64,
    to: u64,
    log: &LogFn,
    tpl: &Tpl,
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
        let has_mirror = cands.len() > 1;
        // e 已经是闭区间末端（base+to-1）：fetch 收开区间末 base+to，别再减 1。
        // 少一字节会让合并层为末字节反复补发，而 1 字节补发的 Range 会变成起点>终点。
        let got = fetch_segment_direct(log, tpl, host, info, replay, &m, s, base + to, has_mirror)
            .await;
        finish_fill(got, &m, host, s, log).await
    } else {
        let guard = LoadGuard::charge(mirror_load(&m), to - from, true);
        // 只有 GET 会走到切片（split_download 早退挡掉其它方法），补发一律 GET。
        let req = hyper::Request::builder()
            .method(http::Method::GET)
            .uri(mirror_url(m.as_str(), orig_url))
            .header(http::header::USER_AGENT, MIRROR_UA)
            .header(http::header::RANGE, segment_range(s, e)?)
            .body(protocol::empty_body())
            .map_err(|e| e.to_string())?;
        let got = mirror_do(req, &m, log).await.map(|resp| (guard, resp));
        finish_fill(got, &m, host, s, log).await
    }
}

/// 直连段获取（首切与补发共用）：charge → Range → 直拨 → 有镜像时设跳预算 → 失败降权。
/// 返回 (guard, resp)——guard 随响应交还调用方接记账；mark_fail 只对直连腿
/// （超时(慢)与硬错误(死)分开降权，慢腿别踢太久）。
#[allow(clippy::too_many_arguments)]
async fn fetch_segment_direct(
    log: &LogFn,
    tpl: &Tpl,
    host: &str,
    info: &super::UpstreamInfo,
    replay: &Option<Bytes>,
    m: &str,
    s: u64,
    e: u64, // 开区间末端；Range 取 [s, e-1]
    has_mirror: bool,
) -> Result<(LoadGuard, hyper::Response<BoxBody>), String> {
    let guard = LoadGuard::charge(mirror_load(m), e - s, true);
    let range = segment_range(s, e - 1)?;
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
        mark_fail(&mirror_load(m), matches!(got.as_ref(), Err(err) if is_timeout_err(err)));
    }
    got.map(|resp| (guard, resp))
}

/// 补发响应收尾（直连/镜像两腿共用）：206 校验段起点并把 guard 接上记账流；
/// 非 206 带状态码报错——两腿原先是逐字拷贝，改一处漏一处的隐患收掉。
async fn finish_fill(
    got: Result<(LoadGuard, hyper::Response<BoxBody>), String>,
    m: &str,
    host: &str,
    s: u64,
    log: &LogFn,
) -> Result<BoxBody, String> {
    match got {
        Ok((guard, resp)) if resp.status() == http::StatusCode::PARTIAL_CONTENT => {
            merge::check_segment_start(
                resp.headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok()),
                s,
            )?;
            let at = Instant::now();
            let guard = guard.segment_from(at);
            Ok(account_seg(
                resp.into_body(),
                guard,
                format!("{host} 补发"),
                m.to_string(),
                log.clone(),
            ))
        }
        Ok((_, resp)) => Err(format!(
            "{m} 补发回 {} 而非 206 (host {host})",
            resp.status()
        )),
        Err(err) => Err(err),
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

/// 切片驱动：发缺口、收停滞、让位慢段，其余只泵数据；起流走旁路任务，建连再久也不挡泵数据与让位。
/// 补发只受卡死上限约束。
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

/// 镜像请求模板：URL = {镜像}/{原始URL}（前缀拼接惯例），剥凭据头、统一注入镜像 UA。
/// 直连切片的镜像救援（direct_split）也走这里，与链条镜像同一套凭据/UA 语义。
/// 按注册表里该镜像的用法模板拼出镜像 URL；无模板（旧条目/未探测）= 前缀拼接。
/// 模板占位符：{mirror} {url} {url_enc} {owner} {repo} {ref} {path}。
/// 用法是镜像服务自己定的约定，光给两条 URL 推不出来——由添加时的用法试探
/// 自动试出并保存（settings.json 的 template 字段），此后不再重试。
fn mirror_url(mirror: &str, orig_url: &str) -> String {
    let tpl = crate::settings::mirror_template(mirror);
    if tpl.is_empty() {
        return format!("{mirror}/{orig_url}");
    }
    fill_template(tpl, mirror, orig_url)
}

/// 填模板：把原链接拆段（scheme://host/seg0/seg1/seg2/rest…）逐占位符替换。
fn fill_template(tpl: String, mirror: &str, orig_url: &str) -> String {
    let after_scheme = orig_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(orig_url);
    let (_, path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let owner = segs.first().copied().unwrap_or("");
    let repo = segs.get(1).copied().unwrap_or("");
    let reference = segs.get(2).copied().unwrap_or("");
    let path_rest = if segs.len() > 3 {
        segs[3..].join("/")
    } else {
        String::new()
    };
    let mut out = tpl
        .replace("{mirror}", mirror)
        .replace("{url}", orig_url)
        .replace("{owner}", owner)
        .replace("{repo}", repo)
        .replace("{ref}", reference)
        .replace("{path}", &path_rest);
    if out.contains("{url_enc}") {
        out = out.replace("{url_enc}", &percent_encode(orig_url));
    }
    out
}

/// 最小百分号编码：字母数字与 . - _ ~ 之外全部转义（整段编码型镜像用）。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 用法试探：把样本链接逐个套进已知用法家族，**并发**真拉一次验货（状态 200/206、
/// 非 HTML、非空），按声明序取第一个命中的模板交回调用方存进注册表——此后照模板用，
/// 不再重试（删除重加才会重探）。每种不符模式都留一行原因，best-effort 也要能归因。
/// 探针不带头 Range：样本只有几 KB，带 Range 会撞上镜像的 chunked 206 怪癖
/// （Cloudflare 系实测头正常、体 0B），全量拉再丢体最简单可靠。
/// 样本 = 本仓库 README（公开、恒在、小）；结构重写型按它拆段。
pub(crate) async fn discover_template(mirror: &str, log: &LogFn) -> Result<String, String> {
    const SAMPLE: &str =
        "https://raw.githubusercontent.com/zhidian-cmd/gitport-github/main/README.md";
    const USAGE_TEMPLATES: &[&str] = &[
        "{mirror}/{url}",
        "{mirror}/{url_enc}",
        "{mirror}/?url={url}",
        "{mirror}/?url={url_enc}",
        "{mirror}/gh/{owner}/{repo}@{ref}/{path}",
    ];
    (log)(&format!(
        "[镜像] {mirror} 用法试探开始({} 种已知用法, 并发)",
        USAGE_TEMPLATES.len()
    ));
    // 并发拉同一个极小样本，按模板声明序取第一个命中的——探测是独立请求，
    // 没有"后发必须后到"的因果，串行只是白等。
    let probes = USAGE_TEMPLATES.iter().map(|tpl| async move {
        let url = fill_template((*tpl).to_string(), mirror, SAMPLE);
        let mut verdict = String::new();
        match hyper::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(http::header::USER_AGENT, MIRROR_UA)
            .body(protocol::empty_body())
        {
            Err(e) => verdict = format!("请求构造失败: {e}"),
            Ok(req) => match mirror_do(req, mirror, log).await {
                Err(e) => verdict = format!("拉取失败: {e}"),
                Ok(resp) => {
                    let status = resp.status();
                    let html = resp
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|t| t.contains("text/html"));
                    if !matches!(
                        status,
                        http::StatusCode::OK | http::StatusCode::PARTIAL_CONTENT
                    ) {
                        verdict = format!("状态 {status}");
                    } else if html {
                        verdict = "响应是 HTML(挑战/错误页)".to_string();
                    } else {
                        let mut body = resp.into_body();
                        let mut n = 0usize;
                        loop {
                            match http_body_util::BodyExt::frame(&mut body).await {
                                Some(Ok(f)) => {
                                    n += f.data_ref().map(|d| d.len()).unwrap_or(0);
                                }
                                Some(Err(e)) => {
                                    // 体流报错与 EOF 必须分家：EOF 空 = 服务端真发了空体，
                                    // 流错误 = 我们的客户端读不出它的响应。
                                    verdict = format!("体流错误: {e}");
                                    break;
                                }
                                None => {
                                    if n == 0 {
                                        verdict = "响应体为空(0B EOF)".to_string();
                                    }
                                    break;
                                }
                            }
                            if n >= 16 {
                                break;
                            }
                        }
                        if verdict.is_empty() && n < 16 {
                            verdict = format!("数据只收到 {n}B");
                        }
                    }
                }
            },
        }
        (*tpl, verdict)
    });
    let results = futures_util::future::join_all(probes).await;
    for (tpl, verdict) in &results {
        if verdict.is_empty() {
            (log)(&format!("[镜像] {mirror} 用法试探命中: {tpl}"));
            return Ok((*tpl).to_string());
        }
        (log)(&format!("[镜像] {mirror} 模式 {tpl} 不符: {verdict}"));
    }
    Err("试遍已知用法都不匹配".to_string())
}

pub(super) fn mirror_request(
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
) -> Result<hyper::Request<BoxBody>, String> {
    let url = mirror_url(mirror, orig_url);
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
/// 单镜像取响应（响应头预算 5s，体流式）。直连切片的镜像救援也走这里。
pub(super) async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    mirror_do_inner(req, mirror, log, false).await
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
