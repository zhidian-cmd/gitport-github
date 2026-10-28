//! 镜像链：内容域回落链（直连全灭时兜底）+ 图片链 TTFB 校准 + 链容量/凭据防护。
//! cookie 语义边界：镜像腿一律剥离 cookie/authorization（第三方镜像不认识会话）。
//! 动态派发：请求级分流——每个请求按“预计最早下完”（在途字节/实测速度）选起点，
//! 失败沿链顺延；不内切、不排队、不缓冲、无并发上限；冷启动退化为链序（小文件链=TTFB 校准）。
//! 慢镜像掐断：带 Range 的流显著慢于同伴(组内中位数/20)即断流，交由下载器重发重进派发。
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

// ---- 动态派发：镜像负载状态 ----

/// 冷启动无速度样本时的统一假设速率(B/s)：此时 ECT 退化为在途最少，再退化为链序。
const DEFAULT_MIRROR_SPEED: u64 = 2 * 1024 * 1024;
/// 近期失败降权窗口：窗口内尽量不派发；全体都在窗口内则忽略过滤按链序兜底。
const MIRROR_FAIL_WINDOW_MS: u64 = 60_000;
/// 开放区间 Range(bytes=X-)与无 Range 请求的体积假设(仅影响派发权重，不影响正确性)。
const ASSUMED_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
/// 长流中途刷新速率采样的间隔(交付字节)。
const SPEED_SAMPLE_BYTES: u64 = 1024 * 1024;
/// 入 EWMA 的最小样本(小于它噪声太大，忽略)。
const SPEED_SAMPLE_MIN_BYTES: u64 = 256 * 1024;

/// 镜像负载：在途未交付字节 / 实测速率 EWMA(B/s, 0=无样本) / 近期失败时间戳(0=从未) /
/// 最近速度样本时间戳(0=从未；掐断检验只信 30s 内交付过的同伴)。
#[derive(Default)]
struct MirrorLoad {
    in_flight_bytes: AtomicU64,
    speed_ewma: AtomicU64,
    last_fail_ms: AtomicU64,
    last_sample_ms: AtomicU64,
}

static MIRROR_LOAD: LazyLock<Mutex<HashMap<String, Arc<MirrorLoad>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 取该镜像的负载条目(无则建)。Arc 共享：守卫与表内是同一份计数。
fn mirror_load(mirror: &str) -> Arc<MirrorLoad> {
    let mut g = MIRROR_LOAD.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(mirror.to_string()).or_default().clone()
}

/// 交付速率采样入 EWMA(α=0.3)：新样本占 3/10。样本太小或耗时为零忽略。
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

/// 掐断路径的强制采样：慢流实测值必须立即入 EWMA(不等 1MB checkpoint、不受
/// 最小样本门槛约束)，否则重发的请求会被旧的高速印象再次派回慢镜像。
fn force_ewma(load: &MirrorLoad, bytes: u64, elapsed: Duration) {
    let ms = elapsed.as_millis() as u64;
    if bytes == 0 || ms == 0 {
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

/// 派发记账守卫：发出请求前按请求体积记在途；交付逐帧归还；Drop 收尾(残余归还 + 末段采样)。
/// 失败路径守卫就地 drop：全额归还，等价于从未占用。随响应体存活，客户端断开同样走到 Drop。
struct LoadGuard {
    load: Arc<MirrorLoad>,
    charged: u64,
    delivered: u64,
    mark_at: Instant,
    mark_bytes: u64,
}

impl LoadGuard {
    fn charge(load: Arc<MirrorLoad>, new_bytes: u64) -> Self {
        load.in_flight_bytes.fetch_add(new_bytes, Ordering::Relaxed);
        LoadGuard {
            load,
            charged: new_bytes,
            delivered: 0,
            mark_at: Instant::now(),
            mark_bytes: 0,
        }
    }

    /// 交付一帧：按帧长归还记账(封顶于记账额，防镜像无视 Range 回全量把计数打成负)；
    /// 累计满一个采样间隔刷新一次速率。
    fn on_frame(&mut self, n: u64) {
        let credit = n.min(self.charged.saturating_sub(self.delivered));
        self.delivered += credit;
        self.load.in_flight_bytes.fetch_sub(credit, Ordering::Relaxed);
        let since_mark = self.delivered - self.mark_bytes;
        if since_mark >= SPEED_SAMPLE_BYTES {
            ewma_update(&self.load, since_mark, self.mark_at.elapsed());
            self.mark_at = Instant::now();
            self.mark_bytes = self.delivered;
        }
    }
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        ewma_update(
            &self.load,
            self.delivered - self.mark_bytes,
            self.mark_at.elapsed(),
        );
        let residual = self.charged.saturating_sub(self.delivered);
        if residual > 0 {
            self.load.in_flight_bytes.fetch_sub(residual, Ordering::Relaxed);
        }
    }
}

/// 动态派发选家：预计最早下完者(ECT = (在途剩余 + 新请求字节) / 速度)。
/// 并列取链序最前(信任校准排名)；60s 内失败过的降权，全体都在窗口内则忽略过滤。
fn pick_mirror(chain: &[String], new_bytes: u64) -> usize {
    let now = pool::now_ms();
    let loads: Vec<Arc<MirrorLoad>> = chain.iter().map(|m| mirror_load(m)).collect();
    // 两轮：先只在健康者(不在失败降权窗口)里选；全军覆没则放开过滤重选。
    for allow_recent_failures in [false, true] {
        let mut best: Option<usize> = None;
        let mut best_ect = u64::MAX;
        for (i, ld) in loads.iter().enumerate() {
            if !allow_recent_failures {
                let lf = ld.last_fail_ms.load(Ordering::Relaxed);
                if lf != 0 && now.saturating_sub(lf) < MIRROR_FAIL_WINDOW_MS {
                    continue;
                }
            }
            let speed = {
                let s = ld.speed_ewma.load(Ordering::Relaxed);
                if s == 0 { DEFAULT_MIRROR_SPEED } else { s }
            };
            let ect = ld.in_flight_bytes.load(Ordering::Relaxed).saturating_add(new_bytes) / speed;
            if ect < best_ect {
                best_ect = ect;
                best = Some(i);
            }
        }
        if let Some(i) = best {
            return i;
        }
    }
    0
}

/// 尝试序列：链旋转到选中家起始，再按单请求尝试预算(limit)截断。
fn walk_order(chain_len: usize, start: usize, limit: usize) -> Vec<usize> {
    if chain_len == 0 {
        return Vec::new();
    }
    (0..chain_len)
        .map(|i| (start + i) % chain_len)
        .take(limit)
        .collect()
}

/// 从 Range 头估请求体积(bytes=a-b → b-a+1)；开放区间/无头/解析失败按常量假设。
fn range_bytes(range: Option<&str>) -> u64 {
    let Some(spec) = range.and_then(|r| r.trim().strip_prefix("bytes=")) else {
        return ASSUMED_REQUEST_BYTES;
    };
    let first = spec.split(',').next().unwrap_or("").trim();
    match first.split_once('-') {
        Some((a, b)) => match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
            (Ok(lo), Ok(hi)) if hi >= lo => hi - lo + 1,
            _ => ASSUMED_REQUEST_BYTES, // bytes=X- 开放区间或畸形
        },
        None => ASSUMED_REQUEST_BYTES,
    }
}

/// 镜像响应资格(纯函数)：非 3xx、非 HTML；带 Range 的请求必须回 206。
/// 304 无正文，缓存校验通过的合法响应，直接放行（原实现曾因 304 带 content-type 误判为假站）。
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

// ---- 慢镜像掐断(仅带 Range 的流)：组内显著性检验 ----
// 判据是相对差值不是绝对水位：该流速度 < 同伴中位数 / 20 = 显著离群。
// 全军低速窗口里谁也不比谁慢 20 倍 → 零误杀；一快多慢时慢鼠照样暴露。

/// 掐断评估的交付水位(每交这么多字节评一次)。
const CUT_CHECKPOINT_BYTES: u64 = 128 * 1024;
/// 评估窗口最短时长：TCP 爬坡期的低速不参评(防冷启动误杀)。
const CUT_MIN_WINDOW_MS: u64 = 2_000;
/// 同伴速度样本的新鲜窗(掐断检验只信最近交付过的镜像)。
const CUT_PEER_FRESH_MS: u64 = 30_000;
/// 显著性阈值：流速度 < 同伴中位数 / 该值 = 显著离群。
const CUT_SIGNIFICANCE_DIVISOR: u64 = 20;
/// 至少要几个新鲜同伴才做检验(防小样本误判)。
const CUT_MIN_PEERS: usize = 3;
/// 每链每窗最多掐断次数：万一评估失真,掐满后放行爬行,宁可慢不可自残。
const CUT_LIMIT_PER_WINDOW: u32 = 4;
const CUT_LIMIT_WINDOW_MS: u64 = 60_000;

/// 同伴速度中位数(除自己外、30s 内有样本、EWMA 非零)；不足 CUT_MIN_PEERS 个 = 无基准。
fn peer_median(peer_rates: &[u64]) -> Option<u64> {
    if peer_rates.len() < CUT_MIN_PEERS {
        return None;
    }
    let mut sorted = peer_rates.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
}

/// 掐断判据(纯函数)：本流速率是否显著低于同伴中位数。
fn should_cut(own_rate: u64, median: Option<u64>) -> bool {
    median.is_some_and(|m| own_rate < m / CUT_SIGNIFICANCE_DIVISOR)
}

static CUT_LIMITER: LazyLock<Mutex<HashMap<String, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 每链限幅：窗口内掐满 CUT_LIMIT_PER_WINDOW 次后放行爬行。
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

/// 掐断上下文(打包成结构，压参数个数)：链归属 / 镜像名 / 日志标签。
struct CutMeta {
    chain_host: String,
    mirror: String,
    label: String,
}

/// 带 Range 的响应体包装：交付途中按水位评估速率，显著慢于同伴即以 Err 终止流——
/// 连接断开，下载器(浏览器外的 Range 客户端)自动重发该 Range 重进 ECT 派发，
/// 慢镜像已被 force_ewma + last_fail 双重降权，不会接到重发。
/// 无 Range 的流永不经过这里(浏览器单线程下载掐了就是用户可见失败)。
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
            None => None, // EOS: state drop → 守卫收尾(残余归还 + 末段采样)
        }
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}


/// 内容域小文件镜像链限前 5 家（仍串行）；大文件域用全链。
fn mirror_chain_cap(host: &str) -> Option<usize> {
    (!pool::route::is_big_file_host(host)).then_some(MIRROR_CHAIN_CAP)
}

pub(super) async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
) -> Result<hyper::Response<BoxBody>, String> {
    // 凭据查询串拒走镜像：signed URL 等价 bearer，交第三方镜像即外泄。
    if let Some(q) = out.uri().query() {
        if has_credential_query(q) {
            return Err(format!("{host} 查询串含凭据参数, 拒绝镜像(防外泄)"));
        }
    }
    let orig_url = format!(
        "https://{host}{}",
        out.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default()
    );
    let path = path_of(out.uri());
    // 链归属与请求 host 解耦：release 附件走 release-assets 专属链（github.com 链头慢且中断）。
    // URL 仍用原 host 构造（镜像自己跟随 302 落点），熔断/限长/链序按归属 host。
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
    let chain = pool::mirror_chain(chain_host);
    if chain.is_empty() {
        return Err(format!("{host} 无镜像链({chain_host})"));
    }
    if pool::MIRROR_BREAKER.open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(chain.len())
        .min(chain.len());
    // 动态派发：按“预计最早下完”（在途字节/实测速度）选起点，失败沿链顺延；
    // 不内切、不排队、不缓冲——单镜像用户行为与旧版逐字节一致。
    let new_bytes = range_bytes(out.headers().get("range").and_then(|v| v.to_str().ok()));
    let start = pick_mirror(&chain, new_bytes);
    for i in walk_order(chain.len(), start, limit) {
        let m = chain[i].as_str();
        let req = match mirror_request(out, m, &orig_url) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 请求构造失败({e}), 链内下一个"));
                continue;
            }
        };
        // 派发记账：发出前按请求体积记在途。成功随响应体逐帧归还；
        // 失败守卫就地 drop 全额归还(last_fail 已在下方记录)。
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
                pool::MIRROR_BREAKER.clear(chain_host); // 链是活的: 清全灭熔断
                // 记账随响应体存活：逐帧归还 + Drop 收尾(客户端断开同样走到)。
                // 带 Range 的流另挂掐断监视(显著慢于同伴即断流交客户端重发)；
                // 无 Range 的流只记账不掐——浏览器单线程下载掐了就是用户可见失败。
                let (parts, body) = resp.into_parts();
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
    pool::MIRROR_BREAKER.set(chain_host); // 整链烧完仍全灭: 熔断 60s, 后续图快速失败
    Err(format!("{host} 镜像链全灭({chain_host} 链 {limit} 个)"))
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
    // CF 系镜像的 Bot Fight Mode 拦非浏览器 UA：镜像腿恒定浏览器 UA（剥掉
    // 客户端原 UA 后统一注入，否则 builder.header 是追加会出现两个 UA），
    // 校准/无 UA 客户端也能过；对外特征一致（见 MIRROR_UA 注释）。
    builder = builder.header(http::header::USER_AGENT, http::HeaderValue::from_static(MIRROR_UA));
    builder.body(upstream::empty_body()).map_err(|e| e.to_string())
}
/// 镜像腿单发：5s 响应头预算 + 假页拒判（≥400 或 text/html 不算成绩）。
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    // 带 Range 的请求必须回 206/304：镜像不认 Range 会把整文件灌回来(见 validate_mirror_response)。
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
    // 镜像须直出内容：3xx=甩锅、HTML=假站、≥400=拒绝；304 例外（缓存热时合法响应，曾误判致整链全灭）。
    validate_mirror_response(had_range, resp.status().as_u16(), ct)
        .map_err(|e| format!("{mirror} {e}"))?;
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(http_body_util::BodyExt::map_err(
        body,
        std::io::Error::other,
    ));
    Ok(hyper::Response::from_parts(parts, body))
}

/// 校准日志措辞：镜像站以 3xx/4xx 明确拒绝（路由未开 / 风控）算"不支持"，
/// 超时与连接错误才是"失败"——混用会让一次正常探测显得像故障。
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

/// 校准探测模板(仅图片/小文件链——大文件域由 ECT 实时调度接管, 不做合成测速)：
/// 每个域一个长期有效的公开资源。改动前必须先手测直连 200——
/// 失效模板会让所有镜像在该域判"不支持"（2026-10-24 踩过：user-images 老图
/// 已失效返 403、media 指了非 LFS 文件直连 404，一度误判为镜像不支持）。
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
// 仅图片(小文件)链响应头测速：大文件链的速度学习已由 ECT 的真实流量 EWMA 接管
// (每个请求都是 MB 级样本, 比合成测速更真且零额外流量)。
// 铁律：host 间严格串行——同一镜像服务多条链，跨链并发互相污染测量。

/// 校准互斥：webui 用 swap(true) 抢跑，跑完 store(false)。
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

/// 镜像腿统一浏览器 UA：CF 系镜像的 Bot Fight Mode 会拦非浏览器 UA（裸
/// Mozilla/5.0 一律 403），校准等代理自发的请求没有 UA 更过不了——恒定注入
/// Chrome UA，浏览器/校准/命令行走镜像腿的对外特征完全一致。
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
/// TTFB 排名：毫秒小者优；失败项记负数，一律排最后（同类之间按耗时）。
fn rank_by_ttfb(rows: &mut [(String, i64)]) {
    rows.sort_by_key(|(_, ms)| (*ms < 0, ms.unsigned_abs()));
}

/// 图片(小文件)链 TTFB 校准：逐 host 串行、逐镜像测响应头耗时，按成绩重排链序落盘。
/// 大文件域不校准——其速度学习由 ECT 的真实流量 EWMA 实时接管(见动态派发)。
pub async fn calibrate_chains(log: &LogFn) -> String {
    let chains = pool::mirror_chains_snapshot();
    let mut report = String::new();
    for (host, chain) in chains {
        if pool::route::is_big_file_host(&host) {
            continue; // 大文件域：ECT 实时调度, 不做合成测速
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
                    rows.push((m.clone(), -(ms.max(1)))); // 负数 = 失败，沉底
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
                assert!(!covered, "{h} 大文件域不校准(ECT 实时接管), 不应有模板");
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
    async fn chain_fetch_refuses_credentialed_url() {
        let log: LogFn = Arc::new(|_: &str| {});
        let req = hyper::Request::builder()
            .uri("https://raw.githubusercontent.com/o/r/f?sig=abc")
            .body(upstream::empty_body())
            .unwrap();
        let err = chain_fetch(&log, &req, "raw.githubusercontent.com")
            .await
            .unwrap_err();
        assert!(err.contains("拒绝镜像"), "签名 URL 不得交给第三方镜像: {err}");
    }

    // ---- 动态派发测试 ----

    /// ECT 选家核心场景(用户直觉钉死)：忙而快的镜像胜过闲而慢的；
    /// 快镜像在途深到一定程度则公式自纠改选空闲者。
    #[test]
    fn ect_prefers_busy_fast_over_idle_slow() {
        let a = mirror_load("ect-a.test");
        let b = mirror_load("ect-b.test");
        a.in_flight_bytes.store(512 * 1024, Ordering::Relaxed);
        a.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        b.speed_ewma.store(512 * 1024, Ordering::Relaxed);
        let chain = vec!["ect-a.test".to_string(), "ect-b.test".to_string()];
        // 新请求 10MB：A (0.5+10)/5 ≈ 2s < B 10/0.5 = 20s → 选 A(链位 0)。
        assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 0);
        // A 在途涨到 100MB：(100+10)/5 = 22 > B 的 20 → 改选 B。
        a.in_flight_bytes.store(100 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 1);
        // 清场：测试键不污染其他测试。
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
    }

    /// 冷启动(无速度样本)：统一默认速率 → 退化为在途最少 → 全零退化为链序。
    #[test]
    fn cold_start_falls_back_to_chain_order() {
        let a = mirror_load("cold-a.test");
        let b = mirror_load("cold-b.test");
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["cold-a.test".to_string(), "cold-b.test".to_string()];
        assert_eq!(pick_mirror(&chain, 1024), 0, "全零：链序首位");
        a.in_flight_bytes.store(8 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 1, "默认速率下按在途字节分");
        a.in_flight_bytes.store(0, Ordering::Relaxed);
    }

    /// 近期失败降权：60s 内失败过的镜像让位；全体都在窗口内则回链序兜底。
    #[test]
    fn recent_failure_deprioritized() {
        let a = mirror_load("fail-a.test");
        let b = mirror_load("fail-b.test");
        a.speed_ewma.store(0, Ordering::Relaxed);
        b.speed_ewma.store(0, Ordering::Relaxed);
        a.in_flight_bytes.store(0, Ordering::Relaxed);
        b.in_flight_bytes.store(0, Ordering::Relaxed);
        let chain = vec!["fail-a.test".to_string(), "fail-b.test".to_string()];
        // 链头 a 刚失败：应让位给健康的 b。
        a.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 1);
        // b 也在窗口内：过滤放开，回链序兜底选 a。
        b.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
        assert_eq!(pick_mirror(&chain, 1024), 0);
        a.last_fail_ms.store(0, Ordering::Relaxed);
        b.last_fail_ms.store(0, Ordering::Relaxed);
    }

    /// 尝试序列：旋转到选中家，单请求预算(limit)截断不变。
    #[test]
    fn rotate_walk_respects_limit() {
        assert_eq!(walk_order(8, 0, 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(walk_order(8, 6, 5), vec![6, 7, 0, 1, 2]);
        assert_eq!(walk_order(3, 0, 8), vec![0, 1, 2], "limit 大于链长：全链");
        assert_eq!(walk_order(1, 0, 5), vec![0], "单镜像：不切分，行为同旧");
    }

    /// Range 体积估计：闭合区间精确；开放区间/无头/畸形用假设值。
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

    /// 响应资格：带 Range 必须回 206/304；HTML 假站与 3xx 拒收；304 永远合法。
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

    /// 记账守卫生命周期：派发加、逐帧归还、Drop 清残余；中途断开也归零(不泄漏)。
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
        } // drop：残余 200 归还
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "Drop 必须清残余");
        // 超额交付(镜像无视 Range 回全量)：按记账封顶，原子不得下溢。
        {
            let mut g = LoadGuard::charge(ld.clone(), 100);
            g.on_frame(500);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "交付封顶于记账");
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
        // 失败路径：守卫未交付即 drop → 全额归还。
        {
            let _g = LoadGuard::charge(ld.clone(), 4096);
            assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 4096);
        }
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
    }

    /// 速率 EWMA：首样本直取，后续按 α=0.3 平滑；小样本忽略。
    #[test]
    fn speed_ewma_smoothing() {
        let ld = mirror_load("ewma.test");
        ld.speed_ewma.store(0, Ordering::Relaxed);
        ewma_update(&ld, 256 * 1024, Duration::from_secs(1)); // 256KB：恰达下限
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), 256 * 1024);
        ewma_update(&ld, 1024 * 1024, Duration::from_secs(1)); // 1MB/s 样本
        let expect = (256 * 1024 * 7 + 1024 * 1024 * 3) / 10;
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), expect);
        ewma_update(&ld, 128, Duration::from_millis(1)); // 太小：忽略
        assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), expect);
        ld.speed_ewma.store(0, Ordering::Relaxed);
    }

    // ---- 慢镜像掐断测试 ----

    /// 掐断判据(纯函数)：相对差值检验——显著慢于同伴中位数才掐；
    /// 全军低速谁也不比谁慢 20 倍 → 零误杀；新鲜同伴不足 3 个 → 不评。
    #[test]
    fn cutoff_significance_median_of_fresh_peers() {
        let m = |rates: &[u64]| peer_median(rates);
        // 同伴 3 个 ~100KB/s, 自己 2KB/s → 显著离群, 掐。
        assert!(should_cut(2 * 1024, m(&[100 * 1024, 100 * 1024, 120 * 1024])));
        // 全军低速：自己 50KB/s, 同伴也 ~50KB/s → 50 < 50/20 不成立, 不掐。
        assert!(!should_cut(50 * 1024, m(&[50 * 1024, 50 * 1024, 60 * 1024])));
        // 一只显著慢鼠：同伴 4 个 ~100KB/s, 鼠 2KB/s → 照样暴露(差值检验不看重叠水位)。
        assert!(should_cut(
            2 * 1024,
            m(&[100 * 1024, 90 * 1024, 110 * 1024, 95 * 1024])
        ));
        // 新鲜同伴不足 CUT_MIN_PEERS：无基准, 不评。
        assert!(!should_cut(0, m(&[100 * 1024, 100 * 1024])));
        assert!(!should_cut(0, m(&[])));
    }

    /// 每链限幅：窗口内掐满 4 次后放行爬行(防全军低速窗口自残)。
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

    /// 掐断流包装：显著慢的 Range 流在 checkpoint 处以 Err 终止(连接断开交客户端重发)；
    /// 守卫随流终结全额归还，慢速率强制入 EWMA + 记 last_fail(防重发乒乓)。
    #[tokio::test]
    async fn cutoff_body_aborts_significantly_slow_stream() {
        // 3 个新鲜快同伴(5MB/s)。
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
        // 两帧 128KB 的流：第一帧立即到(窗口 <2s 不评)，隔 2.2s 后第二帧
        // → 窗口达标, own ≈ 128KB/2.2s ≈ 58KB/s < 5MB/s/20 = 250KB/s → 掐。
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
                Some(Ok(_)) => tokio::time::sleep(Duration::from_millis(2200)).await,
                Some(Err(_)) => {
                    got_err = true;
                    break;
                }
                None => break,
            }
        }
        drop(wrapped); // 流终结：守卫收尾
        assert!(got_err, "显著慢流应在 checkpoint 处被掐断(Err 终止)");
        assert_eq!(
            me.in_flight_bytes.load(Ordering::Relaxed),
            0,
            "掐断后守卫必须全额归还"
        );
        assert_ne!(
            me.last_fail_ms.load(Ordering::Relaxed),
            0,
            "掐断必须记 last_fail(重发不再派回慢镜像)"
        );
        assert!(
            me.speed_ewma.load(Ordering::Relaxed) > 0,
            "掐断必须强制采样慢速率入 EWMA"
        );
        me.speed_ewma.store(0, Ordering::Relaxed);
        me.last_fail_ms.store(0, Ordering::Relaxed);
    }

}
