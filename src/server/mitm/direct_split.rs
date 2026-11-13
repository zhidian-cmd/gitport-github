//! README 大图/视频的纯直连多段：字节拆成多个 Range 摊到池内多条直连通道并发拉，
//! 按字节边界合成一条 200 流。自己从不拨号（通道不够经池子溢出补临时通道），
//! 也不进 get_direct 的兜底——段失败不会被误判成「直连全灭」而转镜像。
use super::{merge, mirror, path_of, UpstreamInfo};
use super::super::{protocol::{self, BoxBody}, upstream};
use crate::{pool, util::LogFn};
use bytes::Bytes;
use futures_util::future::join_all;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::body::Frame;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        LazyLock, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// 门槛：探片多一次往返，小图省不回来。切片判定（含 Range 路径）共用。
pub(super) const MIN_SPLIT_BYTES: u64 = 512 * 1024;
/// 目标段大小；段数钳在 4~8。
const SEG_TARGET_BYTES: u64 = 192 * 1024;
const MAX_SEGS: usize = 8;
/// 探片段大小：兼作交付首段前缀。
const PROBE_BYTES: u64 = 10 * 1024;
/// 同时在途的多段响应个数：按响应体生命周期计数，防一页并发把连接级窗口占死。
const MAX_ACTIVE: usize = 6;
// 单段在用户态的缓冲上限：快段先到先存，超过就暂时不读它（常量与合并层共用，见 merge::SEG_BUFFER_MAX）。
use super::merge::SEG_BUFFER_MAX;
/// 段响应头预算：头应毫秒级，8s 只防上游装死。
const SEG_HEAD_BUDGET: Duration = Duration::from_secs(8);
const MEMO_TTL: Duration = Duration::from_secs(600);

/// host 白名单：静态资源 CDN 才切（大图与大 JS/CSS 同病同治）；会话域不在表内。
pub(super) fn is_split_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "raw.githubusercontent.com"
            | "user-images.githubusercontent.com"
            | "private-user-images.githubusercontent.com"
            | "media.githubusercontent.com"
            | "camo.githubusercontent.com"
            | "gist.githubusercontent.com"
            | "avatars.githubusercontent.com"
            | "github.githubassets.com"
    )
}

/// 媒体判定：图片与视频都切；非媒体探一次记 10 分钟不再探。
fn is_media(ct: Option<&str>) -> bool {
    MediaKind::of_content_type(ct).is_some()
}

pub(super) fn seg_count(total: u64) -> usize {
    ((total / SEG_TARGET_BYTES) as usize).clamp(4, MAX_SEGS)
}

/// 段请求的模板：原请求的 method/uri/headers，每次重建一份干净的 GET。
/// 直连切片与镜像竞速（mirror.rs 的 segment_direct）共用这一个模板。
#[derive(Clone)]
pub(super) struct Tpl {
    pub(super) method: Method,
    pub(super) uri: http::Uri,
    pub(super) headers: HeaderMap,
}

impl Tpl {
    pub(super) fn of(out: &hyper::Request<BoxBody>) -> Self {
        Tpl {
            method: out.method().clone(),
            uri: out.uri().clone(),
            headers: out.headers().clone(),
        }
    }

    /// [s, e) → Range: bytes=s-(e-1)；URL 与凭据头原样保留，只剥改变段语义的头与逐跳头。
    fn build(&self, s: u64, e: u64) -> Result<hyper::Request<BoxBody>, String> {
        let mut b = hyper::Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone());
        for (k, v) in self.headers.iter() {
            if skip_request_header(k.as_str()) {
                continue;
            }
            b = b.header(k.clone(), v.clone());
        }
        let range = HeaderValue::from_str(&format!("bytes={s}-{}", e - 1))
            .map_err(|err| err.to_string())?;
        b = b.header(http::header::RANGE, range);
        b.body(protocol::empty_body()).map_err(|err| err.to_string())
    }
}

/// 段/探片请求头过滤：Range 语义头与逐跳头不透传；条件头剥掉（探片/段不该 304）。
/// accept-encoding **透传**：上游压缩后传输量缩 3 倍（8.6MB→2.87MB 实测），切片按
/// 压缩流字节切，段拼接仍是完整压缩流，content-encoding 原样交浏览器解压。
fn skip_request_header(k: &str) -> bool {
    matches!(
        k,
        "range"
            | "if-range"
            | "if-none-match"
            | "if-modified-since"
            | "connection"
            | "proxy-connection"
            | "transfer-encoding"
            | "content-length"
            | "content-type"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

/// 附加头过滤（镜像/直连共用）：Range 语义头与逐跳头不透传给浏览器。
pub(super) fn skip_response_header(k: &str) -> bool {
    matches!(
        k,
        "content-range"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
    )
}

// Content-Range 的解析统一走 merge::{content_range_total, content_range_start, content_range_end}，
// 与镜像链的 206 校验用同一套标准，别再各写一份。

/// 媒体类别：救援链按它分流——图片段走 routes.json 的"图片"链，视频段走"视频"链，
/// 脚本段链为空（公共镜像不收 githubassets，实测零字节）——直连独走不设救援。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum MediaKind {
    Image,
    Video,
    Script,
}

impl MediaKind {
    fn chain(self) -> &'static str {
        match self {
            MediaKind::Image => pool::MEDIA_IMAGE_CHAIN,
            MediaKind::Video => pool::MEDIA_VIDEO_CHAIN,
            MediaKind::Script => "",
        }
    }
    fn of_content_type(ct: Option<&str>) -> Option<Self> {
        let ct = ct?;
        if ct.starts_with("image/") {
            Some(MediaKind::Image)
        } else if ct.starts_with("video/") {
            Some(MediaKind::Video)
        } else if ct.contains("javascript") || ct.contains("css") {
            Some(MediaKind::Script)
        } else {
            None
        }
    }
}

/// 探片记忆（10min）：总长 + 类别；0 = 探明不可切，不再探。
static MEMO: LazyLock<Mutex<HashMap<String, (u64, MediaKind, Instant)>>> =
    LazyLock::new(Default::default);

fn memo_get(key: &str) -> Option<(u64, MediaKind)> {
    MEMO.lock()
        .unwrap()
        .get(key)
        .filter(|(_, _, at)| at.elapsed() < MEMO_TTL)
        .map(|(t, k, _)| (*t, *k))
}

fn memo_put(key: &str, total: u64, kind: MediaKind) {
    let mut g = MEMO.lock().unwrap();
    if g.len() >= 512 {
        g.retain(|_, (_, _, at)| at.elapsed() < MEMO_TTL);
    }
    g.insert(key.to_string(), (total, kind, Instant::now()));
}

/// 救援链全灭熔断 60s：链死透时别让每段白付链序尝试。
static MEDIA_RESCUE_BREAKER: pool::Breaker = pool::Breaker::new(60);

async fn fetch_segment(
    up: &upstream::H2Upstream,
    tpl: &Tpl,
    s: u64,
    e: u64,
) -> Result<(BoxBody, HeaderMap), String> {
    let req = tpl.build(s, e)?;
    let resp = tokio::time::timeout(SEG_HEAD_BUDGET, upstream::h2_send(up, &req, &None::<Bytes>))
        .await
        .map_err(|_| "段响应头超时".to_string())??;
    if resp.status() != StatusCode::PARTIAL_CONTENT {
        return Err(format!("段回 {}", resp.status()));
    }
    check_segment_bounds(
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        s,
        e,
    )?;
    let (parts, body) = resp.into_parts();
    Ok((body, parts.headers))
}

/// 206 段边界校验：起点规则共用 merge::check_segment_start，另加终点不越界——
/// 越界字节会吃掉总长预算，尾段就发不完了。
fn check_segment_bounds(cr: Option<&str>, start: u64, e: u64) -> Result<(), String> {
    merge::check_segment_start(cr, start)?;
    if merge::content_range_end(cr).is_some_and(|end| end >= e) {
        return Err(format!("段终点越界: 要 <= {}, 拿到 {cr:?}", e - 1));
    }
    Ok(())
}

/// 段的镜像救援：从 start 续传到 e（直连已交付的不重拉），链序逐个试，全灭记熔断。
/// 整段单流取回、不分段。chain 由调用方快照传入（构造时机已判空），这里只管逐个试。
async fn rescue_segment(
    tpl: &Tpl,
    kind: MediaKind,
    chain: &[String],
    start: u64,
    e: u64,
    log: &LogFn,
) -> Option<(BoxBody, HeaderMap)> {
    let chain_key = kind.chain();
    if MEDIA_RESCUE_BREAKER.open(&chain_key) {
        return None;
    }
    if chain.is_empty() {
        return None;
    }
    let orig = tpl.uri.to_string();
    for m in chain {
        let Ok(seg_req) = tpl.build(start, e) else { return None };
        let Ok(req) = mirror::mirror_request(&seg_req, m, &orig) else { continue };
        match mirror::mirror_do(req, m, log).await {
            Ok(resp) => {
                if resp.status() != StatusCode::PARTIAL_CONTENT {
                    continue;
                }
                if check_segment_bounds(
                    resp.headers()
                        .get("content-range")
                        .and_then(|v| v.to_str().ok()),
                    start,
                    e,
                )
                .is_err()
                {
                    continue;
                }
                let (parts, body) = resp.into_parts();
                (log)(&format!(
                    "[直连切片] 段 {start}-{} 由镜像 {} 接手{}",
                    e - 1,
                    m.trim_start_matches("https://"),
                    if start > 0 {
                        format!("(续传自 {start})")
                    } else {
                        String::new()
                    }
                ));
                return Some((body, parts.headers));
            }
            Err(_) => continue,
        }
    }
    MEDIA_RESCUE_BREAKER.set(&chain_key);
    (log)(&format!("[直连切片] {chain_key} 链全灭, 60s 内段救援直接放弃"));
    None
}

/// 跳过原因落一行（每 host 一次，不刷屏）：静默分支全部显式化，排查不再靠猜。
fn log_skip(log: &LogFn, host: &str, path: &str, why: &str) {
    if super::quiet::first_time("split-skip", host) {
        (log)(&format!("[直连切片] {host}{path} 单流直发({why})"));
    }
}

/// 主入口：不满足条件、或任一段没拿到 206，一律返回 None 让 mitm_http 走原来的单流。
/// 只在所有段的响应头都确认之后才组装 200，中途失败不会出现「头已发出、图却花掉」。
pub(super) async fn try_direct_split(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
) -> Option<hyper::Response<BoxBody>> {
    if out.method() != Method::GET || out.headers().contains_key(http::header::RANGE) {
        return None; // 客户端自带 Range：multipart/byteranges 语义不同，别切
    }
    if !is_split_host(host) {
        return None;
    }
    let key = format!("{host}{}", path_of(out.uri()));
    let path = path_of(out.uri());
    let (total, kind, prefix) = match memo_get(&key) {
        Some((0, _)) => {
            log_skip(log, host, &path, "上次探明不可切(10min 记忆)");
            return None;
        }
        Some(hit) => (hit.0, hit.1, None),
        None => {
            let tpl = Tpl::of(out);
            // 探片要一条通道：池冷就借池子的建造（等在途建造最多 3s），建不出退单流。
            let Some(up) = pool::gather_channels(host, 1, log).await.into_iter().next() else {
                log_skip(log, host, &path, "池冷且建连失败");
                return None;
            };
            *info.lock().unwrap() = up.ip.clone();
            let req = tpl.build(0, PROBE_BYTES).ok()?;
            let resp = match tokio::time::timeout(
                SEG_HEAD_BUDGET,
                upstream::h2_send(&up, &req, &None::<Bytes>),
            )
            .await
            {
                Ok(Ok(r)) => r,
                _ => {
                    log_skip(log, host, &path, "探片超时/失败");
                    return None;
                }
            };
            if resp.status() != StatusCode::PARTIAL_CONTENT {
                memo_put(&key, 0, MediaKind::Image); // 上游忽略 Range：10 分钟内别再白探
                log_skip(
                    log,
                    host,
                    &path,
                    &format!("上游不回 206(状态 {}), 记忆不可切", resp.status()),
                );
                return None;
            }
            let Some(t) = merge::content_range_total(
                resp.headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok()),
            ) else {
                memo_put(&key, 0, MediaKind::Image);
                log_skip(log, host, &path, "206 缺 Content-Range");
                return None;
            };
            let Some(kind) = MediaKind::of_content_type(
                resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok()),
            ) else {
                drop(resp.into_body()); // 及时关掉流别占连接窗口
                memo_put(&key, 0, MediaKind::Image); // 非媒体：10 分钟内别再探、更别切
                log_skip(log, host, &path, "非媒体类响应");
                return None;
            };
            // 探片 10KB：字节不浪费，直接当交付首段。
            let probe_hs = resp.headers().clone();
            let probe_body = match tokio::time::timeout(
                SEG_HEAD_BUDGET,
                http_body_util::BodyExt::collect(resp.into_body()),
            )
            .await
            {
                Ok(Ok(c)) => c.to_bytes(),
                _ => {
                    log_skip(log, host, &path, "探片体收集超时");
                    return None;
                }
            };
            memo_put(&key, t, kind); // 记住总长与类别；小图下次直接被 MIN_SPLIT_BYTES 挡掉
            (t, kind, Some((probe_body, probe_hs)))
        }
    };
    if total < MIN_SPLIT_BYTES {
        log_skip(log, host, &path, "文件小于 512KB");
        return None;
    }
    let Some(guard) = ActiveGuard::take() else {
        log_skip(log, host, &path, "并发切片闸已满(6)");
        return None;
    };
    let tpl = Tpl::of(out);
    let tpl_ref = &tpl;
    // 恒 8 段直连切片：探片前缀有则段从 10KB 后接着排，无（memo 命中）则从头排。
    let seg_start = if prefix.is_some() { PROBE_BYTES } else { 0 };
    let segs = merge::split_even(seg_start, total, seg_count(total - seg_start));
    if segs.is_empty() {
        return None;
    }
    // 段摊到池内多条通道：最多借 3 条。
    let chans: std::sync::Arc<[upstream::H2Upstream]> =
        std::sync::Arc::from(pool::gather_channels(host, segs.len().min(3), log).await);
    if chans.is_empty() {
        log_skip(log, host, &path, "池内无可用通道");
        return None;
    }
    // 先直连后镜像：每段 5s 界——头拿不到/段失败立即换镜像，体在 SegmentedBody 里继续受界。
    // Script（githubassets）无救援：公共镜像不收该域（实测零字节），段直连独走，链都不查。
    let t0 = Instant::now();
    let chain = match kind {
        MediaKind::Script => Vec::new(),
        _ => pool::mirror_chain(kind.chain()),
    };
    let n = chans.len();
    let futs = segs.iter().enumerate().map(|(i, &(s, e))| {
        let up = chans[i % n].clone();
        let log2 = log.clone();
        let chain = chain.clone();
        async move {
            match tokio::time::timeout(
                Duration::from_secs(crate::config::MEDIA_RESCUE_WAIT_SECS),
                fetch_segment(&up, tpl_ref, s, e),
            )
            .await
            {
                Ok(Ok((body, hs))) => Ok(SegFetch {
                    body,
                    hs,
                    rescued: false,
                }),
                Ok(Err(_why)) => match rescue_segment(tpl_ref, kind, &chain, s, e, &log2).await {
                    Some((body, hs)) => Ok(SegFetch {
                        body,
                        hs,
                        rescued: true,
                    }),
                    None => Err("段失败且镜像救援不可用".to_string()),
                },
                Err(_) => match rescue_segment(tpl_ref, kind, &chain, s, e, &log2).await {
                    Some((body, hs)) => Ok(SegFetch {
                        body,
                        hs,
                        rescued: true,
                    }),
                    None => Err("段直连 5s 无响应头, 镜像救援也不可用".to_string()),
                },
            }
        }
    });
    let results = join_all(futs).await;
    if let Some((i, why)) = results
        .iter()
        .enumerate()
        .find_map(|(i, r)| r.as_ref().err().map(|e| (i, e)))
    {
        (log)(&format!(
            "[直连切片] {host}{} 第 {} 段失败({why}), 回单流",
            path_of(out.uri()),
            i + 1
        ));
        return None;
    }
    let mut entries: Vec<(BoxBody, usize, u64, bool)> = Vec::with_capacity(segs.len() + 1);
    let mut first_headers: Option<HeaderMap> = None;
    if let Some((bytes, hs)) = &prefix {
        // 探片 10KB = 交付首段：字节已在手，头用它（206 头，Range 语义头会被剥）。
        first_headers = Some(hs.clone());
        entries.push((protocol::full_body(bytes.clone()), bytes.len(), 0, false));
    }
    for (i, r) in results.into_iter().enumerate() {
        let f = r.ok()?;
        if first_headers.is_none() {
            first_headers = Some(f.hs);
        }
        entries.push((f.body, (segs[i].1 - segs[i].0) as usize, segs[i].0, f.rescued));
    }
    // 总长记忆命中时没走过探片，用第一段的 content-type 补一道媒体校验。
    let hs = first_headers.as_ref()?;
    if !is_media(hs.get("content-type").and_then(|v| v.to_str().ok())) {
        return None;
    }
    let mut builder = hyper::Response::builder().status(StatusCode::OK);
    for (k, v) in hs.iter() {
        if skip_response_header(k.as_str()) {
            continue;
        }
        builder = builder.header(k.clone(), v.clone());
    }
    builder = builder
        .header(http::header::CONTENT_LENGTH, total)
        .header(http::header::ACCEPT_RANGES, "bytes");
    // 链空（Script / 未配镜像）= 无救援：不挂救援上下文——段直连独走，不检查不等待。
    let rescue = if chain.is_empty() {
        None
    } else {
        Some(RescueCtx {
            tpl: tpl.clone(),
            kind,
            chain,
            log: log.clone(),
        })
    };
    let body = BoxBody::new(
        SegmentedBody::build(
            entries,
            total,
            rescue,
            t0,
            Duration::from_secs(crate::config::MEDIA_RESCUE_WAIT_SECS),
        )
        .hold(guard),
    );
    (log)(&format!(
        "[直连切片] {host}{} {total}B 切 {} 段 池内直连并发",
        path_of(out.uri()),
        segs.len() + if prefix.is_some() { 1 } else { 0 },
    ));
    builder.body(body).ok()
}

/// 同时在途的多段响应闸。挂在响应体上，播完/客户端断开才归还。
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct ActiveGuard;

impl ActiveGuard {
    fn take() -> Option<Self> {
        let mut cur = ACTIVE.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_ACTIVE {
                return None;
            }
            match ACTIVE.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(ActiveGuard),
                Err(c) => cur = c,
            }
        }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Release);
    }
}

/// 段的镜像救援上下文：模板（按偏移重建 Range 请求）、媒体类别（选链）、
/// 链快照（构造时机判空，运行期不再查全局）、host（缺链告警按它节流）、日志。
#[derive(Clone)]
struct RescueCtx {
    tpl: Tpl,
    kind: MediaKind,
    chain: Vec<String>,
    log: LogFn,
}

/// 段future 的产出：体 + 头 + 是否已来自镜像救援（救援过的体不再做体级 5s 换镜）。
struct SegFetch {
    body: BoxBody,
    hs: HeaderMap,
    rescued: bool,
}

struct Seg {
    body: BoxBody,
    buf: VecDeque<Bytes>,
    buffered: usize,
    expected: usize,
    got: usize,
    done: bool,
    /// 本段请求起点（Range 头），救援续传按它算偏移。
    s: u64,
    /// 本段终点（Range 尾 +1），换体时期望字节按它重算。
    e: u64,
    /// 5s 界触发：冻结直连体，buf 榨干后起救援。
    rescue_due: bool,
    /// 在途的镜像救援任务；就绪即换体。
    handle: Option<tokio::task::JoinHandle<Option<(BoxBody, u64)>>>,
    /// 体已来自镜像（或不可救援）：不再触发体级 5s 换镜。
    no_rescue: bool,
    /// 段起点计时：5s 界从开流算起，不是从拼装算起。
    started: Instant,
}

impl Seg {
    /// 镜像救援换体：直连残体与缓冲一并丢弃，期望字节从续传点重算——
    /// 已交付的都是连续前缀，镜像从同一偏移接着发，流内无重复无缺口。
    fn install_rescue(&mut self, body: BoxBody, start: u64) {
        self.buf.clear();
        self.buffered = 0;
        self.got = 0;
        self.expected = (self.e - start) as usize;
        self.body = body;
        self.handle = None;
        self.no_rescue = true; // 换上来的就是镜像体，不再二次救援
        self.rescue_due = false;
    }
}

/// 按段序交付，但每轮把所有段都 poll 一次——只盯队首会让未读段占死连接级流控窗口。
/// 每段挂 5s 界：没拉完的段冻结直连侧，镜像按已交付偏移续传。
pub(super) struct SegmentedBody {
    segs: Vec<Seg>,
    idx: usize,
    total: u64,
    sent: u64,
    guard: Option<ActiveGuard>,
    finished: bool,
    rescue: Option<RescueCtx>,
    rescue_after: Duration,
}

impl SegmentedBody {
    /// 无救援的拼装（仅测试用）：5s 界整个关掉，生产路径一律走 build。
    #[cfg(test)]
    fn new(entries: Vec<(BoxBody, usize)>, total: u64) -> Self {
        let entries = entries
            .into_iter()
            .map(|(body, expected)| (body, expected, 0, true))
            .collect();
        Self::build(entries, total, None, Instant::now(), Duration::MAX)
    }

    fn build(
        entries: Vec<(BoxBody, usize, u64, bool)>,
        total: u64,
        rescue: Option<RescueCtx>,
        started: Instant,
        rescue_after: Duration,
    ) -> Self {
        SegmentedBody {
            segs: entries
                .into_iter()
                .map(|(body, expected, s, rescued)| Seg {
                    body,
                    buf: VecDeque::new(),
                    buffered: 0,
                    expected,
                    got: 0,
                    done: false,
                    s,
                    e: s + expected as u64,
                    rescue_due: false,
                    handle: None,
                    no_rescue: rescued,
                    started,
                })
                .collect(),
            idx: 0,
            total,
            sent: 0,
            guard: None,
            finished: false,
            rescue,
            rescue_after,
        }
    }

    fn hold(mut self, g: ActiveGuard) -> Self {
        self.guard = Some(g);
        self
    }
}

impl hyper::body::Body for SegmentedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = self.get_mut();
        if me.finished {
            return Poll::Ready(None);
        }
        for seg in me.segs.iter_mut() {
            if seg.done {
                continue;
            }
            // 5s 界（仅配置了救援链的段）：没拉完就冻结直连体，镜像从已交付偏移续传。
            // 无救援上下文（镜像退场/未配置）：段直连独走——不检查、不等待、不落日志。
            if me.rescue.is_some()
                && !seg.no_rescue
                && !seg.rescue_due
                && seg.got < seg.expected
                && seg.started.elapsed() >= me.rescue_after
            {
                if let Some(ctx) = &me.rescue {
                    if !MEDIA_RESCUE_BREAKER.open(ctx.kind.chain()) {
                        seg.rescue_due = true;
                    }
                    // 熔断开着：不置位不判死，继续骑直连流（60s 后熔断关，救援自然恢复）。
                }
            }
            if seg.rescue_due {
                if let Some(ctx) = &me.rescue {
                    if seg.handle.is_none() && seg.buf.is_empty() && seg.got < seg.expected {
                        let c = ctx.clone();
                        let (s, e, got) = (seg.s, seg.e, seg.got as u64);
                        seg.handle = Some(tokio::spawn(async move {
                            rescue_segment(&c.tpl, c.kind, &c.chain, s + got, e, &c.log)
                                .await
                                .map(|(body, _hs)| (body, s + got))
                        }));
                    }
                }
                if let Some(handle) = &mut seg.handle {
                    match Pin::new(handle).poll(cx) {
                        Poll::Ready(Ok(Some((body, start)))) => {
                            seg.install_rescue(body, start);
                        }
                        Poll::Ready(Ok(None)) | Poll::Ready(Err(_)) => {
                            me.finished = true;
                            return Poll::Ready(Some(Err(std::io::Error::other(
                                "直连段 5s 未完且镜像救援失败",
                            ))));
                        }
                        Poll::Pending => {}
                    }
                }
                if seg.handle.is_some() {
                    continue; // 救援在途：本段冻结，等其他段的数据把窗口腾出来
                }
            }
            if seg.buffered >= SEG_BUFFER_MAX {
                continue;
            }
            match Pin::new(&mut seg.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(d) = frame.into_data() {
                        seg.got += d.len();
                        // 终点超长的字节会吃掉全局总长预算，尾段发不完——直接报错。
                        if seg.got > seg.expected {
                            me.finished = true;
                            return Poll::Ready(Some(Err(std::io::Error::other(
                                "直连段超出本段字节数",
                            ))));
                        }
                        seg.buffered += d.len();
                        seg.buf.push_back(d);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    me.finished = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => seg.done = true,
                Poll::Pending => {}
            }
        }
        loop {
            if me.sent >= me.total {
                me.finished = true;
                return Poll::Ready(None);
            }
            let Some(seg) = me.segs.get_mut(me.idx) else {
                me.finished = true;
                return Poll::Ready(None);
            };
            if let Some(chunk) = seg.buf.pop_front() {
                seg.buffered -= chunk.len();
                let room = (me.total - me.sent) as usize;
                let out = if chunk.len() <= room {
                    chunk
                } else {
                    chunk.slice(..room)
                };
                if out.is_empty() {
                    continue;
                }
                me.sent += out.len() as u64;
                return Poll::Ready(Some(Ok(Frame::data(out))));
            }
            if seg.done {
                if seg.got < seg.expected {
                    me.finished = true;
                    return Poll::Ready(Some(Err(std::io::Error::other("直连段提前结束"))));
                }
                me.idx += 1;
                continue;
            }
            // 所有段刚才都被 poll 过，waker 已注册；等任一段来数据再醒。
            return Poll::Pending;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/direct_split.rs"]
mod tests;
