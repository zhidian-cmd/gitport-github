//! 大图/视频纯直连多段：多个 Range 在池内同一条通道上并发拉（stream 非连接），合成 200 流；不拨号、不进兜底。
//! 段的交付/停滞收尸/补发统一挂镜像腿的 MergeBody+drive_split（见 merge.rs），本文件只管段位分配与救援闭包。
use super::merge::MergeBody;
use super::mirror::{drive_split, Fetch, FilledSeg, SplitCtx};
use super::{merge, mirror, path_of, UpstreamInfo};
use super::super::{protocol::{self, BoxBody}, upstream};
use crate::{pool, util::LogFn};
use bytes::Bytes;
use futures_util::future::join_all;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        LazyLock, Mutex,
    },
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
/// 段响应头预算：头应毫秒级，8s 只防上游装死。
const SEG_HEAD_BUDGET: Duration = Duration::from_secs(8);
const MEMO_TTL: Duration = Duration::from_secs(600);

/// 白名单只认静态 CDN；v6.7 起 githubassets 的 JS/CSS 不切（脚本分片无救援、9MB index.js 实测从未走通），改单流直连+缓存兜底。
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
    )
}

/// 媒体判定：图片与视频都切；非媒体探一次记 10 分钟不再探。
fn is_media(ct: Option<&str>) -> bool {
    MediaKind::of_content_type(ct).is_some()
}

pub(super) fn seg_count(total: u64) -> usize {
    ((total / SEG_TARGET_BYTES) as usize).clamp(4, MAX_SEGS)
}

/// 段请求模板：原请求的 method/uri/headers，每次重建干净 GET；与镜像 segment_direct 共用。
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

/// 段请求头过滤：Range 语义头与逐跳头不透传、条件头剥掉（不该 304）；accept-encoding 透传（压缩后传输量缩 3 倍，切片按压缩流字节切）。
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

// Content-Range 解析统一走 merge::{content_range_total/start/end}，与镜像链同一套标准。

/// 媒体类别决定救援链：图片走图片链、视频走视频链；脚本段链为空——公共镜像不收 githubassets，直连独走不设救援。
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

/// 206 段边界校验：起点规则共用 merge::check_segment_start，另加终点不越界——越界会吃掉总长预算，尾段发不完。
fn check_segment_bounds(cr: Option<&str>, start: u64, e: u64) -> Result<(), String> {
    merge::check_segment_start(cr, start)?;
    if merge::content_range_end(cr).is_some_and(|end| end >= e) {
        return Err(format!("段终点越界: 要 <= {}, 拿到 {cr:?}", e - 1));
    }
    Ok(())
}

/// 段的镜像救援：从 start 续传到 e（已交付不重拉），链序逐个试、全灭记熔断；整段单流，链快照由调用方传入。
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

/// 切片主入口：总机下发片数，段级重试/续传内置，输出合并 200 流；任一段最终失败仍返回 None 交回单流（头未发出不会花掉）。
pub(super) async fn try_direct_split(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
    info: &UpstreamInfo,
    want_segs: usize,
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
            // 探片要一条通道：池冷就借池子的建造（等在途建造最多 15s），建不出退单流。
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
    // 恒 N 段：探片前缀存在则段从 10KB 后排，否则从头排；长度按 [seg_start,total)，传 total 会切到文件尾外 10KB 被严格 CDN 退单流。
    let seg_start = if prefix.is_some() { PROBE_BYTES } else { 0 };
    let segs = merge::split_even(
        seg_start,
        total - seg_start,
        seg_count(total - seg_start).min(want_segs.max(1)),
    );
    if segs.is_empty() {
        return None;
    }
    // 单通道模型：全部段骑池给的这一条（并行 stream 不是并行连接——185.199 聚合水管恒定，多连接不加吞吐）。
    let Some(up) = pool::gather_channels(host, 1, log).await.into_iter().next() else {
        log_skip(log, host, &path, "池内无可用通道");
        return None;
    };
    // 段级重试：头阶段失败（连接死/超时）→ 同通道再试，至多 3 次。
    let futs = segs.iter().map(|&(s, e)| {
        let up = up.clone();
        let tpl2 = tpl.clone();
        async move {
            let mut attempt = 0u8;
            loop {
                attempt += 1;
                let res = tokio::time::timeout(
                    Duration::from_secs(crate::config::MEDIA_RESCUE_WAIT_SECS),
                    fetch_segment(&up, &tpl2, s, e),
                )
                .await;
                match res {
                    Ok(Ok((body, hs))) => return Ok((body, hs)),
                    _ => {
                        if attempt >= 3 {
                            return Err("段拉取重试耗尽".to_string());
                        }
                        // 同通道重试：段边界不变整段重拉（共享通道不能中途摘，会杀死同通道其他段的在途流）。
                    }
                }
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
    let mut entries: Vec<(u64, u64, Instant, BoxBody, String, u64)> =
        Vec::with_capacity(segs.len() + 1);
    let mut first_headers: Option<HeaderMap> = None;
    if let Some((bytes, hs)) = &prefix {
        // 探片 10KB = 交付首段：字节已在手，头用它（206 头，Range 语义头会被剥）。
        first_headers = Some(hs.clone());
        entries.push((
            0,
            PROBE_BYTES,
            Instant::now(),
            protocol::full_body(bytes.clone()),
            format!("direct/{}", host),
            0,
        ));
    }
    for (i, r) in results.into_iter().enumerate() {
        let (body, hs) = r.ok()?;
        if first_headers.is_none() {
            first_headers = Some(hs);
        }
        entries.push((
            segs[i].0,
            segs[i].1,
            Instant::now(),
            body,
            format!("direct/{}", host),
            0,
        ));
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
    // 救援收口成一个 Fetch 闭包：有链（图片/视频）→ 镜像续传；无链（脚本/未配镜像）→ 直连同通道从剩余偏移重拉。
    let chain = match kind {
        MediaKind::Script => Vec::new(),
        _ => pool::mirror_chain(kind.chain()),
    };
    let fetch: Fetch = {
        let tpl = std::sync::Arc::new(tpl);
        let host = host.to_string();
        let log = log.clone();
        std::sync::Arc::new(move |from: u64, to: u64| {
            let tpl = tpl.clone();
            let chain = chain.clone();
            let host = host.clone();
            let log = log.clone();
            Box::pin(async move {
                if !chain.is_empty() {
                    return match rescue_segment(&tpl, kind, &chain, from, to, &log).await {
                        Some((body, _hs)) => Ok(FilledSeg {
                            body,
                            owner: format!("direct/{}", host),
                            ramp: 0,
                        }),
                        None => Err("镜像救援不可用(链全灭或熔断中)".to_string()),
                    };
                }
                // 无链：直连同通道从剩余偏移重拉（池自动重建死通道）。
                let (up, _) = pool::get_or_build(&host, &log).await?;
                let req = tpl.build(from, to).map_err(|e| e.to_string())?;
                let resp = tokio::time::timeout(
                    Duration::from_secs(crate::config::MEDIA_RESCUE_WAIT_SECS),
                    upstream::h2_send(&up, &req, &None::<Bytes>),
                )
                .await
                .map_err(|_| "救援段响应头超时".to_string())??;
                if resp.status() != StatusCode::PARTIAL_CONTENT {
                    return Err(format!("救援段回 {}", resp.status()));
                }
                merge::check_segment_start(
                    resp
                        .headers()
                        .get("content-range")
                        .and_then(|v| v.to_str().ok()),
                    from,
                )?;
                Ok(FilledSeg {
                    body: resp.into_body(),
                    owner: format!("direct/{}", host),
                    ramp: 0,
                })
            })
        })
    };
    let body = drive_split(
        // 直连骑单通道：多开流不加吞吐（185.199 聚合水管恒定），不参与重分配，只走停滞补发。
        MergeBody::new(entries, total).without_yield().hold(Box::new(guard)),
        SplitCtx {
            fetch,
            host: host.to_string(),
            log: log.clone(),
        },
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

#[cfg(test)]
#[path = "../../tests/server/mitm/direct_split.rs"]
mod tests;
