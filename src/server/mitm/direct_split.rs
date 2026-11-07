//! README 大图/视频的纯直连多段：同一批字节拆成多个 Range，摊到池里的多条伪装 SNI
//! 直连通道上并发拉（每条通道一个独立拥塞窗口），按字节边界顺序合成一条 200 流交回浏览器。
//!
//! 与 mirror::split_download 是两回事：那边按「镜像源 + 直连」分配段位、走 ECT 记账和
//! 跨源补发；这边只认池子给的直连通道，段不够时经池子按需溢出补临时通道（上限内、
//! 用毕即焚），自己从不拨号，也不经过 get_direct 的兜底，因而不会把一次段失败误判成
//! 「内容域直连全灭」而转镜像。并发是两层叠加：同通道多 stream + 多通道多窗口——
//! 实测单连接 8 段 73.8s→45.0s（1.6 倍封顶），多通道摊段就是为了突破这个天花板。
use super::{merge, path_of, UpstreamInfo};
use super::super::{protocol::{self, BoxBody}, upstream};
use crate::{pool, util::LogFn};
use bytes::Bytes;
use futures_util::future::join_all;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::body::Frame;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        LazyLock, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// 小于这个尺寸别切：探片多一次往返，省下的时间抵不过它。实测 512KB 切 8 段仍有 2.7x，门槛就放这。
const MIN_SPLIT_BYTES: u64 = 512 * 1024;
/// 目标段大小；按总长算段数，钳在 4~8。实测 8 段最好，但一页十几张图不能每张都开满 8 段。
const SEG_TARGET_BYTES: u64 = 192 * 1024;
const MAX_SEGS: usize = 8;
/// 同时在途的「多段响应」个数。浏览器一页十几个 <img> 一起到，全切会把 h2 连接级
/// 流控窗口（4MB）占死；闸按「响应体还在流」计数，靠 body 的生命周期自动归还。
/// 段已摊到多条通道上（单连接压力被摊薄），闸从 3 放宽到 6。
const MAX_ACTIVE: usize = 6;
/// 单段在用户态的缓冲上限：快段先到先存，超过就暂时不读它。
const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 段响应头预算。段本身是 Range 请求，头应该毫秒级；8s 只是防上游装死。
const SEG_HEAD_BUDGET: Duration = Duration::from_secs(8);
const MEMO_TTL: Duration = Duration::from_secs(600);

/// 只按 host 白名单准入：静态图片 CDN 才切，github.com / api.github.com 等会话域
/// 与 README 的 /owner/repo/raw/... 第一跳都不在表内（那跳是 302）。URL 与凭据头
/// 原样保留，段请求只换 Range——签名可能落在 query 或 Authorization 里，剥掉只会
/// 把请求改坏（403/签名校验失败），能不能切交给上游的 206 回答。
pub(super) fn is_image_split_host(host: &str) -> bool {
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

/// 探片与收口共用的媒体判定：图片之外放行视频（README 嵌的 mp4/webm 走同一套
/// Range 切片）。只在白名单 host 内生效，会话域永远不在名单上。
fn is_media(ct: Option<&str>) -> bool {
    ct.is_some_and(|v| v.starts_with("image/") || v.starts_with("video/"))
}

pub(super) fn seg_count(total: u64) -> usize {
    ((total / SEG_TARGET_BYTES) as usize).clamp(4, MAX_SEGS)
}

/// 段请求的模板：原请求的 method/uri/headers，每次重建一份干净的 GET。
struct Tpl {
    method: Method,
    uri: http::Uri,
    headers: HeaderMap,
}

impl Tpl {
    fn of(out: &hyper::Request<BoxBody>) -> Self {
        Tpl {
            method: out.method().clone(),
            uri: out.uri().clone(),
            headers: out.headers().clone(),
        }
    }

    /// [s, e) 半开区间 → Range: bytes=s-(e-1)。URL 与凭据头原样保留：签名可能在
    /// query 里、凭据可能在 Authorization 里，剥掉会直接把请求改坏；只剥会改变段
    /// 语义的头（Range / 条件头 / Accept-Encoding）与逐跳头。
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

fn skip_request_header(k: &str) -> bool {
    matches!(
        k,
        "range"
            | "if-range"
            | "if-none-match"
            | "if-modified-since"
            | "accept-encoding"
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

fn skip_response_header(k: &str) -> bool {
    matches!(
        k,
        "content-range"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "content-encoding"
            | "keep-alive"
            | "proxy-connection"
    )
}

// Content-Range 的解析统一走 merge::{content_range_total, content_range_start, content_range_end}，
// 与镜像链的 206 校验用同一套标准，别再各写一份。

/// 探片/总长记忆：命中省一次真实往返；记 0 表示这个 URL 不支持 Range，10 分钟内别再探。
static MEMO: LazyLock<Mutex<HashMap<String, (u64, Instant)>>> = LazyLock::new(Default::default);

fn memo_get(key: &str) -> Option<u64> {
    MEMO.lock()
        .unwrap()
        .get(key)
        .filter(|(_, at)| at.elapsed() < MEMO_TTL)
        .map(|(t, _)| *t)
}

fn memo_put(key: &str, total: u64) {
    let mut g = MEMO.lock().unwrap();
    if g.len() >= 512 {
        g.retain(|_, (_, at)| at.elapsed() < MEMO_TTL);
    }
    g.insert(key.to_string(), (total, Instant::now()));
}

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
    let cr = resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok());
    if merge::content_range_start(cr) != Some(s) {
        return Err(format!("段边界不符: 要 {s}, 拿到 {cr:?}"));
    }
    // 起点对但终点越界也不能收：多出来的字节会吃掉总长预算，尾段就发不完了。
    if merge::content_range_end(cr).is_some_and(|end| end >= e) {
        return Err(format!("段终点越界: 要 <= {}, 拿到 {cr:?}", e - 1));
    }
    let (parts, body) = resp.into_parts();
    Ok((body, parts.headers))
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
    if !is_image_split_host(host) {
        return None;
    }
    let key = format!("{host}{}", path_of(out.uri()));
    let total = match memo_get(&key) {
        Some(0) => return None,
        Some(t) => t,
        None => {
            let tpl = Tpl::of(out);
            // 探片要一条通道：池冷就借池子的建造（等在途建造最多 3s），建不出退单流。
            let Some(up) = pool::gather_channels(host, 1, log).await.into_iter().next() else {
                return None;
            };
            *info.lock().unwrap() = up.ip.clone();
            let req = tpl.build(0, 1).ok()?;
            let resp = match tokio::time::timeout(
                SEG_HEAD_BUDGET,
                upstream::h2_send(&up, &req, &None::<Bytes>),
            )
            .await
            {
                Ok(Ok(r)) => r,
                _ => return None,
            };
            if resp.status() != StatusCode::PARTIAL_CONTENT {
                memo_put(&key, 0); // 上游忽略 Range：10 分钟内别再白探
                return None;
            }
            let Some(t) = merge::content_range_total(
                resp.headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok()),
            ) else {
                memo_put(&key, 0);
                return None;
            };
            let media = is_media(
                resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok()),
            );
            drop(resp.into_body()); // 探片只有 1 字节，及时关掉流别占连接窗口
            if !media {
                memo_put(&key, 0); // 非媒体：10 分钟内别再探、更别切
                return None;
            }
            memo_put(&key, t); // 记住总长；小图下次直接被 MIN_SPLIT_BYTES 挡掉
            t
        }
    };
    if total < MIN_SPLIT_BYTES {
        return None;
    }
    let guard = ActiveGuard::take()?;
    let tpl = Tpl::of(out);
    let tpl_ref = &tpl;
    let segs = merge::split_even(0, total, seg_count(total));
    if segs.len() < 2 {
        return None;
    }
    // 段摊到池内多条通道上：每条通道一个独立拥塞窗口，比单连接多路复用高一截。
    // 一次响应最多借 3 条；通道不够（上限/建造失败）就按现有的摊，单条也能跑。
    let chans: std::sync::Arc<[upstream::H2Upstream]> =
        std::sync::Arc::from(pool::gather_channels(host, segs.len().min(3), log).await);
    if chans.is_empty() {
        return None;
    }
    let n = chans.len();
    let futs = segs.iter().enumerate().map(|(i, &(s, e))| {
        let up = chans[i % n].clone();
        let all = chans.clone();
        async move {
            match fetch_segment(&up, tpl_ref, s, e).await {
                Ok(r) => Ok(r),
                Err(why) => {
                    // 本通道上的段失败：换一条通道重试一次——多通道摊段后，
                    // 单条通道半死不该拖垮整张图。
                    match all.iter().find(|c| c.id != up.id) {
                        Some(alt) => fetch_segment(alt, tpl_ref, s, e).await,
                        None => Err(why),
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
    let mut bodies: Vec<(BoxBody, usize)> = Vec::with_capacity(segs.len());
    let mut first_headers: Option<HeaderMap> = None;
    for (i, r) in results.into_iter().enumerate() {
        let (body, hs) = r.ok()?;
        if first_headers.is_none() {
            first_headers = Some(hs);
        }
        bodies.push((body, (segs[i].1 - segs[i].0) as usize));
    }
    // 总长记忆命中时没走过探片，用第一段的 content-type 补一道图片校验。
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
    let body = BoxBody::new(SegmentedBody::new(bodies, total).hold(guard));
    (log)(&format!(
        "[直连切片] {host}{} {total}B 切 {} 段, 池内直连并发",
        path_of(out.uri()),
        segs.len()
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

struct Seg {
    body: BoxBody,
    buf: VecDeque<Bytes>,
    buffered: usize,
    expected: usize,
    got: usize,
    done: bool,
}

/// 按段序交付，但每轮把所有段都 poll 一次：h2 的连接级流控窗口是所有 stream 共享的，
/// 只盯着队首那一段读，后面几段的数据会把窗口占满、反过来把队首也卡死。
pub(super) struct SegmentedBody {
    segs: Vec<Seg>,
    idx: usize,
    total: u64,
    sent: u64,
    guard: Option<ActiveGuard>,
    finished: bool,
}

impl SegmentedBody {
    fn new(entries: Vec<(BoxBody, usize)>, total: u64) -> Self {
        SegmentedBody {
            segs: entries
                .into_iter()
                .map(|(body, expected)| Seg {
                    body,
                    buf: VecDeque::new(),
                    buffered: 0,
                    expected,
                    got: 0,
                    done: false,
                })
                .collect(),
            idx: 0,
            total,
            sent: 0,
            guard: None,
            finished: false,
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
            if seg.done || seg.buffered >= SEG_BUFFER_MAX {
                continue;
            }
            match Pin::new(&mut seg.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(d) = frame.into_data() {
                        seg.got += d.len();
                        // 单段只能交自己那 (e-s) 个字节。上游起点对但终点超长时，
                        // 多出的字节会吃掉全局总长预算，尾段就发不出去了。
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
