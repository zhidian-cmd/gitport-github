//! README 大图的纯直连多段：同一批字节拆成多个 Range，全部落在池里现成的伪装 SNI
//! 直连连接上并发拉，按字节边界顺序合成一条 200 流交回浏览器。
//!
//! 与 mirror::split_download 是两回事：那边按「镜像源 + 直连」分配段位、走 ECT 记账和
//! 跨源补发；这边只认池里已有的直连连接，不碰 gh-proxy、不拨新 IP、不扩 MAX_CHANNELS，
//! 也不经过 get_direct 的熔断/兜底，因而不会把一次段失败误判成「内容域直连全灭」而转镜像。
//! 实测同一条通道上多开 stream 也有收益（1MB 单流 73.8s，8 段 45.0s；反序热连接
//! 512KB 单流 48.6s、8 段 20.9s），所以段不必绑定不同 IP。
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
const MAX_ACTIVE: usize = 3;
/// 单段在用户态的缓冲上限：快段先到先存，超过就暂时不读它。
const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 段响应头预算。段本身是 Range 请求，头应该毫秒级；8s 只是防上游装死。
const SEG_HEAD_BUDGET: Duration = Duration::from_secs(8);
const MEMO_TTL: Duration = Duration::from_secs(600);

/// 只认不带登录态的静态图片 CDN。github.com / api.github.com 是会话域，
/// README 的 /owner/repo/raw/... 第一跳带 user_session，绝不能在这里切：
/// 子请求会把 Cookie 复制 N 份、从 N 条通道同时冒出来，正是代码里明令禁止的风控特征。
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

    /// [s, e) 半开区间 → Range: bytes=s-(e-1)。凭据头一律剥掉：这些域本来就不带
    /// Cookie，显式剥是为了哪天请求形状变了也不会把登录态复制成 N 份。
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
        "cookie"
            | "authorization"
            | "proxy-authorization"
            | "range"
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

fn content_range_total(v: Option<&str>) -> Option<u64> {
    let t = v?.trim().rsplit('/').next()?.trim();
    if t == "*" {
        return None;
    }
    t.parse().ok()
}

fn range_start(v: Option<&str>) -> Option<u64> {
    // 标准头是 "bytes 262144-524287/1608296"（空格），别按 "bytes=" 那套 Range 请求的写法猜。
    let s = v?.trim();
    let rest = s
        .strip_prefix("bytes ")
        .or_else(|| s.strip_prefix("bytes="))?;
    rest.split('-').next()?.trim().parse().ok()
}

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

/// 只从池里拿现成的直连连接。池冷（刚启动/刚被摘空）就老实走单流，让主路径自己拨号，
/// 切片不负责建连，也就不会顺带把 MAX_CHANNELS 或拨号单飞语义卷进来。
fn pick_conn(host: &str) -> Option<upstream::H2Upstream> {
    let ips: Vec<String> = pool::route::dial_targets(host)?
        .into_iter()
        .map(|n| n.ip)
        .collect();
    upstream::cached_h2_in(&ips, None)
}

async fn fetch_segment(
    host: &str,
    tpl: &Tpl,
    s: u64,
    e: u64,
) -> Result<(BoxBody, HeaderMap), String> {
    let up = pick_conn(host).ok_or_else(|| "池里没有现成直连通道".to_string())?;
    let req = tpl.build(s, e)?;
    let resp = tokio::time::timeout(SEG_HEAD_BUDGET, upstream::h2_send(&up, &req, &None::<Bytes>))
        .await
        .map_err(|_| "段响应头超时".to_string())??;
    if resp.status() != StatusCode::PARTIAL_CONTENT {
        return Err(format!("段回 {}", resp.status()));
    }
    let cr = resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok());
    if range_start(cr) != Some(s) {
        return Err(format!("段边界不符: 要 {s}, 拿到 {cr:?}"));
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
    // 直连熔断开着说明这个域此刻确实不通，交给主路径按既有规则兜底，别在切片里绕过去。
    if pool::route::is_content(host) && pool::CONTENT_BREAKER.open(host) {
        return None;
    }
    let key = format!("{host}{}", path_of(out.uri()));
    let total = match memo_get(&key) {
        Some(0) => return None,
        Some(t) => t,
        None => {
            let tpl = Tpl::of(out);
            let up = pick_conn(host)?;
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
            let Some(t) = content_range_total(
                resp.headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok()),
            ) else {
                memo_put(&key, 0);
                return None;
            };
            let is_image = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("image/"));
            drop(resp.into_body()); // 探片只有 1 字节，及时关掉流别占连接窗口
            if !is_image {
                memo_put(&key, 0); // 非图片：10 分钟内别再探、更别切
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
    let futs = segs.iter().map(|&(s, e)| {
        let host = host.to_string();
        async move { fetch_segment(&host, tpl_ref, s, e).await }
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
    if !hs
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("image/"))
    {
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
