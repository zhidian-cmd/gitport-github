//! 切片合并：一条请求按镜像数平均切段、并发拉，再按边界顺序泵成单条字节河。
//! 段终点一律用相对偏移（相对本次请求区间的起点），交付线与边界同域，不会错位。

use super::protocol::BoxBody;
use bytes::Bytes;
use hyper::body::{Body as _, Frame};
use std::collections::VecDeque;

/// 平均切 [base, base+len) 为 n 段：相邻共享边界，零重叠零缝，余数归最后一段。
/// n 超过字节数时收缩到字节数，保证每段至少 1 字节。
pub(super) fn split_even(base: u64, len: u64, n: usize) -> Vec<(u64, u64)> {
    if len == 0 {
        return Vec::new();
    }
    let n = (n.max(1) as u64).min(len);
    let per = len / n;
    let mut out = Vec::with_capacity(n as usize);
    let mut s = base;
    for i in 0..n {
        let e = if i + 1 == n { base + len } else { s + per };
        out.push((s, e));
        s = e;
    }
    out
}

/// 客户端 Range 的 (起点, 终点含)。无 Range、多区间、畸形 → None。
pub(super) fn parse_range(range: Option<&str>) -> Option<(u64, Option<u64>)> {
    let spec = range?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // 多区间响应是 multipart/byteranges，切不了
    }
    let (a, b) = spec.trim().split_once('-')?;
    let a: u64 = a.trim().parse().ok()?;
    let b = match b.trim() {
        "" => None,
        s => Some(s.parse::<u64>().ok()?),
    };
    Some((a, b))
}

/// 单字节探片（bytes=N-N）：下载器先探文件大小，走链头直通，不切分也不记分。
pub(super) fn is_probe_range(range: Option<&str>) -> bool {
    matches!(parse_range(range), Some((a, Some(b))) if a == b)
}

/// 从 `Content-Range: bytes 0-0/2097152000` 取文件总长；`*` 或缺失/畸形 → None。
pub(super) fn content_range_total(v: Option<&str>) -> Option<u64> {
    let t = v?.trim().rsplit('/').next()?.trim();
    if t == "*" {
        return None;
    }
    t.parse().ok()
}

/// 按边界顺序泵多段。段早断/出错先登记缺口并结束本轮，由外层补发后续上，
/// 绝不在 poll 里 Pending 等外部——没人唤醒就是死锁。
/// 单段缓冲上限：快段先到先存，超过就暂时不再读它，等交付线推进再读。
/// 八段各 2MB 顶格 16MB，够吸收乱序，也不会把内存堆爆。
const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;

/// 一段：自己的响应体 + 自己的缓冲。九段同时读，交付按边界序。
struct Seg {
    /// 段相对终点。
    end: u64,
    body: BoxBody,
    /// 先到先存的数据，按到达顺序排。
    buf: VecDeque<Bytes>,
    buffered: usize,
    /// 上游已结束（正常收尾或出错）。
    done: bool,
    /// 结束原因（仅 done 时有意义）。
    err: Option<std::io::Error>,
}

impl Seg {
    fn new(end: u64, body: BoxBody) -> Self {
        Seg {
            end,
            body,
            buf: VecDeque::new(),
            buffered: 0,
            done: false,
            err: None,
        }
    }
}

pub(super) struct MergeBody {
    /// 按边界序排列的段，各自带缓冲。
    segs: VecDeque<Seg>,
    /// 已交付字节（相对区间起点）。
    sent: u64,
    /// 缺口终点（相对）。外层补发后 feed_rescue 续上。
    pub(super) gap: Option<u64>,
    finished: bool,
}

impl MergeBody {
    pub(super) fn new(segs: Vec<(u64, BoxBody)>) -> Self {
        MergeBody {
            segs: segs.into_iter().map(|(e, b)| Seg::new(e, b)).collect(),
            sent: 0,
            gap: None,
            finished: false,
        }
    }

    pub(super) fn sent(&self) -> u64 {
        self.sent
    }

    /// 补发流接管：从当前交付线续到缺口终点。
    pub(super) fn feed_rescue(&mut self, gap_end: u64, body: BoxBody) {
        self.segs.push_front(Seg::new(gap_end, body));
    }

    /// 把还在跑的段各推一轮，填进各自缓冲。返回是否有进展（拿到数据或某段结束）。
    /// 缓冲满的段暂时不推——它的 waker 也就不再注册；等交付线推进后自然会再推它。
    fn fill_all(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        let mut progressed = false;
        for seg in self.segs.iter_mut() {
            if seg.done || seg.buffered >= SEG_BUFFER_MAX {
                continue;
            }
            match std::pin::Pin::new(&mut seg.body).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(f))) => {
                    progressed = true;
                    // 非数据帧（trailer 等）直接丢，只关心正文。
                    if let Ok(d) = f.into_data() {
                        seg.buffered += d.len();
                        seg.buf.push_back(d);
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    progressed = true;
                    seg.done = true;
                    seg.err = Some(e);
                }
                std::task::Poll::Ready(None) => {
                    progressed = true;
                    seg.done = true;
                }
                std::task::Poll::Pending => {}
            }
        }
        progressed
    }
}

impl hyper::body::Body for MergeBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = self.get_mut();
        loop {
            if me.finished {
                return std::task::Poll::Ready(None);
            }
            if me.segs.is_empty() {
                me.finished = true;
                return std::task::Poll::Ready(None);
            }
            // 1) 交付线所在的段：缓冲里有货就发（截到段终点，绝不越界）。
            let sent = me.sent;
            let mut emit: Option<Bytes> = None;
            let mut head_closed: Option<u64> = None;
            {
                let seg = me.segs.front_mut().expect("已判空");
                if let Some(chunk) = seg.buf.pop_front() {
                    seg.buffered -= chunk.len();
                    let room = seg.end.saturating_sub(sent) as usize;
                    if room >= chunk.len() {
                        emit = Some(chunk);
                    } else if room > 0 {
                        emit = Some(chunk.slice(..room));
                    }
                } else if seg.done {
                    head_closed = Some(seg.end);
                }
            }
            if let Some(chunk) = emit {
                if !chunk.is_empty() {
                    me.sent += chunk.len() as u64;
                    return std::task::Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                continue;
            }
            if let Some(end) = head_closed {
                if sent < end {
                    // 这一段没交完就断了：记缺口，本轮到此为止，外层补发后续上。
                    me.segs.pop_front();
                    me.gap = Some(end);
                    return std::task::Poll::Ready(None);
                }
                me.segs.pop_front();
                continue;
            }
            // 2) 队首还没货：把其余段各推一轮（它们的数据先进各自缓冲），
            //    只要有进展就回头再看队首；全体没动静才是真的 Pending。
            if me.fill_all(cx) {
                continue;
            }
            return std::task::Poll::Pending;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/merge.rs"]
mod tests;
