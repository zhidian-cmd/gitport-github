//! 切片合并：一条请求按镜像数平均切段、并发拉，再按边界顺序泵成单条字节河。
//! 段终点一律用相对偏移（相对本次请求区间的起点），交付线与边界同域，不会错位。

use super::protocol::BoxBody;
use bytes::Bytes;
use hyper::body::Frame;
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
pub(super) struct MergeBody {
    /// (段相对终点, 段流)，顺序即边界序。
    segs: VecDeque<(u64, BoxBody)>,
    /// 已交付字节（相对区间起点）。
    sent: u64,
    /// 缺口终点（相对）。外层补发后 feed_rescue 续上。
    pub(super) gap: Option<u64>,
    finished: bool,
}

impl MergeBody {
    pub(super) fn new(segs: Vec<(u64, BoxBody)>) -> Self {
        MergeBody {
            segs: segs.into(),
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
        self.segs.push_front((gap_end, body));
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
            let Some((seg_end, body)) = me.segs.front_mut() else {
                me.finished = true;
                return std::task::Poll::Ready(None);
            };
            let end = *seg_end; // 复制出来，后面好和 me.sent 同时用
            match std::pin::Pin::new(body).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(f))) => {
                    // 段请求带精确 Range，镜像多给的部分必须截掉，否则交付线越过边界。
                    let room = end.saturating_sub(me.sent);
                    return match f.into_data() {
                        Ok(mut d) => {
                            if d.len() as u64 > room {
                                d.truncate(room as usize);
                            }
                            me.sent += d.len() as u64;
                            std::task::Poll::Ready(Some(Ok(Frame::data(d))))
                        }
                        Err(other) => std::task::Poll::Ready(Some(Ok(other))),
                    };
                }
                std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                    me.segs.pop_front();
                    if me.sent < end {
                        me.gap = Some(end);
                        // 本轮到此为止，缺口由外层补发后 feed_rescue 再续。
                        return std::task::Poll::Ready(None);
                    }
                    // 交付线已过段终点：边界吻合，继续下一段。
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/merge.rs"]
mod tests;
