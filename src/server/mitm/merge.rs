//! 按历史比例切分: 无 Range / 单字节试探片(下载器首片探路)的请求命中大文件
//! 链时, 代理替下载器并发——按镜像速度比例把文件切成 N 段, 各镜拉自己那段,
//! MergeBody 按预划边界顺序泵, 下载器只见一条连续字节河。每段流速即测速:
//! 交分冻结 ECT, 小片不足 100ms 照交(字节/时间都是实数)。

use super::BoxBody;
use bytes::Bytes;
use hyper::body::Frame;

/// 参与切分的最大段数(防浪涌; 段越多首字节延迟越受最慢段牵制)。
pub(super) const MAX_SEGMENTS: usize = 4;

/// 单字节试探片(bytes=N-N)或无 Range → 可切分。
pub(super) fn splittable_range(range: Option<&str>) -> bool {
    let Some(r) = range else {
        return true; // 无 Range: 浏览器直下/首请求
    };
    let spec = match r.trim().strip_prefix("bytes=") {
        Some(s) => s,
        None => return false,
    };
    let first = spec.split(',').next().unwrap_or("").trim();
    match first.split_once('-') {
        Some((a, b)) => a.trim() == b.trim() && !a.trim().is_empty(), // N-N 单字节
        None => false,
    }
}

/// 按速度比例切 [0, total) 为 n 段; 返回 (start, end) 列表, 相邻共享边界,
/// 零重叠零缝。速度全 0 → 均分。n 先收敛到 MAX_SEGMENTS 与 speeds.len()。
pub(super) fn split_by_speed(total: u64, speeds: &[u64], n: usize) -> Vec<(u64, u64)> {
    let n = n.clamp(1, MAX_SEGMENTS.min(speeds.len().max(1)));
    let speeds: Vec<u64> = speeds.iter().take(n).copied().collect();
    let sum: u64 = speeds.iter().sum();
    let mut bounds: Vec<u64> = Vec::with_capacity(n + 1);
    bounds.push(0);
    if sum == 0 {
        for i in 1..n {
            bounds.push(total * i as u64 / n as u64);
        }
    } else {
        let mut acc: u128 = 0;
        for i in 1..n {
            acc += speeds[i - 1] as u128;
            let b = (acc * total as u128 / sum as u128) as u64;
            bounds.push(b.clamp(bounds[i - 1], total));
        }
    }
    bounds.push(total);
    (0..n)
        .map(|i| (bounds[i], bounds[i + 1]))
        .filter(|(s, e)| e > s) // 零长段丢弃(比例悬殊/total 小)
        .collect()
}

pub(super) struct MergeBody {
    /// 各段 (段终点绝对偏移, 段流)。顺序 = 边界序。
    segs: std::collections::VecDeque<(u64, BoxBody)>,
    /// 交付线(已透传给下载器的绝对偏移)。
    sent: u64,
    /// 缺口: 当前段早断/出错时的段终点。由外层流内联发起补救后 feed_rescue。
    /// None = 无缺口。poll_frame 见缺口即 Ready(None) 结束本轮(绝不 Pending
    /// 等外部——无人唤醒会死锁)。
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

    /// 补救流接管: 从当前交付线续到缺口终点(缺口已由外层 take)。
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
            match std::pin::Pin::new(body).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(f))) => {
                    if let Some(d) = f.data_ref() {
                        me.sent += d.len() as u64;
                    }
                    return std::task::Poll::Ready(Some(Ok(f)));
                }
                std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                    let end = *seg_end;
                    me.segs.pop_front();
                    if me.sent < end {
                        me.gap = Some(end);
                        // 本轮到此为止: 缺口由外层流补救后 feed_rescue 再续。
                        return std::task::Poll::Ready(None);
                    }
                    // 交付线已过段终点(边界吻合): 继续下一段。
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splittable_detection() {
        assert!(splittable_range(None));
        assert!(splittable_range(Some("bytes=123-123")));
        assert!(!splittable_range(Some("bytes=0-135132133")));
        assert!(!splittable_range(Some("bytes=100-")));
        assert!(!splittable_range(Some("bytes=0-99, 200-299")));
    }

    #[test]
    fn split_proportional_bounds() {
        // 12:6 速度比 → 0.9GB 切成 600MB + 300MB。
        let segs = split_by_speed(900 * 1024 * 1024, &[12 * 1024 * 1024, 6 * 1024 * 1024], 2);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].0, 0);
        assert_eq!(segs[0].1, 600 * 1024 * 1024);
        assert_eq!(segs[1].0, 600 * 1024 * 1024);
        assert_eq!(segs[1].1, 900 * 1024 * 1024);
        // 相邻共享边界, 零缝。
        for w in segs.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
    }

    #[test]
    fn split_equal_when_no_speeds() {
        let segs = split_by_speed(900, &[0, 0], 2);
        assert_eq!(segs, vec![(0, 450), (450, 900)]);
    }

    #[test]
    fn split_caps_and_drops_zero_len() {
        // 4 镜但只给 2 个速度 → 2 段。
        let segs = split_by_speed(1000, &[1, 1], 4);
        assert_eq!(segs, vec![(0, 500), (500, 1000)]);
        // 比例悬殊 → 零长段被丢弃, 段数收缩。
        let segs = split_by_speed(3, &[1000, 1, 1], 3);
        assert!(segs.iter().all(|(s, e)| e > s));
        let covered: u64 = segs.iter().map(|(s, e)| e - s).sum();
        assert_eq!(covered, 3, "切分必须覆盖全区间");
    }

    /// MergeBody 顺序泵(poll 驱动, 带内联补救循环——与生产 unfold 同构):
    /// 段 1 供完供段 2; 段早断登记缺口, 补救流接管后续到边界。
    #[tokio::test]
    async fn merge_pumps_and_rescues() {
        let seg = |data: &'static [u8]| -> BoxBody {
            BoxBody::new(http_body_util::StreamBody::new(futures_util::stream::iter(
                vec![Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(data)))],
            )))
        };
        // 段 1 [0..6) 只供 2B 就 EOF(缺口 [2..6)); 段 2 [6..10) 完整。
        let mut m = MergeBody::new(vec![(6, seg(b"AA")), (10, seg(b"BBBB"))]);
        let mut out: Vec<u8> = Vec::new();
        loop {
            let poll = std::future::poll_fn(|cx| {
                hyper::body::Body::poll_frame(std::pin::Pin::new(&mut m), cx)
            })
            .await;
            match poll {
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        out.extend_from_slice(d);
                    }
                }
                Some(Err(e)) => panic!("不应出错: {e}"),
                None => {
                    match m.gap.take() {
                        Some(gap_end) => {
                            assert_eq!(m.sent(), 2, "缺口前交付线: {:?}", out);
                            // 内联补救: 补 [2..6), 4B。
                            m.feed_rescue(gap_end, seg(b"CCCC"));
                        }
                        None => break, // 真 EOS
                    }
                }
            }
        }
        assert_eq!(out, b"AACCCCBBBB", "补救段续到边界后接段 2: {:?}", out);
        assert_eq!(m.sent(), 10);
    }
}
