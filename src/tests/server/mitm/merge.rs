use super::*;

/// 平均切必须零缝覆盖整个区间，相邻段共享边界。
#[test]
fn split_even_covers_without_gap() {
    let segs = split_even(0, 1000, 4);
    assert_eq!(segs, vec![(0, 250), (250, 500), (500, 750), (750, 1000)]);
    for w in segs.windows(2) {
        assert_eq!(w[0].1, w[1].0, "相邻段必须共享边界");
    }
}

/// 除不尽时余数归最后一段，总数不能少一个字节。
#[test]
fn split_even_remainder_goes_to_last() {
    let segs = split_even(0, 1000, 3);
    assert_eq!(segs, vec![(0, 333), (333, 666), (666, 1000)]);
    assert_eq!(segs.iter().map(|(s, e)| e - s).sum::<u64>(), 1000);
}

/// 非零起点：切分围绕客户端请求的区间，不回到 0。
#[test]
fn split_even_keeps_base_offset() {
    let segs = split_even(500, 300, 3);
    assert_eq!(segs, vec![(500, 600), (600, 700), (700, 800)]);
}

/// 段数超过字节数时收缩，不允许出现零长段。
#[test]
fn split_even_shrinks_below_byte_count() {
    let segs = split_even(0, 3, 8);
    assert_eq!(segs.len(), 3);
    assert!(segs.iter().all(|(s, e)| e > s));
    assert_eq!(split_even(0, 0, 4), Vec::new(), "零长区间不切");
}

/// Range 解析：闭区间、开区间、多区间、畸形。
#[test]
fn parse_range_shapes() {
    assert_eq!(parse_range(Some("bytes=0-99")), Some((0, Some(99))));
    assert_eq!(parse_range(Some("bytes=100-")), Some((100, None)));
    // 多区间响应是 multipart/byteranges，切分会拼出坏数据：直接不认。
    assert_eq!(parse_range(Some("bytes=0-99,200-299")), None);
    assert_eq!(parse_range(None), None);
    assert_eq!(parse_range(Some("bytes=abc")), None);
    assert_eq!(parse_range(Some("0-99")), None);
}

/// 单字节探片：下载器探路请求，必须从小文件路径走，不进切分。
#[test]
fn probe_range_detection() {
    assert!(is_probe_range(Some("bytes=0-0")));
    assert!(is_probe_range(Some("bytes=1024-1024")));
    assert!(!is_probe_range(Some("bytes=0-99")));
    assert!(!is_probe_range(Some("bytes=0-")));
    assert!(!is_probe_range(None));
}

/// 从 Content-Range 头取文件总长。
#[test]
fn content_range_total_parse() {
    assert_eq!(
        content_range_total(Some("bytes 0-0/2097152000")),
        Some(2097152000)
    );
    assert_eq!(
        content_range_total(Some("bytes 0-524287999/2097152000")),
        Some(2097152000)
    );
    assert_eq!(content_range_total(Some("bytes 0-0/*")), None);
    assert_eq!(content_range_total(None), None);
}

fn seg(data: &'static [u8]) -> BoxBody {
    BoxBody::new(http_body_util::StreamBody::new(
        futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Frame::data(
            Bytes::from_static(data),
        ))]),
    ))
}

/// 顺序泵：段 1 供完接段 2；段 1 早断登记缺口，补发流续到边界再接段 2。
#[tokio::test]
async fn merge_pumps_and_rescues() {
    // 段 1 [0..6) 只供 2B 就 EOF（缺口 [2..6)）；段 2 [6..10) 完整。
    let mut m = MergeBody::new(vec![(6, seg(b"AA")), (10, seg(b"BBBB"))]);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let poll =
            std::future::poll_fn(|cx| hyper::body::Body::poll_frame(std::pin::Pin::new(&mut m), cx))
                .await;
        match poll {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    out.extend_from_slice(d);
                }
            }
            Some(Err(e)) => panic!("不应出错: {e}"),
            None => match m.gap.take() {
                Some(gap_end) => {
                    assert_eq!(m.sent(), 2, "缺口前交付线");
                    m.feed_rescue(gap_end, seg(b"CCCC"));
                }
                None => break,
            },
        }
    }
    assert_eq!(out, b"AACCCCBBBB", "补发段续到边界后接段 2");
    assert_eq!(m.sent(), 10);
}

/// 九段必须并发读：队首卡住时，后面的段也要被推、数据进各自缓冲。
/// 旧实现只 poll 队首，排队的段在队列里烂掉，轮到它们时只剩一帧就断。
#[test]
fn segments_are_read_concurrently() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Stuck(Arc<AtomicUsize>);
    impl hyper::body::Body for Stuck {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Pending
        }
    }

    struct Counted {
        left: Option<Bytes>,
        polls: Arc<AtomicUsize>,
    }
    impl hyper::body::Body for Counted {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            let me = self.get_mut();
            me.polls.fetch_add(1, Ordering::SeqCst);
            match me.left.take() {
                Some(b) => std::task::Poll::Ready(Some(Ok(Frame::data(b)))),
                None => std::task::Poll::Ready(None),
            }
        }
    }

    let stuck_polls = Arc::new(AtomicUsize::new(0));
    let tail_polls = Arc::new(AtomicUsize::new(0));
    let mut m = MergeBody::new(vec![
        (4, BoxBody::new(Stuck(stuck_polls.clone()))),
        (
            8,
            BoxBody::new(Counted {
                left: Some(Bytes::from_static(b"BBBB")),
                polls: tail_polls.clone(),
            }),
        ),
    ]);
    let waker = futures_util::task::noop_waker_ref();
    let mut cx = std::task::Context::from_waker(waker);
    let first = hyper::body::Body::poll_frame(std::pin::Pin::new(&mut m), &mut cx);
    assert!(first.is_pending(), "队首卡住时不可能有交付");
    assert_eq!(m.sent(), 0, "一个字节都不该出去");
    assert!(
        tail_polls.load(Ordering::SeqCst) >= 2,
        "队首卡着的时候，后面那段必须已经被读完（一帧 + EOF），实际只推了 {} 次",
        tail_polls.load(Ordering::SeqCst)
    );
    assert!(
        stuck_polls.load(Ordering::SeqCst) >= 1,
        "队首也必须被推过"
    );
}

/// 段边界吻合时直接接下一段，不登记缺口。
#[tokio::test]
async fn merge_no_gap_when_boundary_aligned() {
    let mut m = MergeBody::new(vec![(4, seg(b"AAAA")), (8, seg(b"BBBB"))]);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let poll =
            std::future::poll_fn(|cx| hyper::body::Body::poll_frame(std::pin::Pin::new(&mut m), cx))
                .await;
        match poll {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    out.extend_from_slice(d);
                }
            }
            Some(Err(e)) => panic!("不应出错: {e}"),
            None => {
                assert!(m.gap.is_none(), "边界吻合不该有缺口");
                break;
            }
        }
    }
    assert_eq!(out, b"AAAABBBB");
}
