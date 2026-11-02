use super::*;
use std::time::Duration;

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

/// 让位份额：速率反比（3 倍速的帮手拿大头），并扣掉它建连+爬坡期间的空转。
#[test]
fn split_keep_is_rate_proportional() {
    const MB: u64 = 1024 * 1024;
    let keep = split_keep(8 * MB, 1e6, 3e6, SPLIT_SETUP_SECS);
    // 1MB/s 的持有者约保留 (0.5×3MB + 8MB)/4 ≈ 2.37MB，不到一半
    assert!(
        (2 * MB..3 * MB).contains(&keep),
        "持有者只该留一小截，实际 {keep}"
    );
    // 速率相同：各一半（建连成本让持有者略多留）
    let even = split_keep(8 * MB, 2e6, 2e6, SPLIT_SETUP_SECS);
    assert!(even > 4 * MB && even < 5 * MB, "实际 {even}");
    // 永远不能把一段切没
    assert_eq!(split_keep(MIN_PIECE, 1e6, 9e6, SPLIT_SETUP_SECS), MIN_PIECE / 2);
    assert!(split_keep(4 * MIN_PIECE, 1.0, 1000.0, SPLIT_SETUP_SECS) <= 3 * MIN_PIECE);
}

fn seg(data: &'static [u8]) -> BoxBody {
    BoxBody::new(http_body_util::StreamBody::new(futures_util::stream::iter(
        vec![Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(
            data,
        )))],
    )))
}

/// 供 prefix 字节后装死（真停滞，不是 EOF）。
fn stalled(prefix: &'static [u8]) -> BoxBody {
    struct Stalled {
        left: Option<Bytes>,
    }
    impl hyper::body::Body for Stalled {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            let me = self.get_mut();
            match me.left.take() {
                Some(b) => std::task::Poll::Ready(Some(Ok(Frame::data(b)))),
                None => std::task::Poll::Pending,
            }
        }
    }
    BoxBody::new(Stalled {
        left: Some(Bytes::from_static(prefix)),
    })
}

fn poll(
    m: &mut MergeBody,
    cx: &mut std::task::Context<'_>,
) -> std::task::Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
    hyper::body::Body::poll_frame(std::pin::Pin::new(m), cx)
}

/// 拉一次，返回是否已经全部交付。
fn drain(m: &mut MergeBody, out: &mut Vec<u8>) -> bool {
    let waker = futures_util::task::noop_waker_ref();
    let mut cx = std::task::Context::from_waker(waker);
    loop {
        match poll(m, &mut cx) {
            std::task::Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    out.extend_from_slice(d);
                }
            }
            std::task::Poll::Ready(Some(Err(e))) => panic!("不应出错: {e}"),
            std::task::Poll::Ready(None) => return m.sent() >= m.total(),
            std::task::Poll::Pending => return false,
        }
    }
}

/// 顺序泵：段 1 供完接段 2；段 1 早断登记缺口，补发流续到边界再接段 2。
#[test]
fn merge_pumps_and_rescues() {
    let now = Instant::now();
    // 段 1 [0..6) 只供 2B 就 EOF（缺口 [2..6)）；段 2 [6..10) 完整。
    let mut m = MergeBody::new(
        vec![(0, 6, now, seg(b"AA")), (6, 10, now, seg(b"BBBB"))],
        10,
    );
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "缺口在，交付不可能结束");
    assert_eq!(out, b"AA");
    assert_eq!(m.take_fill(), Some((2, 6)), "缺口 [2..6) 排进补发");
    m.feed(2, 6, now, seg(b"CCCC"));
    assert!(drain(&mut m, &mut out), "补上后应走完");
    assert_eq!(out, b"AACCCCBBBB");
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

    let now = Instant::now();
    let stuck_polls = Arc::new(AtomicUsize::new(0));
    let tail_polls = Arc::new(AtomicUsize::new(0));
    let mut m = MergeBody::new(
        vec![
            (0, 4, now, BoxBody::new(Stuck(stuck_polls.clone()))),
            (
                4,
                8,
                now,
                BoxBody::new(Counted {
                    left: Some(Bytes::from_static(b"BBBB")),
                    polls: tail_polls.clone(),
                }),
            ),
        ],
        8,
    );
    let waker = futures_util::task::noop_waker_ref();
    let mut cx = std::task::Context::from_waker(waker);
    let first = poll(&mut m, &mut cx);
    assert!(first.is_pending(), "队首卡住时不可能有交付");
    assert_eq!(m.sent(), 0, "一个字节都不该出去");
    assert!(
        tail_polls.load(Ordering::SeqCst) >= 2,
        "队首卡着的时候，后面那段必须已经被读完（一帧 + EOF），实际只推了 {} 次",
        tail_polls.load(Ordering::SeqCst)
    );
    assert!(stuck_polls.load(Ordering::SeqCst) >= 1, "队首也必须被推过");
}

/// 段边界吻合时直接接下一段，不登记缺口。
#[test]
fn merge_no_gap_when_boundary_aligned() {
    let now = Instant::now();
    let mut m = MergeBody::new(
        vec![(0, 4, now, seg(b"AAAA")), (4, 8, now, seg(b"BBBB"))],
        8,
    );
    let mut out = Vec::new();
    assert!(drain(&mut m, &mut out), "不该有缺口");
    assert!(m.fill.is_empty(), "边界吻合不该排补发");
    assert_eq!(out, b"AAAABBBB");
}

/// 让位：父段边界一缩，交到新边界就放手，尾巴原样排给下一条流。
/// 多收到的字节必须丢掉，不能当成已交付——否则接手方会重下一遍。
#[test]
fn cut_shrinks_boundary_and_hands_off_tail() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![(0, 100, now, seg(&[b'A'; 100]))], 100);
    let cut = m.cut(0, 40, now).expect("应能切");
    assert_eq!(cut, (40, 100));
    assert_eq!(m.take_fill(), Some((40, 100)));
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "尾巴还没人接");
    assert_eq!(out.len(), 40, "父流交到新边界就停");
    assert!(out.iter().all(|&b| b == b'A'));
    m.feed(40, 100, now, seg(&[b'C'; 60]));
    assert!(drain(&mut m, &mut out));
    assert_eq!(out.len(), 100);
    assert!(out[40..].iter().all(|&b| b == b'C'), "尾部必须来自接手的流");
}

/// 停滞只收自己没收到的那截，缓冲里的字节一个都不丢。
#[test]
fn reap_keeps_received_bytes() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![(0, 10, now, stalled(b"AAAA"))], 10);
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "供完 4B 就该停住等");
    assert_eq!(out, b"AAAA");
    assert!(!m.reap_stalled(now), "才刚开始，不该收尸");
    assert!(
        m.reap_stalled(now + Duration::from_millis(STALL_MS + 1)),
        "超时该收尸"
    );
    assert_eq!(m.take_fill(), Some((4, 10)), "只补没收到的那截");
    assert!(!drain(&mut m, &mut out));
    assert_eq!(out, b"AAAA");
    m.feed(4, 10, now, seg(b"BBBBBB"));
    assert!(drain(&mut m, &mut out));
    assert_eq!(out, b"AAAABBBBBB");
}

/// 没有闲连接也能抢：新开一条流要付的建连成本，已经折进收益判据。
#[test]
fn plan_cut_pays_setup_without_idle_connection() {
    let now = Instant::now();
    let slow = 4 * MIN_PIECE;
    let mut m = MergeBody::new(
        vec![
            (0, slow, now - Duration::from_secs(2), stalled(b"")),
            (
                slow,
                8 * MIN_PIECE,
                now - Duration::from_secs(2),
                stalled(b""),
            ),
        ],
        8 * MIN_PIECE,
    );
    // 手工造两条速率样本：一条慢（5KB/s）、一条快（256KB/s）。
    for (k, got) in [(0u64, 10_000u64), (slow, MIN_PIECE)] {
        let s = m.segs.get_mut(&k).unwrap();
        s.got = got;
        s.last_poll = now;
    }
    let cut = m
        .plan_cut(now)
        .expect("收益远大于建连成本，credit=0 也该切");
    assert_eq!(cut.1, slow, "尾巴应到段尾为止");
    assert!(cut.0 > 10_000 && cut.0 < slow, "切点 {cut:?}");
}

/// 两家一样快：谁都不该被抢——抢过来还得付建连，纯亏。
#[test]
fn plan_cut_spares_when_no_faster_peer() {
    let now = Instant::now();
    let half = 4 * MIN_PIECE;
    let mut m = MergeBody::new(
        vec![
            (0, half, now - Duration::from_secs(2), stalled(b"")),
            (
                half,
                8 * MIN_PIECE,
                now - Duration::from_secs(2),
                stalled(b""),
            ),
        ],
        8 * MIN_PIECE,
    );
    for k in [0u64, half] {
        let s = m.segs.get_mut(&k).unwrap();
        s.got = MIN_PIECE;
        s.last_poll = now;
    }
    assert!(m.plan_cut(now).is_none(), "同样快，没有抢的收益");
}

/// 比最快慢就切，但只剩 0.1MB 时抢过去反而更久（要付建连）——这时候不动刀，
/// 是算术不是门槛：remaining/best + 建连 >= remaining/我。
#[test]
fn plan_cut_skips_when_handoff_costs_more() {
    let now = Instant::now();
    let half = 2 * MIN_PIECE;
    let mut m = MergeBody::new(
        vec![
            (0, half, now - Duration::from_secs(2), stalled(b"")),
            (
                half,
                4 * MIN_PIECE,
                now - Duration::from_secs(2),
                stalled(b""),
            ),
        ],
        4 * MIN_PIECE,
    );
    // 慢家 0.95MB/s、快家 1.5MB/s：慢家只剩 0.1MB，抢过去还得付 0.5s 建连，不划算。
    for (k, got) in [(0u64, 1_900_000u64), (half, 3_000_000u64)] {
        let s = m.segs.get_mut(&k).unwrap();
        s.got = got;
        s.last_poll = now;
    }
    assert!(m.plan_cut(now).is_none(), "抢过去更久就不该抢");
}

/// 刀口上限按帮手实测速率折算（≈3 秒的量）：快源被钉死的再平衡上限随速度放开。
#[test]
fn plan_cut_caps_handoff_size() {
    let now = Instant::now();
    let big = 40 * 1024 * 1024;
    let mut m = MergeBody::new(
        vec![
            (0, big / 2, now - Duration::from_secs(2), stalled(b"")),
            (big / 2, big, now - Duration::from_secs(2), stalled(b"")),
        ],
        big,
    );
    // 慢家 0.5MB/s（还剩 19MB）；快家 2MB/s。快家该接走大头。
    for (k, got) in [(0u64, 1_048_576u64), (big / 2, 4 * 1024 * 1024u64)] {
        let s = m.segs.get_mut(&k).unwrap();
        s.got = got;
        s.last_poll = now;
    }
    let (from, to) = m.plan_cut(now).expect("38 秒太久，该抢");
    let handoff = to - from;
    assert!(handoff >= MIN_PIECE, "刀口太小不值一次建连");
    assert!(
        handoff <= handoff_cap(2.0 * 1024.0 * 1024.0),
        "刀口 {handoff} 超过按速折算的封顶"
    );
}

/// 刀口随帮手速率缩放：10MB/s 的快源该拿到比 4MB 旧常数大得多的刀口，
/// 否则快源下完自己的份额后只能以旧常数的龟速捡尾巴，聚合速率上不去。
#[test]
fn handoff_cap_scales_with_helper_speed() {
    assert_eq!(handoff_cap(1024.0), MIN_PIECE, "太小的速率钳在下限");
    assert_eq!(handoff_cap(1e7), 30_000_000, "10MB/s 帮手 ≈ 3s 的量");
    assert_eq!(
        handoff_cap(1e9),
        64 * 1024 * 1024,
        "再快也钳在 64MB，防一次让位掏空整段"
    );
}

/// 近期速率：滑窗有样本按滑窗算，样本不足退回全片均速（短段的全片就是全部真相）。
#[test]
fn recent_rate_prefers_sliding_window() {
    let now = Instant::now();
    let mut s = Seg::new(0, 1 << 20, now, seg(b""));
    s.begin = now - Duration::from_secs(2);
    s.got = 1000;
    assert!(
        (s.recent_rate(now) - 500.0).abs() < 1.0,
        "无近期样本退回全片均速(1000B/2s): {}",
        s.recent_rate(now)
    );
    // 滑窗内 1.2s 收 1200B → 1000B/s；全片均速的历史包袱不进判据。
    s.recent.push_back((now - Duration::from_millis(1200), 1000));
    s.got = 2200; // 生产里 recent 样本就是 (时刻, got) 快照，末样本恒等于 got
    s.recent.push_back((now, s.got));
    let r = s.recent_rate(now);
    assert!((r - 1000.0).abs() < 1.0, "近期速率应按滑窗折算: {r}");
}

/// 有进展就清零：补发只要下到字节，就不该算进"连续空手"。
#[test]
fn dead_fill_counter_resets_on_progress() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![(0, 4, now, seg(b"AAAA"))], 4);
    for _ in 0..MAX_DEAD_FILLS {
        m.fail_fill();
    }
    assert!(m.exhausted());
    let mut out = Vec::new();
    assert!(drain(&mut m, &mut out));
    assert!(!m.exhausted(), "字节流动起来就该清零");
}
