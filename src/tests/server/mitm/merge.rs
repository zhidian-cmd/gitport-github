use super::*;
use std::time::Duration;

/// 测试段：四元组补成生产六元组（owner/ramp 默认 0，普通合并测试用不到）。
fn t(s: u64, e: u64, at: Instant, b: BoxBody) -> (u64, u64, Instant, BoxBody, String, u64) {
    (s, e, at, b, "test".to_string(), 0)
}

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

/// 给段造一个"首帧在 now−1s、已收 got B"的速率样本，供判据测试用。
fn with_rate(m: &mut MergeBody, start: u64, got: u64, now: Instant) {
    let s = m.segs.get_mut(&start).unwrap();
    s.first_at = Some(now - Duration::from_secs(1));
    s.begin = now - Duration::from_secs(1);
    s.got = got;
    s.recent.push_back((now - Duration::from_secs(1), 0));
    s.last_poll = now;
}

/// 顺序泵：段 1 供完接段 2；段 1 早断登记缺口，补发流续到边界再接段 2。
#[test]
fn merge_pumps_and_rescues() {
    let now = Instant::now();
    // 段 1 [0..6) 只供 2B 就 EOF（缺口 [2..6)）；段 2 [6..10) 完整。
    let mut m = MergeBody::new(
        vec![t(0, 6, now, seg(b"AA")), t(6, 10, now, seg(b"BBBB"))],
        10,
    );
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "缺口在，交付不可能结束");
    assert_eq!(out, b"AA");
    assert_eq!(m.take_fill(), Some((2, 6)), "缺口 [2..6) 排进补发");
    m.feed(2, 6, now, seg(b"CCCC"), "test".into(), 0);
    assert!(drain(&mut m, &mut out), "补上后应走完");
    assert_eq!(out, b"AACCCCBBBB");
    assert_eq!(m.sent(), 10);
}

/// 九段必须并发读：队首卡住时，后面的段也要被推、数据进各自缓冲（旧实现只 poll 队首，排队的段在队列里烂掉，轮到它们时只剩一帧就断）。
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
            t(0, 4, now, BoxBody::new(Stuck(stuck_polls.clone()))),
            t(
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
        vec![t(0, 4, now, seg(b"AAAA")), t(4, 8, now, seg(b"BBBB"))],
        8,
    );
    let mut out = Vec::new();
    assert!(drain(&mut m, &mut out), "不该有缺口");
    assert!(m.fill.is_empty(), "边界吻合不该排补发");
    assert_eq!(out, b"AAAABBBB");
}

/// 上游多给的尾巴不能溢出声明总长：交付线到 total 即收，多余字节丢弃（直连切片搬来的回归钉子）。
#[test]
fn merge_stops_at_declared_total() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 40, now, seg(&[3u8; 100]))], 40);
    let mut out = Vec::new();
    assert!(drain(&mut m, &mut out));
    assert_eq!(out.len(), 40);
    assert!(out.iter().all(|&b| b == 3));
}

/// 让位：父段边界一缩，交到新边界就放手，尾巴原样排给下一条流；多收到的字节必须丢掉，不能当成已交付——否则接手方会重下一遍。
#[test]
fn cut_shrinks_boundary_and_hands_off_tail() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 100, now, seg(&[b'A'; 100]))], 100);
    let cut = m.cut(0, 40).expect("应能切");
    assert_eq!(cut, (40, 100));
    assert_eq!(m.take_fill(), Some((40, 100)));
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "尾巴还没人接");
    assert_eq!(out.len(), 40, "父流交到新边界就停");
    assert!(out.iter().all(|&b| b == b'A'));
    m.feed(40, 100, now, seg(&[b'C'; 60]), "test".into(), 0);
    assert!(drain(&mut m, &mut out));
    assert_eq!(out.len(), 100);
    assert!(out[40..].iter().all(|&b| b == b'C'), "尾部必须来自接手的流");
}

/// 整段让出：cut 到 pos 时把 [pos, end) 全部排补发，父段只剩已收部分。
#[test]
fn cut_to_pos_hands_off_whole_remaining() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 100, now, stalled(b"AAAA"))], 100);
    with_rate(&mut m, 0, 40, now); // pos=40, remaining=60
    let cut = m.cut(0, 40).expect("切到 pos 应允许");
    assert_eq!(cut, (40, 100));
    assert_eq!(m.segs.get(&0).unwrap().end, 40, "父段只剩已收那截");
    assert_eq!(m.take_fill(), Some((40, 100)), "整段剩余全排补发");
}

/// 停滞只收自己没收到的那截，缓冲里的字节一个都不丢。
#[test]
fn reap_keeps_received_bytes() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 10, now, stalled(b"AAAA"))], 10);
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
    m.feed(4, 10, now, seg(b"BBBBBB"), "test".into(), 0);
    assert!(drain(&mut m, &mut out));
    assert_eq!(out, b"AAAABBBBBB");
}

/// 两段 fixture：慢段 [0,1M) v=100k/s（R=900k），快段 [1M,2M) v=500k/s（最快、保留）。
/// P 取最快段那家的 ramp（fast_ramp）——判据用接手方爬坡，不用被切段自己的。
fn rebalance_two_seg_fixture(now: Instant, fast_ramp: u64) -> MergeBody {
    let mut m = MergeBody::new(
        vec![
            t(0, 1_000_000, now, stalled(b"")),
            t(1_000_000, 2_000_000, now, stalled(b"")),
        ],
        2_000_000,
    );
    with_rate(&mut m, 0, 100_000, now); // 慢：v=100k/s, R=900k
    with_rate(&mut m, 1_000_000, 500_000, now); // 快：v=500k/s（最快）
    m.segs.get_mut(&1_000_000).unwrap().ramp = fast_ramp;
    m
}

#[test]
fn rebalance_cuts_partial_tail_by_formula() {
    let now = Instant::now();
    let mut m = rebalance_two_seg_fixture(now, 0); // P=0
    // C = 900000 × 500000/(500000+100000) = 750000；留 150000 原地跑。
    let moved = m.rebalance(now);
    assert_eq!(moved, 750_000, "按公式切部分尾巴，不是整段");
    assert_eq!(m.segs.get(&0).unwrap().end, 250_000, "只缩到切点，留 150KB 原地跑");
    assert_eq!(m.segs.get(&1_000_000).unwrap().end, 2_000_000, "最快段保留不切");
    assert_eq!(m.take_fill(), Some((250_000, 1_000_000)));
    assert_eq!(m.last_cut_owner.as_deref(), Some("test"));
}

#[test]
fn rebalance_kept_and_cut_finish_together() {
    let now = Instant::now();
    let mut m = rebalance_two_seg_fixture(now, 0);
    let moved = m.rebalance(now);
    let (kept, kept_ms, cut, cut_ms) = m.last_cut.unwrap();
    assert_eq!(kept, 150_000);
    assert_eq!(cut, moved);
    // 留 150k 按 100k/s = 1500ms；切 750k 按 500k/s = 1500ms。
    assert_eq!(kept_ms, 1_500, "留着原地跑 1.5s");
    assert_eq!(cut_ms, 1_500, "切走的交快流也 1.5s——同时完成不造拖尾");
}

#[test]
fn rebalance_spares_when_keep_not_longer_than_ramp() {
    let now = Instant::now();
    // 最快段 ramp=20s ≥ 本段传完 9s → P·V=2,000,000 > R=900,000 → C≤0 不切。
    let mut m = rebalance_two_seg_fixture(now, 20_000);
    assert_eq!(m.rebalance(now), 0, "预计完成不比爬坡久，切 0");
    assert!(m.fill.is_empty());
}

/// P 取最快段那家的 ramp，不是被切段自己的——慢段 ramp 再大也不影响。
#[test]
fn rebalance_p_uses_fastest_owners_ramp() {
    let now = Instant::now();
    let mut m = rebalance_two_seg_fixture(now, 0);
    m.segs.get_mut(&0).unwrap().ramp = 20_000; // 被切段 ramp 很大
    // 若误用慢段 ramp 会判 0；用最快段 ramp=0 → 照切 750000。
    assert_eq!(m.rebalance(now), 750_000, "P 取最快段 ramp=0，不受慢段 ramp 影响");
}

#[test]
fn rebalance_ignores_seg_without_first_frame() {
    let now = Instant::now();
    // 有 bytes 但没首帧样本 → 没速率，不动刀、也不参与最快比较。
    let mut m = MergeBody::new(vec![t(0, 1_000_000, now, stalled(b""))], 1_000_000);
    m.segs.get_mut(&0).unwrap().got = 100_000;
    m.segs.get_mut(&0).unwrap().last_poll = now;
    assert_eq!(m.rebalance(now), 0, "没首帧不动刀");
    assert!(m.fill.is_empty());
}

#[test]
fn rebalance_cuts_small_tail_when_slow_enough() {
    let now = Instant::now();
    let mut m = MergeBody::new(
        vec![
            t(0, 5_000, now, stalled(b"")),
            t(5_000, 20_000, now, stalled(b"")),
        ],
        20_000,
    );
    with_rate(&mut m, 0, 1_000, now); // 慢：v=1000B/s, R=4000
    with_rate(&mut m, 5_000, 10_000, now); // 快陪衬：v=10k/s（最快）
    // C = 4000 × 10000/11000 = 3636。
    assert_eq!(m.rebalance(now), 3_636, "小尾巴按公式切，无字节下限");
}

#[test]
fn rebalance_only_cuts_once() {
    let now = Instant::now();
    let mut m = rebalance_two_seg_fixture(now, 0);
    assert_eq!(m.rebalance(now), 750_000, "第一轮切");
    assert_eq!(m.take_fill(), Some((250_000, 1_000_000)), "尾巴排补发");
    m.feed(2_000_000, 3_000_000, now, stalled(b""), "test".into(), 0);
    with_rate(&mut m, 2_000_000, 100_000, now);
    assert_eq!(m.rebalance(now), 0, "只切一次，之后不再动刀");
    assert!(m.fill.is_empty(), "第二轮没有再排队尾巴");
}

/// 最快段即使公式判切也保留不切（本就满速，切下来重派反而亏）；慢段照切。
#[test]
fn rebalance_spares_fastest_even_if_worth_cutting() {
    let now = Instant::now();
    let mut m = MergeBody::new(
        vec![
            t(0, 20_000_000, now, stalled(b"")),
            t(20_000_000, 30_000_000, now, stalled(b"")),
        ],
        30_000_000,
    );
    with_rate(&mut m, 0, 10_000_000, now); // A 快：10MB/s（最快）
    with_rate(&mut m, 20_000_000, 1_000_000, now); // B 慢：1MB/s, R=9M
    // B: C = 9000000 × 10000000/11000000 = 8181818
    let moved = m.rebalance(now);
    assert_eq!(moved, 8_181_818, "只切慢段 B 的部分尾巴");
    assert_eq!(m.segs.get(&0).unwrap().end, 20_000_000, "最快段 A 保留不切");
    assert_eq!(m.segs.get(&20_000_000).unwrap().end, 30_000_000 - 8_181_818);
}

/// 并列最快的两段都不切。
#[test]
fn rebalance_spares_all_when_tied_fastest() {
    let now = Instant::now();
    let mut m = MergeBody::new(
        vec![
            t(0, 2_000_000, now, stalled(b"")),
            t(2_000_000, 4_000_000, now, stalled(b"")),
        ],
        4_000_000,
    );
    with_rate(&mut m, 0, 1_000_000, now); // 同速 1MB/s，ramp 0 → 公式都判切
    with_rate(&mut m, 2_000_000, 1_000_000, now);
    assert_eq!(m.rebalance(now), 0, "并列最快都保留");
    assert!(m.fill.is_empty());
}

/// 单段即全场最快 → 永不切自己。
#[test]
fn rebalance_single_seg_never_cuts() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 1_000_000, now, stalled(b""))], 1_000_000);
    with_rate(&mut m, 0, 100_000, now); // ramp 0 → 公式判切
    assert_eq!(m.rebalance(now), 0, "单段是最快，不切自己");
    assert!(m.fill.is_empty());
}

/// 快段在体检点之前下完也要当基准：它冻结的速率进 fastest 比较后，慢段按它算切量；
/// 否则只剩活段的旧速度，切量偏小，快段白跑。done 段本身不进 cands、不被切。
#[test]
fn rebalance_done_segment_rate_becomes_baseline() {
    let now = Instant::now();
    let mut m = MergeBody::new(
        vec![
            t(0, 1_000, now, seg(b"")),
            t(1_000_000, 2_000_000, now, stalled(b"")),
        ],
        2_000_000,
    );
    // A 已正常收尾，冻结 500k/s；B 活着 100k/s、R=900k。
    m.segs.get_mut(&0).unwrap().done = true;
    m.segs.get_mut(&0).unwrap().frozen_rate = Some(500_000.0);
    with_rate(&mut m, 1_000_000, 100_000, now);
    // C = 900000 × 500000/(500000+100000) = 750000。
    assert_eq!(m.rebalance(now), 750_000, "快段冻结速率必须进基准");
    assert_eq!(m.segs.get(&0).unwrap().end, 1_000, "done 段不参与被切");

    // 对照：没有快段基准时，这段自己就是全场最快，不动刀——证明切量确实来自冻结速率。
    let mut alone = MergeBody::new(
        vec![t(1_000_000, 2_000_000, now, stalled(b""))],
        2_000_000,
    );
    with_rate(&mut alone, 1_000_000, 100_000, now);
    assert_eq!(alone.rebalance(now), 0, "无快段基准时单段不切自己");
}

/// 段正常收尾置完成标志：驱动循环据此提前体检，取走即清、不会重复触发。
#[test]
fn segment_completion_raises_done_probe() {
    let now = Instant::now();
    // A 先给 2B 再 EOF，B 留在后面：A 不会被缺口分支从 segs 里移除，能查到冻结值。
    let mut m = MergeBody::new(
        vec![t(0, 2, now, seg(b"AA")), t(2, 10, now, stalled(b""))],
        10,
    );
    assert!(!m.take_done_probe(), "没段收尾不该有信号");
    let mut out = Vec::new();
    assert!(!drain(&mut m, &mut out), "第二段没货，交付不会结束");
    assert_eq!(out, b"AA");
    assert!(m.segs.get(&0).unwrap().done, "段已 EOF 收尾");
    assert!(
        m.segs.get(&0).unwrap().frozen_rate.is_some(),
        "收尾时定格速率，供基准比较"
    );
    assert!(m.take_done_probe(), "完成事件必须置位");
    assert!(!m.take_done_probe(), "取走即清，避免重复触发");
}

/// 近期速率：首帧起算、样本按滑窗折算，无预热门槛。
#[test]
fn recent_rate_prefers_sliding_window() {
    let now = Instant::now();
    let mut s = Seg::new(0, 1 << 20, now, seg(b""), "test".into(), 0);
    assert_eq!(s.rate(now), 0.0, "没首帧 = 没样本 = 0");
    s.on_first_frame(now - Duration::from_secs(2));
    s.got = 1000;
    assert!(
        (s.recent_rate(now) - 500.0).abs() < 1.0,
        "无近期样本退回全片均速(1000B/2s): {}",
        s.recent_rate(now)
    );
    // 滑窗内 1.2s 收 1200B → 1000B/s；全片均速的历史包袱不进判据。
    s.recent
        .push_back((now - Duration::from_millis(1200), 1000));
    s.got = 2200; // 生产里 recent 样本就是 (时刻, got) 快照，末样本恒等于 got
    s.recent.push_back((now, s.got));
    let r = s.recent_rate(now);
    assert!((r - 1000.0).abs() < 1.0, "近期速率应按滑窗折算: {r}");
}

/// 有进展就清零：补发只要下到字节，就不该算进"连续空手"。
#[test]
fn dead_fill_counter_resets_on_progress() {
    let now = Instant::now();
    let mut m = MergeBody::new(vec![t(0, 4, now, seg(b"AAAA"))], 4);
    for _ in 0..MAX_DEAD_FILLS {
        m.dead_fills += 1;
    }
    assert!(m.exhausted());
    let mut out = Vec::new();
    assert!(drain(&mut m, &mut out));
    assert!(!m.exhausted(), "字节流动起来就该清零");
}
