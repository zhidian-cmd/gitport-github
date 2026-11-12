//! 纯直连多段的不变量：准入只认静态 CDN、URL 与凭据头原样保留、段边界严格、
//! 合并后的字节与单流逐字节一致。这些是「图会不会花 / 请求会不会被改坏」的底线。
use super::{
    is_split_host, seg_count, skip_request_header, skip_response_header, SegmentedBody, Tpl,
    MAX_SEGS, MIN_SPLIT_BYTES,
};
use crate::server::mitm::merge::{content_range_end, content_range_start, content_range_total};
use crate::server::protocol::{self, BoxBody};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

fn tpl() -> Tpl {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("bench/1.0"));
    headers.insert("host", HeaderValue::from_static("raw.githubusercontent.com"));
    headers.insert("cookie", HeaderValue::from_static("user_session=SECRET"));
    headers.insert("authorization", HeaderValue::from_static("Bearer SECRET"));
    headers.insert("proxy-authorization", HeaderValue::from_static("Basic SECRET"));
    headers.insert("if-none-match", HeaderValue::from_static("\"etag\""));
    headers.insert("if-range", HeaderValue::from_static("\"etag\""));
    headers.insert("accept-encoding", HeaderValue::from_static("gzip"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    headers.insert("range", HeaderValue::from_static("bytes=9-9"));
    Tpl {
        method: Method::GET,
        uri: "/o/r/main/assets/big.png".parse().unwrap(),
        headers,
    }
}

#[test]
fn session_hosts_never_enter_direct_split() {
    // README 的 /o/r/raw/... 第一跳在 github.com 上，是 302；会话域本就不在静态
    // 资源 CDN 白名单里，不会进纯直连切片。
    for h in ["github.com", "api.github.com", "objects.githubusercontent.com"] {
        assert!(!is_split_host(h), "{h} 不该进纯直连切片");
    }
    assert!(!is_split_host("GitHub.com"));
}

#[test]
fn readme_image_cdns_are_allowed() {
    for h in [
        "raw.githubusercontent.com",
        "user-images.githubusercontent.com",
        "private-user-images.githubusercontent.com",
        "media.githubusercontent.com",
        "camo.githubusercontent.com",
        "gist.githubusercontent.com",
        "avatars.githubusercontent.com",
        "github.githubassets.com",
        "RAW.GitHubUserContent.com",
    ] {
        assert!(is_split_host(h), "{h} 应该是静态资源落点");
    }
}

#[test]
fn segment_request_keeps_credentials_and_sets_exact_range() {
    let req = tpl().build(262_144, 524_288).expect("构造段请求");
    assert_eq!(req.method(), Method::GET);
    assert_eq!(
        req.headers().get("range").unwrap(),
        "bytes=262144-524287",
        "Range 是半开区间 [s,e) → s-(e-1)"
    );
    // URL 与凭据头一字不改：签名可能在 query 里，Authorization 也可能是取图凭据，
    // 剥掉只会把请求改坏（403 / 签名校验失败），不是更安全。
    assert_eq!(req.headers().get("cookie").unwrap(), "user_session=SECRET");
    assert_eq!(req.headers().get("authorization").unwrap(), "Bearer SECRET");
    assert_eq!(
        req.headers().get("proxy-authorization").unwrap(),
        "Basic SECRET"
    );
    // 这几类会改变段语义或属于逐跳头，必须剥掉。
    for k in ["if-none-match", "if-range", "accept-encoding", "connection"] {
        assert!(req.headers().get(k).is_none(), "{k} 不该被复制进段请求");
    }
    assert_eq!(req.headers().get("user-agent").unwrap(), "bench/1.0");
    assert_eq!(
        req.headers().get("host").unwrap(),
        "raw.githubusercontent.com"
    );
}

#[test]
fn signed_query_survives_segment_template() {
    // 带签名 query 的 URL 进段模板后一个字都不能丢，凭据头同样保留。
    let mut t = tpl();
    t.uri =
        "/o/r/main/assets/big.png?jwt=eyJhbGciOiJIUzI1NiJ9&sig=deadbeef&X-Amz-Credential=AKIA"
            .parse()
            .unwrap();
    let req = t.build(0, 1).expect("构造段请求");
    assert_eq!(
        req.uri().path_and_query().unwrap().as_str(),
        "/o/r/main/assets/big.png?jwt=eyJhbGciOiJIUzI1NiJ9&sig=deadbeef&X-Amz-Credential=AKIA"
    );
    assert_eq!(req.headers().get("cookie").unwrap(), "user_session=SECRET");
    assert_eq!(req.headers().get("range").unwrap(), "bytes=0-0");
}

#[test]
fn original_range_header_is_replaced_not_stacked() {
    let req = tpl().build(0, 1).unwrap();
    let ranges: Vec<_> = req.headers().get_all("range").iter().collect();
    assert_eq!(ranges.len(), 1, "原始 Range 必须被替换，不能叠成多区间");
    assert_eq!(ranges[0], "bytes=0-0");
}

#[test]
fn seg_count_scales_with_size_and_is_capped() {
    assert_eq!(seg_count(MIN_SPLIT_BYTES), 4);
    assert_eq!(seg_count(1024 * 1024), 5);
    assert_eq!(seg_count(1_608_296), 8);
    assert_eq!(seg_count(64 * 1024 * 1024), MAX_SEGS);
}

#[test]
fn eight_segments_cover_the_whole_file_without_gap_or_overlap() {
    // 实测那张 1.6MB README 截图：段必须零重叠零缝，错一个字节图片就花。
    let total = 1_608_296u64;
    let segs = crate::server::mitm::merge::split_even(0, total, seg_count(total));
    assert_eq!(segs.len(), 8);
    assert_eq!(segs.first().unwrap().0, 0);
    assert_eq!(segs.last().unwrap().1, total);
    for w in segs.windows(2) {
        assert_eq!(w[0].1, w[1].0, "相邻段之间不能有缝或重叠");
    }
    assert_eq!(segs.iter().map(|(s, e)| e - s).sum::<u64>(), total);
    for (s, e) in &segs {
        let req = tpl().build(*s, *e).unwrap();
        assert_eq!(
            req.headers().get("range").unwrap(),
            &format!("bytes={}-{}", s, e - 1),
            "每段的 Range 必须严格指向自己的边界"
        );
    }
}

#[test]
fn range_helpers_parse_206_headers() {
    assert_eq!(
        content_range_total(Some("bytes 0-0/1608296")),
        Some(1_608_296)
    );
    assert_eq!(content_range_total(Some("bytes 0-0/*")), None);
    assert_eq!(content_range_total(None), None);
    assert_eq!(
        content_range_start(Some("bytes 262144-524287/1608296")),
        Some(262_144)
    );
    assert_eq!(content_range_start(Some("bytes 0-0/*")), Some(0));
    assert_eq!(
        content_range_end(Some("bytes 262144-524287/1608296")),
        Some(524_287)
    );
    assert_eq!(content_range_end(Some("bytes=0-0/*")), Some(0));
    assert_eq!(content_range_end(None), None);
}

#[test]
fn hop_by_hop_and_range_headers_are_not_carried_to_client() {
    for k in ["content-range", "content-length", "transfer-encoding", "connection", "content-encoding"] {
        assert!(skip_response_header(k), "{k} 必须剥掉");
    }
    assert!(!skip_response_header("content-type"), "图片 content-type 必须保留");
    assert!(!skip_response_header("etag"));
    assert!(!skip_request_header("cookie"));
    assert!(!skip_request_header("authorization"));
    assert!(!skip_request_header("proxy-authorization"));
    assert!(skip_request_header("if-none-match"));
    assert!(skip_request_header("if-range"));
    assert!(!skip_request_header("user-agent"));
}

#[tokio::test]
async fn segmented_body_delivers_exact_bytes_in_order() {
    let parts: Vec<Bytes> = (0u8..6).map(|i| Bytes::from(vec![i; 64])).collect();
    let entries: Vec<(BoxBody, usize)> = parts
        .iter()
        .map(|b| (protocol::full_body(b.clone()), b.len()))
        .collect();
    let total: u64 = parts.iter().map(|b| b.len() as u64).sum();
    let got = BodyExt::collect(SegmentedBody::new(entries, total))
        .await
        .expect("合并不能报错")
        .to_bytes();
    let expect: Vec<u8> = parts.iter().flat_map(|b| b.iter().copied()).collect();
    assert_eq!(got.as_ref(), expect.as_slice(), "合并后必须与原文件逐字节一致");
}

#[tokio::test]
async fn segmented_body_rejects_short_segment() {
    // 段提前 EOF 而且字节不够：宁可报错让客户端重取，也不静默交一张缺字节的花图。
    let entries = vec![(protocol::full_body(Bytes::from(vec![7u8; 10])), 64usize)];
    assert!(
        BodyExt::collect(SegmentedBody::new(entries, 64)).await.is_err(),
        "短段必须暴露成错误"
    );
}

#[tokio::test]
async fn segmented_body_stops_at_declared_total() {
    // 上游多给的尾巴不能溢出 content-length。
    let entries = vec![(protocol::full_body(Bytes::from(vec![3u8; 100])), 100usize)];
    let got = BodyExt::collect(SegmentedBody::new(entries, 40))
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(got.len(), 40);
    assert!(got.iter().all(|b| *b == 3));
}

/// 先吐 prefix 字节然后永远 Pending 的体：模拟直连段拉了一半卡死。
struct StallBody {
    prefix: Bytes,
    sent: bool,
}

impl hyper::body::Body for StallBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.sent {
            return Poll::Pending;
        }
        self.sent = true;
        Poll::Ready(Some(Ok(Frame::data(self.prefix.clone()))))
    }
}

/// 5s 界拨到 0、救援链为空：直连段不得被判死——标记 no_rescue 后继续骑直连流
/// （回归：冻结后救援必败曾把能自愈的停滞毁成整图错误）。
#[tokio::test]
async fn empty_rescue_chain_never_kills_stalled_segment() {
    use super::{RescueCtx, MediaKind};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let entries = vec![(
        BoxBody::new(StallBody {
            prefix: Bytes::from_static(b"abcdef"),
            sent: false,
        }),
        30usize,
        0u64,
        false,
    )];
    let mut body = SegmentedBody::build(
        entries,
        30,
        Some(RescueCtx {
            tpl: tpl(),
            kind: MediaKind::Image,
            chain: Vec::new(), // 未配置救援链
            host: "raw.example.com".to_string(),
            log: Arc::new(|_| {}),
        }),
        Instant::now(),
        Duration::ZERO,
    );
    let mut delivered = 0usize;
    let mut err = false;
    for _ in 0..5 {
        match tokio::time::timeout(
            Duration::from_millis(50),
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
        )
        .await
        {
            Ok(Some(Ok(frame))) => delivered += frame.into_data().unwrap().len(),
            Ok(Some(Err(_))) => {
                err = true;
                break;
            }
            Ok(None) | Err(_) => {} // Pending：直连流挂着等数据，正是期望
        }
    }
    assert!(!err, "空链不许把停滞段判死");
    assert_eq!(delivered, 6, "只交付直连已到的字节");
    assert!(body.segs[0].no_rescue, "空链应标记不可救援并解冻");
}

/// 救援换体算术：直连交付的连续前缀 + 镜像续传 = 与整文件逐字节一致（图会不会花的核心）。
#[tokio::test]
async fn rescue_swap_continues_byte_stream() {
    use super::{RescueCtx, MediaKind};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let entries = vec![(
        BoxBody::new(StallBody {
            prefix: Bytes::from_static(b"abcdef"),
            sent: false,
        }),
        30usize,
        0u64,
        false,
    )];
    let mut body = SegmentedBody::build(
        entries,
        30,
        Some(RescueCtx {
            tpl: tpl(),
            kind: MediaKind::Image,
            chain: vec!["https://unused.example.com".to_string()],
            host: "raw.example.com".to_string(),
            log: Arc::new(|_| {}),
        }),
        Instant::now(),
        Duration::MAX, // 不自动冻结：换体由测试手动驱动
    );
    // 先收直连的 6 字节前缀。StallBody 只吐这一帧、之后永久 Pending 且不注册唤醒，
    // 所以只能取一次：连 poll 第二次会永远等下去（本测试曾因此挂死）。
    let mut got: Vec<u8> = Vec::new();
    match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        Some(Ok(f)) => got.extend_from_slice(f.data_ref().unwrap()),
        x => panic!("首帧必须是直连数据: {:?}", x.map(|r| r.is_err())),
    }
    assert_eq!(got, b"abcdef");
    // 模拟救援成功：镜像从 6 续传到 30（install_rescue 的算术：期望 = 30-6 = 24）。
    let rest: Vec<u8> = (6u8..30).map(|i| b'a' + i % 26).collect();
    body.segs[0].install_rescue(BoxBody::new(protocol::full_body(Bytes::from(rest.clone()))), 6);
    assert_eq!(body.segs[0].expected, 24, "期望字节从续传点重算");
    // 续传体接着交付，拼起来与整文件逐字节一致。
    let tail = BodyExt::collect(body)
        .await
        .expect("换体后不许报错")
        .to_bytes();
    got.extend_from_slice(&tail);
    let whole = [b"abcdef".as_slice(), rest.as_slice()].concat();
    assert_eq!(got, whole, "前缀 + 续传必须逐字节还原整文件");
}

#[test]
fn media_kind_routes_to_its_chain() {
    use super::MediaKind;
    assert_eq!(
        MediaKind::Image.chain("avatars.githubusercontent.com"),
        crate::pool::MEDIA_IMAGE_CHAIN
    );
    assert_eq!(
        MediaKind::Video.chain("avatars.githubusercontent.com"),
        crate::pool::MEDIA_VIDEO_CHAIN
    );
    // 脚本段走 host 自己的镜像链：githubassets 的 worker 镜像就在自己的链里。
    assert_eq!(
        MediaKind::Script.chain("github.githubassets.com"),
        "github.githubassets.com"
    );
    assert_eq!(
        MediaKind::of_content_type(Some("video/mp4")),
        Some(MediaKind::Video)
    );
    assert_eq!(
        MediaKind::of_content_type(Some("image/png")),
        Some(MediaKind::Image)
    );
    assert_eq!(
        MediaKind::of_content_type(Some("application/javascript")),
        Some(MediaKind::Script)
    );
    assert_eq!(
        MediaKind::of_content_type(Some("text/css")),
        Some(MediaKind::Script)
    );
    assert_eq!(MediaKind::of_content_type(Some("text/html")), None);
    assert_eq!(MediaKind::of_content_type(None), None);
}

#[tokio::test]
async fn segmented_body_rejects_overlong_segment() {
    // 上游给的字节超过本段声明长度：报错重取，别让多出来的尾巴吃掉后面段的预算。
    let entries = vec![(protocol::full_body(Bytes::from(vec![9u8; 100])), 64usize)];
    assert!(
        BodyExt::collect(SegmentedBody::new(entries, 64)).await.is_err(),
        "超长段必须暴露成错误"
    );
}
