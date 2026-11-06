//! 纯直连多段的不变量：准入只认静态 CDN、子请求不带凭据、段边界严格、
//! 合并后的字节与单流逐字节一致。这些是「图会不会花 / 会不会踩风控」的底线。
use super::{
    is_image_split_host, seg_count, skip_request_header, skip_response_header, SegmentedBody, Tpl,
    MAX_SEGS, MIN_SPLIT_BYTES,
};
use crate::server::mitm::merge::{content_range_end, content_range_start, content_range_total};
use crate::server::protocol::{self, BoxBody};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use http_body_util::BodyExt;

fn tpl() -> Tpl {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("bench/1.0"));
    headers.insert("host", HeaderValue::from_static("raw.githubusercontent.com"));
    headers.insert("cookie", HeaderValue::from_static("user_session=SECRET"));
    headers.insert("authorization", HeaderValue::from_static("Bearer SECRET"));
    headers.insert("if-none-match", HeaderValue::from_static("\"etag\""));
    headers.insert("accept-encoding", HeaderValue::from_static("gzip"));
    headers.insert("range", HeaderValue::from_static("bytes=9-9"));
    Tpl {
        method: Method::GET,
        uri: "/o/r/main/assets/big.png".parse().unwrap(),
        headers,
    }
}

#[test]
fn session_hosts_never_enter_direct_split() {
    // README 的 /o/r/raw/... 第一跳在 github.com 上、带 user_session；切它等于把
    // 同一登录态复制 N 份从多条通道同时发出去，正是上游代码明令禁止的风控特征。
    for h in ["github.com", "api.github.com", "github.githubassets.com", "objects.githubusercontent.com"] {
        assert!(!is_image_split_host(h), "{h} 不该进纯直连切片");
    }
    assert!(!is_image_split_host("GitHub.com"));
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
        "RAW.GitHubUserContent.com",
    ] {
        assert!(is_image_split_host(h), "{h} 应该是 README 图片落点");
    }
}

#[test]
fn segment_request_drops_credentials_and_sets_exact_range() {
    let req = tpl().build(262_144, 524_288).expect("构造段请求");
    assert_eq!(req.method(), Method::GET);
    assert_eq!(
        req.headers().get("range").unwrap(),
        "bytes=262144-524287",
        "Range 是半开区间 [s,e) → s-(e-1)"
    );
    for k in ["cookie", "authorization", "if-none-match", "accept-encoding"] {
        assert!(req.headers().get(k).is_none(), "{k} 不该被复制到每个段");
    }
    assert_eq!(req.headers().get("user-agent").unwrap(), "bench/1.0");
    assert_eq!(
        req.headers().get("host").unwrap(),
        "raw.githubusercontent.com"
    );
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
    assert!(skip_request_header("cookie"));
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

#[tokio::test]
async fn segmented_body_rejects_overlong_segment() {
    // 上游给的字节超过本段声明长度：报错重取，别让多出来的尾巴吃掉后面段的预算。
    let entries = vec![(protocol::full_body(Bytes::from(vec![9u8; 100])), 64usize)];
    assert!(
        BodyExt::collect(SegmentedBody::new(entries, 64)).await.is_err(),
        "超长段必须暴露成错误"
    );
}
