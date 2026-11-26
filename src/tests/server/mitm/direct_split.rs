//! 纯直连多段不变量：准入只认静态 CDN、URL 与凭据头原样保留、段边界严格、合并字节与单流逐字节一致。
use super::{
    is_split_host, probe_body_ok, probe_range_ok, seg_count, skip_request_header,
    skip_response_header, Tpl, MAX_SEGS, MIN_SPLIT_BYTES,
};
use crate::server::mitm::merge::{content_range_end, content_range_start, content_range_total};
use http::{HeaderMap, HeaderValue, Method};

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
    // 会话域不在静态 CDN 白名单，不进切片。
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
        "RAW.GitHubUserContent.com",
    ] {
        assert!(is_split_host(h), "{h} 应该是静态资源落点");
    }
    // githubassets JS/CSS 不切片，走单流直连+缓存。
    assert!(
        !is_split_host("github.githubassets.com"),
        "githubassets 不得再进切片"
    );
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
    // URL 与凭据头原样保留。
    assert_eq!(req.headers().get("cookie").unwrap(), "user_session=SECRET");
    assert_eq!(req.headers().get("authorization").unwrap(), "Bearer SECRET");
    assert_eq!(
        req.headers().get("proxy-authorization").unwrap(),
        "Basic SECRET"
    );
    // if-none-match/if-range/connection 剥掉；accept-encoding 透传。
    for k in ["if-none-match", "if-range", "connection"] {
        assert!(req.headers().get(k).is_none(), "{k} 不该被复制进段请求");
    }
    assert_eq!(req.headers().get("user-agent").unwrap(), "bench/1.0");
    assert_eq!(
        req.headers().get("accept-encoding").unwrap(),
        "gzip",
        "压缩协商必须透传——切片按压缩流字节切"
    );
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
    // 段必须零重叠零缝。
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
    for k in ["content-range", "content-length", "transfer-encoding", "connection"] {
        assert!(skip_response_header(k), "{k} 必须剥掉");
    }
    // content-encoding 透传。
    assert!(!skip_response_header("content-encoding"));
    assert!(!skip_response_header("content-type"), "图片 content-type 必须保留");
    assert!(!skip_response_header("etag"));
    assert!(!skip_request_header("cookie"));
    assert!(!skip_request_header("authorization"));
    assert!(!skip_request_header("proxy-authorization"));
    assert!(skip_request_header("if-none-match"));
    assert!(skip_request_header("if-range"));
    assert!(!skip_request_header("user-agent"));
}

#[test]
fn media_kind_routes_to_its_chain() {
    use super::MediaKind;
    assert_eq!(MediaKind::Image.chain(), crate::pool::MEDIA_IMAGE_CHAIN);
    assert_eq!(MediaKind::Video.chain(), crate::pool::MEDIA_VIDEO_CHAIN);
    // 脚本段救援链为空。
    assert_eq!(MediaKind::Script.chain(), "");
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

/// 探片区间必须精确覆盖 [0, 10240)。
#[test]
fn probe_range_must_be_exactly_first_10k() {
    assert!(probe_range_ok(Some("bytes 0-10239/200000")).is_ok());
    // 服务端只回 4KB：终点没越界，但区间比请求短 —— 必须拒。
    assert!(
        probe_range_ok(Some("bytes 0-4095/200000")).is_err(),
        "短区间必须退回单流"
    );
    // 起点被归一化/错位：字节会贴到错误偏移上。
    assert!(probe_range_ok(Some("bytes 1-10240/200000")).is_err());
    assert!(probe_range_ok(Some("bytes 4096-14335/200000")).is_err());
    // 终点越界：会吃掉总长预算。
    assert!(probe_range_ok(Some("bytes 0-20479/200000")).is_err());
    // 缺头 / 不合法。
    assert!(probe_range_ok(None).is_err());
    assert!(probe_range_ok(Some("bytes */200000")).is_err());
    // bytes= 写法等价接受。
    assert!(probe_range_ok(Some("bytes=0-10239/200000")).is_ok());
}

/// 头声明满 10KB、体提前结束时不能按常量记账。
#[test]
fn probe_body_must_be_full_10k() {
    assert!(probe_body_ok(10 * 1024));
    assert!(!probe_body_ok(0));
    assert!(!probe_body_ok(4096));
    assert!(!probe_body_ok(10 * 1024 - 1));
}
