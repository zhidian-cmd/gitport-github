use super::*;
use crate::server::protocol;

#[test]
fn defuse_retry_decision() {
    // 空归属：重试上限 3 次
    assert!(defuse_retry(true, 0, 0));
    assert!(defuse_retry(true, 3, 0));
    assert!(!defuse_retry(true, 4, 0));
    // 有归属：试满 DEFUSE_MAX_TRIES 才停；同 IP 再现不提前放弃。
    assert!(defuse_retry(false, 0, 0));
    assert!(defuse_retry(false, 0, DEFUSE_MAX_TRIES - 1));
    assert!(!defuse_retry(false, 0, DEFUSE_MAX_TRIES));
}

#[tokio::test]
async fn gzip_sniff_detects_block_and_keeps_raw_prefix() {
    use std::io::Write;
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }
    let mut html = b"<!doctype html><html><body><h1>".to_vec();
    html.extend_from_slice(&vec![b'a'; 2000]);
    html.extend_from_slice(b"</h1><p>Whoa there, pardner!</p></body></html>");
    let compressed = gzip(&html);
    let body = protocol::full_body(Bytes::from(compressed.clone()));
    let (parts, _) = hyper::Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "gzip")
        .body(())
        .unwrap()
        .into_parts();
    let mut resp = hyper::Response::from_parts(parts, body);
    assert!(
        is_gh_block_page(&mut resp).await,
        "gzip 压缩的拦截页应被判定"
    );
    let raw = resp
        .extensions()
        .get::<PeekRaw>()
        .expect("必须保留原始压缩帧")
        .0
        .clone();
    let joined: Vec<u8> = raw.iter().flat_map(|b| b.to_vec()).collect();
    assert!(!joined.is_empty());
    assert!(
        compressed.starts_with(&joined),
        "写回前缀必须是原始压缩流的真前缀"
    );
    let normal = gzip(b"<!doctype html><html><body>hello</body></html>");
    let body2 = protocol::full_body(Bytes::from(normal));
    let (parts2, _) = hyper::Response::builder()
        .header("content-type", "text/html")
        .header("content-encoding", "gzip")
        .body(())
        .unwrap()
        .into_parts();
    let mut resp2 = hyper::Response::from_parts(parts2, body2);
    assert!(!is_gh_block_page(&mut resp2).await);
}

fn html_resp(status: u16, body: &[u8]) -> hyper::Response<protocol::BoxBody> {
    let (parts, _) = hyper::Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(())
        .unwrap()
        .into_parts();
    hyper::Response::from_parts(parts, protocol::full_body(Bytes::from(body.to_vec())))
}

/// 通用 400 页不得判成风控。
#[tokio::test]
async fn generic_bad_request_page_is_not_block() {
    let page = br#"<!DOCTYPE html>
<html><head><title>400 Bad Request</title></head>
<body><center><h1>400 Bad Request</h1></center>
<p>Your browser sent a request that this server could not understand.</p>
<hr><center>nginx</center></body></html>"#;
    assert!(
        !is_gh_block_page(&mut html_resp(400, page)).await,
        "通用 400 页面被误判成风控"
    );
}

/// GitHub 两种拦截文案仍须识别。
#[tokio::test]
async fn github_block_wording_still_detected() {
    let whoa = b"<html><body><h1>Whoa there!</h1><p>You have exceeded a secondary rate limit.</p></body></html>";
    assert!(
        is_gh_block_page(&mut html_resp(400, whoa)).await,
        "whoa there 应判拦截"
    );
    let restricted = b"<html><body><h1>Access to this repository has been restricted.</h1></body></html>";
    assert!(
        is_gh_block_page(&mut html_resp(403, restricted)).await,
        "has been restricted 应判拦截"
    );
}
