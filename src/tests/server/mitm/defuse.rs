use super::*;

#[test]
fn defuse_retry_decision() {
    // 空归属：重试上限 3 次
    assert!(defuse_retry(true, 0, false));
    assert!(defuse_retry(true, 3, false));
    assert!(!defuse_retry(true, 4, false));
    // 有归属：新 IP 重试，同 IP 再现 = 全灭终止
    assert!(defuse_retry(false, 0, false));
    assert!(!defuse_retry(false, 0, true));
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
    let body = upstream::full_body(Bytes::from(compressed.clone()));
    let (parts, _) = hyper::Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "gzip")
        .body(())
        .unwrap()
        .into_parts();
    let mut resp = hyper::Response::from_parts(parts, body);
    assert!(is_gh_block_page(&mut resp).await, "gzip 压缩的拦截页应被判定");
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
    let body2 = upstream::full_body(Bytes::from(normal));
    let (parts2, _) = hyper::Response::builder()
        .header("content-type", "text/html")
        .header("content-encoding", "gzip")
        .body(())
        .unwrap()
        .into_parts();
    let mut resp2 = hyper::Response::from_parts(parts2, body2);
    assert!(!is_gh_block_page(&mut resp2).await);
}
