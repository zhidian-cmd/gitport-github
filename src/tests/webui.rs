use super::*;

#[test]
fn local_host_and_origin_gate() {
    assert!(local_host("127.0.0.1:7811"));
    assert!(local_host("LOCALHOST:7811"));
    assert!(!local_host("evil.com"));
    assert!(!local_host("127.0.0.2:7811"));
    let port = config::webui_port();
    assert!(local_origin(&format!("http://127.0.0.1:{port}")));
    assert!(local_origin(&format!("http://localhost:{port}/")));
    assert!(!local_origin(&format!("http://127.0.0.1:{port}@evil.com")));
    assert!(!local_origin("http://evil.com"));
    assert!(!local_origin(""));
}

#[test]
fn same_site_write_rules() {
    let mut h = HeaderMap::new();
    assert!(
        !same_site_write(&h),
        "无 Origin/Referer 且没带 X-GitPort-Request：不再默认放行"
    );
    h.insert("x-gitport-request", HeaderValue::from_static("1"));
    assert!(same_site_write(&h), "带意图头的本机脚本应放行");
    h.remove("x-gitport-request");
    let base = format!("http://127.0.0.1:{}", config::webui_port());
    h.insert(
        "origin",
        HeaderValue::from_str(&base).unwrap(),
    );
    assert!(same_site_write(&h));
    h.insert("origin", HeaderValue::from_static("http://evil.com"));
    assert!(!same_site_write(&h));
    h.remove("origin");
    h.insert(
        "referer",
        HeaderValue::from_str(&format!("{base}/x")).unwrap(),
    );
    assert!(same_site_write(&h));
    h.insert("referer", HeaderValue::from_static("http://evil.com/x"));
    assert!(!same_site_write(&h));
}
