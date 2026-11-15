use super::*;

#[test]
fn avatar_entry_shape() {
    assert!(is_avatar_entry("/Venkateshvenki404224.png"));
    assert!(is_avatar_entry("/x.PNG"), "扩展名大小写不敏感");
    assert!(!is_avatar_entry("/u/123.png"), "两段路径不是头像入口");
    assert!(!is_avatar_entry("/search"));
    assert!(!is_avatar_entry("/"));
    assert!(!is_avatar_entry("/x.png/extra"));
}

#[test]
fn record_then_local_answer() {
    let target = "https://avatars.githubusercontent.com/u/1?v=4&s=40";
    assert!(
        cached_location("github.com", "/a.png", Some("size=40")).is_none(),
        "未学过不应命中"
    );
    observe("github.com", "/a.png", Some("size=40"), target);
    assert_eq!(
        cached_location("github.com", "/a.png", Some("size=40")).as_deref(),
        Some(target)
    );
    // 不同 size = 不同键，各学各的
    assert!(cached_location("github.com", "/a.png", Some("size=80")).is_none());
    // 非 github.com 不生效
    assert!(cached_location("api.github.com", "/a.png", Some("size=40")).is_none());
    // 非 .png 入口不记不答
    observe("github.com", "/search", None, "https://elsewhere/");
    assert!(cached_location("github.com", "/search", None).is_none());
}

#[test]
fn ttl_expiry() {
    observe(
        "github.com",
        "/ttl.png",
        Some("size=40"),
        "https://avatars.githubusercontent.com/u/9",
    );
    assert!(cached_location("github.com", "/ttl.png", Some("size=40")).is_some());
    backdate("/ttl.png", Some("size=40"));
    assert!(
        cached_location("github.com", "/ttl.png", Some("size=40")).is_none(),
        "过期后应重学"
    );
}

/// 301/307/308 也是头像入口的合法跳转；只认 302 会漏学，每次渲染都要重问一遍。
#[test]
fn other_redirect_statuses_are_learned() {
    for (i, st) in [
        http::StatusCode::MOVED_PERMANENTLY,
        http::StatusCode::TEMPORARY_REDIRECT,
        http::StatusCode::PERMANENT_REDIRECT,
    ]
    .into_iter()
    .enumerate()
    {
        let path = format!("/status{i}.png");
        let target = format!("https://avatars.githubusercontent.com/u/{i}");
        let uri: http::Uri = path.parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("location", target.parse().unwrap());
        observe_response("github.com", &uri, st, &headers);
        assert_eq!(
            cached_location("github.com", &path, None),
            Some(target),
            "{st} 应被记下"
        );
    }
    // 非重定向状态码仍不记。
    let uri: http::Uri = "/status-ok.png".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "location",
        "https://avatars.githubusercontent.com/u/9".parse().unwrap(),
    );
    observe_response("github.com", &uri, http::StatusCode::OK, &headers);
    assert!(cached_location("github.com", "/status-ok.png", None).is_none());
}

/// 异常落点（登录跳转/风控页/污染回包）不记仇：存不进、命中前也会被清。
#[test]
fn non_avatar_target_is_never_memoized() {
    observe("github.com", "/bad.png", Some("s=40"), "https://github.com/login");
    observe("github.com", "/bad2.png", Some("s=40"), "https://evil.example/a.png");
    assert!(cached_location("github.com", "/bad.png", Some("s=40")).is_none());
    assert!(cached_location("github.com", "/bad2.png", Some("s=40")).is_none());
    // 历史遗留条目（旧版存进来的异常落点）命中时当场清掉。
    {
        let mut g = memo().lock().unwrap_or_else(|p| p.into_inner());
        g.insert(
            memo_key("/legacy.png", Some("s=40")),
            ("https://github.com/session".to_string(), Instant::now()),
        );
    }
    assert!(
        cached_location("github.com", "/legacy.png", Some("s=40")).is_none(),
        "遗留异常落点应被清除"
    );
}
