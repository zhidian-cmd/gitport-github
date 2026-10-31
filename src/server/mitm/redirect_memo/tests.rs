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
    observe("github.com", "/ttl.png", Some("size=40"), "https://t/1");
    assert!(cached_location("github.com", "/ttl.png", Some("size=40")).is_some());
    backdate("/ttl.png", Some("size=40"));
    assert!(
        cached_location("github.com", "/ttl.png", Some("size=40")).is_none(),
        "过期后应重学"
    );
}
