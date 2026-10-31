use super::*;

#[test]
fn pattern_star_dot() {
    assert!(pattern_match("api.github.com", "*.github.com"));
    assert!(pattern_match("github.com", "github.com"));
    assert!(!pattern_match("xgithub.com", "*.github.com"));
    assert!(!pattern_match("github.com", "*.github.com"));
    assert!(!pattern_match("evilgithub.com", "*.github.com"));
}

#[test]
fn pool_routing() {
    assert_eq!(pool_for("github.com"), "core");
    assert_eq!(pool_for("api.github.com"), "api");
    assert_eq!(pool_for("api.github.com.cn"), ""); // 不误伤非 api.github.com 后缀
    assert!(is_direct("objects-origin.githubusercontent.com"));
    assert_eq!(pool_for("objects-origin.githubusercontent.com"), "");
    assert!(is_direct("uploads.github.com"));
    assert_eq!(pool_for("uploads.github.com"), "");
    assert!(is_direct("viewscreen.githubusercontent.com"));
    assert_eq!(pool_for("viewscreen.githubusercontent.com"), "");
    assert!(is_direct("api.mcp.github.com")); // *.github.com 通配吞它，白名单精确短路
    assert_eq!(pool_for("api.mcp.github.com"), "");
    // 白名单：PAC 里故意不出现（要进代理才能分片），池名必须是 edge，且带段号。
    for w in WHITELIST_HOSTS {
        assert!(is_whitelist(w.host), "{} 应在白名单", w.host);
        assert!(
            !is_direct(w.host),
            "{} 不能进 DIRECT：那样流量被拦在代理外，拿不到分片",
            w.host
        );
        assert_eq!(pool_for(w.host), "edge", "{} 应判为 edge 池", w.host);
        assert_eq!(whitelist_seg(w.host), Some(w.seg), "{} 段号读不出", w.host);
    }
    // 段号必须覆盖四类：.154 / .153 / .133 / Azure 前缀
    assert_eq!(whitelist_seg("docs.github.com"), Some("154"));
    assert_eq!(whitelist_seg("pages.github.com"), Some("153"));
    assert_eq!(whitelist_seg("support.github.com"), Some("133"));
    assert_eq!(
        whitelist_seg("copilot-proxy.githubusercontent.com"),
        Some("4.249")
    );
    assert_eq!(pool_for("codeload.github.com"), "core");
    assert_eq!(pool_for("raw.githubusercontent.com"), "edge");
    assert_eq!(pool_for("avatars.githubusercontent.com"), "edge");
    assert_eq!(pool_for("camo.githubusercontent.com"), "edge");
    assert_eq!(pool_for("gist.githubusercontent.com"), "edge");
    assert_eq!(pool_for("github.githubassets.com"), "edge");
    assert_eq!(pool_for("foo.github.io"), "edge");
    assert_eq!(pool_for("github.io"), "edge");
    assert_eq!(pool_for("githubapp.com"), "edge");
    assert_eq!(pool_for("api.githubapp.com"), "edge");
    assert_eq!(pool_for("example.com"), "");
}
