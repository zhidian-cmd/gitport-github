use super::*;

fn mk(ip: &str, sni: &str) -> SerialPlan {
    SerialPlan {
        ip: ip.into(),
        sni: sni.into(),
    }
}

/// 白名单四族：按 seg 认域名、按段认 IP。段号填错或族序排错都会在这里红。
#[test]
fn whitelist_families_route_by_seg() {
    for (host, fam, ip) in [
        ("docs.github.com", "wl154", "185.199.108.154"),
        ("pages.github.com", "wl153", "185.199.108.153"),
        ("support.github.com", "wl133", "185.199.108.133"),
    ] {
        let f = serial_family("edge", host, false)
            .unwrap_or_else(|| panic!("{host} 没有命中任何族"));
        assert_eq!(f.name, fam, "{host} 落错族");
        assert!((f.serves)(host, &mk(ip, "baidu.com")), "{host} 应认 {ip}");
    }

    // Azure 段不是 Fastly 四段之一，必须按前缀认
    let cp = "copilot-proxy.githubusercontent.com";
    let f = serial_family("edge", cp, false).unwrap();
    assert_eq!(f.name, "wl_azure", "copilot-proxy 被别的族抢走了");
    assert!((f.serves)(cp, &mk("4.249.131.160", "baidu.com")));

    // 反例一：githubapp 系的兜底族不能把 Azure 段当候选（连过去是别的服务）
    let auth = serial_family("edge", "api.githubapp.com", false).unwrap();
    assert_eq!(auth.name, "auth");
    assert!(!(auth.serves)(
        "api.githubapp.com",
        &mk("4.249.131.160", "baidu.com")
    ));

    // 反例二：老族行为不变，content 仍只认 .133
    let content = serial_family("edge", "avatars.githubusercontent.com", false).unwrap();
    assert_eq!(content.name, "content");
    assert!((content.serves)(
        "avatars.githubusercontent.com",
        &mk("185.199.110.133", "baidu.com")
    ));
    assert!(!(content.serves)(
        "avatars.githubusercontent.com",
        &mk("185.199.110.154", "baidu.com")
    ));
}


#[test]
fn master_route_all_hosts() {
    use Route::*;
    assert_eq!(
        master_route("objects-origin.githubusercontent.com", "PUT", "/x"),
        System
    );
    assert_eq!(master_route("uploads.github.com", "GET", "/"), System);
    assert_eq!(
        master_route("viewscreen.githubusercontent.com", "GET", "/"),
        System
    );
    assert_eq!(
        master_route("api.mcp.github.com", "GET", "/x"),
        System,
        "core 池证书不覆盖 api.mcp，必须白名单短路"
    );
    assert_eq!(
        master_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
        Mirror
    );
    assert_eq!(
        master_route("objects.githubusercontent.com", "HEAD", "/x"),
        Mirror
    );
    assert_eq!(
        master_route(
            "github.com",
            "GET",
            "/git-lfs/git-lfs/releases/download/v3.5.1/x.zip"
        ),
        Mirror
    );
    assert_eq!(master_route("github.com", "GET", "/o/r/archive/x.zip"), Mirror);
    assert_eq!(
        master_route("github.com", "POST", "/o/r/releases/download/x"),
        Pool
    );
    assert_eq!(
        master_route("github.com", "GET", "/o/r/releases"),
        Pool
    );
    assert_eq!(
        master_route("github.com", "GET", "/"),
        Pool
    );
    assert_eq!(
        master_route("gist.github.com", "GET", "/"),
        Pool
    );
    assert_eq!(
        master_route("api.github.com", "GET", "/"),
        Pool
    );
    assert_eq!(master_route("example.com", "GET", "/"), Tunnel);
    assert_eq!(master_route("githubstatus.com", "GET", "/"), Tunnel);
}

#[test]
fn master_route_edge_families() {
    use Route::*;
    for (host, fam) in [
        ("raw.githubusercontent.com", "content"),
        ("avatars.githubusercontent.com", "content"),
        ("camo.githubusercontent.com", "content"),
        ("user-images.githubusercontent.com", "content"),
        ("media.githubusercontent.com", "content"),
        ("private-user-images.githubusercontent.com", "content"),
        ("github.githubassets.com", "assets"),
        ("assets.githubassets.com", "assets"),
        ("github.io", "io"),
        ("octocat.github.io", "io"),
        ("githubapp.com", "auth"),
        ("api.githubapp.com", "auth"),
    ] {
        assert_eq!(
            master_route(host, "GET", "/x"),
            Pool,
            "{host} 应归 edge 池"
        );
        assert_eq!(
            serial_family("edge", host, false).map(|f| f.name),
            Some(fam),
            "{host} 的族应为 {fam}"
        );
    }
}


#[test]
fn family_entry_serves() {
    assert!(host_is_content("avatars.githubusercontent.com"));
    assert_eq!(fastly_last_octet("185.199.110.133"), Some("133"));
    assert_eq!(fastly_last_octet("185.199.110.154"), Some("154"));
    assert!(fastly_last_octet("140.82.112.3").is_none());
    assert!((FAMILY_CONTENT.serves)("x", &mk("185.199.110.133", "baidu.com")));
    assert!(!(FAMILY_CONTENT.serves)("x", &mk("185.199.110.154", "baidu.com")));
    assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.215", "baidu.com")));
    assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.154", "baidu.com")));
    assert!(!(FAMILY_ASSETS.serves)(
        "x",
        &mk("185.199.110.133", "baidu.com")
    ));
    assert!((FAMILY_IO.serves)("x", &mk("185.199.110.153", "baidu.com")));
    assert!(!(FAMILY_IO.serves)("x", &mk("185.199.110.154", "baidu.com")));
    assert!((FAMILY_AUTH.serves)("x", &mk("140.82.112.29", "baidu.com")));
    assert!(!(FAMILY_AUTH.serves)(
        "x",
        &mk("185.199.110.133", "baidu.com")
    ));
    assert!((FAMILY_ALL.serves)("x", &mk("140.82.112.3", "baidu.com")));
}

fn fam(pool: &str, host: &str) -> &'static str {
    serial_family(pool, host, false).map_or("", |f| f.name)
}

#[test]
fn family_for_and_fallback() {
    assert_eq!(fam("core", "github.com"), "all");
    assert_eq!(fam("api", "api.github.com"), "all");
    assert_eq!(fam("edge", "raw.githubusercontent.com"), "content");
    assert_eq!(fam("edge", "github.githubassets.com"), "assets");
    assert_eq!(fam("edge", "octocat.github.io"), "io");
    assert_eq!(fam("edge", "githubapp.com"), "auth");
    assert_eq!(fam("edge", "future.edge.host"), "auth");
    assert_eq!(fam("codeload", "codeload.github.com"), "");
    assert_eq!(
        fallback_for("edge", "raw.githubusercontent.com"),
        Fallback::MirrorDns
    );
    assert_eq!(
        fallback_for("edge", "camo.githubusercontent.com"),
        Fallback::MirrorDns
    );
    assert_eq!(fallback_for("edge", "github.githubassets.com"), Fallback::Dns);
    assert_eq!(fallback_for("edge", "octocat.github.io"), Fallback::Dns);
    assert_eq!(fallback_for("edge", "githubapp.com"), Fallback::Dns);
    assert_eq!(fallback_for("core", "github.com"), Fallback::Dns);
    assert_eq!(fallback_for("api", "api.github.com"), Fallback::Dns);
}

#[test]
fn serial_family_edge_fallback() {
    let f = serial_family("edge", "future.edge.host", false).unwrap();
    assert_eq!(f.name, "auth");
    assert!((f.serves)("x", &mk("140.82.112.29", "baidu.com")));
    assert!(!(f.serves)("x", &mk("185.199.110.133", "real")));
}

#[test]
fn content_serves_splits_by_leg() {
    let mitm = serial_family("edge", "raw.githubusercontent.com", false).unwrap();
    let pt = serial_family("edge", "raw.githubusercontent.com", true).unwrap();
    assert_eq!(mitm.name, "content");
    assert_eq!(pt.name, "content", "游标键不随模式分裂");
    // MITM 假名腿：只有 .133（默认证书 SAN 覆盖内容族）
    assert!((mitm.serves)("x", &mk("185.199.110.133", "baidu.com")));
    // 透传真名腿：.133/.154/.215 全放行，.153(io 组)不放行
    for last in ["133", "154", "215"] {
        let ip = format!("185.199.110.{last}");
        assert!((pt.serves)("x", &mk(&ip, "baidu.com")), "透传应放行 {ip}");
    }
    for last in ["154", "215"] {
        let ip = format!("185.199.110.{last}");
        assert!(!(mitm.serves)("x", &mk(&ip, "baidu.com")), "MITM 仍拒绝 {ip}");
    }
    assert!(!(pt.serves)("x", &mk("185.199.110.153", "baidu.com")));
    // 非 content 族不受模式影响
    let assets = serial_family("edge", "github.githubassets.com", true).unwrap();
    assert_eq!(assets.name, "assets");
    assert!((assets.serves)("x", &mk("185.199.110.154", "baidu.com")));
}

#[test]
fn mirror_chain_host_dedicated() {
    assert_eq!(
        mirror_chain_host("github.com", "/o/r/releases/download/v1/f.exe"),
        "release-assets.githubusercontent.com"
    );
    assert_eq!(
        mirror_chain_host("github.com", "/o/r/releases/latest/download/f.exe"),
        "release-assets.githubusercontent.com"
    );
    assert_eq!(
        mirror_chain_host("github.com", "/o/r/archive/refs/tags/v1.tar.gz"),
        "codeload.github.com"
    );
    assert_eq!(
        mirror_chain_host(
            "release-assets.githubusercontent.com",
            "/x?sig=abc"
        ),
        "release-assets.githubusercontent.com"
    );
    assert_eq!(
        mirror_chain_host("codeload.github.com", "/o/r/tar.gz/x"),
        "codeload.github.com"
    );
    assert_eq!(mirror_chain_host("raw.githubusercontent.com", "/o/r/f"), "raw.githubusercontent.com");
    assert_eq!(mirror_chain_host("github.com", "/o/r"), "github.com");
    assert_eq!(mirror_chain_host("github.com", "/o/r/releases"), "github.com");
    assert_eq!(
        master_route("github.com", "GET", "/o/r/releases/latest/download/f.exe"),
        Route::Mirror
    );
}
