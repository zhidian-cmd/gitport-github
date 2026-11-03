use super::*;

/// 造一行：key 是域名，body 是开关位（可为空对象）。
fn row(key: &str, body: &str) -> RouteRow {
    let mut v: serde_json::Value = if body.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(body).expect("body 应是合法 JSON")
    };
    v["key"] = serde_json::Value::String(key.to_string());
    RouteRow::new(serde_json::from_value(v).expect("spec 应可解析")).expect("行应可编译")
}

fn install_rows(specs: &[(&str, &str)]) {
    let rows: Vec<RouteRow> = specs.iter().map(|(k, b)| row(k, b)).collect();
    install(rows);
}

/// 多条同时命中时取最长的键：更具体的域名天然压过父域，与书写顺序无关。
#[test]
fn longest_key_wins() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for order in [0, 1] {
        let mut spec = vec![
            ("github.com", r#"{"plans":[{"ip":"2.2.2.2"}]}"#),
            ("api.github.com", r#"{"plans":[{"ip":"1.1.1.1"}]}"#),
        ];
        if order == 1 {
            spec.reverse();
        }
        install_rows(&spec);
        assert_eq!(
            route_for("api.github.com").expect("精确键应命中").plans[0].ip,
            "1.1.1.1",
            "长键必须压过父域，顺序不影响"
        );
        assert_eq!(
            route_for("www.github.com").expect("父域兜底").plans[0].ip,
            "2.2.2.2"
        );
        assert_eq!(
            route_for("github.com").expect("裸域命中").plans[0].ip,
            "2.2.2.2"
        );
    }
}

/// 裸域名键 = 自己 + 任意级子域；`*.` 键只认子域，裸域不命中。
#[test]
fn key_covers_self_and_subdomains() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("github.com", r#"{"plans":[]}"#),
        ("*.githubusercontent.com", r#"{"plans":[]}"#),
    ]);
    assert!(route_for("github.com").is_some(), "裸域");
    assert!(route_for("www.github.com").is_some(), "一级子域");
    assert!(route_for("a.b.github.com").is_some(), "多级子域");
    assert!(route_for("xgithub.com").is_none(), "前缀相同但不是子域");
    assert!(route_for("github.com.evil.tld").is_none(), "不得当前缀");
    assert!(
        route_for("avatars.githubusercontent.com").is_some(),
        "*. 认子域"
    );
    assert!(
        route_for("githubusercontent.com").is_none(),
        "*. 不认裸域——和 (.*\\.) 语义一致"
    );
}

/// 具体的直连键压过父域通配：objects-origin 不能被 githubusercontent 吞掉。
#[test]
fn direct_key_beats_parent_wildcard() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        (
            "*.githubusercontent.com",
            r#"{"content":true,"fallback":"mirror","plans":[]}"#,
        ),
        (
            "objects-origin.githubusercontent.com",
            r#"{"action":"direct","pac":"objects-origin.githubusercontent.com"}"#,
        ),
    ]);
    assert!(!is_managed("objects-origin.githubusercontent.com"), "直连");
    assert!(is_managed("avatars.githubusercontent.com"), "其余仍走代理");
}

/// 域名不区分大小写，key 写大写小写都一样。
#[test]
fn host_and_key_case_insensitive() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[("GitHub.com", r#"{"plans":[]}"#)]);
    assert!(route_for("api.GITHUB.com").is_some());
    assert!(route_for("GitHub.COM").is_some());
}

/// 四个开关位都由数据给，代码不再从 host 形状推断。
#[test]
fn flags_come_from_the_row() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        (
            "direct.example",
            r#"{"action":"direct","pac":"direct.example"}"#,
        ),
        (
            "*.githubusercontent.com",
            r#"{"content":true,"fallback":"mirror","plans":[]}"#,
        ),
        ("githubassets.com", r#"{"donor":true,"plans":[]}"#),
    ]);
    assert!(route_for("direct.example").unwrap().flags.direct);
    assert!(!is_managed("direct.example"), "直连行不进代理");
    assert!(is_managed("a.githubusercontent.com"));
    assert!(is_content("a.githubusercontent.com"));
    assert_eq!(fallback_for("a.githubusercontent.com"), Fallback::MirrorDns);
    assert!(is_donor("x.githubassets.com"));
    assert!(!is_donor("a.githubusercontent.com"));
    assert_eq!(fallback_for("other.example"), Fallback::Dns, "表外默认 DNS");
}

/// 真名腿（隧道 / real 路由）才带上 realPlans；伪装腿绝不碰它们。
#[test]
fn real_plans_only_on_real_wire() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let r = row(
        "x.example",
        r#"{"plans":[{"ip":"1.1.1.1"}],"realPlans":[{"ip":"2.2.2.2"}]}"#,
    );
    assert_eq!(r.dial_plans(false).len(), 1, "伪装腿只有 plans");
    let both = r.dial_plans(true);
    assert_eq!(both.len(), 2, "真名腿加 realPlans");
    assert_eq!(both[1].ip, "2.2.2.2");
}

/// PAC 名单从路由行取：直连行进 direct，其余带 pac 的进代理名单。
#[test]
fn pac_lists_split_direct_and_proxy() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("a.example", r#"{"action":"direct","pac":"a.example"}"#),
        (
            "*.githubusercontent.com",
            r#"{"pac":"githubusercontent.com","plans":[]}"#,
        ),
        ("no-pac.example", r#"{"plans":[]}"#),
    ]);
    let (proxy, direct) = pac_lists();
    assert_eq!(direct, vec!["a.example".to_string()]);
    assert_eq!(proxy, vec!["githubusercontent.com".to_string()]);
}

/// 游标键跟路由行一一对应（就是域名键），直连行不占键。
#[test]
fn cursor_keys_follow_routes() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("a.example", r#"{"action":"direct","pac":"a.example"}"#),
        ("b.example", r#"{"plans":[]}"#),
    ]);
    assert_eq!(cursor_keys(), vec!["b.example", "b.example~2"]);
}

/// 总路由：直连行短路 → System；表外 → Tunnel；镜像路径照旧。
#[test]
fn master_route_direct_tunnel_mirror() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        (
            "objects-origin.githubusercontent.com",
            r#"{"action":"direct","pac":"objects-origin.githubusercontent.com"}"#,
        ),
        ("github.com", r#"{"plans":[]}"#),
        ("*.githubusercontent.com", r#"{"content":true,"plans":[]}"#),
    ]);
    assert_eq!(
        master_route("objects-origin.githubusercontent.com", "PUT", "/x"),
        Route::System
    );
    assert_eq!(master_route("github.com", "GET", "/"), Route::Pool);
    assert_eq!(
        master_route("github.com", "GET", "/o/r/archive/x.zip"),
        Route::Mirror
    );
    assert_eq!(
        master_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
        Route::Mirror
    );
    assert_eq!(
        master_route("example.com", "GET", "/"),
        Route::Tunnel,
        "表外域名走隧道"
    );
}

/// 坏键在校验期就拒绝：空、缺域名、通配不在开头、带协议/路径、action/fallback 拼错。
#[test]
fn invalid_rows_are_rejected() {
    let bad = |key: &str, body: &str| {
        let mut v: serde_json::Value = serde_json::from_str(body).unwrap();
        v["key"] = serde_json::Value::String(key.to_string());
        match serde_json::from_value::<RouteSpec>(v) {
            Ok(spec) => RouteRow::new(spec).is_err(),
            Err(_) => true,
        }
    };
    assert!(bad("", r#"{}"#), "空键");
    assert!(bad("example", r#"{}"#), "没有点，不像域名");
    assert!(bad("https://x.com", r#"{}"#), "带协议");
    assert!(bad("x.com/path", r#"{}"#), "带路径");
    assert!(bad("a.*.com", r#"{}"#), "星号只能在开头");
    assert!(bad("*.", r#"{}"#), "缺域名");
    assert!(bad("x.com", r#"{"action":"proxy"}"#), "action 未知");
    assert!(bad("x.com", r#"{"fallback":"mirror2"}"#), "fallback 未知");
    assert!(!bad("x.com", r#"{}"#), "正常键必须接受");
    assert!(!bad("*.x.com", r#"{}"#), "子域键必须接受");
}

#[test]
fn mirror_chain_host_dedicated() {
    assert_eq!(
        mirror_chain_host("github.com", "/o/r/releases/download/v1/f.exe"),
        "release-assets.githubusercontent.com"
    );
    assert_eq!(
        mirror_chain_host("github.com", "/o/r/archive/refs/tags/v1.tar.gz"),
        "codeload.github.com"
    );
    assert_eq!(
        mirror_chain_host("codeload.github.com", "/o/r/tar.gz/x"),
        "codeload.github.com"
    );
    assert_eq!(mirror_chain_host("github.com", "/o/r"), "github.com");
}
