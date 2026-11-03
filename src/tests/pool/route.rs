use super::*;

fn row(spec: &str) -> RouteRow {
    RouteRow::new(serde_json::from_str(spec).expect("spec 应是合法 JSON")).expect("行应可编译")
}

fn install_rows(specs: &[&str]) {
    install(specs.iter().map(|s| row(s)).collect());
}

/// 只有一条匹配规则：数组从上往下，先命中先用。顺序就是用户排的顺序。
#[test]
fn first_match_wins_in_array_order() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        r#"{"match":"docs\\.github\\.com","real":true,"plans":[{"ip":"1.1.1.1"}]}"#,
        r#"{"match":"(.*\\.)?github\\.com","plans":[{"ip":"2.2.2.2"}]}"#,
    ]);
    let docs = route_for("docs.github.com").expect("精确项应命中");
    assert_eq!(docs.pattern, "docs\\.github\\.com");
    assert_eq!(docs.plans[0].ip, "1.1.1.1");
    assert!(docs.flags.real, "real 标记应随行带出");
    assert_eq!(
        route_for("api.github.com").expect("通配项应兜住").plans[0].ip,
        "2.2.2.2"
    );
    assert!(route_for("example.com").is_none(), "表外域名不归代理管");

    // 顺序颠倒：通配写在前面就会吞掉精确项，这是用户自己排的，不再有隐藏优先级。
    install_rows(&[
        r#"{"match":"(.*\\.)?github\\.com","plans":[{"ip":"2.2.2.2"}]}"#,
        r#"{"match":"docs\\.github\\.com","plans":[{"ip":"1.1.1.1"}]}"#,
    ]);
    assert_eq!(
        route_for("docs.github.com").expect("应命中").plans[0].ip,
        "2.2.2.2",
        "先命中的通配说了算"
    );
}

/// 整串匹配：`github\.com` 只认它自己，不做子串也不做后缀。
#[test]
fn match_is_whole_string() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[r#"{"match":"github\\.com","plans":[{"ip":"1.1.1.1"}]}"#]);
    assert!(route_for("github.com").is_some());
    assert!(route_for("api.github.com").is_none(), "子域不该被裸域命中");
    assert!(route_for("xgithub.com").is_none(), "后缀相同但不是子域");
    assert!(route_for("github.com.evil.tld").is_none(), "不得当前缀");
}

/// 四个开关位都由数据给，代码不再从 host 形状推断。
#[test]
fn flags_come_from_the_row() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        r#"{"match":"direct\\.example","action":"direct","pac":"direct.example"}"#,
        r#"{"match":".*\\.githubusercontent\\.com","content":true,"fallback":"mirror","plans":[]}"#,
        r#"{"match":".*\\.githubassets\\.com","donor":true,"plans":[]}"#,
    ]);
    assert!(route_for("direct.example").unwrap().flags.direct);
    assert!(!is_managed("direct.example"), "直连行不进代理");
    assert!(is_managed("a.githubusercontent.com"));
    assert!(is_content("a.githubusercontent.com"));
    assert_eq!(
        fallback_for("a.githubusercontent.com"),
        Fallback::MirrorDns
    );
    assert!(is_donor("x.githubassets.com"));
    assert!(!is_donor("a.githubusercontent.com"));
    assert_eq!(fallback_for("other.example"), Fallback::Dns, "表外默认 DNS");
}

/// 真名腿（隧道 / real 路由）才带上 realPlans；伪装腿绝不碰它们。
#[test]
fn real_plans_only_on_real_wire() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let r = row(
        r#"{"match":"x","plans":[{"ip":"1.1.1.1"}],"realPlans":[{"ip":"2.2.2.2"}]}"#,
    );
    assert_eq!(r.dial_plans(false).len(), 1, "伪装腿只有 plans");
    let both = r.dial_plans(true);
    assert_eq!(both.len(), 2, "真名腿加 realPlans");
    assert_eq!(both[1].ip, "2.2.2.2");
}

/// PAC 名单从路由行取：直连行进 direct，其余带 pac 的进代理名单。
#[test]
fn pac_lists_split_direct_and_proxy() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        r#"{"match":"a\\.example","action":"direct","pac":"a.example"}"#,
        r#"{"match":".*\\.githubusercontent\\.com","pac":"githubusercontent.com","plans":[]}"#,
        r#"{"match":"no-pac\\.example","plans":[]}"#,
    ]);
    let (proxy, direct) = pac_lists();
    assert_eq!(direct, vec!["a.example".to_string()]);
    assert_eq!(proxy, vec!["githubusercontent.com".to_string()]);
}

/// 游标键跟路由行一一对应，直连行不占键。
#[test]
fn cursor_keys_follow_routes() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        r#"{"match":"a\\.example","action":"direct","pac":"a.example"}"#,
        r#"{"match":"b\\.example","plans":[]}"#,
    ]);
    assert_eq!(cursor_keys(), vec!["b\\.example", "b\\.example~2"]);
}

/// 总路由：直连行短路 → System；表外 → Tunnel；镜像路径照旧。
#[test]
fn master_route_direct_tunnel_mirror() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        r#"{"match":"objects-origin\\.githubusercontent\\.com","action":"direct","pac":"objects-origin.githubusercontent.com"}"#,
        r#"{"match":"(.*\\.)?github\\.com","plans":[]}"#,
        r#"{"match":".*\\.githubusercontent\\.com","content":true,"plans":[]}"#,
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

/// 坏行在校验期就拒绝：正则写错、action/fallback 拼错都不许静默通过。
#[test]
fn invalid_rows_are_rejected() {
    assert!(RouteRow::new(serde_json::from_str(r#"{"match":"([a-z"}"#).unwrap()).is_err());
    assert!(
        RouteRow::new(serde_json::from_str(r#"{"match":"x","action":"proxy"}"#).unwrap()).is_err()
    );
    assert!(
        RouteRow::new(serde_json::from_str(r#"{"match":"x","fallback":"mirror2"}"#).unwrap())
            .is_err()
    );
    assert!(RouteRow::new(serde_json::from_str(r#"{"match":""}"#).unwrap()).is_err());
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
