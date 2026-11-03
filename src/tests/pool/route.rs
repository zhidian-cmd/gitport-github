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

fn install_table(rows: &[(&str, &str)], nodes: &[&str]) {
    let rows: Vec<RouteRow> = rows.iter().map(|(k, b)| row(k, b)).collect();
    let nodes: Vec<IpNode> = nodes
        .iter()
        .map(|j| {
            let spec: IpSpec = serde_json::from_str(j).expect("节点应可解析");
            super::super::build_node(spec).expect("节点应可编译")
        })
        .collect();
    install(rows, nodes);
}

fn install_rows(specs: &[(&str, &str)]) {
    install_table(specs, &[]);
}

/// 多条同时命中时取最长的键：更具体的域名天然压过父域，与书写顺序无关。
#[test]
fn longest_key_wins() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for order in [0, 1] {
        let mut spec = vec![("github.com", "{}"), ("api.github.com", "{}")];
        if order == 1 {
            spec.reverse();
        }
        install_table(
            &spec,
            &[
                r#"{"ip":"2.2.2.2","hosts":["github.com"]}"#,
                r#"{"ip":"1.1.1.1","hosts":["api.github.com"]}"#,
            ],
        );
        assert_eq!(
            dial_targets("api.github.com").expect("精确键应命中")[0].ip,
            "1.1.1.1",
            "长键必须压过父域，顺序不影响"
        );
        assert_eq!(
            dial_targets("www.github.com").expect("父域兜底")[0].ip,
            "2.2.2.2"
        );
        assert_eq!(
            dial_targets("github.com").expect("裸域命中")[0].ip,
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
    install_rows(&[("github.com", "{}"), ("*.githubusercontent.com", "{}")]);
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
            r#"{"content":true,"fallback":"mirror"}"#,
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
    install_rows(&[("GitHub.com", "{}")]);
    assert!(route_for("api.GITHUB.com").is_some());
    assert!(route_for("GitHub.COM").is_some());
}

/// 开关位都由数据给，代码不再从 host 形状推断。
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
            r#"{"content":true,"fallback":"mirror"}"#,
        ),
    ]);
    assert!(route_for("direct.example").unwrap().flags.direct);
    assert!(!is_managed("direct.example"), "直连行不进代理");
    assert!(is_managed("a.githubusercontent.com"));
    assert!(is_content("a.githubusercontent.com"));
    assert_eq!(fallback_for("a.githubusercontent.com"), Fallback::MirrorDns);
    assert_eq!(fallback_for("other.example"), Fallback::Dns, "表外默认 DNS");
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
            r#"{"pac":"githubusercontent.com"}"#,
        ),
        ("no-pac.example", "{}"),
    ]);
    let (proxy, direct) = pac_lists();
    assert_eq!(direct, vec!["a.example".to_string()]);
    assert_eq!(proxy, vec!["githubusercontent.com".to_string()]);
}

/// 游标键跟路由行一一对应（主键 + `_vice` 副键），直连行不占键。
#[test]
fn cursor_keys_follow_routes() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("a.example", r#"{"action":"direct","pac":"a.example"}"#),
        ("b.example", "{}"),
    ]);
    assert_eq!(cursor_keys(), vec!["b.example", "b.example_vice"]);
}

/// 总路由：直连行短路 → System；表外 → Tunnel；大文件域/附件下载 → Mirror；archive 走池。
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
        ("github.com", "{}"),
        ("*.githubusercontent.com", r#"{"content":true}"#),
    ]);
    assert_eq!(
        master_route("objects-origin.githubusercontent.com", "PUT", "/x"),
        Route::System
    );
    assert_eq!(master_route("github.com", "GET", "/"), Route::Pool);
    assert_eq!(
        master_route("github.com", "GET", "/o/r/releases/download/v1/f.zip"),
        Route::Mirror
    );
    assert_eq!(
        master_route("github.com", "GET", "/o/r/archive/x.zip"),
        Route::Pool,
        "archive 迁池，不再走镜像"
    );
    assert_eq!(
        master_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
        Route::Pool,
        "codeload 命中 github.com 裸键走池"
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
        match serde_json::from_value::<HostSpec>(v) {
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
        "github.com",
        "archive 迁池"
    );
    assert_eq!(
        mirror_chain_host("objects.githubusercontent.com", "/x"),
        "objects.githubusercontent.com"
    );
    assert_eq!(mirror_chain_host("github.com", "/o/r"), "github.com");
}

/// 末段范围展开：单段范围、多段笛卡尔积、越界拒绝。
#[test]
fn expand_ip_ranges() {
    assert_eq!(
        expand_ip("140.82.112-114.5-6").expect("应展开"),
        vec![
            "140.82.112.5",
            "140.82.112.6",
            "140.82.113.5",
            "140.82.113.6",
            "140.82.114.5",
            "140.82.114.6"
        ]
    );
    assert_eq!(expand_ip("1.2.3.4").expect("单 IP 原样"), vec!["1.2.3.4"]);
    assert!(expand_ip("1.2.3.9-7").is_err(), "起点大于终点");
    assert!(expand_ip("1.2.3.0-999").is_err(), "超 255");
    assert!(expand_ip("1.2.3-9.0-255.0-255").is_err(), "展开超 64");
}

/// dial_targets：按路由键汇边、去重、滤黑边。
#[test]
fn dial_targets_dedup_and_filter() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_table(
        &[("github.com", "{}")],
        &[
            r#"{"ip":"1.1.1.1","sni":"baidu.com","verify":"github.com","hosts":["github.com"]}"#,
            r#"{"ip":"1.1.1.1","hosts":["github.com"]}"#,
            r#"{"ip":"2.2.2.2","hosts":["github.com"]}"#,
        ],
    );
    let t = dial_targets("github.com").expect("应命中");
    assert_eq!(t.len(), 2, "同 IP 去重");
    assert_eq!(t[0].sni, "baidu.com");
    crate::pool::edges::mark_reject("1.1.1.1", "github.com");
    let t2 = dial_targets("github.com").expect("应命中");
    assert_eq!(t2.len(), 1, "黑边被滤");
    assert_eq!(t2[0].ip, "2.2.2.2");
    crate::pool::edges::clear_all();
    let t3 = dial_targets("github.com").expect("应命中");
    assert_eq!(t3.len(), 2, "清黑后恢复");
    crate::pool::edges::clear_all();
}

/// 节点 verify 留空 = 回退按目标 host 校验（迁移期安全默认；空串会让 BoringSSL 校验必败）。
#[test]
fn empty_verify_falls_back_to_host() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_table(
        &[("github.com", "{}")],
        &[r#"{"ip":"1.1.1.1","sni":"baidu.com","hosts":["github.com"]}"#],
    );
    let t = dial_targets("GitHub.com").expect("应命中");
    assert_eq!(t[0].verify, "github.com", "空锚点回退为小写目标 host");
    crate::pool::edges::clear_all();
}

/// 全黑 → Some(空)，调用方走 fallback；表外 → None。
#[test]
fn dial_targets_empty_vs_none() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_table(
        &[("github.com", "{}")],
        &[r#"{"ip":"1.1.1.1","hosts":["github.com"]}"#],
    );
    crate::pool::edges::mark_reject("1.1.1.1", "github.com");
    let t = dial_targets("github.com").expect("在表内");
    assert!(t.is_empty(), "全黑 = 空组走 fallback");
    assert!(dial_targets("other.example").is_none(), "表外 = None");
    crate::pool::edges::clear_all();
}
