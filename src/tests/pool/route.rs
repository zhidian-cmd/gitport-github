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

/// `*.x` 与裸 `x` 同 rank：子域必须落到 `*.x`，裸域仍走 `x`，与书写顺序无关。
#[test]
fn star_row_wins_subdomains_on_tie() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for order in [0, 1] {
        let mut spec = vec![("github.com", "{}"), ("*.github.com", "{}")];
        if order == 1 {
            spec.reverse();
        }
        install_table(
            &spec,
            &[
                r#"{"ip":"2.2.2.2","hosts":["github.com"]}"#,
                r#"{"ip":"1.1.1.1","hosts":["*.github.com"]}"#,
            ],
        );
        assert_eq!(
            dial_targets("maintainers.github.com").expect("子域应命中")[0].ip,
            "1.1.1.1",
            "同 rank 时 *. 行压过裸键"
        );
        assert_eq!(
            dial_targets("github.com").expect("裸域应命中")[0].ip,
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
            r#"{"action":"direct"}"#,
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
            r#"{"action":"direct"}"#,
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

/// PAC 名单从路由行取：直连行进 direct，其余行进代理名单（pac 不落盘，缺省 = 裸键）。
#[test]
fn pac_lists_split_direct_and_proxy() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("a.example", r#"{"action":"direct"}"#),
        (
            "*.githubusercontent.com",
            r#"{}"#,
        ),
        ("no-pac.example", "{}"),
    ]);
    let (proxy, direct) = pac_lists();
    assert_eq!(direct, vec!["a.example".to_string()]);
    assert_eq!(
        proxy,
        vec![
            "githubusercontent.com".to_string(),
            "no-pac.example".to_string()
        ],
        "缺省 pac = 裸键，不再有'不写 pac 就不进名单'的行"
    );
}

/// 游标键只跟串发域一一对应：内容域竞速选路不记游标，直连行不占键。
#[test]
fn cursor_keys_follow_routes() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        ("a.example", r#"{"action":"direct"}"#),
        ("b.example", "{}"),
        ("c.example", r#"{"content":true}"#),
    ]);
    assert_eq!(
        cursor_keys(),
        vec!["b.example"],
        "内容域(c.example)竞速选路, 游标无人读, 不占键位"
    );
}

/// 总路由判定：只有镜像分流被生产读取——大文件域/附件 GET|HEAD 为真，
/// 直连行/表外/普通页面为假（原 System/Tunnel/Pool 语义由反面断言钉住）。
#[test]
fn mirror_route_matches_big_and_attachment_only() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_rows(&[
        (
            "objects-origin.githubusercontent.com",
            r#"{"action":"direct"}"#,
        ),
        ("github.com", "{}"),
        ("*.githubusercontent.com", r#"{"content":true}"#),
    ]);
    // 直连行 → false（原 System 语义）
    assert!(!is_mirror_route(
        "objects-origin.githubusercontent.com",
        "PUT",
        "/x"
    ));
    // 表外 → false（原 Tunnel 语义）
    assert!(!is_mirror_route("example.com", "GET", "/"));
    // 普通页面/archive/codeload → false（原 Pool 语义；codeload 已迁池）
    assert!(!is_mirror_route("github.com", "GET", "/"));
    assert!(
        !is_mirror_route("github.com", "GET", "/o/r/archive/x.zip"),
        "archive 迁池，不再走镜像"
    );
    assert!(
        !is_mirror_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
        "codeload 命中 github.com 裸键走池"
    );
    // 附件下载 GET|HEAD → true（原 Mirror 语义）
    assert!(is_mirror_route(
        "github.com",
        "GET",
        "/o/r/releases/download/v1/f.zip"
    ));
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

/// 拨号实测回流：EMA 防抖（首样直入，之后均值）；黑洞降权翻倍且钳 3~10s；表外 IP no-op。
#[test]
fn latency_note_and_sink_semantics() {
    let _g = crate::pool::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    install(
        vec![],
        vec![crate::pool::build_node(
            serde_json::from_str::<IpSpec>(
                r#"{"ip":"9.9.9.9","hosts":["github.com"]}"#,
            )
            .unwrap(),
        )
        .unwrap()],
    );
    note_latency("9.9.9.9", 800);
    note_latency("9.9.9.9", 200);
    assert_eq!(latency_of("9.9.9.9"), 500, "(800+200)/2");
    sink_latency("9.9.9.9");
    assert_eq!(latency_of("9.9.9.9"), 3000, "沉到已测队尾: 3s 下限");
    sink_latency("8.8.8.8");
    assert_eq!(latency_of("8.8.8.8"), 0, "表外 IP no-op 不炸");
    install(vec![], vec![]); // 清场
}

/// build_node：范围/非法写法拒绝（单 IP 格式已下线多地址）。
#[test]
fn build_node_rejects_non_single_ip() {
    let spec = |ip: &str| serde_json::from_str::<IpSpec>(&format!(r#"{{"ip":"{ip}","hosts":["github.com"]}}"#)).unwrap();
    assert!(crate::pool::build_node(spec("1.2.3.4")).is_ok(), "单点分地址应通过");
    assert!(crate::pool::build_node(spec("1.2.3.9-7")).is_err(), "范围段拒绝");
    assert!(crate::pool::build_node(spec("1.2.3.0-999")).is_err(), "超 255 拒绝");
    assert!(crate::pool::build_node(spec("999.1.1.1")).is_err(), "段越界拒绝");
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

/// 通配键子域：边冷却必须按路由键记账才能滤到；老实现按子域 host 记，内容域超时冷却从来没滤到过。
#[test]
fn wildcard_key_stall_filters_subdomain_dial() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_table(
        &[("*.githubusercontent.com", r#"{"content":true}"#)],
        &[r#"{"ip":"1.1.1.1","sni":"baidu.com","hosts":["*.githubusercontent.com"]}"#],
    );
    crate::pool::edges::mark_stall("1.1.1.1", "*.githubusercontent.com");
    let t = dial_targets("raw.githubusercontent.com").expect("通配命中");
    assert!(t.is_empty(), "按路由键记的冷却必须滤到子域查询");
    crate::pool::edges::clear_all();
}

/// 渲染族六域必须拨 k8s 边缘、不得落 Fastly 池：通配行把 *.githubusercontent.com 全压到 185.199，
/// 而 Fastly 不伺服这些域（"500 Domain Not Found"→421 风暴把共享 IP 冤枉冷却 4 小时，
/// notebook 渲染 "Unable to render code block"，2026-11-22 实证）。
#[test]
fn render_family_dials_k8s_edge_not_fastly() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    const FAMILY: [&str; 6] = [
        "notebooks.githubusercontent.com",
        "render.githubusercontent.com",
        "cloud-camo.githubusercontent.com",
        "github-production-user-asset-6210df1e.githubusercontent.com",
        "experiments.githubusercontent.com",
        "github.githubusercontent.com",
    ];
    for h in FAMILY {
        let row = route_for(h).expect("渲染族应有显式行");
        assert!(!row.flags.big, "{h} 不是大文件域");
        assert!(!row.flags.content, "{h} 脱离内容竞速池");
        let targets = dial_targets(h).expect("渲染族应有拨号边");
        assert!(!targets.is_empty(), "{h} 拨号边不应为空");
        for t in &targets {
            assert!(
                t.ip.starts_with("140.82."),
                "{h} 应拨 k8s 边缘, 实际拨 {}",
                t.ip
            );
        }
    }
    // 对照组：Fastly 族原样不动，不得混入 k8s 边。
    for h in [
        "raw.githubusercontent.com",
        "avatars.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ] {
        let targets = dial_targets(h).expect("Fastly 族应有拨号边");
        assert!(
            targets.iter().any(|t| t.ip.starts_with("185.199.")),
            "{h} 应仍走 Fastly 池"
        );
        assert!(
            targets.iter().all(|t| !t.ip.starts_with("140.82.")),
            "{h} 不得混入 k8s 边"
        );
    }
    // 既有渲染域不回退：viewscreen/objects-origin 仍拨 k8s 边。
    for h in [
        "viewscreen.githubusercontent.com",
        "objects-origin.githubusercontent.com",
    ] {
        let targets = dial_targets(h).expect("既有渲染域应有拨号边");
        assert!(
            targets.iter().any(|t| t.ip.starts_with("140.82.")),
            "{h} 应仍拨 k8s 边缘"
        );
    }
}
