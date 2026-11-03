/// 备份判定: 别家同形态 PAC(127.0.0.1:port/proxy.pac)必须备份, 我们上次写的(last_pac)和正要写的不算。
#[test]
fn should_backup_foreign_pac_shapes() {
    let pac = "http://127.0.0.1:7811/proxy.pac";
    assert!(should_backup_foreign(
        "http://127.0.0.1:7890/proxy.pac",
        pac,
        ""
    ));
    assert!(!should_backup_foreign(pac, pac, ""));
    assert!(!should_backup_foreign(
        "http://127.0.0.1:9999/proxy.pac",
        pac,
        "http://127.0.0.1:9999/proxy.pac"
    ));
    assert!(!should_backup_foreign("", pac, ""));
}

/// 清场只认 last_pac：运行期间别家接管了 PAC（同形态），不许当自己的删掉。
#[test]
fn clear_only_exact_last_pac() {
    let ours = "http://127.0.0.1:7811/proxy.pac";
    assert!(is_our_current_pac(ours, ours));
    assert!(
        !is_our_current_pac("http://127.0.0.1:7890/proxy.pac", ours),
        "别家同形态不算我们的，退出时不许动"
    );
    // 我们换过端口：上次写的那个仍是我们的
    assert!(is_our_current_pac(
        "http://127.0.0.1:9999/proxy.pac",
        "http://127.0.0.1:9999/proxy.pac"
    ));
    // 旧配置没有 last_pac：退回形状判定，老版本残留仍可清
    assert!(is_our_current_pac(ours, ""));
    assert!(!is_our_current_pac("http://corp.example/pac.js", ""));
}

/// 备份还原：别家同形态的备份必须还回去，只有"恰是我们写过的"才丢弃。
#[test]
fn restore_keeps_foreign_same_shape_backup() {
    let last = "http://127.0.0.1:7811/proxy.pac";
    assert!(
        !backup_is_ours("http://127.0.0.1:7890/proxy.pac", last),
        "同形态的别家备份必须还原，按形状丢掉等于备份白做"
    );
    assert!(!backup_is_ours("http://corp.example/pac.js", last));
    assert!(backup_is_ours(last, last), "上次写的自己不该还原(死 PAC)");
    // 旧配置：形状判定兜底，防把我们的旧地址写回系统
    assert!(backup_is_ours(last, ""));
    assert!(!backup_is_ours("http://corp.example/pac.js", ""));
}

/// 自愈门: 开关关 + 无备份 = 我们从没摸过系统 PAC——形态再像也是别人的。
#[test]
fn heal_gate_spares_foreign_pac() {
    assert!(!heal_should_touch(false, ""));
    assert!(heal_should_touch(true, ""));
    assert!(heal_should_touch(false, "http://127.0.0.1:8080/proxy.pac"));
}
use super::*;

#[test]
fn autostart_cmd_parse() {
    assert_eq!(
        parse_exe_path(r#""C:\x\a.exe" -tray"#),
        Some("C:\\x\\a.exe")
    );
    assert_eq!(
        parse_exe_path(r#""C:\no\such.exe" -tray"#),
        Some("C:\\no\\such.exe")
    );
    assert_eq!(parse_exe_path("C:\\x\\a.exe"), Some("C:\\x\\a.exe"));
    assert_eq!(parse_exe_path(""), None);
    assert_eq!(parse_exe_path("   "), None);
}

#[test]
fn is_our_pac_port_agnostic() {
    assert!(is_our_pac("http://127.0.0.1:7811/proxy.pac"));
    assert!(is_our_pac("https://127.0.0.1:9999/proxy.pac"));
    assert!(is_our_pac("http://127.0.0.1:65535/proxy.pac"));
    assert!(!is_our_pac("http://127.0.0.2:7811/proxy.pac"));
    assert!(!is_our_pac("http://127.0.0.1/proxy.pac")); // 无端口
    assert!(!is_our_pac("http://localhost:7811/proxy.pac")); // 非 127.0.0.1
    assert!(!is_our_pac("http://127.0.0.1:7811/other.pac"));
    assert!(!is_our_pac("http://example.com:7811/proxy.pac"));
    assert!(!is_our_pac(""));
    assert!(!is_our_pac("socks5://127.0.0.1:7811/proxy.pac"));
    assert!(!is_our_pac("http://127.0.0.1:78a1/proxy.pac")); // 端口非数字
    assert!(!is_our_pac("http://127.0.0.1:7811/proxy.pac?x=1"));
}

fn keys(pairs: &[(String, String)]) -> Vec<&str> {
    pairs.iter().map(|(k, _)| k.as_str()).collect()
}

/// 读配置时路由表还没装载：游标原样保留，不能把上次驻留的位置丢掉。
#[test]
fn last_ip_preserved_before_routes_load() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // 明确装一张空表 = "路由还没装载"，免得别的用例先装好了。
    crate::pool::route::install(Vec::new(), Vec::new());
    let v = parse(
        r#"{"closeToTray":true,"mitm":true,"winRect":[0,0,800,600],"githubPAC":true,
                "lastIp":{"edge/content":"185.199.110.133","core/all":"20.27.177.114"}}"#,
    );
    assert!(v.close_to_tray && v.mitm && v.github_pac, "其他字段被连坐");
    // 对象形态经 serde 进 HashMap，顺序不保证；只验内容原样保留。
    let mut marks = v.last_ip.marks().to_vec();
    marks.sort();
    assert_eq!(
        marks,
        vec![
            ("core/all".to_string(), "20.27.177.114".to_string()),
            ("edge/content".to_string(), "185.199.110.133".to_string()),
        ],
        "路由表未装载时应原样保留"
    );

    // 数组形态同样保留；整段缺失 = 空表，键位等路由装载后由 set_last_ips 铺。
    let arr = parse(r#"{"lastIp":[["edge/io","1.2.3.4"]]}"#);
    assert_eq!(keys(arr.last_ip.marks()), ["edge/io"]);
    assert_eq!(arr.last_ip.marks()[0].1, "1.2.3.4");
    let none = parse(r#"{"mitm":true}"#);
    assert!(none.mitm);
    assert!(none.last_ip.marks().is_empty());
}

/// 路由表装好之后：按路由表顺序规范化，缺位补空串，表外旧键丢弃。
#[test]
fn last_ip_canonicalizes_once_routes_are_loaded() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let v = parse(r#"{"lastIp":{"core/all":"1.1.1.1","stale/key":"9.9.9.9"}}"#);
    let marks = v.last_ip.marks().to_vec();
    let expect = crate::pool::circle_keys();
    assert_eq!(marks.len(), expect.len(), "应铺满路由键位");
    assert_eq!(marks[0].0, expect[0]);
    assert!(
        marks.iter().all(|(k, _)| k != "stale/key"),
        "路由表外的旧键应丢: {marks:?}"
    );
    assert!(
        marks
            .iter()
            .all(|(_, ip)| ip != "1.1.1.1" && ip != "9.9.9.9"),
        "旧键的值不再沿用"
    );
}

#[test]
fn save_emits_full_schema_in_canonical_order() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let keys = crate::pool::circle_keys();
    let first = keys[0].clone();
    let f = SettingsFile {
        close_to_tray: true,
        mitm: false,
        win_rect: [1, 2, 3, 4],
        github_pac: false,
        proxy_backup: String::new(),
        last_pac: String::new(),
        last_ip: LastIpTable::from_marks(vec![(first.clone(), "140.82.114.6".to_string())]),
        worker_mirrors: vec![WorkerMirror {
            url: "https://my.worker".to_string(),
            on: true,
            trusted: false,
        }],
    };
    let json = serde_json::to_string_pretty(&f).unwrap();
    let saved: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        saved["lastIp"][&first], "140.82.114.6",
        "落盘应按路由键序且保留值:\n{json}"
    );
    assert_eq!(
        f.last_ip.marks().len(),
        keys.len(),
        "落盘 schema 应覆盖全部路由键"
    );
    // 落盘 → 再读必须回同值（写读闭环）
    let back = parse(&json);
    assert_eq!(back.last_ip.marks(), f.last_ip.marks());
    assert_eq!(back.win_rect, [1, 2, 3, 4]);
}

#[test]
fn single_bad_field_does_not_wipe_file() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::route::install(Vec::new(), Vec::new());
    // winRect 写坏：只回退该字段，开关与游标照读。
    let v = parse(
        r#"{"closeToTray":true,"mitm":true,"winRect":"oops","lastIp":{"edge/io":"1.1.1.1"}}"#,
    );
    assert!(v.close_to_tray && v.mitm, "一个字段笔误不得连坐整份配置");
    assert_eq!(v.win_rect, [0; 4]);
    assert_eq!(
        v.last_ip
            .marks()
            .iter()
            .find(|(k, _)| k == "edge/io")
            .map(|(_, ip)| ip.as_str()),
        Some("1.1.1.1")
    );
    // 非 JSON 垃圾才整体回默认
    assert!(!parse("not json").close_to_tray);
}

#[test]
fn worker_mirrors_roundtrip() {
    // 正常清单：url + 启停状态原样回读
    let v = parse(
        r#"{"workerMirrors":[{"url":"https://my.worker","on":true},{"url":"https://b.worker","on":false}]}"#,
    );
    assert_eq!(v.worker_mirrors.len(), 2);
    assert_eq!(v.worker_mirrors[0].url, "https://my.worker");
    assert!(v.worker_mirrors[0].on);
    assert!(!v.worker_mirrors[1].on);
    // 缺键 = 空注册表
    let v2 = parse("{}");
    assert!(v2.worker_mirrors.is_empty());
    // 整段写坏 = 回空表（不连坐其他字段）
    let v3 = parse(r#"{"workerMirrors":"oops","mitm":true}"#);
    assert!(v3.worker_mirrors.is_empty());
    assert!(v3.mitm);
}
