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

/// git 键的三态动作：我们写的才清/还原，别家或空一律不动。
#[test]
fn git_key_action_only_touches_ours() {
    let ours = "http://127.0.0.1:7810";
    // 我们写的 + 没备份 → 清除
    assert!(matches!(
        git_key_action(Some(ours), ours, ""),
        GitKeyAction::Unset
    ));
    // 我们写的 + 有备份 → 还原原值
    assert!(matches!(
        git_key_action(Some(ours), ours, "http://127.0.0.1:9999"),
        GitKeyAction::Restore(v) if v == "http://127.0.0.1:9999"
    ));
    // 别家的 → 不动
    assert!(matches!(
        git_key_action(Some("http://127.0.0.1:9999"), ours, ""),
        GitKeyAction::Keep
    ));
    // 没设 → 不动
    assert!(matches!(git_key_action(None, ours, ""), GitKeyAction::Keep));
}

/// 清场只认 last_pac：运行期间别家接管了 PAC（同形态），不许当自己的删掉。
#[test]
fn clear_only_exact_last_pac() {
    let ours = "http://127.0.0.1:7811/proxy.pac";
    assert!(pac_is_ours(ours, ours));
    assert!(
        !pac_is_ours("http://127.0.0.1:7890/proxy.pac", ours),
        "别家同形态不算我们的，退出时不许动"
    );
    // 我们换过端口：上次写的那个仍是我们的
    assert!(pac_is_ours(
        "http://127.0.0.1:9999/proxy.pac",
        "http://127.0.0.1:9999/proxy.pac"
    ));
    // 旧配置没有 last_pac：退回形状判定，老版本残留仍可清
    assert!(pac_is_ours(ours, ""));
    assert!(!pac_is_ours("http://corp.example/pac.js", ""));
}

/// 备份还原：别家同形态的备份必须还回去，只有"恰是我们写过的"才丢弃。
#[test]
fn restore_keeps_foreign_same_shape_backup() {
    let last = "http://127.0.0.1:7811/proxy.pac";
    assert!(
        !pac_is_ours("http://127.0.0.1:7890/proxy.pac", last),
        "同形态的别家备份必须还原，按形状丢掉等于备份白做"
    );
    assert!(!pac_is_ours("http://corp.example/pac.js", last));
    assert!(pac_is_ours(last, last), "上次写的自己不该还原(死 PAC)");
    // 旧配置：形状判定兜底，防把我们的旧地址写回系统
    assert!(pac_is_ours(last, ""));
    assert!(!pac_is_ours("http://corp.example/pac.js", ""));
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
    let expect = crate::pool::route::cursor_keys();
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
    let keys = crate::pool::route::cursor_keys();
    let first = keys[0].clone();
    let f = SettingsFile {
        close_to_tray: true,
        mitm: false,
        win_rect: [1, 2, 3, 4],
        github_pac: false,
        proxy_backup: String::new(),
        git_proxy_backup: String::new(),
        last_pac: String::new(),
        last_ip: LastIpTable::from_marks(vec![(first.clone(), "140.82.114.6".to_string())]),
        worker_mirrors: vec![WorkerMirror {
            url: "https://my.worker".to_string(),
            on: true,
            template: String::new(),
            invalid: false,
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

/// 手写注册表的常见写法都要认：只写 URL、snake_case 键名、省略 on、忘了数组括号。
#[test]
fn worker_mirrors_accepts_handwritten_forms() {
    let v = parse(r#"{"workerMirrors":["https://only-url.example"]}"#);
    assert_eq!(v.worker_mirrors.len(), 1);
    assert_eq!(v.worker_mirrors[0].url, "https://only-url.example");
    assert!(v.worker_mirrors[0].on, "只写 URL 应默认启用");

    let v = parse(r#"{"worker_mirrors":["https://snake.example"]}"#);
    assert_eq!(
        v.worker_mirrors.first().map(|m| m.url.as_str()),
        Some("https://snake.example"),
        "snake_case 键名也要认"
    );

    let v = parse(r#"{"workerMirrors":[{"url":"https://no-on.example"}]}"#);
    assert!(v.worker_mirrors[0].on, "手写省略 on 应默认启用");

    let v = parse(r#"{"workerMirrors":"https://one.example"}"#);
    assert_eq!(v.worker_mirrors.len(), 1, "单条忘了数组括号也收");

    let v = parse(r#"{"workerMirrors":123,"mitm":true}"#);
    assert!(v.worker_mirrors.is_empty(), "类型不对只丢这一段");
    assert!(v.mitm);
}

/// 坏 JSON 里字符串值自包含：语法坏的是别的字段，gitProxyBackup 要原样捞回；夹具用 serde_json::to_string 生成，与真实落盘一致。
#[test]
fn salvage_recovers_git_proxy_backup_from_broken_json() {
    let sep = char::from_u32(1).unwrap();
    let backup = format!("http://corp-proxy:8080{sep}http://corp2:3128");
    let escaped = serde_json::to_string(&backup).unwrap();
    let raw = format!(
        r#"{{"closeToTray":true, "winRect": [1, 2, "坏" 3], "gitProxyBackup": {escaped}}}"#
    );
    assert_eq!(
        super::salvage_str_field(&raw, "gitProxyBackup").as_deref(),
        Some(backup.as_str()),
        "键序在后/转义分隔符都要能捞"
    );
    assert_eq!(
        super::salvage_str_field(r#"{"git_proxy_backup":"http://snake:1"}"#, "git_proxy_backup")
            .as_deref(),
        Some("http://snake:1"),
        "snake_case 兼容写法也认"
    );
}

/// 值本身被语法错误截断 / 缺引号 / 缺字段：捞不回就 None，绝不编造。
#[test]
fn salvage_gives_up_on_truncated_or_missing_value() {
    assert_eq!(
        super::salvage_str_field(r#"{"gitProxyBackup":"http://trunc"#, "gitProxyBackup"),
        None
    );
    assert_eq!(
        super::salvage_str_field(r#"{"gitProxyBackup":null}"#, "gitProxyBackup"),
        None
    );
    assert_eq!(super::salvage_str_field(r#"{"mitm":true}"#, "gitProxyBackup"), None);
}

// ---- gitconfig 文件编辑（替代 git.exe 子进程，根治关机 0xc0000142 弹窗）----

/// 样本：gitport 会碰的键都在，外加用户自己的内容；值含 git 写法的转义路径。
const GITCFG_SAMPLE: &str = "[core]\n\trepositoryformatversion = 0\n\
[user]\n\tname = someone\n\
[http]\n\tproxy = http://127.0.0.1:9999\n\
[http \"https://github.com/\"]\n\tsslCAInfo = C:\\\\Users\\\\me\\\\ca.crt\n\
[http \"https://objects.githubusercontent.com/\"]\n\tsslCAInfo = C:\\\\Users\\\\me\\\\ca.crt\n";

/// 键值读回：多值键取最后；键名还原完整形式；转义路径反转义。
#[test]
fn gitcfg_parse_reads_pairs_and_unescapes() {
    let entries = super::git_parse(GITCFG_SAMPLE).unwrap();
    let pairs = super::git_pairs(&entries);
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("core.repositoryformatversion").as_deref(), Some("0"));
    assert_eq!(get("http.proxy").as_deref(), Some("http://127.0.0.1:9999"));
    // 键名与 git config --list 同语义：key 部分一律小写（subsection 原样）
    assert_eq!(
        get("http.https://github.com/.sslcainfo").as_deref(),
        Some("C:\\Users\\me\\ca.crt"),
        "git 写文件的 \\\\ 转义要还原成真实路径"
    );
    // 多值键取最后（HashMap 覆盖语义 = git --get 取最后一次出现）
    let two = "[http]\n\tproxy = a\n\tproxy = b\n";
    let pairs = super::git_pairs(&super::git_parse(two).unwrap());
    let last = pairs.iter().rev().find(|(k, _)| k == "http.proxy").unwrap();
    assert_eq!(last.1, "b");
}

/// 解析拒绝：非法转义与 git 同判，整份 Err → 调用方只读不动。
#[test]
fn gitcfg_parse_rejects_bad_escape() {
    assert!(super::git_parse("[http]\n\tproxy = C:\\Users\\x\n").is_err());
    assert!(super::git_parse("[http\n").is_err());
}

/// Set：替换最后一次出现；未编辑的行字节级原样保留。
#[test]
fn gitcfg_set_replaces_last_and_keeps_rest() {
    let entries = &mut super::git_parse(GITCFG_SAMPLE).unwrap();
    let target = super::git_split_key("http.proxy").unwrap();
    assert!(super::git_apply(entries, target, super::GitEdit::Set("http://127.0.0.1:7810".into())));
    let out: String = entries.iter().map(|e| e.raw.as_str()).collect();
    assert!(out.contains("proxy = http://127.0.0.1:7810\n"));
    assert!(!out.contains("http://127.0.0.1:9999"));
    // 未编辑行原样：core 段、user 段、CA 转义路径都在
    assert!(out.contains("[core]\n\trepositoryformatversion = 0\n"));
    assert!(out.contains("[user]\n\tname = someone\n"));
    assert!(out.contains("sslCAInfo = C:\\\\Users\\\\me\\\\ca.crt\n"));
    // 同值再 Set：无改动不落盘
    let entries = &mut super::git_parse("[http]\n\tproxy = http://127.0.0.1:7810\n").unwrap();
    assert!(!super::git_apply(
        entries,
        super::git_split_key("http.proxy").unwrap(),
        super::GitEdit::Set("http://127.0.0.1:7810".into())
    ));
}

/// Set：段在键不在 → 追加进段内；段也不在 → 文件尾建段头 + 键行。
#[test]
fn gitcfg_set_appends_and_creates_section() {
    // 段在键不在：插在段内最后（下一个段头之前）
    let entries = &mut super::git_parse("[https]\n\tkeep = 1\n[http]\n\ta = b\n").unwrap();
    assert!(super::git_apply(
        entries,
        super::git_split_key("https.proxy").unwrap(),
        super::GitEdit::Set("http://127.0.0.1:7810".into())
    ));
    let out: String = entries.iter().map(|e| e.raw.as_str()).collect();
    assert_eq!(
        out,
        "[https]\n\tkeep = 1\n\thttps-proxy-placeholder\n[http]\n\ta = b\n"
            .replace("https-proxy-placeholder", "proxy = http://127.0.0.1:7810")
    );
    // 段不在：文件尾建 [http "url"] 段头 + 键行
    let entries = &mut super::git_parse("[core]\n\tok = 1\n").unwrap();
    assert!(super::git_apply(
        entries,
        super::git_split_key("http.https://objects.githubusercontent.com/.sslCAInfo").unwrap(),
        super::GitEdit::Set("C:\\gp\\ca.crt".into())
    ));
    let out: String = entries.iter().map(|e| e.raw.as_str()).collect();
    assert!(out.starts_with("[core]\n\tok = 1\n"));
    assert!(out.contains("[http \"https://objects.githubusercontent.com/\"]\n\tsslcainfo = C:\\\\gp\\\\ca.crt\n"));
}

/// Unset：删最后一次出现；键不存在零改动（不许凭空创建文件内容）。
#[test]
fn gitcfg_unset_removes_last_only() {
    let two = "[http]\n\tproxy = mine\n\tproxy = ours\n\tkeep = 1\n";
    let entries = &mut super::git_parse(two).unwrap();
    assert!(super::git_apply(
        entries,
        super::git_split_key("http.proxy").unwrap(),
        super::GitEdit::Unset
    ));
    let out: String = entries.iter().map(|e| e.raw.as_str()).collect();
    assert_eq!(out, "[http]\n\tproxy = mine\n\tkeep = 1\n");
    let entries = &mut super::git_parse("[core]\n\tok = 1\n").unwrap();
    assert!(!super::git_apply(
        entries,
        super::git_split_key("http.proxy").unwrap(),
        super::GitEdit::Unset
    ));
}

/// 往返：接管写入的键值，读回一致——文件编辑与 git.exe 行为等价的底线。
#[test]
fn gitcfg_roundtrip_set_read_unset() {
    let ours = "http://127.0.0.1:7810";
    let entries = &mut super::git_parse(GITCFG_SAMPLE).unwrap();
    super::git_apply(entries, super::git_split_key("http.proxy").unwrap(), super::GitEdit::Set(ours.into()));
    super::git_apply(entries, super::git_split_key("http.proxy").unwrap(), super::GitEdit::Unset);
    let round = super::git_parse(&entries.iter().map(|e| e.raw.as_str()).collect::<String>()).unwrap();
    let pairs = super::git_pairs(&round);
    assert!(!pairs.iter().any(|(k, v)| k == "http.proxy" && v == ours), "写完即删后不许残留");
    // 没被编辑的 CA 键往返无损（转义 ↔ 反转义；键名与 git --list 同为小写）
    assert_eq!(
        pairs.iter().find(|(k, _)| k == "http.https://github.com/.sslcainfo").unwrap().1,
        "C:\\Users\\me\\ca.crt"
    );
}

/// 键名拆段：三种形态，URL 子节里的点不参与拆分。
#[test]
fn gitcfg_split_key_shapes() {
    assert_eq!(
        super::git_split_key("http.proxy"),
        Some(("http".into(), None, "proxy".into()))
    );
    assert_eq!(
        super::git_split_key("https.proxy"),
        Some(("https".into(), None, "proxy".into()))
    );
    assert_eq!(
        super::git_split_key("http.https://objects.githubusercontent.com/.sslCAInfo"),
        Some((
            "http".into(),
            Some("https://objects.githubusercontent.com/".into()),
            "sslcainfo".into()
        ))
    );
    assert_eq!(super::git_split_key("nopoint"), None);
    assert_eq!(super::git_split_key(".proxy"), None);
}

/// 防回归：GIT_CA_KEYS 与解析器输出的键名（key 部分一律小写）必须精确对得上——
/// 大小写错位会让 remove 判定查不到键，CA 键永远清不掉（2026-11-24 修复的既有 bug）。
#[test]
fn gitcfg_ca_keys_match_parsed_names() {
    for key in super::GIT_CA_KEYS {
        let (_, Some(sub), _) = super::git_split_key(key).unwrap() else {
            panic!("CA 键 {key:?} 拆不出子节");
        };
        // 子节按原样写回段头（URL 大小写敏感），键行用 git 实际写法（保留原大小写也能解析成小写键名）
        let file = format!("[http \"{sub}\"]\n\tsslCAInfo = v\n");
        let entries = super::git_parse(&file).unwrap();
        let names: Vec<String> = super::git_pairs(&entries).into_iter().map(|(k, _)| k).collect();
        assert!(
            names.contains(&key.to_string()),
            "常量键 {key:?} 与解析输出 {names:?} 对不上"
        );
    }
}

/// 非 UTF-8（GBK 中文 user.name）的 .gitconfig：整份解析必然失败，按字节兜底必须仍然
/// 清掉我们写的 http.proxy / sslCAInfo，同时把 GBK 字节原样留住（不能顺手转码重写）。
#[test]
fn git_byte_scrub_clears_ours_in_gbk_config() {
    let cfg = super::git_config_path();
    let dir = std::env::temp_dir().join(format!("gitport_gitcfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(".gitconfig");

    let ours = super::git_proxy_url();
    let ca = super::exe_dir().join("ca.crt").to_string_lossy().to_string();
    // 值必须按 git 的真实写法转义生成（Windows 路径的 \ → \\），手写单反斜杠会让测试假绿。
    let escaped_ours = super::git_escape_value(&ours);
    let escaped_ca = super::git_escape_value(&ca);
    let gbk_name: [u8; 4] = [0xD5, 0xC5, 0xC8, 0xFD]; // "张三" 的 GBK 编码，不是合法 UTF-8

    let mut raw: Vec<u8> = Vec::new();
    raw.extend_from_slice(b"[user]\n\tname = ");
    raw.extend_from_slice(&gbk_name);
    raw.extend_from_slice(b"\n\temail = me@example.com\n");
    raw.extend_from_slice(b"[http]\n\tproxy = ");
    raw.extend_from_slice(escaped_ours.as_bytes());
    raw.extend_from_slice(b"\n");
    raw.extend_from_slice(b"[http \"https://github.com/\"]\n\tsslCAInfo = ");
    raw.extend_from_slice(escaped_ca.as_bytes());
    raw.extend_from_slice(b"\n");
    std::fs::write(&path, &raw).unwrap();
    assert!(
        String::from_utf8_lossy(&raw).contains("\\\\"),
        "夹具必须带 git 的转义反斜杠（真实文件形态）: {}",
        String::from_utf8_lossy(&raw)
    );

    // 前提：整份解析确实因非 UTF-8 失败（git_map 内部就是 read_to_string），否则走不到兜底分支。
    assert!(
        std::fs::read_to_string(&path).is_err(),
        "夹具必须是真非 UTF-8，否则测的不是兜底路径"
    );

    assert!(super::git_byte_scrub(&path).unwrap(), "应清掉我们的键");
    let out = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains(&escaped_ours), "http.proxy 残留: {text}");
    assert!(!text.contains(&escaped_ca), "sslCAInfo 残留: {text}");
    assert!(text.contains("me@example.com"), "用户自己的键被误删: {text}");
    assert!(
        out.windows(gbk_name.len()).any(|w| w == gbk_name),
        "GBK 字节必须原样保留，不能被转码改写"
    );
    assert!(
        !super::git_byte_scrub(&path).unwrap(),
        "已清干净后再扫不应报告有改动"
    );

    let _ = cfg;
    let _ = std::fs::remove_dir_all(&dir);
}
