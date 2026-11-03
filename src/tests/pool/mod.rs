use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
// 全局串行锁在 pool::TEST_LOCK：路由表/串发表/连接池都是进程级全局态。

fn tmpdir() -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("gitport_test_{}_{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 生产路径：settings 只存注册表，存完由调用方用 removed 触发链对齐。
fn apply_worker_mirrors(list: Vec<crate::settings::WorkerMirror>) -> Result<(), String> {
    let (_, removed) = crate::settings::set_worker_mirrors(list)?;
    sync_custom_mirrors(&removed, true);
    Ok(())
}

/// 当前路由键下的候选 IP 序列（便捷断言用）。
fn target_ips(host: &str) -> Vec<String> {
    route::dial_targets(host)
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.ip)
        .collect()
}

#[test]
fn breakers_open_set_clear_by_host() {
    let raw = "raw.githubusercontent.com";
    let camo = "camo.githubusercontent.com";
    assert!(!CONTENT_BREAKER.open(raw));
    CONTENT_BREAKER.set(raw);
    assert!(CONTENT_BREAKER.open(raw));
    assert!(
        !CONTENT_BREAKER.open(camo),
        "熔断按 host 记账，不得串到同池其他域"
    );
    CONTENT_BREAKER.clear(raw);
    assert!(!CONTENT_BREAKER.open(raw));

    assert!(!MIRROR_BREAKER.open(camo));
    MIRROR_BREAKER.set(camo);
    assert!(MIRROR_BREAKER.open(camo));
    MIRROR_BREAKER.clear(camo);
    assert!(!MIRROR_BREAKER.open(camo));
}

#[test]
fn breaker_expired_entry_lazily_removed() {
    // ttl=0：set 后立即过期。open 必须判 false 并把条目清掉——过期条目沉淀在表里只进不出（修复前 open 只读不删）。
    let b = Breaker::new(0);
    b.set("expired.example");
    assert!(!b.open("expired.example"), "过期条目不得判熔断中");
    assert!(b.lock().is_empty(), "过期条目应被惰性清除");
    // 活条目不受影响：open 通过且仍留在表里
    let live = Breaker::new(600);
    live.set("live.example");
    assert!(live.open("live.example"));
    assert!(
        live.lock().contains_key("live.example"),
        "活条目应保留在表里"
    );
    live.clear("live.example");
    assert!(!live.open("live.example"));
}

#[test]
fn bad_route_row_does_not_wipe_table() {
    // 单行写坏只丢那一行，其余路由与镜像链原样保留；原文件先备份。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "routes": [
    {"match": "(.*\\.)?github\\.com", "pac": "github.com", "plans": [{"ip": "1.2.3.4", "sni": "baidu.com"}]},
    {"match": "bad\\.example", "fallback": "mirror2", "plans": []}
  ],
  "mirrors": {"raw.githubusercontent.com": ["https://v4.gh-proxy.org"]}
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));

    let ips = target_ips("github.com");
    assert_eq!(ips[0], "1.2.3.4", "用户条目必须在前且不被连坐");
    assert!(ips.len() > 1, "种子应正常补边: {ips:?}");
    assert!(route::route_for("bad.example").is_none(), "坏行应丢弃");
    assert_eq!(
        mirror_chain("raw.githubusercontent.com"),
        vec!["https://v4.gh-proxy.org".to_string()],
        "镜像链必须保留"
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("hosts[bad.example] 丢弃")),
        "日志应指明坏的是哪行: {:?}",
        seen.lock().unwrap()
    );
    assert!(dir.join("routes.json.bak").exists(), "有行写坏应备份原文件");
}

#[test]
fn legacy_plans_file_renamed_to_routes() {
    // 老用户的 plans.json 必须原样搬成 routes.json：表不能被种子顶掉，原表留 .bak。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("plans.json"),
        r#"{
  "routes": [
    {"match": "(.*\\.)?github\\.com", "pac": "github.com", "plans": [{"ip": "9.9.9.1", "sni": "baidu.com"}]}
  ],
  "mirrors": {"raw.githubusercontent.com": ["https://v4.gh-proxy.org"]}
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));

    assert!(!dir.join("plans.json").exists(), "旧名应被搬走, 不能留两份");
    assert!(dir.join("routes.json").exists(), "新名必须出现");
    assert!(dir.join("routes.json.bak").exists(), "搬之前应留 .bak 保险");
    let ips = target_ips("github.com");
    assert_eq!(ips[0], "9.9.9.1", "老表必须原样生效且在前, 不能被种子顶掉");
    assert!(ips.len() > 1, "种子应正常补边: {ips:?}");
    assert_eq!(
        mirror_chain("raw.githubusercontent.com"),
        vec!["https://v4.gh-proxy.org".to_string()],
        "镜像链也要跟着搬过来"
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("已更名为 routes.json")),
        "日志应说明改名: {:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn existing_routes_file_wins_over_legacy() {
    // 新表已在时旧名必须被忽略：否则用户改 plans.json 会"改了但不生效"。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{"routes": [{"match": "(.*\\.)?github\\.com", "pac": "github.com", "plans": [{"ip": "1.1.1.1"}]}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("plans.json"),
        r#"{"routes": [{"match": "(.*\\.)?github\\.com", "pac": "github.com", "plans": [{"ip": "2.2.2.2"}]}]}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);

    let ips = target_ips("github.com");
    assert_eq!(ips[0], "1.1.1.1", "routes.json 是唯一权威, 旧名不得覆盖");
    assert!(
        !ips.contains(&"2.2.2.2".to_string()),
        "旧名条目不得混入: {ips:?}"
    );
    assert!(
        dir.join("plans.json").exists(),
        "旧文件不由程序删, 留给用户处理"
    );
}

#[test]
fn former_direct_domains_now_pooled() {
    // v2：原 direct 4 域实测后进池（§8），hosts 行保留 pac 但不再直连。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    for host in [
        "objects-origin.githubusercontent.com",
        "uploads.github.com",
        "viewscreen.githubusercontent.com",
        "api.mcp.github.com",
    ] {
        assert!(route::is_managed(host), "{host} 应进代理");
        assert_eq!(
            route::master_route(host, "GET", "/"),
            route::Route::Pool,
            "{host} 应走池"
        );
        assert!(!target_ips(host).is_empty(), "{host} 应有种子补的 IP 边");
    }
    assert!(route::is_managed("github.com"), "普通域名照常进代理");
}

#[test]
fn legacy_pools_migrate_to_route_rows() {
    // 旧三池 → v2：完整行集，IP 摊成节点，direct/real/donor 标志按 v2 语义处置。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "core": [
    {"ip": "1.2.3.4", "sni": "ech", "成功次数": "9/9", "分数": 99}
  ],
  "edge": [
    {"ip": "140.82.112.29", "sni": "real"},
    {"ip": "185.199.108.154", "sni": "sni"},
    {"ip": "185.199.109.153", "sni": "sni"},
    {"ip": "185.199.110.133", "sni": "baidu.com"}
  ]
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);

    let github = target_ips("github.com");
    assert!(
        github.contains(&"1.2.3.4".to_string()),
        "core 摊到 github.com: {github:?}"
    );
    let row = route::route_for("github.com").expect("core 应迁到 github.com 行");
    assert_eq!(row.pac.as_deref(), Some("github.com"));

    let content = target_ips("avatars.githubusercontent.com");
    assert!(
        content.contains(&"185.199.110.133".to_string()),
        "133 段服务内容域: {content:?}"
    );
    assert!(
        !content.contains(&"185.199.108.154".to_string()),
        "154 段不再混进内容域(verify 锚点不同): {content:?}"
    );
    assert!(route::is_content("avatars.githubusercontent.com"));
    assert_eq!(
        route::fallback_for("avatars.githubusercontent.com"),
        route::Fallback::MirrorDns
    );

    let assets = target_ips("github.githubassets.com");
    assert!(
        assets.contains(&"185.199.108.154".to_string()),
        "assets 行: {assets:?}"
    );

    let io = target_ips("octocat.github.io");
    assert!(io.contains(&"185.199.109.153".to_string()), "io 行: {io:?}");

    let app = target_ips("api.githubapp.com");
    assert!(
        app.contains(&"140.82.112.29".to_string()),
        "githubapp 行: {app:?}"
    );

    // 启动只读不写：旧格式文件原样留在盘上，迁移只发生在运行时表里。
    let b = std::fs::read_to_string(dir.join("routes.json")).unwrap();
    assert!(
        b.contains("\"core\"") && !b.contains("\"hosts\""),
        "手改表不应被启动重写: {b}"
    );
}

#[test]
fn seed_topup_appends_missing_and_keeps_order() {
    // 用户条目在前，种子只补缺；已存在的 IP 不重复。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "routes": [
    {"match": ".*\\.githubusercontent\\.com", "content": true, "fallback": "mirror",
     "plans": [{"ip": "9.9.9.9", "sni": "baidu.com"}]}
  ]
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));
    let ips = target_ips("raw.githubusercontent.com");
    assert_eq!(ips[0], "9.9.9.9", "用户手排顺序保留, 补缺只追加");
    assert!(ips.len() > 1, "应叠加种子: {ips:?}");
    assert!(
        seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
        "补缺应打一行日志"
    );
    // 补缺只进内存：手改文件保持原样，启动不做任何规范化重写。
    let b = std::fs::read_to_string(dir.join("routes.json")).unwrap();
    assert!(
        !b.contains("185.199.108-111.133"),
        "启动不应改写手改表: {b}"
    );
}

#[test]
fn encode_routes_roundtrip() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let rows: Vec<route::RouteRow> = [
        r#"{"key":"github.com","pac":"github.com"}"#,
        r#"{"key":"*.githubusercontent.com","pac":"githubusercontent.com","content":true,"fallback":"mirror"}"#,
    ]
    .iter()
    .map(|j| route::RouteRow::new(serde_json::from_str(j).unwrap()).unwrap())
    .collect();
    let nodes: Vec<route::IpNode> = [
        r#"{"ip":"1.2.3.4","sni":"baidu.com","hosts":["github.com"]}"#,
        r#"{"ip":"5.6.7.8","sni":"baidu.com","hosts":["github.com"]}"#,
        r#"{"ip":"185.199.110.133","hosts":["*.githubusercontent.com"]}"#,
    ]
    .iter()
    .map(|j| {
        let spec: route::IpSpec = serde_json::from_str(j).unwrap();
        build_node(spec).unwrap()
    })
    .collect();
    route::install(rows, nodes);
    let mut mirrors = HashMap::new();
    mirrors.insert(
        "raw.githubusercontent.com".to_string(),
        vec![
            "https://axisnow.gh-proxy.org".to_string(),
            "https://v4.gh-proxy.org".to_string(),
        ],
    );
    let b = encode_routes(&mirrors);
    // 节点条目必须单行
    for line in b.lines() {
        let t = line.trim();
        if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
            panic!("条目被展开成多行: {line:?}");
        }
    }
    assert!(b.contains("\"mirrors_small\""), "镜像链板块应落盘: {b}");
    let back: serde_json::Value = serde_json::from_str(&b).unwrap();
    let hosts = back["hosts"].as_object().expect("hosts 应是对象(域名作键)");
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts["*.githubusercontent.com"]["content"], true);
    assert_eq!(hosts["*.githubusercontent.com"]["fallback"], "mirror");
    let ips = back["ips"].as_array().expect("ips 应是数组");
    assert_eq!(ips.len(), 3);
    assert_eq!(ips[1]["ip"], "5.6.7.8");
    assert_eq!(ips[2]["sni"], "");
    assert_eq!(
        back["mirrors_small"]["raw.githubusercontent.com"]
            .as_array()
            .map(|a| a.len()),
        Some(2)
    );
}

#[test]
fn cursor_park_is_memory_only_and_freezes_order() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    let row = route::route_for("github.com").expect("github.com 应有路由");
    let key = row.key.clone();
    let base = target_ips("github.com");
    assert!(base.len() >= 3, "初始表过小: {}", base.len());
    let head_before = base[0].clone();
    let target = base[2].clone();
    assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
    let file_before = std::fs::read_to_string(dir.join("routes.json")).unwrap();
    cursor_note("github.com", &target, true, 1);
    // 表序冻结:成功驻留只动内存游标,不动物理顺序、不触发写盘
    assert_eq!(target_ips("github.com")[0], head_before, "表序冻结");
    assert_eq!(
        std::fs::read_to_string(dir.join("routes.json")).unwrap(),
        file_before,
        "游标驻留零写盘"
    );
    let g = SERIAL.lock().unwrap();
    assert_eq!(
        g.as_ref().unwrap().cursor.get(&key).map(String::as_str),
        Some(target.as_str()),
        "游标应驻留 target"
    );
}

#[test]
fn custom_mirrors_align() {
    // 清单对齐：启用的置前（按清单序），停用的移除，其余成员相对顺序不变
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    m.insert(
        "github.com".into(),
        vec![
            "https://pub1".into(),
            "https://customA".into(),
            "https://pub2".into(),
        ],
    );
    m.insert(
        "raw.githubusercontent.com".into(),
        vec!["https://pub1".into()],
    );
    let enabled = vec!["https://customB".to_string(), "https://customA".to_string()];
    let disabled = vec!["https://customC".to_string()];
    assert!(align_custom_mirrors(
        &mut m, &enabled, &disabled, &enabled, &disabled
    ));
    // github.com：链里没有的 customB 追加到链尾；已在链中的成员位置不动
    assert_eq!(
        m["github.com"],
        vec![
            "https://pub1".to_string(),
            "https://customA".to_string(),
            "https://pub2".to_string(),
            "https://customB".to_string(),
        ]
    );
    // raw：customB、customA 都追加到链尾，customC 本就不在链中无影响
    assert_eq!(
        m["raw.githubusercontent.com"],
        vec![
            "https://pub1".to_string(),
            "https://customB".to_string(),
            "https://customA".to_string()
        ]
    );
    // 幂等：再跑一次无变更
    assert!(!align_custom_mirrors(
        &mut m, &enabled, &disabled, &enabled, &disabled
    ));
    // 删除：customB 移出启用清单（进 disabled）→ 从全部链消失；其余不动
    let enabled2 = vec!["https://customA".to_string()];
    let disabled2 = vec!["https://customB".to_string(), "https://customC".to_string()];
    assert!(align_custom_mirrors(
        &mut m, &enabled2, &disabled2, &enabled2, &disabled2
    ));
    assert!(!m["github.com"].iter().any(|x| x == "https://customB"));
    assert_eq!(
        m["github.com"],
        vec![
            "https://pub1".to_string(),
            "https://customA".to_string(),
            "https://pub2".to_string(),
        ]
    );
}

#[test]
fn worker_chain_replace_old_url() {
    // 换地址：新地址追加到链尾的同时旧地址必须移除（防新旧并存）
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    m.insert(
        "github.com".into(),
        vec!["https://old.worker".into(), "https://a.example".into()],
    );
    let new = vec!["https://new.worker".to_string()];
    let old = vec!["https://old.worker".to_string()];
    align_custom_mirrors(&mut m, &new, &old, &new, &old);
    let c = &m["github.com"];
    assert_eq!(
        c,
        &vec![
            "https://a.example".to_string(),
            "https://new.worker".to_string()
        ]
    );
    assert!(!c.iter().any(|x| x.contains("old.worker")));
}

/// 开关语义：启动/关闭只摘大文件链；小文件链全量按序保留(off 的也留)。
#[test]
fn toggle_gates_big_file_chains_only() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "core": [],
  "mirrors_big":   {"objects.githubusercontent.com": ["https://on.example", "https://off.example"]},
  "mirrors_small": {"raw.githubusercontent.com": ["https://on.example"]}
}"#,
    )
    .unwrap();
    crate::settings::save_worker_mirrors(vec![
        crate::settings::WorkerMirror {
            url: "https://on.example".into(),
            on: true,
            trusted: false,
        },
        crate::settings::WorkerMirror {
            url: "https://off.example".into(),
            on: false,
            trusted: false,
        },
    ]);
    serial_load(&dir, Vec::new(), None);
    sync_custom_mirrors(&[], true);
    let big = mirror_chain("objects.githubusercontent.com");
    assert!(
        big.contains(&"https://on.example".to_string()),
        "启用镜留在大文件链: {big:?}"
    );
    assert!(
        !big.contains(&"https://off.example".to_string()),
        "关闭镜从大文件链摘除: {big:?}"
    );
    let small = mirror_chain("raw.githubusercontent.com");
    assert!(
        small.contains(&"https://on.example".to_string())
            && small.contains(&"https://off.example".to_string()),
        "小文件链不受开关影响, 关闭镜按链序保留: {small:?}"
    );
    crate::settings::save_worker_mirrors(Vec::new());
}

/// 双字典合并优先级：同 host 三处都有时，mirrors_big/small 赢、旧 mirrors 不覆盖；仅旧字典有的 host 照常并入（升级兼容的钉子）。
#[test]
fn merged_chains_prefers_typed_dictionaries_over_legacy() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    // 隔离：.example 自建镜像会被收编进注册表并跨测试持久化，先清空。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "core": [],
  "mirrors_big":   {"objects.githubusercontent.com": ["https://big.example"]},
  "mirrors_small": {"raw.githubusercontent.com": ["https://small.example"]},
  "mirrors": {
    "objects.githubusercontent.com": ["https://legacy-wrong.example"],
    "raw.githubusercontent.com": ["https://legacy-wrong.example"],
    "gist.githubusercontent.com": ["https://legacy-only.example"]
  }
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    // 断言只锁优先级：旧 mirrors 不得覆盖新字典，新字典成员居首，旧字典独有成员追加在尾。
    let big = mirror_chain("objects.githubusercontent.com");
    assert_eq!(
        big.first(),
        Some(&"https://big.example".to_string()),
        "mirrors_big 赢, 旧 mirrors 不得覆盖(legacy-wrong 缺席且 big 居首): {big:?}"
    );
    assert!(
        !big.contains(&"https://legacy-wrong.example".to_string()),
        "旧 mirrors 不得覆盖新字典已声明的 host: {big:?}"
    );
    let small = mirror_chain("raw.githubusercontent.com");
    assert_eq!(
        small.first(),
        Some(&"https://small.example".to_string()),
        "mirrors_small 赢: {small:?}"
    );
    assert!(
        !small.contains(&"https://legacy-wrong.example".to_string()),
        "旧 mirrors 不得覆盖新字典已声明的 host: {small:?}"
    );
    let legacy = mirror_chain("gist.githubusercontent.com");
    assert!(
        legacy.contains(&"https://legacy-only.example".to_string()),
        "仅旧字典有的 host 照常并入: {legacy:?}"
    );
    // 清场：正规路径删除自建镜像（注册表 + 全部链），不给后续测试留全局残留。
    apply_worker_mirrors(Vec::new()).ok();
}

/// 全新安装+添加镜像 → 启用镜像必须落进全部内容域链（v0.5.0 回归：空表遍历不到，镜像只进注册表）。
#[test]
fn fresh_install_mirror_lands_in_all_chains() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(dir.join("routes.json"), r#"{"core": []}"#).unwrap();
    serial_load(&dir, Vec::new(), None);
    assert!(
        mirror_chain("raw.githubusercontent.com").is_empty(),
        "前置: 全新安装链应为空"
    );
    // 模拟 UI 添加并启用一个镜像：settings 存 + 调用方触发链对齐。
    apply_worker_mirrors(vec![crate::settings::WorkerMirror {
        url: "https://my-worker.example.com".to_string(),
        on: true,
        trusted: false,
    }])
    .unwrap();
    for h in CONTENT_HOSTS {
        let c = mirror_chain(h);
        assert!(
            c.contains(&"https://my-worker.example.com".to_string()),
            "{h} 链必须收到启用中的镜像(全新安装也必须生效): {c:?}"
        );
    }
    // 清场：正规路径删除，注册表与全部链恢复空。
    apply_worker_mirrors(Vec::new()).ok();
}

#[test]
fn mirror_chain_load_and_topup() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    // 隔离：自定义镜像注册表经 settings.json 跨进程持久化（上一轮 serial_load 收养的自建镜像会留在里面），不清空的话 sync_custom_mirrors 会把它们追加进本测试的链。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "core": [{"ip": "140.82.112.3", "sni": "baidu.com"}],
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org", "https://my-self.example.com"],
    "not-a-content.host": ["https://v4.gh-proxy.org"]
  }
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));
    // 镜像链数据权威：用户写什么用什么（含自部署镜像），不白名单、不自动补缺
    let raw_chain = mirror_chain("raw.githubusercontent.com");
    assert_eq!(
        raw_chain,
        vec![
            "https://v4.gh-proxy.org".to_string(),
            "https://my-self.example.com".to_string()
        ],
        "用户链原样保留(含自部署镜像): {raw_chain:?}"
    );
    // 缺链 host：注册表有启用镜像时按 CONTENT_HOSTS 铺键并对齐全量(自建镜像进所有链是既有设计)；无启用镜像时该 host 真正无链。
    let media = mirror_chain("media.githubusercontent.com");
    assert_eq!(
        media,
        vec![
            "https://v4.gh-proxy.org".to_string(),
            "https://my-self.example.com".to_string()
        ],
        "media 无自带链, 应被注册表对齐填成启用镜像全量: {media:?}"
    );
    // 启动不写盘：手改文件原样保留（未知 host 只在运行时表里被丢）。
    let b = std::fs::read_to_string(dir.join("routes.json")).unwrap();
    assert!(
        b.contains("not-a-content.host"),
        "启动不应改写手改表: {b}"
    );
    let mut new_chain = raw_chain.clone();
    new_chain.reverse();
    assert!(
        set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
        "新链应写入"
    );
    // 运行时改链才落盘：此刻文件被规范化，未知 host 丢弃、镜像链入库。
    let b = std::fs::read_to_string(dir.join("routes.json")).unwrap();
    assert!(
        !b.contains("not-a-content.host"),
        "改链落盘后未知 host 应丢弃: {b}"
    );
    assert!(
        b.contains("\"mirrors_small\""),
        "镜像链应落盘(raw 为小文件域): {b}"
    );
    assert!(
        !set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
        "同链应 no-op"
    );
    assert!(
        !set_mirror_chain("github.githubassets.com", &new_chain, "测试"),
        "非内容域 host 应拒收"
    );
}

#[test]
fn cursor_advance_on_failure_then_park_on_success() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    let row = route::route_for("github.com").expect("github.com 应有路由");
    let key = row.key.clone();
    let base = target_ips("github.com");
    assert!(base.len() >= 6, "初始表过小: {}", base.len());
    let head = base[0].clone();
    let next = base[1].clone();

    // 失败:记号前移到圈中下一候选
    cursor_note("github.com", &head, false, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&key).map(String::as_str),
            Some(next.as_str()),
            "失败后记号应前移到下一候选"
        );
    }

    // 成功:记号驻留;表序全程未变
    cursor_note("github.com", &next, true, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&key).map(String::as_str),
            Some(next.as_str())
        );
    }
    let now = target_ips("github.com");
    assert!(
        now.iter().zip(base.iter()).all(|(a, b)| a == b),
        "表序应冻结(游标不重排)"
    );
}

/// 成功清黑：421 拉黑的边被一次成功拨号/请求洗白。
#[test]
fn success_clears_bad_edge() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    let ip = target_ips("github.com")[0].clone();
    edges::mark_reject(&ip, "github.com");
    assert!(edges::is_bad(&ip, "github.com"));
    cursor_note("github.com", &ip, true, 1);
    assert!(!edges::is_bad(&ip, "github.com"), "成功必须清黑");
}

/// 串发重试引擎实机圈：TCP 拒 → 沿圈到活条 → 驻留 + 死亡退避。
// 串行锁有意全程持有: 测试期间独占全局表, 跨 await 是本意。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn serial_dial_rotates_on_failure_and_parks_on_success() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    // 只有 127.0.0.2 在监听；127.0.0.1 的同端口连接会被立刻拒绝。
    let Ok(ln) = tokio::net::TcpListener::bind("127.0.0.2:0").await else {
        eprintln!("跳过: 本机绑不了 127.0.0.2(回环 /8 行为不同), 串发实测留给真机");
        return;
    };
    let port = ln.local_addr().unwrap().port();
    dial::set_dial_port(port);
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{"core":[{"ip":"127.0.0.1","sni":"a.example"},{"ip":"127.0.0.2","sni":"a.example"}]}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);

    let (conn, ip, _) = serial_dial_skip(
        DialSkip {
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            slot: 1,
            crew: None,
        },
        None,
    )
    .await
    .expect("第二个候选能拨通");
    drop(conn);
    assert_eq!(ip, "127.0.0.2", "被拒的候选应垫底, 活着的那条胜出");
    {
        let g = SERIAL.lock().unwrap();
        let t = g.as_ref().unwrap();
        assert_eq!(
            t.cursor.get("github.com").map(String::as_str),
            Some("127.0.0.2"),
            "成功必须驻留记号(下次从它起步)"
        );
        assert!(t.dead.contains_key("127.0.0.1"), "TCP 层失败应进死亡退避表");
    }

    // 第二次：从驻留记号起步，直接拿 127.0.0.2（不再先撞被拒的那条）。
    let (conn, ip, _) = serial_dial_skip(
        DialSkip {
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            slot: 1,
            crew: None,
        },
        None,
    )
    .await
    .expect("驻留后应直接命中");
    drop(conn);
    assert_eq!(ip, "127.0.0.2");
    dial::set_dial_port(0); // 复位，别影响别的测试
}

/// 种子表本身就是二部图格式：新装直接可用，不再依赖旧三池迁移。
#[test]
fn seeds_are_new_routes_format() {
    let seeds = seed_db();
    assert!(
        seeds.hosts.len() >= 10,
        "种子 hosts 行过少: {}",
        seeds.hosts.len()
    );
    let github_nodes: Vec<&route::IpSpec> = seeds
        .ips
        .iter()
        .filter(|n| n.hosts.iter().any(|h| h == "github.com"))
        .collect();
    assert!(!github_nodes.is_empty(), "主站种子 IP 不能为空");
    for spec in &seeds.ips {
        route::expand_ip(&spec.ip).expect("种子每条 ip 都必须能展开");
    }
    for spec in &seeds.hosts {
        route::RouteRow::new(spec.clone()).expect("种子每行都必须能编译");
    }
}

/// 拨号顺序：游标 IP 优先；其余按实测延迟升序；未测的垫底并保持表序。
#[test]
fn dial_order_cursor_first_then_latency_asc() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mk = |ip: &str| route::NodeIp {
        ip: ip.into(),
        sni: String::new(),
        verify: String::new(),
    };
    let circle = vec![mk("1.1.1.1"), mk("2.2.2.2"), mk("3.3.3.3"), mk("4.4.4.4")];
    latency::install(HashMap::new());
    latency::seed("2.2.2.2", 300);
    latency::seed("3.3.3.3", 200);
    latency::seed("4.4.4.4", 100);
    assert_eq!(dial_order(&circle, Some("1.1.1.1")), vec![0, 3, 2, 1]);
    assert_eq!(dial_order(&circle, None), vec![3, 2, 1, 0]);
    assert_eq!(dial_order(&circle, Some("3.3.3.3")), vec![2, 3, 1, 0]);
    latency::install(HashMap::new());
}
