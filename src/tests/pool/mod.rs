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
    sync_custom_mirrors(&removed);
    Ok(())
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
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("plans.json"),
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

    let good = route::route_for("github.com").expect("好行必须保留");
    assert_eq!(good.plans[0].ip, "1.2.3.4", "好行的用户条目不能被连坐");
    assert!(route::route_for("bad.example").is_none(), "坏行应丢弃");
    assert_eq!(
        mirror_chain("raw.githubusercontent.com"),
        vec!["https://v4.gh-proxy.org".to_string()],
        "镜像链必须保留"
    );
    assert!(
        seen.lock().unwrap().iter().any(|l| l.contains("routes[1] 丢弃")),
        "日志应指明坏的是第几行: {:?}",
        seen.lock().unwrap()
    );
    assert!(dir.join("plans.json.bak").exists(), "有行写坏应备份原文件");
}

#[test]
fn direct_rows_bypass_proxy() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tmpdir();
    serial_load(&dir, Vec::new(), None);
    for host in [
        "objects-origin.githubusercontent.com",
        "uploads.github.com",
        "viewscreen.githubusercontent.com",
        "api.mcp.github.com",
    ] {
        assert!(!route::is_managed(host), "{host} 不应进代理");
        assert_eq!(
            route::master_route(host, "GET", "/"),
            route::Route::System,
            "{host} 应短路为直连"
        );
    }
    assert!(route::is_managed("github.com"), "普通域名照常进代理");
}

#[test]
fn legacy_pools_migrate_to_route_rows() {
    // 旧三池 → routes：按段拆回各自槽位，sni 原样，未知字段丢弃，落盘换成新格式。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
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

    let core = route::route_for("github.com").expect("core 应迁到 github.com 行");
    assert_eq!(core.plans[0].ip, "1.2.3.4");
    assert_eq!(core.plans[0].sni, "ech", "sni 原样透传");

    let content = route::route_for("avatars.githubusercontent.com").expect("内容域行");
    assert!(content.flags.content && content.fallback == route::Fallback::MirrorDns);
    assert!(content.plans.iter().any(|p| p.ip == "185.199.110.133"));
    assert!(
        !content.plans.iter().any(|p| p.ip == "185.199.108.154"),
        "伪装腿不该带 154: {:?}",
        content.plans
    );
    assert!(
        content.real_plans.iter().any(|p| p.ip == "185.199.108.154"),
        "真名腿才带 154: {:?}",
        content.real_plans
    );

    let assets = route::route_for("github.githubassets.com").expect("assets 行");
    assert!(assets.flags.donor);
    assert!(assets.plans.iter().any(|p| p.ip == "185.199.108.154"));

    let io = route::route_for("octocat.github.io").expect("io 行");
    assert!(io.plans.iter().any(|p| p.ip == "185.199.109.153"));

    let app = route::route_for("api.githubapp.com").expect("auth 行");
    assert!(app.plans.iter().any(|p| p.ip == "140.82.112.29"));

    let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    let back: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert!(back.get("routes").is_some(), "应写回新格式: {b}");
    assert!(back.get("core").is_none() && back.get("edge").is_none());
    assert!(!b.contains("成功次数") && !b.contains("分数"));
}

#[test]
fn seed_topup_appends_missing_and_keeps_order() {
    // 用户条目在前，种子只往尾部补缺；已存在的 IP 不重复。
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
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
    let row = route::route_for("raw.githubusercontent.com").expect("内容域行");
    assert_eq!(row.plans[0].ip, "9.9.9.9", "用户手排顺序保留, 补缺只追加尾部");
    assert!(row.plans.len() > 1, "应叠加种子: {:?}", row.plans);
    assert!(
        seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
        "补缺应打一行日志"
    );
    let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    assert!(b.contains("185.199.110.133"), "补缺应落盘: {b}");
}

#[test]
fn encode_plans_roundtrip() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    route::install(vec![
        route::RouteRow::new(
            route::RouteSpec {
                matcher: r"(.*\.)?github\.com".into(),
                pac: Some("github.com".into()),
                action: None,
                real: false,
                content: false,
                donor: false,
                fallback: None,
                plans: vec![
                    SerialPlan { ip: "1.2.3.4".into(), sni: "baidu.com".into() },
                    SerialPlan { ip: "5.6.7.8".into(), sni: "baidu.com".into() },
                ],
                real_plans: Vec::new(),
            },
        )
        .unwrap(),
        route::RouteRow::new(
            route::RouteSpec {
                matcher: r".*\.githubusercontent\.com".into(),
                pac: Some("githubusercontent.com".into()),
                action: None,
                real: false,
                content: true,
                donor: false,
                fallback: Some("mirror".into()),
                plans: vec![SerialPlan { ip: "185.199.110.133".into(), sni: String::new() }],
                real_plans: vec![SerialPlan { ip: "185.199.108.154".into(), sni: String::new() }],
            },
        )
        .unwrap(),
    ]);
    let mut mirrors = HashMap::new();
    mirrors.insert(
        "raw.githubusercontent.com".to_string(),
        vec!["https://axisnow.gh-proxy.org".to_string(), "https://v4.gh-proxy.org".to_string()],
    );
    let b = encode_plans(&mirrors);
    // IP 条目必须单行
    for line in b.lines() {
        let t = line.trim();
        if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
            panic!("条目被展开成多行: {line:?}");
        }
    }
    assert!(b.contains("\"mirrors_small\""), "镜像链板块应落盘: {b}");
    let back: serde_json::Value = serde_json::from_str(&b).unwrap();
    let rows = back["routes"].as_array().expect("routes 应是数组");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["match"], "(.*\\.)?github\\.com");
    assert_eq!(rows[0]["plans"][1]["ip"], "5.6.7.8");
    assert_eq!(rows[1]["content"], true);
    assert_eq!(rows[1]["fallback"], "mirror");
    assert_eq!(rows[1]["realPlans"][0]["ip"], "185.199.108.154");
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
    let dir = tmpdir();
    serial_load(&dir, Vec::new(), None);
    let row = route::route_for("github.com").expect("github.com 应有路由");
    let pattern = row.pattern.clone();
    let plans = row.plans.clone();
    assert!(plans.len() >= 3, "初始表过小: {}", plans.len());
    let head_before = plans[0].ip.clone();
    let target = plans[2].ip.clone();
    assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
    let file_before = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    cursor_note("github.com", &target, true, 1);
    // 表序冻结:成功驻留只动内存游标,不动物理顺序、不触发写盘
    assert_eq!(
        route::route_for("github.com").unwrap().plans[0].ip,
        head_before,
        "表序冻结"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("plans.json")).unwrap(),
        file_before,
        "游标驻留零写盘"
    );
    let g = SERIAL.lock().unwrap();
    assert_eq!(
        g.as_ref().unwrap().cursor.get(&pattern).map(String::as_str),
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
    m.insert("raw.githubusercontent.com".into(), vec!["https://pub1".into()]);
    let enabled = vec!["https://customB".to_string(), "https://customA".to_string()];
    let disabled = vec!["https://customC".to_string()];
    assert!(align_custom_mirrors(&mut m, &enabled, &disabled, &enabled, &disabled));
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
        vec!["https://pub1".to_string(), "https://customB".to_string(), "https://customA".to_string()]
    );
    // 幂等：再跑一次无变更
    assert!(!align_custom_mirrors(&mut m, &enabled, &disabled, &enabled, &disabled));
    // 删除：customB 移出启用清单（进 disabled）→ 从全部链消失；其余不动
    let enabled2 = vec!["https://customA".to_string()];
    let disabled2 = vec!["https://customB".to_string(), "https://customC".to_string()];
    assert!(align_custom_mirrors(&mut m, &enabled2, &disabled2, &enabled2, &disabled2));
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
    m.insert("github.com".into(), vec!["https://old.worker".into(), "https://a.example".into()]);
    let new = vec!["https://new.worker".to_string()];
    let old = vec!["https://old.worker".to_string()];
    align_custom_mirrors(&mut m, &new, &old, &new, &old);
    let c = &m["github.com"];
    assert_eq!(
        c,
        &vec!["https://a.example".to_string(), "https://new.worker".to_string()]
    );
    assert!(!c.iter().any(|x| x.contains("old.worker")));
}

/// 开关语义：启动/关闭只摘大文件链；小文件链全量按序保留(off 的也留)。
#[test]
fn toggle_gates_big_file_chains_only() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
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
    sync_custom_mirrors(&[]);
    let big = mirror_chain("objects.githubusercontent.com");
    assert!(big.contains(&"https://on.example".to_string()), "启用镜留在大文件链: {big:?}");
    assert!(!big.contains(&"https://off.example".to_string()), "关闭镜从大文件链摘除: {big:?}");
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
    // 隔离：.example 自建镜像会被收编进注册表并跨测试持久化，先清空。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
        r#"{
  "core": [],
  "mirrors_big":   {"codeload.github.com": ["https://big.example"]},
  "mirrors_small": {"raw.githubusercontent.com": ["https://small.example"]},
  "mirrors": {
    "codeload.github.com": ["https://legacy-wrong.example"],
    "raw.githubusercontent.com": ["https://legacy-wrong.example"],
    "gist.githubusercontent.com": ["https://legacy-only.example"]
  }
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    // 断言只锁"优先级"这一点：自建镜像收编(sync_custom_mirrors)会把非内置镜像追加进所有链尾，属既有设计，不在本测试射程。
    // ① 旧 mirrors 不得覆盖新字典 → codeload 链里绝不允许出现 legacy-wrong；② 新字典成员在前 → 链头必须是 big/small，旧字典独有成员追加在尾。
    let big = mirror_chain("codeload.github.com");
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

/// 全新安装+添加镜像 → 启用镜像必须落进全部 8 条链（v0.5.0 回归：空表遍历不到，镜像只进注册表）。
#[test]
fn fresh_install_mirror_lands_in_all_chains() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(dir.join("plans.json"), r#"{"core": []}"#).unwrap();
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
    // 隔离：自定义镜像注册表经 settings.json 跨进程持久化（上一轮 serial_load 收养的自建镜像会留在里面），不清空的话 sync_custom_mirrors 会把它们追加进本测试的链。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
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
    let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    assert!(!b.contains("not-a-content.host"), "未知 host 应丢弃: {b}");
    assert!(b.contains("\"mirrors_small\""), "镜像链应落盘(raw 为小文件域): {b}");
    let mut new_chain = raw_chain.clone();
    new_chain.reverse();
    assert!(
        set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
        "新链应写入"
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
    let dir = tmpdir();
    serial_load(&dir, Vec::new(), None);
    let row = route::route_for("github.com").expect("github.com 应有路由");
    let pattern = row.pattern.clone();
    let base = row.plans.clone();
    assert!(base.len() >= 6, "初始表过小: {}", base.len());
    let head = base[0].ip.clone();
    let next = base[1].ip.clone();

    // 失败:记号前移到圈中下一候选
    cursor_note("github.com", &head, false, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&pattern).map(String::as_str),
            Some(next.as_str()),
            "失败后记号应前移到下一候选"
        );
    }

    // 成功:记号驻留;表序全程未变
    cursor_note("github.com", &next, true, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&pattern).map(String::as_str),
            Some(next.as_str())
        );
    }
    let now = route::route_for("github.com").unwrap().plans.clone();
    assert!(
        now.iter().zip(base.iter()).all(|(a, b)| a.ip == b.ip),
        "表序应冻结(游标不重排)"
    );
}

/// 串发重试引擎实机圈：TCP 拒 → 沿圈到活条 → 驻留 + 死亡退避。
// 串行锁有意全程持有: 测试期间独占全局表, 跨 await 是本意。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn serial_dial_rotates_on_failure_and_parks_on_success() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // 只有 127.0.0.2 在监听；127.0.0.1 的同端口连接会被立刻拒绝。
    let Ok(ln) = tokio::net::TcpListener::bind("127.0.0.2:0").await else {
        eprintln!("跳过: 本机绑不了 127.0.0.2(回环 /8 行为不同), 串发实测留给真机");
        return;
    };
    let port = ln.local_addr().unwrap().port();
    dial::set_dial_port(port);
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
        r#"{"core":[{"ip":"127.0.0.1","sni":"a.example"},{"ip":"127.0.0.2","sni":"a.example"}]}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);

    let (conn, ip, _) = serial_dial_skip(
        DialSkip {
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            tunnel: false,
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
            t.cursor
                .get("(.*\\.)?github\\.com")
                .map(String::as_str),
            Some("127.0.0.2"),
            "成功必须驻留记号(下次从它起步)"
        );
        assert!(
            t.dead.contains_key("127.0.0.1"),
            "TCP 层失败应进死亡退避表"
        );
    }

    // 第二次：从驻留记号起步，直接拿 127.0.0.2（不再先撞被拒的那条）。
    let (conn, ip, _) = serial_dial_skip(
        DialSkip {
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            tunnel: false,
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
