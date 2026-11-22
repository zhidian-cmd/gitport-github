// TEST_LOCK 跨 await 独占全局路由表/连接池是刻意的：用例跑在 current_thread runtime 上，无人抢锁。
#![allow(clippy::await_holding_lock)]
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
// 全局串行锁在 pool::TEST_LOCK：路由表/串发表/连接池都是进程级全局态。

fn tmpdir() -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("gitport_test_{}_{n}", std::process::id()));
    // pid 会被系统复用：残留旧 routes/plans.json 会让"全新安装"测试读到旧表间歇性失败（实测踩到过）。
    let _ = std::fs::remove_dir_all(&d);
    if let Err(e) = std::fs::create_dir_all(&d) {
        panic!("测试临时目录创建失败 {d:?}: {e}");
    }
    d
}

/// 生产路径：settings 只存注册表，存完由调用方用 removed 触发链对齐。
fn apply_worker_mirrors(list: Vec<crate::settings::WorkerMirror>) -> Result<(), String> {
    let (_, removed, _) = crate::settings::set_worker_mirrors(list)?;
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
    // CONTENT_BREAKER 已删除，Breaker 类型的行为由 SERIAL_COOL 覆盖验证。
    let raw = "raw.githubusercontent.com";
    let camo = "camo.githubusercontent.com";
    assert!(!SERIAL_COOL.open(raw));
    SERIAL_COOL.set(raw);
    assert!(SERIAL_COOL.open(raw));
    assert!(
        !SERIAL_COOL.open(camo),
        "冷却按 host 记账，不得串到同池其他域"
    );
    SERIAL_COOL.clear(raw);
    assert!(!SERIAL_COOL.open(raw));

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
  "ips": [{"ip": "1.2.3.4", "sni": "baidu.com", "hosts": ["github.com"]}],
  "hosts": {"github.com": {}, "bad.example": {"fallback": "mirror2"}},
  "mirrors_small": {"raw.githubusercontent.com": ["https://v4.gh-proxy.org"]}
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

/// v1/0.5.3 旧格式不再被读懂：路由行按种子重建、原文件备份 .bak，绝不静默半重建。
#[test]
fn old_format_routes_rebuild_from_seeds() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "routes": [
    {"match": "(.*\\.)?github\\.com", "pac": "github.com", "plans": [{"ip": "9.9.9.1", "sni": "baidu.com"}]}
  ]
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));

    assert!(
        route::route_for("github.com").is_some(),
        "旧格式文件路由行按种子重建, github.com 照常可路由"
    );
    assert!(!target_ips("github.com").is_empty(), "种子 IP 边应就位");
    assert!(
        dir.join("routes.json.bak").exists(),
        "旧格式原文件应备份为 routes.json.bak"
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("无 ips/hosts 路由行")),
        "日志应说清按种子重建: {:?}",
        seen.lock().unwrap()
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
        assert!(
            !route::is_mirror_route(host, "GET", "/"),
            "{host} 应走池（非镜像分流）"
        );
        assert!(!target_ips(host).is_empty(), "{host} 应有种子补的 IP 边");
    }
    assert!(route::is_managed("github.com"), "普通域名照常进代理");
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
  "ips": [{"ip": "9.9.9.9", "sni": "baidu.com", "hosts": ["*.githubusercontent.com"]}],
  "hosts": {"*.githubusercontent.com": {"content": true, "fallback": "mirror"}}
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
    route::note_latency("1.2.3.4", 111);
    let big = vec![
        "https://big-a.example".to_string(),
        "https://big-b.example".to_string(),
    ];
    let b = encode_routes(&mirrors, &big);
    // 大文件单链必须按列表落盘，且回读逐项相等（删掉落盘段/写成对象都会红）。
    assert!(
        b.contains("\"mirrors_big\": ["),
        "大文件单链应按列表落盘: {b}"
    );
    // 节点条目必须单行
    for line in b.lines() {
        let t = line.trim();
        if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
            panic!("条目被展开成多行: {line:?}");
        }
    }
    assert!(b.contains("\"mirrors_small\""), "镜像链板块应落盘: {b}");
    assert!(!b.contains("\"pac\""), "pac 不再落盘: {b}");
    assert!(
        b.contains("\"latency\": 111"),
        "测速值应以标量挂在节点条目里: {b}"
    );
    let (doc, _) = parse_routes_tolerant(&b, None).expect("编码结果应可解析");
    assert_eq!(doc.big, big, "大文件单链落盘后必须能逐项回读");
    assert_eq!(
        doc.ips
            .iter()
            .find(|s| s.ip == "1.2.3.4")
            .and_then(|s| s.latency),
        Some(111),
        "测速值应可回读"
    );
    let _row = route::RouteRow::new(
        serde_json::from_str::<route::HostSpec>(r#"{"key":"github.com"}"#).unwrap(),
    )
    .unwrap();
    // “pac 缺省 = 裸键”的派生行为由 pac_lists_split_direct_and_proxy 钉着。
    let back: serde_json::Value = serde_json::from_str(&b).unwrap();
    let hosts = back["hosts"].as_object().expect("hosts 应是对象(域名作键)");
    assert_eq!(
        hosts.len(),
        1,
        "全默认且有节点服务的域名不落盘（由节点 hosts 声明）: {b}"
    );
    assert_eq!(hosts["*.githubusercontent.com"]["content"], true);
    assert_eq!(hosts["*.githubusercontent.com"]["fallback"], "mirror");
    assert!(
        b.contains("\"hosts\": [\"github.com\"]"),
        "节点 hosts 数组必须单行: {b}"
    );
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

/// 落盘省略的默认域名，读回时从节点 hosts 补齐（否则 PAC/路由会丢域名）。
#[test]
fn hosts_filled_from_nodes() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut doc = TopoDoc {
        hosts: vec![route::HostSpec {
            key: "b.example".to_string(),
            ..Default::default()
        }],
        ips: vec![route::IpSpec {
            ip: "1.2.3.4".to_string(),
            hosts: vec!["a.example".to_string(), "b.example".to_string()],
            ..Default::default()
        }],
        ..Default::default()
    };
    fill_hosts_from_nodes(&mut doc);
    let keys: Vec<&str> = doc.hosts.iter().map(|h| h.key.as_str()).collect();
    assert_eq!(
        keys,
        vec!["b.example", "a.example"],
        "缺的域名按节点补，已有的不重复"
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
    cursor_note("github.com", &target, true);
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
    assert!(align_custom_mirrors(&mut m, &enabled, &disabled));
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
    assert!(!align_custom_mirrors(&mut m, &enabled, &disabled));
    // 删除：customB 移出启用清单（进 disabled）→ 从全部链消失；其余不动
    let enabled2 = vec!["https://customA".to_string()];
    let disabled2 = vec!["https://customB".to_string(), "https://customC".to_string()];
    assert!(align_custom_mirrors(&mut m, &enabled2, &disabled2));
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
    align_custom_mirrors(&mut m, &new, &old);
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
  "hosts": {"objects.githubusercontent.com": {"content": true, "big": true}},
  "mirrors_big":   {"objects.githubusercontent.com": ["https://on.example", "https://off.example"]},
  "mirrors_small": {"raw.githubusercontent.com": ["https://on.example"]}
}"#,
    )
    .unwrap();
    crate::settings::save_worker_mirrors(vec![
        crate::settings::WorkerMirror {
            url: "https://on.example".into(),
            on: true,
            template: String::new(),
            invalid: false,
        },
        crate::settings::WorkerMirror {
            url: "https://off.example".into(),
            on: false,
            template: String::new(),
            invalid: false,
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

/// 裸 mirrors 旧字典已随两代迁移层停读：新字典照常生效，旧段整段忽略（gist 链不再并入）。
#[test]
fn bare_mirrors_segment_is_no_longer_read() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    // 隔离：.example 自建镜像会被收编进注册表并跨测试持久化，先清空。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "hosts": {"objects.githubusercontent.com": {"content": true, "big": true}},
  "mirrors_big":   ["https://big.example"],
  "mirrors_small": {"raw.githubusercontent.com": ["https://small.example"]},
  "mirrors": {
    "objects.githubusercontent.com": ["https://legacy-wrong.example"],
    "gist.githubusercontent.com": ["https://legacy-only.example"]
  }
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    let big = mirror_chain("objects.githubusercontent.com");
    assert_eq!(
        big.first(),
        Some(&"https://big.example".to_string()),
        "mirrors_big 照常生效: {big:?}"
    );
    assert!(
        !big.contains(&"https://legacy-wrong.example".to_string()),
        "裸 mirrors 段已停读, 不得混入: {big:?}"
    );
    let small = mirror_chain("raw.githubusercontent.com");
    assert_eq!(
        small.first(),
        Some(&"https://small.example".to_string()),
        "mirrors_small 照常生效: {small:?}"
    );
    assert!(
        !mirror_chain("gist.githubusercontent.com")
            .contains(&"https://legacy-only.example".to_string()),
        "裸 mirrors 段的链不再并入"
    );
    // 清场：正规路径删除自建镜像（注册表 + 全部链），不给后续测试留全局残留。
    apply_worker_mirrors(Vec::new()).ok();
}

/// 手改进 mirrors_big 的镜像必须收编进注册表：否则工作台看不到、开关管不到、删不掉，界面和文件两套真相。
#[test]
fn hand_written_big_mirror_is_adopted_into_registry() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "hosts": {"objects.githubusercontent.com": {"content": true, "big": true}},
  "mirrors_big": ["https://big-self.example"]
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    let registry = crate::settings::worker_mirrors();
    assert!(
        registry
            .iter()
            .any(|w| w.url == "https://big-self.example" && w.on),
        "手改的 big 镜像必须进注册表: {registry:?}"
    );
    crate::settings::save_worker_mirrors(Vec::new());
}

/// 混合格式：mirrors_big 已是新版非空列表时，旧 per-host 里 big host 的链不得静默丢弃。
#[test]
fn legacy_big_host_chains_are_merged_not_dropped() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "hosts": {"objects.githubusercontent.com": {"content": true, "big": true}},
  "mirrors_big": ["https://new.example"],
  "mirrors_small": {"objects.githubusercontent.com": ["https://legacy.example"]}
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    let big = mirror_chain("objects.githubusercontent.com");
    assert_eq!(
        big.first(),
        Some(&"https://new.example".to_string()),
        "新版列表链序优先: {big:?}"
    );
    assert!(
        big.contains(&"https://legacy.example".to_string()),
        "列表非空时旧 big host 链不得静默丢弃: {big:?}"
    );
    assert_eq!(big.len(), 2, "合并应去重: {big:?}");
    crate::settings::save_worker_mirrors(Vec::new());
}

/// 全新安装+添加镜像 → 启用镜像必须落进全部内容域链（v0.5.0 回归：空表遍历不到，镜像只进注册表）。
#[test]
fn fresh_install_mirror_lands_in_all_chains() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("routes.json"),
        r#"{"ips": [], "hosts": {}, "mirrors_small": {}}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);
    assert!(
        mirror_chain("raw.githubusercontent.com").is_empty(),
        "前置: 全新安装链应为空"
    );
    // 模拟 UI 添加并启用一个镜像：settings 存 + 调用方触发链对齐。
    apply_worker_mirrors(vec![crate::settings::WorkerMirror {
        url: "https://my-worker.example.com".to_string(),
        on: true,
        template: String::new(),
        invalid: false,
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
  "ips": [{"ip": "140.82.112.3", "sni": "baidu.com", "hosts": ["github.com"]}],
  "hosts": {"github.com": {}},
  "mirrors_small": {
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
    cursor_note("github.com", &head, false);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&key).map(String::as_str),
            Some(next.as_str()),
            "失败后记号应前移到下一候选"
        );
    }

    // 成功:记号驻留;表序全程未变
    cursor_note("github.com", &next, true);
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
    cursor_note("github.com", &ip, true);
    assert!(!edges::is_bad(&ip, "github.com"), "成功必须清黑");
}

/// 内容域竞速选路，游标无人读：成功不落游标；但清边冷却的兼职保留（421 洗白）。
#[test]
fn content_host_success_never_parks_cursor_but_clears_edges() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    let host = "raw.githubusercontent.com";
    let ip = target_ips(host)[0].clone();
    let key = route::route_for(host)
        .expect("内容域应有路由")
        .key
        .clone();
    edges::mark_reject(&ip, &key);
    cursor_note(host, &ip, true);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get(&key).map(String::as_str),
            None,
            "内容域成功不该落游标(竞速选路无人读)"
        );
    }
    assert!(!edges::is_bad(&ip, &key), "内容域成功仍要洗白 421 短冷却");
}

/// 风控冷却免疫"成功"回写：block 页也算一次成功 HTTP 交换，可清就会在风暴中被并发回写洗掉（26 家候选 3 轮回头事件的根因）。
#[test]
fn risk_cooldown_survives_success_note() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    edges::clear_all();
    let dir = tmpdir();
    crate::settings::save_worker_mirrors(Vec::new());
    serial_load(&dir, Vec::new(), None);
    let ip = target_ips("github.com")[0].clone();
    edges::mark_risk(&ip, "github.com");
    assert!(edges::is_bad(&ip, "github.com"));
    cursor_note("github.com", &ip, true);
    assert!(
        edges::is_bad(&ip, "github.com"),
        "风控冷却不得被成功回写清掉"
    );
    // 活着的风控冷却也不被短冷却降级成"可清"
    edges::mark_stall(&ip, "github.com");
    cursor_note("github.com", &ip, true);
    assert!(edges::is_bad(&ip, "github.com"), "短冷却不得降级活着的风控");
}

/// 串发重试引擎实机圈：TCP 拒→沿圈到活条→驻留+死亡退避；跨 await 持 TEST_LOCK 是本意（独占全局表，current_thread runtime）。
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
        r#"{
  "ips": [
    {"ip": "127.0.0.1", "sni": "a.example", "hosts": ["github.com"]},
    {"ip": "127.0.0.2", "sni": "a.example", "hosts": ["github.com"]}
  ],
  "hosts": {}
}"#,
    )
    .unwrap();
    serial_load(&dir, Vec::new(), None);

    let (conn, ip, _) = serial_dial_skip(
        DialSkip {
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
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
        assert!(
            spec.ip.split('.').count() == 4
                && spec
                    .ip
                    .split('.')
                    .all(|s| s.parse::<u32>().map(|v| v <= 255).unwrap_or(false)),
            "种子每条 ip 都必须是单个点分地址: {}",
            spec.ip
        );
    }
    for spec in &seeds.hosts {
        route::RouteRow::new(spec.clone()).expect("种子每行都必须能编译");
    }
}

/// 拨号顺序：游标 IP 优先；其余按实测延迟升序；未测的垫底并保持表序。
#[test]
fn dial_order_cursor_first_then_latency_asc() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mk = |ip: &str, latency: u64| route::NodeIp {
        ip: ip.into(),
        sni: String::new(),
        verify: String::new(),
        latency,
    };
    let circle = vec![
        mk("1.1.1.1", 0),
        mk("2.2.2.2", 300),
        mk("3.3.3.3", 200),
        mk("4.4.4.4", 100),
    ];
    assert_eq!(dial_order(&circle, Some("1.1.1.1")), vec![0, 3, 2, 1]);
    assert_eq!(dial_order(&circle, None), vec![3, 2, 1, 0]);
    assert_eq!(dial_order(&circle, Some("3.3.3.3")), vec![2, 3, 1, 0]);
}

/// 种子/运行表一 IP 一节点；codeload 单独成行，只挂实测能出 zip 的 IP。
#[test]
fn codeload_route_isolated_to_verified_ips() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let seeds = seed_db();
    assert!(
        seeds.ips.iter().all(|n| !n.ip.contains('-')),
        "种子表不许再用范围 IP，一个字典只放一个 IP"
    );
    let verified = ["20.27.177.114", "20.205.243.165"];
    let declared: Vec<&str> = seeds
        .ips
        .iter()
        .filter(|n| n.hosts.iter().any(|h| h == "codeload.github.com"))
        .map(|n| n.ip.as_str())
        .collect();
    assert_eq!(declared.len(), 2, "codeload 只该挂两个实测可用的 IP");
    assert!(verified.iter().all(|ip| declared.contains(ip)));

    // 生产加载路径要自己补出 codeload 行，别退回 github.com 整组 IP；空目录=全新安装吃种子，dist 目录=现有用户表。
    let mut dirs = vec![tmpdir()];
    if let Ok(raw) = std::fs::read_to_string("dist/routes.json") {
        let d = tmpdir();
        std::fs::write(d.join("routes.json"), raw).unwrap();
        dirs.push(d);
    }
    for dir in &dirs {
        serial_load(dir, Vec::new(), None);
        let hit = route::route_for("codeload.github.com").expect("codeload 应在表内");
        assert_eq!(
            hit.key, "codeload.github.com",
            "必须命中自己的行，不能蹭 github.com 裸键"
        );
        let targets = route::dial_targets("codeload.github.com").expect("应有候选");
        assert!(
            targets.iter().all(|t| verified.contains(&t.ip.as_str())),
            "codeload 候选混进了不对口 IP: {:?}",
            targets.iter().map(|t| &t.ip).collect::<Vec<_>>()
        );
    }
}

/// 媒体救援链（图片/视频）是保留键：解析、落盘回写、注册表对齐都不能弄丢；全程纯函数不碰磁盘真网。
#[test]
fn media_rescue_chains_roundtrip_and_align_skip() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let raw = r#"{
  "ips": [],
  "hosts": {},
  "mirrors_small": {
    "raw.githubusercontent.com": ["https://a.example.com"],
    "图片": ["https://img.example.com"],
    "视频": ["https://vid.example.com", "https://vid2.example.com"]
  }
}"#;
    let (doc, salvaged) = parse_routes_tolerant(raw, None).expect("媒体链必须能解析");
    assert!(!salvaged);
    assert_eq!(
        doc.chains.get(crate::pool::MEDIA_IMAGE_CHAIN).map(|c| c.len()),
        Some(1),
        "图片链必须进表"
    );
    assert_eq!(
        doc.chains.get(crate::pool::MEDIA_VIDEO_CHAIN).map(|c| c.len()),
        Some(2),
        "视频链必须进表"
    );

    // 落盘回写：手改的媒体链不能因 encode 丢掉。
    install_seed_routes();
    let mut mirrors = HashMap::new();
    mirrors.insert(
        crate::pool::MEDIA_IMAGE_CHAIN.to_string(),
        vec!["https://img.example.com".to_string()],
    );
    mirrors.insert(
        crate::pool::MEDIA_VIDEO_CHAIN.to_string(),
        vec!["https://vid.example.com".to_string()],
    );
    mirrors.insert(
        "raw.githubusercontent.com".to_string(),
        vec!["https://a.example.com".to_string()],
    );
    let big = vec!["https://big-media.example".to_string()];
    let encoded = encode_routes(&mirrors, &big);
    assert!(encoded.contains("\"图片\""), "图片链必须回写落盘");
    assert!(encoded.contains("\"视频\""), "视频链必须回写落盘");
    let (doc2, _) = parse_routes_tolerant(&encoded, None).expect("回写后必须还能解析");
    assert_eq!(doc2.big, big, "大文件单链与媒体链必须同时可回读");
    assert_eq!(
        doc2.chains.get(crate::pool::MEDIA_IMAGE_CHAIN).map(|c| c.len()),
        Some(1)
    );

    // 注册表对齐与小文件链同一套：工作台启用的镜像自动进图片/视频链（按小文件档）。
    align_custom_mirrors(
        &mut mirrors,
        &["https://new.example.com".to_string()],
        &["https://a.example.com".to_string()],
    );
    for key in [crate::pool::MEDIA_IMAGE_CHAIN, crate::pool::MEDIA_VIDEO_CHAIN] {
        assert!(
            mirrors[key].iter().any(|m| m == "https://new.example.com"),
            "{key} 链应自动获得工作台启用的镜像"
        );
    }
    assert!(
        mirrors[crate::pool::MEDIA_IMAGE_CHAIN]
            .iter()
            .any(|m| m == "https://img.example.com"),
        "手改成员不在注册表移除清单里：位置与成员原样保留"
    );
    assert!(
        !mirrors["raw.githubusercontent.com"]
            .iter()
            .any(|m| m == "https://a.example.com"),
        "注册表移除的镜像从普通链摘除（对照组）"
    );
    // 小文件链照常对齐（对照组证明对齐逻辑本身还在跑）。
    assert!(
        mirrors["raw.githubusercontent.com"]
            .iter()
            .any(|m| m == "https://new.example.com"),
        "普通链的注册表对齐不受影响"
    );
}
