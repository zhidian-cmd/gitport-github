use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
// SERIAL/SERIAL_DIR 是进程级全局态，测试并行会互相踩踏 → 需要全局态的测试串行
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn tmpdir() -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("gitport_test_{}_{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn reset_state(dir: &Path) {
    serial_load(dir, Vec::new(), None);
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
    // ttl=0：set 后立即过期。open 必须判 false 并把条目清掉——
    // 过期条目沉淀在表里只进不出（修复前 open 只读不删）。
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
fn plans_json_single_bad_pool_does_not_wipe_table() {
    // 单池写坏只丢该池（按种子补缺），其余池与镜像链原样保留——
    // 旧行为是 flatten 全有或全无：一处笔误 → 整表按种子重建。
    let _guard = TEST_LOCK.lock().unwrap();
    let dir = tmpdir();
    // 隔离：自定义镜像注册表经 settings.json 跨测试/跨轮次持久化，别处收养的
    // 自建镜像会被 sync_custom_mirrors 追加回既有链——先清空，本断言只验
    // plans.json 里的链是否原样保留，不掺注册表状态。
    crate::settings::save_worker_mirrors(Vec::new());
    std::fs::write(
        dir.join("plans.json"),
        r#"{
  "core": [{"ip": "1.2.3.4", "sni": "baidu.com"}],
  "edge": "写坏了-不是数组",
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org"]
  }
}"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));
    // 好池的用户条目保留（+ 种子补缺）
    let core = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("core").unwrap().clone()
    };
    assert_eq!(core[0].ip, "1.2.3.4", "好池必须保留: {core:?}");
    assert!(core.len() > 1, "好池应叠加种子补缺: {core:?}");
    // 整个写坏的池 → 按种子重建（不连坐）
    let edge_n = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("edge").unwrap().len()
    };
    assert!(edge_n > 0, "坏池应按种子重建: {edge_n}");
    // 镜像链保留
    assert_eq!(
        mirror_chain("raw.githubusercontent.com"),
        vec!["https://v4.gh-proxy.org".to_string()],
        "镜像链必须保留"
    );
    // 日志指明哪个池坏了；原文件备份（坏段可从 .bak 捡回）
    assert!(
        seen.lock().unwrap().iter().any(|l| l.contains("池 edge 写坏")),
        "应记录坏池名: {:?}",
        seen.lock().unwrap()
    );
    assert!(
        dir.join("plans.json.bak").exists(),
        "有段落坏应备份原文件"
    );
}

#[test]
fn direct_hosts_never_pooled() {
    for host in [
        "objects-origin.githubusercontent.com",
        "uploads.github.com",
        "viewscreen.githubusercontent.com",
    ] {
        assert!(crate::config::is_direct(host), "{host} 应在直连白名单");
        assert_eq!(crate::config::pool_for(host), "", "{host} 不应归任何池");
    }
}

#[test]
fn fastly_pools_no_longer_serial() {
    assert!(!SERIAL_POOLS.contains(&"fastly"));
    assert!(!SERIAL_POOLS.contains(&"codeload"));
    for p in ["core", "api", "edge"] {
        assert!(SERIAL_POOLS.contains(&p), "{p} 应为串发池");
    }
    assert!(!SERIAL_POOLS.contains(&"uploads"));
}

#[test]
fn migrate_drops_stats_and_normalizes_shapes() {
    let _guard = TEST_LOCK.lock().unwrap();
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
        r#"{
  "core": [
    {"ip": "1.2.3.4", "sni": "ech", "成功次数": "9/9", "分数": 99},
    {"ip": "5.6.7.8", "sni": "real"},
    {"ip": "bad-ip", "sni": "real"}
  ],
  "edge": [
    {"ip": "140.82.112.29", "sni": "real"},
    {"ip": "185.199.108.154", "sni": "sni"},
    {"ip": "185.199.109.153", "sni": "sni"}
  ],
  "ghapp": [{"ip": "9.9.9.9", "sni": "baidu.com"}],
  "assets": [{"ip": "8.8.8.8", "sni": "sni"}]
}"#,
    )
    .unwrap();
    reset_state(&dir);
    let ps = {
        let g = SERIAL.lock().unwrap();
        let tab = g.as_ref().unwrap();
        tab.pools.get("core").unwrap().clone()
    };
    let core_seed_n = seed_db().pools.get("core").map(|v| v.len()).unwrap_or(0);
    assert_eq!(
        ps.len(),
        2 + core_seed_n,
        "补缺后 = 用户条目 + 全部种子: {ps:?}"
    );
    assert_eq!(
        ps[0],
        SerialPlan {
            ip: "1.2.3.4".into(),
            sni: "ech".into()
        },
        "sni 原样透传(写什么传什么)"
    );
    assert_eq!(
        ps[1],
        SerialPlan {
            ip: "5.6.7.8".into(),
            sni: "real".into()
        },
        "sni 原样透传(写什么传什么, 含真名写法)"
    );
    let edge_ps = {
        let g = SERIAL.lock().unwrap();
        let tab = g.as_ref().unwrap();
        tab.pools.get("edge").unwrap().clone()
    };
    assert!(edge_ps.len() >= 3, "edge 至少含旧表 3 条: {edge_ps:?}");
    assert!(
        edge_ps.contains(&SerialPlan {
            ip: "140.82.112.29".into(),
            sni: "real".into()
        }),
        "ghapp 条目保留, sni 原样透传: {edge_ps:?}"
    );
    assert!(
        edge_ps.contains(&SerialPlan {
            ip: "185.199.108.154".into(),
            sni: "sni".into()
        }) && edge_ps.contains(&SerialPlan {
            ip: "185.199.109.153".into(),
            sni: "sni".into()
        }),
        "sni 文件权威——旧表显式真名写法原样保留: {edge_ps:?}"
    );
    assert!(
        edge_ps
            .iter()
            .any(|p| route::fastly_last_octet(&p.ip) == Some("133") && p.sni == "baidu.com"),
        "种子补缺应追加 .133 伪装内容域条目: {edge_ps:?}"
    );
    let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    assert!(!b.contains("成功次数") && !b.contains("分数"));
    let back: serde_json::Value = serde_json::from_str(&b).unwrap();
    for gone in ["fastly", "codeload", "ghapp", "assets"] {
        assert!(back.get(gone).is_none(), "{gone} 不应再落盘: {back}");
    }
    assert!(back.get("edge").is_some(), "edge 池应落盘: {back}");
}

#[test]
fn seed_topup_appends_missing_and_keeps_order() {
    let _guard = TEST_LOCK.lock().unwrap();
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
        r#"{ "edge": [{"ip": "140.82.112.29", "sni": "baidu.com"}] }"#,
    )
    .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    serial_load(&dir, Vec::new(), Some(log));
    let ps = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("edge").unwrap().clone()
    };
    assert_eq!(
        ps[0].ip, "140.82.112.29",
        "用户手排顺序保留, 补缺只追加尾部"
    );
    let seeds = seed_db();
    let seed = seeds.pools.get("edge").unwrap();
    assert_eq!(ps.len(), seed.len(), "补缺后应覆盖全部种子: {ps:?}");
    assert!(
        seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
        "补缺应打一行日志"
    );
    let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    assert!(b.contains("185.199.110.133"), "补缺应落盘: {b}");
    // 2026-10-19 起三个 .133 复活移出退役清单、入种子——应随补缺落盘（伪装形态）
    assert!(
        b.contains("185.199.108.133")
            && b.contains("185.199.109.133")
            && b.contains("185.199.111.133"),
        "复活的内容边缘应随种子补缺落盘: {b}"
    );
}

#[test]
fn encode_plans_roundtrip() {
    let mut tab = HashMap::new();
    tab.insert(
        "core".into(),
        vec![
            SerialPlan {
                ip: "1.2.3.4".into(),
                sni: "baidu.com".into(),
            },
            SerialPlan {
                ip: "5.6.7.8".into(),
                sni: "baidu.com".into(),
            },
        ],
    );
    tab.insert(
        "api".into(),
        vec![SerialPlan {
            ip: "140.82.112.5".into(),
            sni: "baidu.com".into(),
        }],
    );
    tab.insert(
        "edge".into(),
        vec![
            SerialPlan {
                ip: "185.199.108.154".into(),
                sni: "sni".into(),
            },
            SerialPlan {
                ip: "140.82.112.29".into(),
                sni: "baidu.com".into(),
            },
        ],
    );
    let mut mirrors = HashMap::new();
    mirrors.insert(
        "raw.githubusercontent.com".to_string(),
        vec![
            "https://axisnow.gh-proxy.org".to_string(),
            "https://v4.gh-proxy.org".to_string(),
        ],
    );
    let b = encode_plans(&tab, &mirrors);
    for line in b.lines() {
        let t = line.trim();
        if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
            panic!("条目被展开成多行: {line:?}");
        }
    }
    assert!(b.contains("\"mirrors_small\""), "镜像链板块应落盘: {b}");
    assert!(b.contains("raw.githubusercontent.com"));
    let back_file: PlansFile = serde_json::from_str(&b).unwrap();
    assert_eq!(
        back_file
            .mirrors_small
            .get("raw.githubusercontent.com")
            .map(|c| c.len()),
        Some(2),
        "镜像链应可读回(小文件域落 mirrors_small): {:?}",
        back_file.mirrors_small
    );
    let back: HashMap<String, Vec<SerialPlan>> = back_file.pools;
    assert_eq!(back["core"].len(), 2);
    assert_eq!(back["core"][0].sni, "baidu.com");
    assert_eq!(back["edge"].len(), 2);
    assert_eq!(back["edge"][0].sni, "sni");
    assert!(!b.contains("fastly") && !b.contains("codeload"));
}

#[test]
fn cursor_park_is_memory_only_and_freezes_order() {
    let _guard = TEST_LOCK.lock().unwrap();
    let dir = tmpdir();
    serial_load(&dir, Vec::new(), None);
    let head_before = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("core").unwrap()[0].ip.clone()
    };
    let target = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("core").unwrap()[2].ip.clone()
    };
    assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
    let file_before = std::fs::read_to_string(dir.join("plans.json")).unwrap();
    cursor_note("core", "github.com", &target, true, false, 1);
    // 表序冻结:成功驻留只动内存游标,不动物理顺序、不触发写盘
    assert_eq!(
        SERIAL.lock().unwrap().as_ref().unwrap().pools.get("core").unwrap()[0].ip,
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
        g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
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
    let _guard = TEST_LOCK.lock().unwrap();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(
        dir.join("plans.json"),
        r#"{
  "core": [],
  "mirrors_big":   {"codeload.github.com": ["https://on.example", "https://off.example"]},
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
    let big = mirror_chain("codeload.github.com");
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

/// 双字典合并优先级：同 host 三处都有时，mirrors_big/small 赢、旧 mirrors 不覆盖；
/// 仅旧字典有的 host 照常并入（升级兼容的钉子）。
#[test]
fn merged_chains_prefers_typed_dictionaries_over_legacy() {
    let _guard = TEST_LOCK.lock().unwrap();
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
    // 断言只锁"优先级"这一点：自建镜像收编(sync_custom_mirrors)会把非内置
    // 镜像追加进所有链尾，属既有设计，不在本测试射程。
    // ① 旧 mirrors 不得覆盖新字典 → codeload 链里绝不允许出现 legacy-wrong。
    // ② 新字典成员在前 → 链头必须是 big/small；旧字典独有成员追加在尾。
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
    crate::settings::set_worker_mirrors(Vec::new()).ok();
}

/// 全新安装(链全空) + 添加镜像 → 启用中的镜像必须落进全部 8 条链。
/// v0.5.0 回归：values_mut() 对空表遍历不到任何东西，镜像只进注册表不进链。
#[test]
fn fresh_install_mirror_lands_in_all_chains() {
    let _guard = TEST_LOCK.lock().unwrap();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = tmpdir();
    std::fs::write(dir.join("plans.json"), r#"{"core": []}"#).unwrap();
    serial_load(&dir, Vec::new(), None);
    assert!(
        mirror_chain("raw.githubusercontent.com").is_empty(),
        "前置: 全新安装链应为空"
    );
    // 模拟 UI 添加并启用一个镜像(整表保存走 sync_custom_mirrors)。
    crate::settings::set_worker_mirrors(vec![crate::settings::WorkerMirror {
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
    crate::settings::set_worker_mirrors(Vec::new()).ok();
}

#[test]
fn mirror_chain_load_and_topup() {
    let _guard = TEST_LOCK.lock().unwrap();
    // 隔离：自定义镜像注册表经 settings.json 跨进程持久化（上一轮 serial_load 收养的
    // 自建镜像会留在里面），不清空的话 sync_custom_mirrors 会把它们追加进本测试的链。
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
    // 缺链 host：注册表有启用镜像时按 CONTENT_HOSTS 铺键并对齐全量
    // (自建镜像进所有链是既有设计)；无启用镜像时该 host 真正无链。
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
    let _guard = TEST_LOCK.lock().unwrap();
    let dir = tmpdir();
    serial_load(&dir, Vec::new(), None);
    let base = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get("core").unwrap().clone()
    };
    assert!(base.len() >= 6, "初始表过小: {}", base.len());
    let head = base[0].ip.clone();
    let next = base[1].ip.clone();

    // 失败:记号前移到圈中下一候选
    cursor_note("core", "github.com", &head, false, false, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
            Some(next.as_str()),
            "失败后记号应前移到下一候选"
        );
    }

    // 成功:记号驻留;表序全程未变
    cursor_note("core", "github.com", &next, true, false, 1);
    {
        let g = SERIAL.lock().unwrap();
        assert_eq!(
            g.as_ref().unwrap().cursor.get("core/all").map(String::as_str),
            Some(next.as_str())
        );
        let ps = g.as_ref().unwrap().pools.get("core").unwrap();
        let order_unchanged = ps.iter().zip(base.iter()).all(|(a, b)| a.ip == b.ip);
        assert!(order_unchanged, "表序应冻结(游标不重排)");
    }
}

/// 串发重试引擎实机圈：TCP 拒 → 沿圈到活条 → 驻留 + 死亡退避。
// 串行锁有意全程持有: 测试期间独占全局表, 跨 await 是本意。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn serial_dial_rotates_on_failure_and_parks_on_success() {
    let _guard = TEST_LOCK.lock().unwrap();
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
            pool_name: "core",
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            passthrough: false,
            slot: 1,
            crew: None,
        },
        CancellationToken::new(),
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
            t.cursor.get("core/all").map(String::as_str),
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
            pool_name: "core",
            host: "github.com",
            tls_handshake: false,
            skip_ips: &[],
            passthrough: false,
            slot: 1,
            crew: None,
        },
        CancellationToken::new(),
        None,
    )
    .await
    .expect("驻留后应直接命中");
    drop(conn);
    assert_eq!(ip, "127.0.0.2");
    dial::set_dial_port(0); // 复位，别影响别的测试
}
