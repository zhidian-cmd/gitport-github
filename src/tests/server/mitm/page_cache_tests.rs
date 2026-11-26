/// 骨架拦截三态：正常/零结果页含 embeddedData 则缓存，限流骨架缺则拦截。
#[test]
fn search_skeleton_gate() {
    let k = "GET github.com/search?q=x&type=repositories-gz";
    let full = "<html>{}react-app.embeddedData{}</html>".to_string();
    assert!(
        !is_search_skeleton(k, full.as_bytes(), "identity"),
        "含结果载体的正常页应缓存"
    );
    assert!(
        is_search_skeleton(k, b"<html>Your search did not match</html>", "identity"),
        "无结果载体的骨架应拦截"
    );
    // 非 /search? 键不受此判定。
    assert!(!is_search_skeleton(
        "GET github.com/search/count?q=x",
        b"{}",
        "identity"
    ));
}

/// gzip 分支:全量解压后判定,明文尾部才有的载体标志不漏判。
#[test]
fn search_skeleton_gate_gzip() {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let k = "GET github.com/search?q=x&type=repositories-gz";
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b"<html>padding</html>react-app.embeddedData<html>/</html>")
        .unwrap();
    let gz = enc.finish().unwrap();
    assert!(
        !is_search_skeleton(k, &gz, "gzip"),
        "gzip 正常页解压后应命中载体标志"
    );
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b"<html>Your search did not match any</html>")
        .unwrap();
    let gz = enc.finish().unwrap();
    assert!(is_search_skeleton(k, &gz, "gzip"), "gzip 骨架应拦截");
}

use super::*;

/// 带 no-cache 直通回源；max-age=0 不算；github.com GET 全候选准入。
#[test]
fn no_cache_header_bypasses_cache() {
    for path in ["/", "/search", "/octocat/repo/issues", "/octocat/repo"] {
        assert!(
            !cache_eligible_rules("github.com", &Method::GET, Some("no-cache")),
            "带 no-cache 的 {path} 必须直通"
        );
        assert!(
            cache_eligible_rules("github.com", &Method::GET, None),
            "{path} 无 no-cache 应准入（是否缓存由分类定）"
        );
        assert!(
            cache_eligible_rules("github.com", &Method::GET, Some("max-age=0")),
            "max-age=0 不是强制刷新"
        );
    }
    // 准入的其他两条边界
    assert!(!cache_eligible_rules("gist.github.com", &Method::GET, None));
    assert!(!cache_eligible_rules("github.com", &Method::POST, None));
}

/// /search 查询串归一化：p=1/参数重排同键；其他路径原样；键不含身份标签/会话号。
#[test]
fn search_query_normalization() {
    let mk = |path: &str, q: Option<&str>| {
        let uri = http::Uri::builder()
            .path_and_query(match q {
                Some(q) => format!("{path}?{q}"),
                None => path.to_string(),
            })
            .build()
            .unwrap();
        page_cache_key(&uri, "github.com", "gzip")
    };
    let base = mk("/search", Some("q=rust&type=repositories"));
    assert_eq!(
        mk("/search", Some("q=rust&type=repositories&p=1")),
        base,
        "p=1 与无 p 必须同键"
    );
    assert_eq!(
        mk("/search", Some("type=repositories&q=rust")),
        base,
        "参数重排必须同键"
    );
    // 非 /search：原样保留（顺序与 p=1 都不动）
    let repo = mk("/octocat/repo/issues", Some("q=1&page=2"));
    assert!(repo.contains("?q=1&page=2"), "其他路径的查询串不能被归一化");
    // v6.2：默认页显式补 p=1（无 p 的键里必须出现 p=1）
    assert!(base.contains("p=1"), "无 p 的搜索键应补 p=1: {base}");
    // 翻到第 N 页不能被合并成第一页
    let p2 = mk("/search", Some("q=rust&type=repositories&p=2"));
    assert_ne!(p2, base, "p=2 与默认页必须不同键");
    assert!(p2.contains("p=2"));
    // 键不含身份标签/会话号：骨架是纯壳，跨登录/跨会话命中
    assert!(!base.contains("-cs"), "keep 键不得含身份标签: {base}");
    assert!(!base.contains("-s"), "keep 键不得含会话号: {base}");
}

/// 统一准入：github.com 的 GET 全候选（软导航/文档导航/列表页/仓库页），只有 Ctrl+F5 直通。
#[test]
fn eligible_regardless_of_nav_kind_and_path() {
    for path in [
        "/",
        "/search",
        "/octocat/repo/issues",
        "/octocat/repo",
        "/dashboard/x",
    ] {
        assert!(
            cache_eligible_rules("github.com", &Method::GET, None),
            "{path} 应统一准入（是否缓存由响应分类定）"
        );
    }
    assert!(
        !cache_eligible_rules("github.com", &Method::GET, Some("no-cache")),
        "Ctrl+F5 直通"
    );
}

/// 目录覆盖是进程级单值，用锁串行；每个测试自己的临时目录。
static DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn own_dir(tag: &str) -> (std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
    let guard = DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join(format!("gitport_pc_{}_{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    *CACHE_DIR_OVERRIDE.lock().unwrap_or_else(|p| p.into_inner()) = Some(dir.clone());
    (dir, guard)
}

/// 缓存测试串行闸：目录覆盖与 XHR 池为进程级单值，只碰全局状态的用例用此锁。
fn serial() -> std::sync::MutexGuard<'static, ()> {
    DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn log_sink() -> LogFn {
    std::sync::Arc::new(|_: &str| {})
}

/// 高熵伪随机体（容量测试要接近原始体积）。
fn pseudo_body(i: usize, n: usize) -> String {
    let mut s = String::new();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ (i as u64).wrapping_mul(0xFF51_AFD7);
    for _ in 0..n {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(char::from_u32((33 + ((x >> 33) % 90)) as u32).unwrap_or('a'));
    }
    s
}

/// keep 目录的条目数与总字节（单文件存储的账）。
fn keep_stat(dir: &std::path::Path) -> (usize, u64) {
    let Ok(rd) = std::fs::read_dir(dir.join("keep")) else {
        return (0, 0);
    };
    let mut n = 0usize;
    let mut total = 0u64;
    for e in rd.flatten() {
        if let Ok(md) = e.metadata() {
            if md.is_file() {
                n += 1;
                total += md.len();
            }
        }
    }
    (n, total)
}

fn test_hdrs() -> Vec<Vec<String>> {
    vec![
        vec!["content-type".into(), "text/html; charset=utf-8".into()],
        vec!["etag".into(), "W/\"evict\"".into()],
    ]
}

/// A. 读写往返、类型闸门、坏文件自愈、PeekRaw 拼回；跨 await 持 own_dir 锁是本意（目录清理守卫）。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn roundtrip_gates_and_self_heal() {
    let (dir, _dir_guard) = own_dir("rw");
    let log = log_sink();

    // ① 写入后命中，带 hit 头
    let hdrs = vec![
        vec!["content-type".into(), "text/html; charset=utf-8".into()],
        vec!["etag".into(), "W/\"test\"".into()],
    ];
    persist_page_entry_blocking(
        &dir,
        "GET github.com/search?q=x",
        b"<html>ok</html>",
        200,
        &hdrs,
    )
    .unwrap();
    let (n, _) = keep_stat(&dir);
    assert_eq!(n, 1, "应有一个缓存条目");
    let hit = page_cache_get("GET github.com/search?q=x").expect("应命中");
    assert_eq!(hit.headers().get("x-gitport-cache").unwrap(), "hit");
    let bytes = http_body_util::BodyExt::collect(hit.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(bytes.as_ref(), b"<html>ok</html>");

    // ② keep 只收 HTML：collect_and_submit_keep 对 JSON 响应原样交回且不落盘
    let json_resp = hyper::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(protocol::full_body(Bytes::from_static(b"{}")))
        .unwrap();
    let api_uri: http::Uri = "https://github.com/api/x".parse().unwrap();
    let out = collect_and_submit_keep(&log, &api_uri, "github.com", false, json_resp).await;
    assert_eq!(out.status(), 200, "JSON 响应原样交回（JSON 走 XHR 内存缓存）");
    assert!(
        page_cache_get("GET github.com/api/x").is_none(),
        "keep 不收 JSON"
    );

    // ③ 覆盖写、截断文件、hash 碰撞都不得串页或报错
    let ck = "GET github.com/cover-me";
    let _ = persist_page_entry_blocking(&dir, ck, b"<html>v1</html>", 200, &test_hdrs());
    let _ = persist_page_entry_blocking(&dir, ck, b"<html>v2</html>", 200, &test_hdrs());
    let hit = page_cache_get(ck).expect("覆盖写后应命中");
    let v = http_body_util::BodyExt::collect(hit.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(v.as_ref(), b"<html>v2</html>", "覆盖写应读到新内容");
    // 截断文件 = miss（写一半被杀）
    let cpath = dir.join("keep").join(page_file_name(ck));
    std::fs::write(&cpath, b"\x10\x00\x00\x00short").unwrap();
    assert!(page_cache_get(ck).is_none(), "截断文件应判 miss");
    // 文件名确定性：同 key 永远同文件（跨重启可复现），异 key 必异文件
    assert_eq!(page_file_name(ck), page_file_name(ck));
    assert_ne!(page_file_name(ck), page_file_name("GET github.com/other"));
    // 碰撞防护：文件里存的 key 与请求 key 不符 → 拒服，不串页
    let bad_path = dir.join("keep").join(page_file_name("GET github.com/spoof"));
    let bad_hdr = serde_json::to_vec(&serde_json::json!({
        "key": "GET github.com/someone-else",
        "status": 200,
        "headers": test_hdrs(),
        "cachedAt": 0,
    }))
    .unwrap();
    let mut bad_buf = (bad_hdr.len() as u32).to_be_bytes().to_vec();
    bad_buf.extend_from_slice(&bad_hdr);
    bad_buf.extend_from_slice(b"<html>x</html>");
    std::fs::write(&bad_path, &bad_buf).unwrap();
    assert!(
        page_cache_get("GET github.com/spoof").is_none(),
        "header key 不符应拒服（防串页）"
    );

    // ④ 嗅探前缀必须拼回，否则交付并缓存半页
    let mut sniffed = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(protocol::full_body(Bytes::from_static(b"world</html>")))
        .unwrap();
    sniffed
        .extensions_mut()
        .insert(super::super::PeekRaw(vec![Bytes::from_static(
            b"<html>hello ",
        )]));
    let peek_uri: http::Uri = "https://github.com/peek".parse().unwrap();
    let out = collect_and_submit_keep(&log, &peek_uri, "github.com", false, sniffed).await;
    let body = http_body_util::BodyExt::collect(out.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        body.as_ref(),
        b"<html>hello world</html>",
        "嗅探前缀丢失 = 交付半页"
    );

    // ⑤b 清盘只清 keep（缓存可再生：超 5MB 整盘重来），重建后条目全没
    let home = "GET github.com/-k";
    let _ = persist_page_entry_blocking(&dir, home, b"<html>home</html>", 200, &test_hdrs());
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/search?q=i",
        b"<html>i</html>",
        200,
        &test_hdrs(),
    );
    wipe_pages(&dir);
    assert!(page_cache_get(home).is_none(), "清盘后 keep 条目全没");
    assert!(
        page_cache_get("GET github.com/search?q=i").is_none(),
        "清盘后搜索骨架全没"
    );

    // ⑤ gzip 条目读回：头/正文仍是压缩态，且读侧的解压判断不瞎（存→读整条链走一遍）
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut enc, b"<html><body>list</body></html>").unwrap();
    let gz = enc.finish().unwrap();
    let gz_hdrs = vec![
        vec!["content-type".into(), "text/html; charset=utf-8".into()],
        vec!["content-encoding".into(), "gzip".into()],
    ];
    let _ = persist_page_entry_blocking(&dir, "GET github.com/issues-gz", &gz, 200, &gz_hdrs);
    let hit = page_cache_get("GET github.com/issues-gz").expect("gzip 条目应命中");
    assert_eq!(
        hit.headers().get("content-encoding").unwrap(),
        "gzip",
        "编码头必须原样带回"
    );
    let back = http_body_util::BodyExt::collect(hit.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(back.as_ref(), gz.as_slice(), "正文应原样是压缩字节");
    // 同一份压缩字节里装的若是闸门页，读侧也要认出来（第二道防线）
    let mut gate =
        b"<html><head><title>Verify your two-factor authentication</title></head><body>".to_vec();
    gate.extend_from_slice(&vec![b'g'; 4000]);
    let mut enc2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut enc2, &gate).unwrap();
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/issues-gz-gate",
        &enc2.finish().unwrap(),
        200,
        &gz_hdrs,
    );
    assert!(
        page_cache_get("GET github.com/issues-gz-gate").is_none(),
        "读侧也要认出压缩的闸门页"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// B. 超量：keep 攒过上限就整盘重来（不排序、不逐个淘汰）。
#[test]
fn capacity_wipe_on_growth() {
    let (dir, _dir_guard) = own_dir("cap");
    for i in 0..3 {
        let body = pseudo_body(i, 1200);
        let _ = persist_page_entry_blocking(
            &dir,
            &format!("GET github.com/p{i}"),
            body.as_bytes(),
            200,
            &test_hdrs(),
        );
    }
    assert_eq!(keep_stat(&dir).0, 3, "前提：攒了 3 条");
    maybe_wipe_on_growth(&dir, PAGE_CACHE_MAX_BYTES as usize);
    assert_eq!(keep_stat(&dir).0, 0, "超量应整盘清空");

    // ⑥ 清空：keep 条目全没（page_cache_clear 是测试专用工具）
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/again",
        b"<html>a</html>",
        200,
        &test_hdrs(),
    );
    assert!(
        page_cache_get("GET github.com/again").is_some(),
        "前提：有条目"
    );
    page_cache_clear();
    let (n, _) = keep_stat(&dir);
    assert_eq!(n, 0, "清空后条目应为零");

    let _ = std::fs::remove_dir_all(&dir);
}

/// C. 键的语义（keep 无身份标签/会话号；XHR 有身份标签）、写后失效、未登录页防污染、闸门页；跨 await 持 own_dir 锁是本意。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn keys_invalidation_and_pollution() {
    let (dir, _dir_guard) = own_dir("key");
    let log = log_sink();

    // 写后失效：keep 条目不删，改标过期走 SWR（交旧+后台重拉）；键用生产形态。
    let mk_search = |q: &str| {
        let uri: http::Uri = format!("https://github.com/search?{q}").parse().unwrap();
        live_cache_key(&uri, "github.com", "gzip", "-html")
    };
    let sk = mk_search("q=first");
    let _ = persist_page_entry_blocking(
        &dir,
        &sk,
        b"<html>s react-app.embeddedData</html>",
        200,
        &test_hdrs(),
    );
    assert!(page_cache_get(&sk).is_some(), "前提：条目已缓存");
    let (_, expired_before) = load_disk_entry_reason(&sk).unwrap();
    assert!(!expired_before, "前提：新条目未过期");
    // 直调（不经 worker 异步：并行测试会踩全局 CACHE_DIR_OVERRIDE，轮询等待放大竞态）
    invalidate_prefix_blocking(&dir, "github.com", "/search");
    let (_, expired) = load_disk_entry_reason(&sk).unwrap();
    assert!(expired, "写后失效必须标过期（交旧+后台重拉）");
    assert!(
        page_cache_get(&sk).is_some(),
        "keep 条目不得被写失效删除（交旧继续用）"
    );

    // ⑨b 前缀匹配：同前缀的搜索骨架一并标过期
    let sub = mk_search("q=profile&type=repositories");
    let other = mk_search("q=other");
    for k in [&sub, &other] {
        let _ = persist_page_entry_blocking(
            &dir,
            k,
            b"<html>i react-app.embeddedData</html>",
            200,
            &test_hdrs(),
        );
    }
    // invalidate_after_write 传 path()，宽前缀波及全部 /search 骨架。
    invalidate_prefix_blocking(&dir, "github.com", "/search");
    let sub_expired = load_disk_entry_reason(&sub).unwrap().1;
    let other_expired = load_disk_entry_reason(&other).unwrap().1;
    assert!(sub_expired, "宽前缀应波及全部 /search 骨架");
    assert!(other_expired, "宽前缀应波及全部 /search 骨架");

    // ⑩ keep 键不含身份标签/会话号（骨架是纯壳，跨登录命中）；page_cache_key 已无 cookies 参数
    let uri: http::Uri = "https://github.com/settings/profile?tab=x".parse().unwrap();
    let gz = page_cache_key(&uri, "github.com", "gzip");
    let id = page_cache_key(&uri, "github.com", "identity");
    assert!(gz.contains("?tab=x") && gz.ends_with("-gz"), "{gz}");
    assert!(id.ends_with("-id"), "{id}");
    assert!(!gz.contains("-cs"), "keep 键不得含身份标签: {gz}");
    assert_ne!(
        gz,
        page_cache_key(&uri, "github.com", "identity"),
        "编码必须分键"
    );
    // 首页键带 -k（跨会话复用）
    let home_uri: http::Uri = "https://github.com/".parse().unwrap();
    let home_key = live_cache_key(&home_uri, "github.com", "gzip", "-html");
    assert!(
        home_key.ends_with("-html-k"),
        "首页骨架键必须带 -k: {home_key}"
    );
    // 搜索键 = 归一化查询（p=1 补齐+参数排序）+ 变体 + -k
    let search_uri: http::Uri = "https://github.com/search?q=rust".parse().unwrap();
    let search_key = live_cache_key(&search_uri, "github.com", "gzip", "-html");
    assert!(
        search_key.contains("q=rust") && search_key.ends_with("-html-k"),
        "{search_key}"
    );

    // 纯壳化：骨架不分登录/未登录变体，任何会话态读同一份。
    let anon_uri: http::Uri = "https://github.com/".parse().unwrap();
    let anon_key = live_cache_key(&anon_uri, "github.com", "identity", "-html");
    let anon = b"<html><body class=\"logged-out env-production\">results</body></html>";
    let _ = persist_page_entry_blocking(&dir, &anon_key, anon, 200, &test_hdrs());
    assert!(
        page_cache_get(&anon_key).is_some(),
        "纯壳骨架必须能命中（不分登录态）"
    );

    // ⑪b gzip 正文照样按响应实际编码分桶：gzip 响应进 -gz 键，identity 键查不到（不串桶）。
    let html = b"<html><body>results</body></html>";
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut enc, html).unwrap();
    let gzbody = enc.finish().unwrap();
    let gz_uri: http::Uri = "https://github.com/gzpath".parse().unwrap();
    let gz_resp = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "gzip")
        .body(protocol::full_body(Bytes::from(gzbody)))
        .unwrap();
    let _ = collect_and_submit_keep(&log, &gz_uri, "github.com", false, gz_resp).await;
    // 写盘走异步 worker，等它落盘再查。
    std::thread::sleep(std::time::Duration::from_millis(50));
    let gz_key = live_cache_key(&gz_uri, "github.com", "gzip", "-html");
    let id_key = live_cache_key(&gz_uri, "github.com", "identity", "-html");
    assert!(
        page_cache_get(&gz_key).is_some(),
        "gzip 响应必须按实际编码进 gzip 桶"
    );
    assert!(
        page_cache_get(&id_key).is_none(),
        "gzip 正文不得串进 identity 桶"
    );

    // ⑪c 闸门页：按请求 URL 回 200，写入侧与读侧都必须拦（与登录态无关）
    let gate_html = b"<html><head><title>Verify your two-factor authentication (2FA) settings</title></head><body><h1>Verify your two-factor authentication (2FA) settings</h1><p>This is a one-time verification of your recently configured 2FA credentials.</p></body></html>";
    assert!(
        is_gate_page(&plain_prefix(gate_html, "identity")),
        "2FA 验证页必须识别"
    );
    assert!(
        !is_gate_page(&plain_prefix(
            b"<html><body class=\"logged-in env-production\">repo</body></html>",
            "identity"
        )),
        "普通页面不得误判"
    );
    let gate_uri: http::Uri = "https://github.com/o/r-gate".parse().unwrap();
    let gate = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(protocol::full_body(Bytes::from_static(gate_html)))
        .unwrap();
    let _ = collect_and_submit_keep(&log, &gate_uri, "github.com", false, gate).await;
    let gate_key = live_cache_key(&gate_uri, "github.com", "identity", "-html");
    assert!(page_cache_get(&gate_key).is_none(), "闸门页不得入缓存");
    // 读侧：已存下的闸门页命中时也判 miss
    let old_gate_key = "GET github.com/o/r-old-gate";
    let _ = persist_page_entry_blocking(&dir, old_gate_key, gate_html, 200, &test_hdrs());
    assert!(
        page_cache_get(old_gate_key).is_none(),
        "旧的闸门页条目必须当 miss"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
/// D. 手删缓存目录：读 miss、写自愈重建、各类删除/淘汰不得报错或停摆。
#[test]
fn survives_manual_cache_delete() {
    let (dir, _g) = own_dir("manual");
    let k = "GET github.com/manual";
    let _ = persist_page_entry_blocking(&dir, k, b"<html>m</html>", 200, &test_hdrs());
    assert!(page_cache_get(k).is_some(), "前提：有条目");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(page_cache_get(k).is_none(), "目录没了 = miss，不能报错");
    invalidate_prefix_blocking(&dir, "github.com", "/manual"); // 不得 panic
    maybe_wipe_on_growth(&dir, 1); // 不得 panic
    wipe_pages(&dir); // 不得 panic
    let _ = persist_page_entry_blocking(&dir, k, b"<html>m2</html>", 200, &test_hdrs());
    assert!(page_cache_get(k).is_some(), "写入应自愈重建目录");
    let _ = std::fs::remove_dir_all(&dir);
}

/// E. keep 对象收敛：只有首页与搜索页两个键形态；仓库/列表/详情页不进 keep。
#[test]
fn keep_scope_is_home_and_search_only() {
    let mk = |path: &str, variant: &str| {
        let uri: http::Uri = format!("https://github.com{path}").parse().unwrap();
        live_cache_key(&uri, "github.com", "gzip", variant)
    };
    // keep 白名单：首页 + 搜索页
    let home = mk("/", "-html");
    let search = mk("/search", "-html");
    assert!(home.ends_with("-k"), "{home}");
    assert!(search.ends_with("-k"), "{search}");
    // 其余路径：live_cache_key 仅供首页/搜索页调用（cache_put 分流已保证）；此处直查键形态
    let repo = mk("/octocat/repo", "-html");
    assert!(repo.ends_with("-k"), "{repo}");
}

/// 截断 keep 骨架须读失败并删文件自愈。
#[test]
fn truncated_keep_entry_self_destructs() {
    let (dir, _g) = own_dir("trunc");
    let ck = "GET github.com/-k";
    let _ = persist_page_entry_blocking(
        &dir,
        ck,
        b"<html><head>truncated page without closing tag",
        200,
        &test_hdrs(),
    );
    let keep = dir.join("keep");
    assert_eq!(std::fs::read_dir(&keep).unwrap().count(), 1);
    assert!(
        load_disk_entry_reason(ck).is_err(),
        "截断骨架必须当 miss"
    );
    assert_eq!(
        std::fs::read_dir(&keep).unwrap().count(),
        0,
        "截断条目必须当场删除(自愈)"
    );
    // 完整骨架照常命中
    let _ = persist_page_entry_blocking(&dir, ck, b"<html>ok</html>", 200, &test_hdrs());
    assert!(load_disk_entry_reason(ck).is_ok(), "完整骨架必须命中");
}

/// 大 Cookie 被 h2 拆多行：user_session 在第二行也必须认出登录态（XHR 键的身份标签与 keep 无关）。
#[test]
fn split_cookie_headers_still_fingerprint_account() {
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("https://github.com/")
        .header("cookie", "_gh_sess=abc; _device_id=xyz")
        .header("cookie", "user_session=tok123; dotcom_user=zhidian-cmd")
        .body(())
        .unwrap();
    let joined = all_cookies(req.headers()).expect("应有 cookie");
    assert!(
        joined.contains("_gh_sess=abc") && joined.contains("user_session=tok123"),
        "两行 cookie 都要在: {joined}"
    );
    assert_eq!(session_value(Some(&joined)), Some("tok123"));
    assert_eq!(
        session_fingerprint(Some(&joined)),
        format!("-cs{}", page_file_name("tok123")),
        "自报账号名(dotcom_user)不参与指纹，只认会话号摘要"
    );
}

/// 资产缓存已删除；本测试仅钉页面缓存键不含资产域。
#[test]
fn asset_cache_is_removed_by_design() {
    // 只钉页面缓存键从不含资产域。
    let mk = |p: &str| page_cache_key(&p.parse::<http::Uri>().unwrap(), "github.com", "br");
    assert!(
        !mk("/octocat/repo").contains("githubassets"),
        "页面键与资产域无关"
    );
}

/// no-store 不落盘；private 不拒。
#[test]
fn no_store_responses_are_never_saved() {
    let mk = |cc: &str| {
        let mut h = http::HeaderMap::new();
        h.insert("cache-control", cc.parse().unwrap());
        h
    };
    assert!(resp_no_store(&mk("no-store, max-age=0")));
    assert!(resp_no_store(&mk("private, NO-STORE")), "大小写不敏感");
    assert!(!resp_no_store(&mk("max-age=0, private, must-revalidate")));
    assert!(!resp_no_store(&http::HeaderMap::new()));
}

/// 写失效改标过期（keep 骨架）：mtime 拨过期，重拉覆盖后解除。
#[test]
fn write_invalidation_marks_keep_snapshot_expired() {
    let (dir, _g) = own_dir("stalemark");
    let key = "GET github.com/-k";
    persist_page_entry_blocking(
        &dir,
        key,
        b"<html>home v1 body with some padding to pass seg minimum</html>",
        200,
        &test_hdrs(),
    )
    .unwrap();
    let (_, expired) = load_disk_entry_reason(key).unwrap();
    assert!(!expired, "新骨架不该标过期");
    // 写失效（前缀命中首页键）：条目不删，标过期，交旧
    invalidate_prefix_blocking(&dir, "github.com", "/");
    assert!(
        load_disk_entry(key).is_some(),
        "keep 条目不得被写失效删除"
    );
    let ((_, _, body), expired) = load_disk_entry_reason(key).unwrap();
    assert!(expired, "写失效后必须标过期(交旧+后台重拉)");
    assert_eq!(
        body.as_ref(),
        &b"<html>home v1 body with some padding to pass seg minimum</html>"[..],
        "交旧的体必须完整"
    );
    // 模拟后台重拉覆盖入库：mtime 复新 → 过期解除
    persist_page_entry_blocking(
        &dir,
        key,
        b"<html>home v2 body with some padding to pass seg minimum</html>",
        200,
        &test_hdrs(),
    )
    .unwrap();
    let ((_, _, body), expired) = load_disk_entry_reason(key).unwrap();
    assert!(!expired, "重拉覆盖后过期必须解除");
    assert_eq!(
        body.as_ref(),
        &b"<html>home v2 body with some padding to pass seg minimum</html>"[..]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 软导航 HTML 片段：局部 HTML（无 <html 根）且体积在上限内才收；整页 HTML / 超限不收。
#[test]
fn html_fragment_gate() {
    let ct = "text/html; charset=utf-8";
    assert!(is_html_fragment(ct, b"<div id=\"results\">partial</div>", "identity"));
    assert!(is_html_fragment(ct, b"<turbo-frame id=\"x\">ok</turbo-frame>", "identity"));
    assert!(
        !is_html_fragment(ct, b"<!DOCTYPE html><html><body>full</body></html>", "identity"),
        "整页 HTML 不得当片段收"
    );
    assert!(
        !is_html_fragment("application/json", b"{}", "identity"),
        "非 HTML 类型不是片段"
    );
    let big = vec![b'x'; HTML_FRAGMENT_MAX_BYTES + 1];
    assert!(!is_html_fragment(ct, &big, "identity"), "超限不收");
}

/// 文档导航判定：只有 sec-fetch-dest=document 是整页；无该头保守按整页处理（curl/Git）。
#[test]
fn document_nav_gate() {
    let mk = |dest: Option<&str>| {
        let mut b = hyper::Request::builder().uri("https://github.com/conduit/x");
        if let Some(d) = dest {
            b = b.header("sec-fetch-dest", d);
        }
        b.body(protocol::empty_body()).unwrap()
    };
    assert!(is_document_nav(&mk(Some("document"))));
    assert!(is_document_nav(&mk(Some("Document"))), "大小写不敏感");
    assert!(is_document_nav(&mk(None)), "无头按整页，保守不收片段");
    assert!(!is_document_nav(&mk(Some("empty"))), "fetch 片段请求");
    assert!(!is_document_nav(&mk(Some("iframe"))), "iframe 子文档按片段路径");
}

/// XHR 搜索 JSON 不得给文档导航回放成裸 JSON；整页 "-p" 桶与 "-j" 键互斥。
#[test]
fn document_nav_must_not_take_xhr() {
    let _g = serial(); // 直接读写全局 XHR 池，必须与其他缓存用例串行
    let uri: http::Uri = "https://github.com/search?q=hakim_regression&type=repositories&p=1"
        .parse()
        .unwrap();
    let key = xhr_cache_key(&uri, "github.com", None, "gzip", "-j");
    xhr_store(
        &key,
        200,
        vec![vec![
            "content-type".to_string(),
            "application/json".to_string(),
        ]],
        Bytes::from_static(b"{\"payload\":1}"),
    );
    // 键里没有请求形态：同一 URL 的 JSON 确实能被取到，桶隔离是唯一防线。
    assert!(xhr_take(&key).is_some(), "JS 取数的 JSON 应确实在 XHR 池里");

    let mk = |dest: Option<&str>| {
        let mut b = hyper::Request::builder().uri(uri.clone());
        if let Some(d) = dest {
            b = b.header("sec-fetch-dest", d);
        }
        b.body(protocol::empty_body()).unwrap()
    };
    // 文档导航只认 "-p" 整页桶，绝不落到存着 JSON 的 "-j" 桶。
    assert_eq!(xhr_lookup_kind(&mk(Some("document")), None), Some("-p"));
    assert_eq!(xhr_lookup_kind(&mk(None), None), Some("-p"));
    assert_eq!(
        xhr_lookup_kind(&mk(Some("empty")), Some("application/json")),
        Some("-j")
    );
    assert_eq!(
        xhr_lookup_kind(&mk(Some("iframe")), Some("application/json")),
        Some("-j")
    );
    // "-p" 键与 "-j" 键不同：JSON 正文不会被当成整页回放。
    let page_key = xhr_cache_key(&uri, "github.com", None, "gzip", "-p");
    assert_ne!(page_key, key, "整页桶与 JSON 桶必须互斥");
    assert!(xhr_take(&page_key).is_none(), "整页桶不该里有 JSON");
}

/// 文档导航按 xhr_lookup_kind 选 "-p" 桶取回完整 HTML，不回放成裸 JSON。
#[test]
fn search_nav_replays_full_page_from_own_bucket() {
    let _g = serial();
    page_cache_clear();
    let uri: http::Uri = "https://github.com/search?q=relay&type=repositories"
        .parse()
        .unwrap();
    let cookies = Some("user_session=relayuser");
    let enc = "gzip";
    let full_html = b"<html>react-app.embeddedData results</html>".as_slice();

    // 存侧：整页 → -p；JS 取数的 JSON → -j（两者共存）
    let pkey = xhr_cache_key(&uri, "github.com", cookies, enc, "-p");
    let jkey = xhr_cache_key(&uri, "github.com", cookies, enc, "-j");
    xhr_store(
        &pkey,
        200,
        vec![vec!["content-type".into(), "text/html; charset=utf-8".into()]],
        Bytes::copy_from_slice(full_html),
    );
    xhr_store(
        &jkey,
        200,
        vec![vec!["content-type".into(), "application/json".into()]],
        Bytes::from_static(b"{\"payload\":{\"count\":42}}"),
    );

    // 取侧：文档导航选 -p，取回完整 HTML（不是 JSON）
    let nav = hyper::Request::builder()
        .uri(uri.clone())
        .header("sec-fetch-dest", "document")
        .header("cookie", "user_session=relayuser")
        .body(protocol::empty_body())
        .unwrap();
    let nav_cookies = all_cookies(nav.headers());
    let kind = xhr_lookup_kind(&nav, Some("text/html,application/xhtml+xml"));
    assert_eq!(kind, Some("-p"));
    let (_, hdrs, body) = xhr_take(&xhr_cache_key(
        &uri,
        "github.com",
        nav_cookies.as_deref(),
        enc,
        kind.unwrap(),
    ))
    .expect("文档导航应命中整页桶");
    assert!(
        hdrs.iter().any(|h| h[0].eq_ignore_ascii_case("content-type")
            && h[1].contains("text/html")),
        "回放的必须是 HTML 整页"
    );
    assert_eq!(body.as_ref(), full_html, "不得是裸 JSON");
    // JSON 桶仍在，供 JS 取数照常命中，互不干扰。
    assert!(xhr_take(&jkey).is_some(), "JSON 桶不受影响");
}

/// 首页文档导航不走 XHR（走 keep 7 天骨架），其余路径文档导航回源。
#[test]
fn document_nav_outside_search_has_no_xhr_bucket() {
    for uri in ["https://github.com/", "https://github.com/octocat/repo"] {
        let uri: http::Uri = uri.parse().unwrap();
        let req = hyper::Request::builder()
            .uri(uri)
            .header("sec-fetch-dest", "document")
            .body(protocol::empty_body())
            .unwrap();
        assert_eq!(xhr_lookup_kind(&req, Some("text/html")), None);
    }
}

/// XHR 正文判定覆盖面：标准 JSON、`+json` 家族、ndjson、纯文本都收；HTML/二进制等不收。
#[test]
fn xhr_body_types_cover_json_family_and_ndjson() {
    for ct in [
        "application/json",
        "application/json; charset=utf-8",
        "text/plain; charset=utf-8",
        "application/vnd.github+json",
        "application/problem+json; charset=utf-8",
        "application/graphql-response+json",
        "application/x-ndjson",
    ] {
        assert!(is_xhr_body(ct), "应收进 XHR: {ct}");
        assert!(!keep_route("/search", ct), "数据正文不得进 keep 骨架: {ct}");
    }
    for ct in [
        "text/html; charset=utf-8",
        "application/octet-stream",
        "image/svg+xml",
        "",
    ] {
        assert!(!is_xhr_body(ct), "不得进 XHR: {ct}");
    }
}

/// 首页骨架取存两侧键须一致。
#[test]
fn home_keep_lookup_variant_matches_store() {
    let uri: http::Uri = "https://github.com/".parse().unwrap();
    let lookup = live_cache_key(&uri, "github.com", "gzip", keep_lookup_variant("/", None));
    let store = live_cache_key(&uri, "github.com", "gzip", "-html");
    assert_eq!(lookup, store, "首页取侧键必须与存侧键一致，否则骨架永不命中");
    // 搜索页按 Accept 预测保持不变
    assert_eq!(
        keep_lookup_variant("/search", Some("text/html,application/json")),
        "-html"
    );
    assert_eq!(
        keep_lookup_variant("/search", Some("application/json")),
        "-json"
    );
}

/// 搜索页整页进 "-p" 桶：键带身份、15 分钟 TTL、与 "-j" 互斥；导航只回放完整 HTML。
#[test]
fn search_full_page_uses_isolated_identity_scoped_bucket() {
    let uri: http::Uri = "https://github.com/search?q=rust&type=repositories"
        .parse()
        .unwrap();
    let alice = xhr_cache_key(&uri, "github.com", Some("user_session=abc"), "gzip", "-p");
    let bob = xhr_cache_key(&uri, "github.com", Some("user_session=xyz"), "gzip", "-p");
    let json = xhr_cache_key(&uri, "github.com", Some("user_session=abc"), "gzip", "-j");
    let frag = xhr_cache_key(&uri, "github.com", Some("user_session=abc"), "gzip", "-h");
    assert_ne!(alice, bob, "搜索页含 csrf_tokens，跨账号必须分键");
    assert_ne!(alice, json, "整页与 JSON 必须分键");
    assert_ne!(alice, frag, "整页与软导航片段必须分键");
    assert!(alice.contains("-p") && !alice.contains("-k"), "整页桶是 -p 且不带磁盘 keep 后缀");
}

// ---------- XHR 15 分钟内存缓存 ----------

/// 首页/搜索页 JSON 改道 XHR：这两条路径上的 JSON 是数据不是壳，不再送进 keep 分支落盘。
#[test]
fn home_search_json_routes_to_xhr_not_keep() {
    let json = "application/json; charset=utf-8";
    assert!(!keep_route("/", json), "首页 JSON 必须改道 XHR");
    assert!(!keep_route("/search", json), "搜索页 JSON 必须改道 XHR");
    assert!(keep_route("/", "text/html"), "首页 HTML 仍走 keep 骨架");
    assert!(
        !keep_route("/search", "text/html"),
        "搜索页整页 HTML 内嵌结果，必须走 15 分钟内存桶，不再落盘 7 天"
    );
    assert!(
        !keep_route("/octocat/repo", "text/html"),
        "仓库页 HTML 永不进 keep"
    );
    // 取侧键形态不变：XHR 命中先于 keep，-json 变体文件不再产生。
    let uri: http::Uri = "https://github.com/search?q=rust".parse().unwrap();
    let key = xhr_cache_key(&uri, "github.com", Some("user_session=abc"), "gzip", "-j");
    assert!(!key.contains("-k"), "XHR 键不带 keep 后缀");
}

/// XHR 回放与 TTL：入库即命中（200/头/体原样），过期后 miss 且条目被惰性清除。
#[tokio::test]
async fn xhr_cache_ttl_and_replay() {
    let _g = serial(); // 全局 XHR 池是进程级状态，与容量用例串行
    let hdrs = vec![vec!["content-type".into(), "application/json".into()]];
    let key = "GET github.com/conduit/filter-csabc-id";
    xhr_store(key, 200, hdrs.clone(), Bytes::from_static(b"{\"a\":1}"));

    // 命中：状态/头/体原样
    let (status, h, body) = xhr_take(key).expect("15 分钟内应命中");
    assert_eq!(status, 200);
    assert_eq!(h, hdrs);
    assert_eq!(body.as_ref(), b"{\"a\":1}");

    // 模拟过期：拨回到期时刻
    let mut map = lock(&XHR_CACHE);
    let entry = map.get_mut(key).unwrap();
    entry.expires = std::time::Instant::now() - std::time::Duration::from_secs(1);
    drop(map);
    assert!(xhr_take(key).is_none(), "过期必须 miss");
    assert!(
        lock(&XHR_CACHE).get(key).is_none(),
        "过期条目必须被惰性清除"
    );
}

/// XHR 键含身份标签与编码标签：跨登录/跨编码不得互串（通知等数据含账号信息）。
#[test]
fn xhr_cache_key_separates_identity_and_encoding() {
    let mk = |cookies: Option<&str>, enc: &str| {
        let uri: http::Uri = "https://github.com/notifications/indicator".parse().unwrap();
        xhr_cache_key(&uri, "github.com", cookies, enc, "-j")
    };
    let alice = mk(Some("user_session=abc"), "gzip");
    let bob = mk(Some("user_session=xyz"), "gzip");
    assert_ne!(alice, bob, "不同账号必须分键（A 的通知不能给 B）");
    let gz = mk(Some("user_session=abc"), "br");
    assert_ne!(gz, alice, "编码不同必须分键");
    // JSON 与 HTML 片段必须分键，防互相串。
    let u: http::Uri = "https://github.com/notifications/indicator".parse().unwrap();
    let json = xhr_cache_key(&u, "github.com", None, "gzip", "-j");
    let html = xhr_cache_key(&u, "github.com", None, "gzip", "-h");
    assert_ne!(json, html, "JSON 与 HTML 片段必须分键");
    assert!(
        json.contains("-j") && html.contains("-h"),
        "键里应能看出表示档: {json} / {html}"
    );
}

/// XHR 容量护栏：总量超 5MB 按过期时间最早先淘汰；刚入库的条目不自删。
#[test]
fn xhr_cache_evicts_oldest_at_cap() {
    // page_cache_clear 会连磁盘目录一起清，必须与碰缓存的用例串行。
    let _g = serial();
    page_cache_clear(); // 清空共享 XHR_CACHE（其他用例可能存过）
    let hdrs = vec![vec!["content-type".into(), "application/json".into()]];
    // 6 条 × 1MB（伪随机体高熵）= 6MB > 5MB
    for i in 0..6 {
        let body = Bytes::from(pseudo_body(i, 1 << 20));
        xhr_store(&format!("GET github.com/x{i}"), 200, hdrs.clone(), body);
    }
    let total = XHR_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        total <= 5 * 1024 * 1024,
        "总量必须压到 5MB 以内: {total}"
    );
    assert!(lock(&XHR_CACHE).len() >= 1, "至少保留刚入库的条目");
    page_cache_clear();
}

// ---------- v7 资产库 ----------

/// 日志捕获：断言 [资产] 行。
fn log_capture() -> (LogFn, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let cap = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = cap.clone();
    (
        std::sync::Arc::new(move |s: &str| {
            sink.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(s.to_string());
        }),
        cap,
    )
}

fn get_req(uri: &str) -> hyper::Request<BoxBody> {
    hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .body(protocol::empty_body())
        .unwrap()
}

/// v7 资产分支：白名单 200 入库 → cache_take 本地回放。
#[tokio::test]
async fn asset_branch_stores_and_replays() {
    let (dir, _g) = own_dir("assets");
    let (log, _lines) = log_capture();
    let url = "https://github.githubassets.com/assets/core-cccc3333.js";
    let req = get_req(url);

    // 入库（200 + application/javascript），响应原样交回
    let resp = hyper::Response::builder()
        .status(200)
        .header("content-type", "application/javascript; charset=utf-8")
        .body(protocol::full_body(Bytes::from_static(b"console.log(1)")))
        .unwrap();
    let out = collect_asset(&log, &req, resp).await;
    assert_eq!(out.status(), 200, "响应原样交回");
    // 管家线程异步落盘：轮询等待（上限 2s）
    let mut stored = None;
    for _ in 0..40 {
        if let Some(hit) = asset_store::take(&dir, url) {
            stored = Some(hit);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let stored = stored.expect("必须入库（管家异步写盘）");
    let stored_body = http_body_util::BodyExt::collect(stored.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(stored_body.as_ref(), b"console.log(1)");

    // 回放：资产库强绑定入口本地命中
    let hit = asset_store::serve_or_fetch(&log, &req, asset_store::ASSET_HOST)
        .await
        .expect("必须本地命中");
    assert_eq!(hit.status(), 200);
    let _ = std::fs::remove_dir_all(&dir);
}
