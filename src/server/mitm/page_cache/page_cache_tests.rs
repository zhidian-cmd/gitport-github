/// 骨架拦截三态:正常结果页与真实零结果页恒含 embeddedData(缓存),
/// blackbird 限流骨架恒缺(拦截)。GitHub 改 payload 封装名时这里会红,
/// 避免搜索页缓存静默失效。
#[test]
fn search_skeleton_gate() {
    let k = "GET github.com/search?q=x&type=repositories-cloggedout-gz";
    let full = "<html>{}react-app.embeddedData{}</html>".to_string();
    assert!(
        !is_search_skeleton(k, full.as_bytes(), false),
        "含结果载体的正常页应缓存"
    );
    assert!(
        is_search_skeleton(k, b"<html>Your search did not match</html>", false),
        "无结果载体的骨架应拦截"
    );
    // 非 /search? 键不受此判定(count XHR 的骨架照缓存,无害)
    assert!(!is_search_skeleton(
        "GET github.com/search/count?q=x-cloggedout",
        b"{}",
        false
    ));
}

/// gzip 分支:全量解压后判定,明文尾部才有的载体标志不漏判。
#[test]
fn search_skeleton_gate_gzip() {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let k = "GET github.com/search?q=x&type=repositories-cloggedout-gz";
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b"<html>padding</html>react-app.embeddedData<html>/</html>")
        .unwrap();
    let gz = enc.finish().unwrap();
    assert!(
        !is_search_skeleton(k, &gz, true),
        "gzip 正常页解压后应命中载体标志"
    );
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(b"<html>Your search did not match any</html>").unwrap();
    let gz = enc.finish().unwrap();
    assert!(is_search_skeleton(k, &gz, true), "gzip 骨架应拦截");
}

use super::*;

/// Ctrl+F5 直通：带 no-cache 的请求必须回源，哪怕路径是列表页。
/// max-age=0 不算——浏览器后退/前进也带它，当成强制刷新会让缓存永远命不中。
#[test]
fn no_cache_header_bypasses_cache() {
    let list = "/octocat/repo/issues";
    assert!(
        !cache_eligible_rules("github.com", &Method::GET, list, Some("no-cache"), true),
        "带 no-cache 的列表页不该进缓存"
    );
    assert!(
        cache_eligible_rules("github.com", &Method::GET, list, None, true),
        "同一条请求去掉 no-cache 就该进"
    );
    assert!(
        cache_eligible_rules("github.com", &Method::GET, list, Some("max-age=0"), true),
        "max-age=0 不是强制刷新"
    );
    // 准入的其他三条边界
    assert!(!cache_eligible_rules(
        "gist.github.com",
        &Method::GET,
        list,
        None,
        true
    ));
    assert!(!cache_eligible_rules(
        "github.com",
        &Method::POST,
        list,
        None,
        true
    ));
    assert!(!cache_eligible_rules(
        "github.com",
        &Method::GET,
        "/octocat/repo",
        None,
        true
    ));
}

/// /search 查询串归一化：p=1 与无 p 同键、参数重排同键；
/// 其他路径的查询串一个字符都不动（参数顺序可能有语义）。
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
        page_cache_key(&uri, "github.com", None, true)
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
    assert!(
        repo.contains("?q=1&page=2"),
        "其他路径的查询串不能被归一化"
    );
}

/// 搜索翻页页按软导航（sec-fetch-dest: empty → doc_nav=false）也要能进缓存：
/// GitHub 翻页是 React 软导航，按导航形态收会让翻页页永远不入缓存。
/// 非 /search 路径的软导航照旧不收（维持原有防杂收口）。
#[test]
fn search_page_eligible_regardless_of_nav_kind() {
    assert!(
        cache_eligible_rules("github.com", &Method::GET, "/search", None, false),
        "软导航的搜索页必须能存"
    );
    assert!(
        cache_eligible_rules("github.com", &Method::GET, "/search", None, true),
        "文档导航的搜索页照常能存"
    );
    assert!(
        cache_eligible_rules("github.com", &Method::GET, "/search/count", None, false),
        "/search/count 走 XHR 名单，软导航本就能存（既有设计）"
    );
    assert!(
        !cache_eligible_rules(
            "github.com",
            &Method::GET,
            "/octocat/repo/issues",
            None,
            false
        ),
        "其他列表页的软导航维持原状不收"
    );
    assert!(
        !cache_eligible_rules("github.com", &Method::GET, "/search", Some("no-cache"), false),
        "Ctrl+F5 直通对搜索页同样生效"
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

/// pages 目录的条目数与总字节（单文件存储的账）。
fn pages_stat(dir: &std::path::Path) -> (usize, u64) {
    let Ok(rd) = std::fs::read_dir(dir.join("pages")) else {
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

/// A. 读写往返、类型闸门、坏文件自愈、PeekRaw 拼回。
// own_dir 串行锁有意存活到测试结束(目录清理守卫), 跨 await 是本意。
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
        "GET github.com/search?q=x-cabc",
        b"<html>ok</html>",
        200,
        &hdrs,
    )
    .unwrap();
    let (n, _) = pages_stat(&dir);
    assert_eq!(n, 1, "应有一个缓存条目");
    let hit = page_cache_get("GET github.com/search?q=x-cabc").expect("应命中");
    assert_eq!(hit.headers().get("x-gitport-cache").unwrap(), "hit");
    let bytes = http_body_util::BodyExt::collect(hit.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(bytes.as_ref(), b"<html>ok</html>");

    // ② 非 HTML 不缓存（类型闸门在投递前，无后台写无竞速）
    let resp = hyper::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(upstream::full_body(Bytes::from_static(b"{}")))
        .unwrap();
    let _ = collect_and_submit(&log, "GET github.com/api/x", false, false, false, resp).await;
    assert!(page_cache_get("GET github.com/api/x").is_none(), "非 HTML 不缓存");

    // ②c 正文类型闸门（纯函数，落盘有时序所以不断言命中）
    assert!(body_type_allowed(Some("text/html; charset=utf-8"), false));
    assert!(body_type_allowed(Some("application/json; charset=utf-8"), true));
    assert!(body_type_allowed(Some("text/plain; charset=utf-8"), true));
    assert!(
        !body_type_allowed(Some("application/json; charset=utf-8"), false),
        "列表页不收 JSON"
    );
    assert!(!body_type_allowed(None, true), "没有 content-type 不收");

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
    let cpath = dir.join("pages").join(page_file_name(ck));
    std::fs::write(&cpath, b"\x10\x00\x00\x00short").unwrap();
    assert!(page_cache_get(ck).is_none(), "截断文件应判 miss");
    // 文件名确定性：同 key 永远同文件（跨重启可复现），异 key 必异文件
    assert_eq!(page_file_name(ck), page_file_name(ck));
    assert_ne!(page_file_name(ck), page_file_name("GET github.com/other"));
    // 碰撞防护：文件里存的 key 与请求 key 不符 → 拒服，不串页
    let bad_path = dir.join("pages").join(page_file_name("GET github.com/spoof"));
    let bad_hdr = serde_json::to_vec(&serde_json::json!({
        "key": "GET github.com/someone-else",
        "status": 200,
        "headers": test_hdrs(),
        "cachedAt": now_ms(),
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
        .body(upstream::full_body(Bytes::from_static(b"world</html>")))
        .unwrap();
    sniffed
        .extensions_mut()
        .insert(super::super::PeekRaw(vec![Bytes::from_static(
            b"<html>hello ",
        )]));
    let out =
        collect_and_submit(&log, "GET github.com/peek", false, false, false, sniffed).await;
    let body = http_body_util::BodyExt::collect(out.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        body.as_ref(),
        b"<html>hello world</html>",
        "嗅探前缀丢失 = 交付半页"
    );

    // ⑤b 首页骨架（-k）跨会话存活：会话清盘只清 pages/
    let home = "GET github.com/-cloggedout-gz-k";
    let _ = persist_page_entry_blocking(&dir, home, b"<html>home</html>", 200, &test_hdrs());
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/issues-s1",
        b"<html>i</html>",
        200,
        &test_hdrs(),
    );
    wipe_pages(&dir);
    assert!(page_cache_get(home).is_some(), "首页骨架必须跨会话存活");
    assert!(
        page_cache_get("GET github.com/issues-s1").is_none(),
        "会话条目应被清掉"
    );

    // ⑤ gzip 条目读回：头/正文仍是压缩态，且读侧的解压判断不瞎
    // （只测"解压函数认得出来"不够，得把存→读整条链走一遍）
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
    let mut gate = b"<html><head><title>Verify your two-factor authentication</title></head><body>"
        .to_vec();
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

/// B. 超量：一个会话攒过上限就整盘重来（不排序、不逐个淘汰）。
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
    assert_eq!(pages_stat(&dir).0, 3, "前提：攒了 3 条");
    maybe_wipe_on_growth(&dir, PAGE_CACHE_MAX_BYTES as usize);
    assert_eq!(pages_stat(&dir).0, 0, "超量应整盘清空");

    // ⑥ 清空：pages 条目全没（page_cache_clear 是测试专用工具）
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/again",
        b"<html>a</html>",
        200,
        &test_hdrs(),
    );
    assert!(page_cache_get("GET github.com/again").is_some(), "前提：有条目");
    page_cache_clear();
    let (n, _) = pages_stat(&dir);
    assert_eq!(n, 0, "清空后条目应为零");

    let _ = std::fs::remove_dir_all(&dir);
}

/// C. 键的语义（身份 / 编码 / 会话边界）、写后失效、未登录页防污染、闸门页。
// own_dir 串行锁有意存活到测试结束(目录清理守卫), 跨 await 是本意。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn keys_invalidation_and_pollution() {
    let (dir, _dir_guard) = own_dir("key");
    let log = log_sink();

    // ⑧ 会话边界：空闲超阈值（或进程第一页）→ 清盘并从空白重来；紧跟的请求不再清
    set_last_nav(0);
    assert!(note_nav(), "进程启动/空闲后的第一页必须判为新会话");
    assert!(!note_nav(), "紧跟其后的第二页不该再清盘（swap 只让第一个请求拿到旧时间戳）");
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/old-session",
        b"<html>o</html>",
        200,
        &test_hdrs(),
    );
    assert!(page_cache_get("GET github.com/old-session").is_some(), "前提：有旧条目");
    assert_eq!(wipe_pages(&dir), 1, "应清掉上一会话的 1 条");
    assert_eq!(wipe_pages(&dir), 0, "空目录再清一次不得报错");
    assert!(
        page_cache_get("GET github.com/old-session").is_none(),
        "清盘后上一会话的条目不得再命中"
    );

    // ⑨ 写后失效：同路径前缀删除
    let sk = "GET github.com/settings/profile-cabc";
    let _ = persist_page_entry_blocking(&dir, sk, b"<html>s</html>", 200, &test_hdrs());
    assert!(page_cache_get(sk).is_some(), "前提：条目已缓存");
    invalidate_after_write(&log, "github.com", "/settings/profile");
    invalidate_prefix_blocking(&dir, "github.com", "/settings/profile");
    assert!(page_cache_get(sk).is_none(), "写操作后磁盘条目应失效");

    // ⑨b 子路径写端点：评论后议题页失效
    let issue_key = "GET github.com/o/r/issues/5-calice-gz";
    let other_key = "GET github.com/o/r/pulls/9-calice-gz";
    for k in [issue_key, other_key] {
        let _ = persist_page_entry_blocking(
            &dir,
            k,
            b"<html>i</html>",
            200,
            &test_hdrs(),
        );
    }
    invalidate_prefix_blocking(&dir, "github.com", "/o/r/issues/5/comment");
    assert!(
        page_cache_get(issue_key).is_none(),
        "评论后议题页必须失效（父路径匹配）"
    );
    assert!(page_cache_get(other_key).is_some(), "无关页面不得被牵连");

    // ⑩ 身份标签：账号进键（同机两个账号不得共享页面）
    let a = session_fingerprint(Some("user_session=abc; dotcom_user=alice"));
    let a2 = session_fingerprint(Some("user_session=zzz; dotcom_user=alice"));
    let b = session_fingerprint(Some("dotcom_user=bob; user_session=q"));
    assert_eq!(a, "-calice", "登录态标签带账号名");
    assert_eq!(a, a2, "同账号轮换 user_session 不换键");
    assert_ne!(a, b, "不同账号必须分键（A 的设置页不能给 B）");
    assert_eq!(session_fingerprint(None), "-cloggedout", "未登录固定标签");
    assert_eq!(
        session_fingerprint(Some("_gh_sess=r1; _octo=GH1")),
        "-cloggedout",
        "只有 _gh_sess 不算登录"
    );
    // 拿不到 dotcom_user：退回 session 值哈希，仍按账号分开（轮换只损失命中）
    let h1 = session_fingerprint(Some("user_session=abc"));
    let h2 = session_fingerprint(Some("user_session=xyz"));
    assert!(h1.starts_with("-cs") && h1 != h2, "{h1} / {h2}");
    // _gh_sess 每个响应都轮换：兜底哈希只取 user_session 值，键必须稳住
    assert_eq!(
        session_fingerprint(Some("user_session=abc; _gh_sess=r1; _octo=GH1.1")),
        session_fingerprint(Some("user_session=abc; _gh_sess=r2; _octo=GH1.1")),
        "轮换 _gh_sess 不得换键（否则每请求一个新的缓存文件）"
    );
    // 键里同时带身份与编码：curl 与浏览器不会互串
    let uri: http::Uri = "https://github.com/settings/profile?tab=x".parse().unwrap();
    let alice = "user_session=s1; dotcom_user=alice";
    let bob = "user_session=s2; dotcom_user=bob";
    let gz = page_cache_key(&uri, "github.com", Some(alice), true);
    let id = page_cache_key(&uri, "github.com", Some(alice), false);
    assert!(gz.contains("?tab=x") && gz.ends_with("-calice-gz"), "{gz}");
    assert!(id.ends_with("-calice-id"), "{id}");
    assert_ne!(
        gz,
        page_cache_key(&uri, "github.com", Some(bob), true),
        "同机换账号必须换键"
    );
    // ⑩a 首页键带 -k（不带会话号，跨会话复用）
    let home_uri: http::Uri = "https://github.com/".parse().unwrap();
    assert!(
        live_cache_key(&home_uri, "github.com", Some(alice), true, "").ends_with("-k"),
        "首页骨架键必须带 -k"
    );

    // ⑩b 换会话后旧键必须失效（不依赖清盘是否成功）
    let k_before = live_cache_key(&uri, "github.com", Some(alice), true, "");
    set_last_nav(0);
    assert!(note_nav(), "伪造一次空闲");
    let k_after = live_cache_key(&uri, "github.com", Some(alice), true, "");
    assert_ne!(k_before, k_after, "换会话后同一页面必须是新键");
    // ⑩c 两次"进程首启"的会话号必须不同：否则重启后又拿回 -s2，与上一轮的盘上条目撞号
    let k1 = {
        set_last_nav(0);
        note_nav();
        live_cache_key(&uri, "github.com", None, true, "")
    };
    std::thread::sleep(std::time::Duration::from_millis(3));
    let k2 = {
        set_last_nav(0);
        note_nav();
        live_cache_key(&uri, "github.com", None, true, "")
    };
    assert_ne!(k1, k2, "重启后会话号不得与上一轮相同");

    // ⑪ 未登录页不入缓存（带会话却拿到登录页 = 会话已死）
    let poisoned = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(upstream::full_body(Bytes::from_static(
            b"<html><body class=\"logged-out env-production\">sign in</body></html>",
        )))
        .unwrap();
    let _ = collect_and_submit(&log, "GET github.com/-cauthed-poison", false, false, true, poisoned).await;
    assert!(
        page_cache_get_logged_in("GET github.com/-cauthed-poison").is_none(),
        "会话死亡期间的未登录页不得进缓存"
    );

    // ⑪d 匿名页双向判定：未登录浏览存下的页面，匿名请求必须能命中；
    // 同一份正文被带会话的请求拿到才算污染。少了前者，未登录用户的缓存全废
    // （线上症状：缓存写进去了却永远不命中）。
    let anon = b"<html><body class=\"logged-out env-production\">results</body></html>";
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/search-cloggedout-gz",
        anon,
        200,
        &test_hdrs(),
    );
    assert!(
        page_cache_get("GET github.com/search-cloggedout-gz").is_some(),
        "匿名页必须能命中（否则未登录用户的缓存等于全废）"
    );
    assert!(
        page_cache_get_logged_in("GET github.com/search-cloggedout-gz").is_none(),
        "带会话却拿到未登录页 = 会话已死，仍要当 miss"
    );

    // ⑪b gzip 正文：不解压就永远看不到标记（主站正文恒 gzip，旧版这道守卫等于没有）
    let mut html = b"<html><body class=\"logged-out env-production\">".to_vec();
    html.extend_from_slice(&vec![b'x'; 6000]);
    html.extend_from_slice(b"</body></html>");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut enc, &html).unwrap();
    let gzbody = enc.finish().unwrap();
    assert!(
        !is_logged_out_body(&plain_prefix(&gzbody, false)),
        "压缩体裸扫扫不到——这就是旧版失效的原因"
    );
    assert!(
        is_logged_out_body(&plain_prefix(&gzbody, true)),
        "解压后必须认出未登录页"
    );
    let poisoned_gz = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "gzip")
        .body(upstream::full_body(Bytes::from(gzbody)))
        .unwrap();
    let _ = collect_and_submit(
        &log,
        "GET github.com/-cauthed-gz-poison", false,
        false,
        true,
        poisoned_gz,
    )
    .await;
    assert!(
        page_cache_get_logged_in("GET github.com/-cauthed-gz-poison").is_none(),
        "gzip 未登录页同样不得入缓存"
    );

    // ⑪c 闸门页：按请求 URL 回 200，写入侧与读侧都必须拦
    let gate_html = b"<html><head><title>Verify your two-factor authentication (2FA) settings</title></head><body><h1>Verify your two-factor authentication (2FA) settings</h1><p>This is a one-time verification of your recently configured 2FA credentials.</p></body></html>";
    assert!(
        is_gate_page(&plain_prefix(gate_html, false)),
        "2FA 验证页必须识别"
    );
    assert!(
        !is_gate_page(&plain_prefix(
            b"<html><body class=\"logged-in env-production\">repo</body></html>",
            false
        )),
        "普通页面不得误判"
    );
    // 写入侧：与登录态无关，一律不存
    let gate = hyper::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(upstream::full_body(Bytes::from_static(gate_html)))
        .unwrap();
    let _ = collect_and_submit(&log, "GET github.com/o/r-gate", false, false, false, gate).await;
    assert!(
        page_cache_get("GET github.com/o/r-gate").is_none(),
        "闸门页不得入缓存"
    );
    // 读侧：已存下的闸门页命中时也判 miss
    let _ = persist_page_entry_blocking(
        &dir,
        "GET github.com/o/r-old-gate",
        gate_html,
        200,
        &test_hdrs(),
    );
    assert!(
        page_cache_get_logged_in("GET github.com/o/r-old-gate").is_none(),
        "旧的闸门页条目必须当 miss"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
/// D. 手删缓存目录：读 miss、写自愈重建、各类删除/淘汰不得报错或停摆。
#[test]
fn survives_manual_cache_delete() {
    let (dir, _dir_guard) = own_dir("manual");
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

/// E. 只缓存列表页：列表命中，仓库首页/文件/详情/设置一律不缓存。
#[test]
fn list_path_gate() {
    for p in [
        "/search",
        "/o/r/issues",
        "/o/r/pulls",
        "/o/r/commits/main",
        "/o/r/issues/assigned",
        "/o/r/releases",
        "/notifications",
        "/trending/python",
        "/topics/rust",
        "/o/r/stargazers",
    ] {
        assert!(is_list_path(p), "{p} 应判为列表页");
    }
    for p in [
        "/",
        "/o/r",
        "/o/r/blob/main/README.md",
        "/o/r/tree/main/src",
        "/o/r/issues/5",
        "/o/r/pull/123",
        "/o/r/commit/abc123",
        "/o/r/releases/tag/v1.0.0",
        "/o/r/issues/new", // 表单页：防伪 token 会被轮换踢掉
        "/o/r/releases/new",
        "/o/r/issues/5/edit",
        "/settings/profile",
        "/u/r/main/f.txt",
    ] {
        assert!(!is_list_path(p), "{p} 不该缓存");
    }
    // 跟班 XHR 前缀：列表页规则管不着它们，得单独放行
    for p in [
        "/search/count",
        "/search/blackbird_count",
        "/search/warm_blackbird_caches",
        "/in-product-messaging/",
        "/github-copilot/chat/repositories_search",
    ] {
        assert!(is_xhr_path(p), "{p} 应判为跟班 XHR");
    }
    for p in ["/", "/o/r", "/o/r/issues", "/search"] {
        assert!(!is_xhr_path(p), "{p} 不该判为跟班 XHR");
    }
    // 首页：纯骨架，单独放行
    assert!(is_home_path("/"));
    assert!(is_home_path(""));
    assert!(!is_home_path("/feed"));
    assert!(!is_home_path("/o/r"));
}
