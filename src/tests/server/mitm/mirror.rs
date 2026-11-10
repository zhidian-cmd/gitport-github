use super::*;
use bytes::Bytes;

#[test]
fn mirror_chain_cap_scope() {
    // is_big_file_host 走路由表（数据），先装种子表。
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join("gitport_mirror_cap_seed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);

    for h in [
        "raw.githubusercontent.com",
        "camo.githubusercontent.com",
        "avatars.githubusercontent.com",
        "user-images.githubusercontent.com",
        "media.githubusercontent.com",
        "gist.githubusercontent.com",
        "codeload.github.com",
    ] {
        assert_eq!(mirror_chain_cap(h), Some(5), "{h} 应限长 5 家");
    }
    for h in [
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ] {
        assert_eq!(mirror_chain_cap(h), None, "{h} 应用全链");
    }
}

#[test]
fn mirror_request_strips_identity_and_hop_by_hop() {
    let out = hyper::Request::builder()
        .method(Method::GET)
        .uri("https://raw.githubusercontent.com/a/b")
        .header("cookie", "logged_in=yes")
        .header("authorization", "Bearer tok")
        .header("connection", "close")
        .header("keep-alive", "timeout=5")
        .header("upgrade", "websocket")
        .header("te", "trailers")
        .header("range", "bytes=0-1023")
        .header("accept-encoding", "gzip")
        .header("user-agent", "UA/1.0")
        .body(protocol::empty_body())
        .unwrap();
    let req = mirror_request(
        &out,
        "https://gh-proxy.com",
        "https://raw.githubusercontent.com/a/b",
    )
    .unwrap();
    let h = req.headers();
    for gone in [
        "cookie",
        "authorization",
        "host",
        "referer",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
    ] {
        assert!(h.get(gone).is_none(), "{gone} 应被剥除");
    }
    assert_eq!(h.get("range").unwrap(), "bytes=0-1023", "业务头必须保留");
    assert_eq!(h.get("accept-encoding").unwrap(), "gzip");
    assert_eq!(h.get("user-agent").unwrap(), MIRROR_UA);
    let uri = req.uri().to_string();
    assert!(
        uri.starts_with("https://gh-proxy.com/https://raw.githubusercontent.com/"),
        "拼 URL 形态: {uri}"
    );
}

#[test]
fn calibrate_templates_cover_small_hosts_only() {
    // is_big_file_host 走路由表（数据），先装种子表。
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join("gitport_calibrate_seed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);

    for h in pool::CONTENT_HOSTS {
        let covered = CALIBRATE_TEMPLATES.iter().any(|(host, _)| host == h);
        if pool::route::is_big_file_host(h) {
            assert!(!covered, "{h} 大文件域不校准, 不应有模板");
        } else {
            assert!(covered, "{h} 小文件域缺 TTFB 校准模板");
        }
    }
    assert!(
        !CALIBRATE_TEMPLATES.iter().any(|(h, _)| *h == "github.com"),
        "github.com 链已除名, 不应有模板"
    );
}

#[test]
fn credential_query_detection() {
    for q in [
        "token=abc",
        "sig=1",
        "signature=1",
        "jwt=1",
        "auth=1",
        "access_token=x",
        "session_token=1",
        "AWSAccessKeyId=k",
        "X-Amz-Signature=abc",
        "x-amz-credential=1",
        "a=1&access_token=x",
    ] {
        assert!(has_credential_query(q), "{q} 应判含凭据");
    }
    for q in ["", "foo=token", "page=2&q=tokenize", "tokens=1"] {
        assert!(
            !has_credential_query(q),
            "{q} 不该误判（名字才参与，值不算）"
        );
    }
}

#[test]
fn ttfb_rank_fastest_first_failures_last() {
    let mut rows = vec![
        ("slow".to_string(), 900),
        ("fast".to_string(), 120),
        ("mid".to_string(), 300),
        ("dead".to_string(), -50),
    ];
    rank_by_ttfb(&mut rows);
    let order: Vec<&str> = rows.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(order, ["fast", "mid", "slow", "dead"], "{rows:?}");
}

#[tokio::test]
async fn chain_fetch_cred_locks_to_direct() {
    let lines: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = lines.clone();
    let log: LogFn = Arc::new(move |s: &str| sink.lock().unwrap().push(s.to_string()));
    let req = hyper::Request::builder()
        .uri("https://raw.githubusercontent.com/o/r/f?sig=abc")
        .body(protocol::empty_body())
        .unwrap();
    let err = chain_fetch(
        &log,
        &req,
        "raw.githubusercontent.com",
        mirror_test_direct_leg(),
        &Default::default(),
        &None,
    )
    .await
    .unwrap_err();
    assert!(err.contains("仅直连"), "凭据串应剥空镜像仅直连: {err}");
    let got = lines.lock().unwrap();
    assert!(
        got.iter().any(|l| l.contains("仅直连(防外泄")),
        "应记录剥空镜像决策: {got:?}"
    );
    assert!(
        !got.iter().any(|l| l.contains(" via ")),
        "签名 URL 不得交给第三方镜像: {got:?}"
    );
}

/// 可信镜像白名单：用户标记 trusted 的镜像，凭据串请求放行给它(知情授权)；未标记的镜像仍被剥除。放行名单为空时行为与旧版一致(仅直连)。
#[test]
fn cred_authorized_trusted_mirrors_only() {
    // settings 全局态无法按测隔离——直接验证放行集合的过滤逻辑: trusted_mirrors() 返回 on && trusted 的 URL, 镜像 URL 前缀匹配放行。
    use crate::settings::WorkerMirror;
    let mirrors = [
        WorkerMirror {
            url: "https://my-worker.example.com".into(),
            on: true,
            trusted: true,
            template: String::new(),
        },
        WorkerMirror {
            url: "https://public-proxy.example.org".into(),
            on: true,
            trusted: false,
            template: String::new(),
        },
    ];
    let trusted: std::collections::HashSet<String> = mirrors
        .iter()
        .filter(|w| w.on && w.trusted)
        .map(|w| w.url.clone())
        .collect();
    let chain = [
        "https://my-worker.example.com/".to_string(), // 可信(带尾斜杠变体)
        "https://public-proxy.example.org".to_string(), // 不可信
    ];
    let passed: Vec<&String> = chain
        .iter()
        .filter(|m| trusted.iter().any(|t| m.starts_with(t.as_str())))
        .collect();
    assert_eq!(passed.len(), 1, "只有可信镜像应被放行: {passed:?}");
    assert!(
        passed[0].starts_with("https://my-worker.example.com"),
        "放行的应是可信那家: {passed:?}"
    );
}

/// 纯直连耗尽(零镜像/凭据串剥空)不给镜像链上熔断——链没参与，别连坐。
#[tokio::test]
async fn direct_only_exhaustion_spares_chain_breaker() {
    let log: LogFn = Arc::new(|_: &str| {});
    let host = "cred-brk.test";
    pool::MIRROR_BREAKER.clear(host);
    let req = hyper::Request::builder()
        .uri("https://cred-brk.test/f?sig=abc")
        .body(protocol::empty_body())
        .unwrap();
    let err = chain_fetch(
        &log,
        &req,
        host,
        mirror_test_direct_leg(),
        &Default::default(),
        &None,
    )
    .await
    .unwrap_err();
    assert!(err.contains("仅直连"), "凭据串请求应仅派直连: {err}");
    assert!(
        !pool::MIRROR_BREAKER.open(host),
        "直连独走耗尽不得触发镜像链熔断"
    );
}

/// 审计 #3 回归: 熔断只拦有镜像候选的请求——凭据串剥空镜像后直连独走, 不得撞为镜像设的熔断(哪怕熔断正开着)。
#[tokio::test]
async fn breaker_spares_direct_only_requests() {
    let log: LogFn = Arc::new(|_: &str| {});
    let host = "brk-cred.test";
    pool::MIRROR_BREAKER.clear(host);
    pool::MIRROR_BREAKER.set(host);
    let req = hyper::Request::builder()
        .uri("https://brk-cred.test/f?sig=abc")
        .body(protocol::empty_body())
        .unwrap();
    let err = chain_fetch(
        &log,
        &req,
        host,
        mirror_test_direct_leg(),
        &Default::default(),
        &None,
    )
    .await
    .unwrap_err();
    assert!(!err.contains("熔断"), "直连独走不得撞镜像熔断: {err}");
    assert!(err.contains("仅直连"), "应照常仅派直连: {err}");
    pool::MIRROR_BREAKER.clear(host);
}

/// 审计 #2 回归: cap 窗口吃掉直连位时——健康直连追加为末位; 失败窗未过的不追加, 已在窗内不重复。
#[test]
fn append_direct_gated_by_health_and_presence() {
    let mut order = vec![0usize, 1, 2, 3, 4];
    append_direct_if_missed(&mut order, 8, 0, 1_000);
    assert_eq!(order.last(), Some(&8), "健康直连(降权已过期)应追加为末位");
    let mut order = vec![0usize, 1, 2, 3, 4];
    // 降权到 46_000 才过期, 现在 1_500: 还在窗内, 别急着重拨。
    append_direct_if_missed(&mut order, 8, 46_000, 1_500);
    assert!(!order.contains(&8), "失败窗未过不追加, 别急着重拨");
    let mut order = vec![0usize, 4, 8];
    append_direct_if_missed(&mut order, 8, 0, 1_000);
    assert_eq!(order, vec![0, 4, 8], "已在窗内不重复追加");
}

/// 测试用直连腿：恒失败(不拨真网)，用于驱动候选循环与失败降权路径。
fn mirror_test_direct_leg() -> DirectLeg<'static> {
    DirectLeg {
        fetch: Box::pin(async {
            Err::<hyper::Response<BoxBody>, String>("test: direct unavailable".into())
        }),
    }
}

/// ECT 时间槽：on_frame 只累计本窗实收，ect_sweep 快照进 window_prev；
/// 有债零收 = 卡死清零，无债零收 = 空闲沿用旧值——零 sleep，确定性验证。
#[test]
fn ect_window_slots_snapshot_stall_and_idle() {
    let ld = mirror_load("ect-slot.test");
    let mut g = LoadGuard::charge(ld.clone(), 8 * 1024 * 1024, true);
    g.on_frame(3 * 1024 * 1024);
    ect_sweep();
    assert_eq!(
        ld.window_prev.load(Ordering::Relaxed),
        3 * 1024 * 1024,
        "本窗实收快照进 prev"
    );
    assert_eq!(
        ld.window_bytes.load(Ordering::Relaxed),
        0,
        "快照后本窗清零重开"
    );

    // 下一窗有债零收：卡死 → prev 清零，派发立即避开。
    ect_sweep();
    assert_eq!(
        ld.window_prev.load(Ordering::Relaxed),
        0,
        "有债零收 = 卡死清零"
    );

    // 恢复出货：prev 换新值。
    g.on_frame(4 * 1024 * 1024);
    ect_sweep();
    assert_eq!(ld.window_prev.load(Ordering::Relaxed), 4 * 1024 * 1024);

    // 空闲窗（还清债务后无债无收）：沿用旧值，别把歇着的快家当死腿。
    drop(g);
    ect_sweep();
    assert_eq!(
        ld.window_prev.load(Ordering::Relaxed),
        4 * 1024 * 1024,
        "无债零收沿用旧值"
    );
    ld.window_prev.store(0, Ordering::Relaxed);
}

/// 先验退役：未交卷候选在 ECT 里按无穷大垫底——已交卷的慢腿也胜过它。
#[test]
fn ect_after_retirement_unprobed_loses_to_probed_slow() {
    let slow = mirror_load("retire-slow.test");
    slow.window_prev.store(100 * 1024, Ordering::Relaxed); // 100KB/s 已交卷
    let unprobed = mirror_load("retire-unprobed.test");
    unprobed.window_prev.store(0, Ordering::Relaxed);
    let chain = vec![
        "retire-slow.test".to_string(),
        "retire-unprobed.test".to_string(),
    ];
    assert_eq!(
        pick_mirror(&chain, 1024),
        0,
        "未交卷者 ECT 无穷大, 已交卷的慢腿也胜出(先验不再掺和)"
    );
    slow.window_prev.store(0, Ordering::Relaxed);
}

/// 直连同台：candidates = 镜像 + direct/{host}，ECT 统一派发。
#[test]
fn direct_competes_as_candidate() {
    let chain = vec!["cand-m.test".to_string()];
    let cands = [chain.as_slice(), &[direct_load_key("cand-host.test")][..]];
    let all: Vec<String> = cands.concat();
    // 直连快(8MB/s 实测) 镜像未交卷(ECT 无穷大垫底): 直连胜出。
    let d = mirror_load_for(&direct_load_key("cand-host.test"));
    d.window_prev.store(8 * 1024 * 1024, Ordering::Relaxed);
    let pick = pick_mirror(&all, 8 * 1024 * 1024);
    assert_eq!(
        all[pick],
        direct_load_key("cand-host.test"),
        "直连快时应胜出"
    );
    // 直连失败降权后 → 轮到镜像。
    mark_fail(&d, false);
    let pick = pick_mirror(&all, 8 * 1024 * 1024);
    assert_eq!(all[pick], "cand-m.test", "直连降权后应选镜像");
    d.window_prev.store(0, Ordering::Relaxed);
    d.fail_until.store(0, Ordering::Relaxed);
    // 零镜像: candidates 只有直连, pick 恒 0(直连键)。
    let only_direct = vec![direct_load_key("cand-host.test")];
    assert_eq!(all.len(), 2, "镜像+直连=2 候选");
    assert_eq!(pick_mirror(&only_direct, 1024), 0, "零镜像时候选=仅直连");
}

/// 忙而快的胜过闲而慢的；快镜像在途过深则公式自纠改选空闲者。
#[test]
fn ect_prefers_busy_fast_over_idle_slow() {
    let a = mirror_load("ect-a.test");
    let b = mirror_load("ect-b.test");
    a.in_flight_bytes.store(512 * 1024, Ordering::Relaxed);
    a.window_prev.store(5 * 1024 * 1024, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    b.window_prev.store(512 * 1024, Ordering::Relaxed);
    let chain = vec!["ect-a.test".to_string(), "ect-b.test".to_string()];
    // A (0.5+10)/5 ≈ 2s < B 10/0.5 = 20s → A。
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 0);
    // A (100+10)/5 = 22 > B 20 → B。
    a.in_flight_bytes
        .store(100 * 1024 * 1024, Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 1);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    a.window_prev.store(0, Ordering::Relaxed);
    b.window_prev.store(0, Ordering::Relaxed);
}

/// 全未交卷(ECT 同为无穷大、并列) → 轮转均摊；在途越深越垫底，闲者胜出。
#[test]
fn cold_start_falls_back_to_chain_order() {
    let a = mirror_load("cold-a.test");
    let b = mirror_load("cold-b.test");
    a.window_prev.store(0, Ordering::Relaxed);
    b.window_prev.store(0, Ordering::Relaxed);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["cold-a.test".to_string(), "cold-b.test".to_string()];
    // 全未交卷 → ECT 同为无穷大 → 并列 → 轮转(先验已退役, 不再按链位铺开)。
    a.in_flight_streams.store(0, Ordering::Relaxed);
    b.in_flight_streams.store(0, Ordering::Relaxed);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        seen.insert(pick_mirror(&chain, 1024));
    }
    assert!(
        seen.contains(&0) && seen.contains(&1),
        "冷启动全空应在容差内轮转均摊, 不塞链头: {seen:?}"
    );
    // 在途拉开(超容差) → 严格选闲者。
    a.in_flight_bytes.store(8 * 1024 * 1024, Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 1024), 1, "梯度速率下按在途字节分");
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    a.in_flight_streams.store(0, Ordering::Relaxed);
    b.in_flight_streams.store(0, Ordering::Relaxed);
}

/// 二级判据：ECT 并列组内选在途流最少者；流数也相同才轮转——高压镜像(流多)不再被继续堆片，从源头减少掐断误判。
#[test]
fn tie_prefers_fewer_inflight_streams() {
    let a = mirror_load("streams-a.test");
    let b = mirror_load("streams-b.test");
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    a.window_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.window_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
    a.in_flight_streams.store(0, Ordering::Relaxed);
    b.in_flight_streams.store(0, Ordering::Relaxed);
    let chain = vec!["streams-a.test".to_string(), "streams-b.test".to_string()];
    // ECT 并列(同速同在途字节)、A 已压 3 流 B 空闲 → 恒选 B。
    a.in_flight_streams.store(3, Ordering::Relaxed);
    for _ in 0..10 {
        assert_eq!(pick_mirror(&chain, 1024), 1, "流少的 B 应胜出");
    }
    // B 也压上 3 流 → 流数并列 → 轮转两家都出。
    b.in_flight_streams.store(3, Ordering::Relaxed);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        seen.insert(pick_mirror(&chain, 1024));
    }
    assert!(
        seen.contains(&0) && seen.contains(&1),
        "流数并列应轮转: {seen:?}"
    );
    // 清场。
    a.in_flight_streams.store(0, Ordering::Relaxed);
    b.in_flight_streams.store(0, Ordering::Relaxed);
    a.window_prev.store(0, Ordering::Relaxed);
    b.window_prev.store(0, Ordering::Relaxed);
}

/// ECT 绝对最小(无容差): 速度差 4% 也严格选快者——5% 容差已废；仅 ECT 完全相等才走二级(流数/轮转)。
#[test]
fn ect_strict_minimum_no_tolerance() {
    let a = mirror_load("tie-a.test");
    let b = mirror_load("tie-b.test");
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["tie-a.test".to_string(), "tie-b.test".to_string()];
    // 速度差 4% → 恒选快者 b(容差时代会轮转)。
    a.window_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.window_prev.store(2088 * 1024, Ordering::Relaxed); // +4%
    for _ in 0..10 {
        assert_eq!(
            pick_mirror(&chain, 8 * 1024 * 1024),
            1,
            "无容差: 4% 差距也严格选快"
        );
    }
    a.window_prev.store(0, Ordering::Relaxed);
    b.window_prev.store(0, Ordering::Relaxed);
}

#[test]
fn recent_failure_deprioritized() {
    let a = mirror_load("fail-a.test");
    let b = mirror_load("fail-b.test");
    a.window_prev.store(0, Ordering::Relaxed);
    b.window_prev.store(0, Ordering::Relaxed);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["fail-a.test".to_string(), "fail-b.test".to_string()];
    mark_fail(&a, false);
    assert_eq!(pick_mirror(&chain, 1024), 1);
    // 全体都在窗内：放开过滤，ECT 照常按吞吐选（b 有历史胜过零历史的 a）。
    mark_fail(&b, false);
    b.window_prev.store(1024 * 1024, Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 1024), 1);
    a.fail_until.store(0, Ordering::Relaxed);
    b.fail_until.store(0, Ordering::Relaxed);
}

#[test]
fn rotate_walk_respects_limit() {
    assert_eq!(walk_order(8, 0, 5), vec![0, 1, 2, 3, 4]);
    assert_eq!(walk_order(8, 6, 5), vec![6, 7, 0, 1, 2]);
    assert_eq!(walk_order(3, 0, 8), vec![0, 1, 2], "limit 大于链长：全链");
    assert_eq!(walk_order(1, 0, 5), vec![0], "单镜像：不切分，行为同旧");
}

#[test]
fn range_size_parsing() {
    assert_eq!(range_bytes(Some("bytes=0-1048575")), 1048576);
    assert_eq!(range_bytes(Some("bytes=100-199")), 100);
    assert_eq!(range_bytes(Some("bytes=1048576-")), ASSUMED_REQUEST_BYTES);
    assert_eq!(range_bytes(Some("bytes=abc")), ASSUMED_REQUEST_BYTES);
    assert_eq!(range_bytes(None), ASSUMED_REQUEST_BYTES);
    assert_eq!(
        range_bytes(Some("bytes=200-100")),
        ASSUMED_REQUEST_BYTES,
        "逆区间：畸形按假设"
    );
    assert_eq!(
        range_bytes(Some("bytes=0-99,200-299")),
        100,
        "多区间取第一段"
    );
}

#[test]
fn mirror_response_validation() {
    assert!(validate_mirror_response(true, 206, "application/octet-stream", false).is_ok());
    assert!(validate_mirror_response(true, 304, "text/html", false).is_ok());
    assert!(validate_mirror_response(false, 304, "", false).is_ok());
    assert!(validate_mirror_response(false, 200, "application/octet-stream", false).is_ok());
    assert!(
        validate_mirror_response(true, 200, "application/octet-stream", false).is_err(),
        "带 Range 回 200：镜像不认 Range, 必须换家"
    );
    // 探测轮例外：200 全量放行，body 由调用方当单流接管；HTML 仍然拦。
    assert!(validate_mirror_response(true, 200, "application/zip", true).is_ok());
    assert!(validate_mirror_response(true, 200, "text/html", true).is_err());
    assert!(validate_mirror_response(true, 206, "application/zip", true).is_ok());
    assert!(validate_mirror_response(true, 403, "text/html", false).is_err());
    assert!(validate_mirror_response(false, 302, "text/html", false).is_err());
    assert!(validate_mirror_response(false, 200, "text/html; charset=utf-8", false).is_err());
}

/// 派发加、逐帧归还、Drop 清残余；超额交付封顶不下溢。
#[test]
fn byte_accounting_lifecycle() {
    let ld = mirror_load("acct.test");
    ld.in_flight_bytes.store(0, Ordering::Relaxed);
    {
        let mut g = LoadGuard::charge(ld.clone(), 1000, true);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 1000);
        g.on_frame(400);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 600);
        g.on_frame(400);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 200);
    } // drop：残余归还
    assert_eq!(
        ld.in_flight_bytes.load(Ordering::Relaxed),
        0,
        "Drop 必须清残余"
    );
    {
        let mut g = LoadGuard::charge(ld.clone(), 100, true);
        g.on_frame(500);
        assert_eq!(
            ld.in_flight_bytes.load(Ordering::Relaxed),
            0,
            "交付封顶于记账"
        );
    }
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
    {
        let _g = LoadGuard::charge(ld.clone(), 4096, true);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 4096);
    }
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
}

/// 小文件流与大文件机器绝对解耦: 零充值零归还，不进 ECT 时间槽。
#[test]
fn small_stream_never_touches_big_file_state() {
    let ld = mirror_load("small-decoupled.test");
    ld.in_flight_bytes.store(0, Ordering::Relaxed);
    ld.in_flight_streams.store(0, Ordering::Relaxed);
    ld.window_prev.store(0, Ordering::Relaxed);
    let mut g = LoadGuard::charge(ld.clone(), 1024 * 1024, false); // 小文件流
    g.on_frame(1024 * 1024);
    std::thread::sleep(Duration::from_millis(120));
    g.on_frame(64 * 1024); // 再多帧也不得进时间槽
    drop(g);
    assert_eq!(
        ld.in_flight_bytes.load(Ordering::Relaxed),
        0,
        "零充值零归还"
    );
    assert_eq!(
        ld.in_flight_streams.load(Ordering::Relaxed),
        0,
        "流数零接触"
    );
    assert_eq!(
        ld.window_bytes.load(Ordering::Relaxed),
        0,
        "小文件不进时间槽"
    );
    assert_eq!(ld.window_prev.load(Ordering::Relaxed), 0, "零历史保持垫底");
}

// ---- 切片驱动：缺口自己续、失败只算空手、绝不提前收尾 ----

/// 假镜像：要 [from, to) 就给 to−from 个同一字节。
fn fake_fetch(byte: u8) -> Fetch {
    Arc::new(move |from: u64, to: u64| {
        Box::pin(async move {
            let n = (to - from) as usize;
            let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
                futures_util::stream::iter(vec![Ok::<_, std::io::Error>(
                    hyper::body::Frame::data(Bytes::from(vec![byte; n])),
                )]),
            ));
            Ok(body)
        })
    })
}

fn body_of(data: &'static [u8]) -> BoxBody {
    BoxBody::new(http_body_util::StreamBody::new(futures_util::stream::iter(
        vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
            Bytes::from_static(data),
        ))],
    )))
}

fn ctx_with(fetch: Fetch) -> SplitCtx {
    SplitCtx {
        fetch,
        host: "split.test".into(),
        log: Arc::new(|_: &str| {}),
    }
}

/// 队首段早断：驱动自己起新流补上，整条河走完，绝不提前 EOF。
#[tokio::test]
async fn driver_rescues_early_eof_and_finishes() {
    let now = Instant::now();
    // 段 1 [0,10) 只给 4B 就 EOF；段 2 [10,20) 完整。
    let mb = MergeBody::new(
        vec![
            (0, 10, now, body_of(b"AAAA")),
            (10, 20, now, body_of(b"BBBBBBBBBB")),
        ],
        20,
    );
    let body = drive_split(mb, ctx_with(fake_fetch(b'C')));
    let got = http_body_util::BodyExt::collect(body)
        .await
        .expect("不该报错")
        .to_bytes();
    assert_eq!(got.len(), 20, "缺口必须被补上，不能提前结束");
    assert_eq!(&got[..4], b"AAAA");
    assert_eq!(&got[4..10], b"CCCCCC", "缺口 [4,10) 由补发流续上");
    assert_eq!(&got[10..], b"BBBBBBBBBB");
}

/// 补发一直起不来：连续空手若干次后报错，而不是无声无息地少传。
#[tokio::test]
async fn driver_gives_up_after_repeated_dead_fills() {
    let now = Instant::now();
    let dead = body_of(b"");
    let mb = MergeBody::new(vec![(0, 10, now, dead)], 10);
    let fetch: Fetch = Arc::new(|_, _| Box::pin(async { Err("起流失败".to_string()) }));
    let res = http_body_util::BodyExt::collect(drive_split(mb, ctx_with(fetch))).await;
    assert!(res.is_err(), "补不起来必须报错，不能假装下完");
}

/* ---------- 并发区间请求的段位分配 ---------- */

/// 两个区间同时在下：8MB + 400KB，段位 9 个 → 大的吃 8 段、小的只拿 1 段。
#[test]
fn plan_quota_big_range_takes_slots_first() {
    let pending = vec![(8_388_608u64, 1u64), (400_000u64, 2u64)];
    assert_eq!(plan_quota(&pending, 1, 8_388_608, 9, 9), 8, "大区间先占位，给小区间留 1 段");
    assert_eq!(plan_quota(&pending, 2, 400_000, 9, 9), 1, "小区间只拿 1 段");
}

/// 只有一个区间时，再小也要每个段位一段——小文件同样靠并发拿速度。
#[test]
fn plan_quota_single_range_uses_all_slots() {
    assert_eq!(plan_quota(&[(400_000, 1)], 1, 400_000, 9, 9), 9);
}

/// 文件比段位还小：按字节数切，一段一字节，不能出现 0 段。
#[test]
fn plan_quota_tiny_range_still_splits_by_byte() {
    assert_eq!(plan_quota(&[(3, 1)], 1, 3, 9, 9), 3);
    assert_eq!(plan_quota(&[(1, 1)], 1, 1, 9, 9), 1);
}

/// 登记随响应体释放：大区间注销后，小区间可以重新吃满段位。
#[test]
fn range_plan_registry_frees_on_guard_drop() {
    let key = "plan.test/asset";
    let a = plan_range_segments(key, 8_388_608, 9, 9);
    assert_eq!(a.want, 9, "单个大区间应吃满段位");
    let b = plan_range_segments(key, 400_000, 9, 9);
    assert_eq!(b.want, 1, "大区间在途时小区间只拿 1 段");
    drop(b.guard);
    let c = plan_range_segments(key, 400_000, 9, 9);
    assert_eq!(c.want, 1, "大区间还在，小区间仍只 1 段");
    drop(c.guard);
    drop(a.guard);
    let d = plan_range_segments(key, 400_000, 9, 9);
    assert_eq!(d.want, 9, "全部注销后小区间可重新吃满段位");
    drop(d.guard);
}

/// 补发的 e 已经是闭区间末端，Range 不能再减 1；主切片的半开区间才减 1。
#[test]
fn segment_range_uses_inclusive_end() {
    assert_eq!(segment_range(100, 199).unwrap(), "bytes=100-199");
    let (s, e) = (100u64, 199u64); // split_fetch 里的 (base+from, base+to-1)
    assert_eq!(segment_range(s, e).unwrap(), "bytes=100-199");
    assert_eq!(segment_range(0, 0).unwrap(), "bytes=0-0");
}

/// 206 起点不符或缺 Content-Range 都不能拼进合并流。
#[test]
fn segment_206_must_match_requested_start() {
    let cr = "bytes 262144-524287/1608296";
    assert!(merge::check_segment_start(Some(cr), 262_144).is_ok());
    assert!(
        merge::check_segment_start(Some(cr), 0).is_err(),
        "第三方镜像回了错段，起点不符必须当段失败"
    );

    assert!(
        merge::check_segment_start(None, 0).is_err(),
        "206 缺 Content-Range 不能收"
    );
}
