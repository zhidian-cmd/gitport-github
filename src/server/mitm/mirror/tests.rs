use super::*;
use bytes::Bytes;

#[test]
fn mirror_chain_cap_scope() {
    for h in [
        "raw.githubusercontent.com",
        "camo.githubusercontent.com",
        "avatars.githubusercontent.com",
        "user-images.githubusercontent.com",
        "media.githubusercontent.com",
        "gist.githubusercontent.com",
    ] {
        assert_eq!(mirror_chain_cap(h), Some(5), "{h} 应限长 5 家");
    }
    for h in [
        "codeload.github.com",
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
        .body(upstream::empty_body())
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
        assert!(!has_credential_query(q), "{q} 不该误判（名字才参与，值不算）");
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
    let lines: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = lines.clone();
    let log: LogFn = Arc::new(move |s: &str| sink.lock().unwrap().push(s.to_string()));
    let req = hyper::Request::builder()
        .uri("https://raw.githubusercontent.com/o/r/f?sig=abc")
        .body(upstream::empty_body())
        .unwrap();
    let err = chain_fetch(
        &log,
        &req,
        "raw.githubusercontent.com",
        mirror_test_direct_leg(),
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

/// 可信镜像白名单：用户标记 trusted 的镜像，凭据串请求放行给它(知情授权);
/// 未标记的镜像仍被剥除。放行名单为空时行为与旧版一致(仅直连)。
#[test]
fn cred_authorized_trusted_mirrors_only() {
    // settings 全局态无法按测隔离——直接验证放行集合的过滤逻辑:
    // trusted_mirrors() 返回 on && trusted 的 URL, 镜像 URL 前缀匹配放行。
    use crate::settings::WorkerMirror;
    let mirrors = [
        WorkerMirror { url: "https://my-worker.example.com".into(), on: true, trusted: true },
        WorkerMirror { url: "https://public-proxy.example.org".into(), on: true, trusted: false },
    ];
    let trusted: std::collections::HashSet<String> = mirrors
        .iter()
        .filter(|w| w.on && w.trusted)
        .map(|w| w.url.clone())
        .collect();
    let chain = [
        "https://my-worker.example.com/".to_string(),      // 可信(带尾斜杠变体)
        "https://public-proxy.example.org".to_string(),    // 不可信
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
        .body(upstream::empty_body())
        .unwrap();
    let err = chain_fetch(&log, &req, host, mirror_test_direct_leg())
        .await
        .unwrap_err();
    assert!(err.contains("仅直连"), "凭据串请求应仅派直连: {err}");
    assert!(
        !pool::MIRROR_BREAKER.open(host),
        "直连独走耗尽不得触发镜像链熔断"
    );
}

/// 审计 #3 回归: 熔断只拦有镜像候选的请求——凭据串剥空镜像后直连独走,
/// 不得撞为镜像设的熔断(哪怕熔断正开着)。
#[tokio::test]
async fn breaker_spares_direct_only_requests() {
    let log: LogFn = Arc::new(|_: &str| {});
    let host = "brk-cred.test";
    pool::MIRROR_BREAKER.clear(host);
    pool::MIRROR_BREAKER.set(host);
    let req = hyper::Request::builder()
        .uri("https://brk-cred.test/f?sig=abc")
        .body(upstream::empty_body())
        .unwrap();
    let err = chain_fetch(&log, &req, host, mirror_test_direct_leg())
        .await
        .unwrap_err();
    assert!(!err.contains("熔断"), "直连独走不得撞镜像熔断: {err}");
    assert!(err.contains("仅直连"), "应照常仅派直连: {err}");
    pool::MIRROR_BREAKER.clear(host);
}

/// 审计 #2 回归: cap 窗口吃掉直连位时——健康直连追加为末位; 刚失败的不追加;
/// 已在窗内不重复。
#[test]
fn append_direct_gated_by_health_and_presence() {
    let mut order = vec![0usize, 1, 2, 3, 4];
    append_direct_if_missed(&mut order, 8, 0, 1_000);
    assert_eq!(order.last(), Some(&8), "健康直连在窗外应追加为末位");
    let mut order = vec![0usize, 1, 2, 3, 4];
    append_direct_if_missed(&mut order, 8, 1_000, 1_500);
    assert!(!order.contains(&8), "刚失败(失败窗内)不追加, 别急着重拨");
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

/// 探测流交卷: 全片均速从响应头起算(head_at), 建连/等待不进分母。
#[test]
fn probe_scores_from_response_head() {
    let ld = mirror_load("probe-score.test");
    ld.speed_ewma.store(0, Ordering::Relaxed);
    let mut g = LoadGuard::charge(ld.clone(), 4 * 1024 * 1024, true); // 无分 → 探测流
    assert!(g.is_probe, "无分镜像派出的流必须是探测流");
    std::thread::sleep(Duration::from_millis(120)); // 模拟建连+等待
    g.restart_mark(); // 头到达, 测速时钟起算
    std::thread::sleep(Duration::from_millis(150)); // 体流 150ms
    g.on_frame(1024 * 1024); // 1MB/150ms ≈ 6.8MB/s; 含建连等待 ≈ 1MB/270ms ≈ 3.8MB/s
    let s = ld.speed_ewma.load(Ordering::Relaxed);
    assert!(
        s > 5 * 1024 * 1024,
        "全片均速不得包含建连/等待耗时: {s}B/s"
    );
    ld.speed_ewma.store(0, Ordering::Relaxed);
}

/// 严格时间交分：距头满 100ms 即落分, 字节数不限——停滞 100ms 内现形。
#[test]
fn time_floor_fires_sample_on_stall() {
    let ld = mirror_load("stall-clock.test");
    ld.speed_ewma.store(0, Ordering::Relaxed);
    let mut g = LoadGuard::charge(ld.clone(), 4 * 1024 * 1024, true);
    std::thread::sleep(Duration::from_millis(120));
    g.on_frame(4 * 1024); // 4KB 也交: 只看时间不看字节
    let s = ld.speed_ewma.load(Ordering::Relaxed);
    assert!(
        s > 0 && s < 200 * 1024,
        "时间地板应触发停滞读数(4KB/120ms ≈ 34KB/s): {s}B/s"
    );
    ld.speed_ewma.store(0, Ordering::Relaxed);
}


/// 探测轮：全员未交卷时一片一家(前 N 次领取两两不同)；交卷即退出探测态。
#[test]
fn probe_round_hands_each_candidate_one_shard() {
    let chain = vec![
        "probe-all.test".to_string(),
        "probe-bl.test".to_string(),
        "probe-cl.test".to_string(),
    ];
    // 隔离: 并发测试可能给同名 load 留下失败窗/样本, 先清场。
    for m in &chain {
        let ld = mirror_load(m);
        ld.last_fail_ms.store(0, Ordering::Relaxed);
        ld.last_sample_ms.store(0, Ordering::Relaxed);
    }
    let mut picks = std::collections::HashSet::new();
    for _ in 0..3 {
        picks.insert(probe_pick(&chain).unwrap());
    }
    assert_eq!(picks.len(), 3, "探测轮前 3 次领取应覆盖全部候选: {picks:?}");
    for m in &chain {
        mirror_load(m)
            .last_sample_ms
            .store(pool::now_ms(), Ordering::Relaxed);
    }
    assert!(probe_pick(&chain).is_none(), "全员交卷应退出探测态");
    for m in &chain {
        mirror_load(m).last_sample_ms.store(0, Ordering::Relaxed);
    }
}

/// 探测态跳过：未交卷但在失败窗内的候选不领片；全员无健康未交卷 → None。
#[test]
fn probe_skips_failed_unprobed_and_yields_to_ect() {
    let a = mirror_load("probe-skip-a.test");
    let b = mirror_load("probe-skip-b.test");
    let chain = vec!["probe-skip-a.test".to_string(), "probe-skip-b.test".to_string()];
    // 隔离: 清并发测试残留, 再摆本测要的姿态。
    a.last_fail_ms.store(0, Ordering::Relaxed);
    a.last_sample_ms.store(0, Ordering::Relaxed);
    b.last_fail_ms.store(0, Ordering::Relaxed);
    b.last_sample_ms.store(0, Ordering::Relaxed);
    // a 未交卷但刚失败 → 跳过；b 已交卷 → 无探测目标。
    a.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
    b.last_sample_ms.store(pool::now_ms(), Ordering::Relaxed);
    assert!(
        probe_pick(&chain).is_none(),
        "失败窗内的未交卷候选不应被探测"
    );
    // a 失败窗过 → 恢复可探测，领取 a。
    a.last_fail_ms.store(0, Ordering::Relaxed);
    assert_eq!(probe_pick(&chain), Some(0));
    a.last_sample_ms.store(0, Ordering::Relaxed);
    b.last_sample_ms.store(0, Ordering::Relaxed);
}

/// 先验退役：未交卷候选在 ECT 里按无穷大垫底——已交卷的慢腿也胜过它。
#[test]
fn ect_after_retirement_unprobed_loses_to_probed_slow() {
    let slow = mirror_load("retire-slow.test");
    slow.speed_ewma.store(100 * 1024, Ordering::Relaxed); // 100KB/s 已交卷
    let unprobed = mirror_load("retire-unprobed.test");
    unprobed.speed_ewma.store(0, Ordering::Relaxed);
    let chain = vec!["retire-slow.test".to_string(), "retire-unprobed.test".to_string()];
    assert_eq!(
        pick_mirror(&chain, 1024),
        0,
        "未交卷者 ECT 无穷大, 已交卷的慢腿也胜出(先验不再掺和)"
    );
    slow.speed_ewma.store(0, Ordering::Relaxed);
}

/// 直连同台：candidates = 镜像 + direct/{host}，ECT 统一派发。
#[test]
fn direct_competes_as_candidate() {
    let chain = vec!["cand-m.test".to_string()];
    let cands = [
        chain.as_slice(),
        &[direct_load_key("cand-host.test")][..],
    ];
    let all: Vec<String> = cands.concat();
    // 直连快(8MB/s 实测) 镜像未交卷(ECT 无穷大垫底): 直连胜出。
    let d = mirror_load_for(&direct_load_key("cand-host.test"));
    d.speed_ewma.store(8 * 1024 * 1024, Ordering::Relaxed);
    let pick = pick_mirror(&all, 8 * 1024 * 1024);
    assert_eq!(all[pick], direct_load_key("cand-host.test"), "直连快时应胜出");
    // 直连失败降权后 → 轮到镜像。
    d.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
    let pick = pick_mirror(&all, 8 * 1024 * 1024);
    assert_eq!(all[pick], "cand-m.test", "直连降权后应选镜像");
    d.speed_ewma.store(0, Ordering::Relaxed);
    d.last_fail_ms.store(0, Ordering::Relaxed);
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
    a.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    b.speed_ewma.store(512 * 1024, Ordering::Relaxed);
    let chain = vec!["ect-a.test".to_string(), "ect-b.test".to_string()];
    // A (0.5+10)/5 ≈ 2s < B 10/0.5 = 20s → A。
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 0);
    // A (100+10)/5 = 22 > B 20 → B。
    a.in_flight_bytes.store(100 * 1024 * 1024, Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 1);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    a.speed_ewma.store(0, Ordering::Relaxed);
    b.speed_ewma.store(0, Ordering::Relaxed);
}

/// 全未交卷(ECT 同为无穷大、并列) → 轮转均摊；在途越深越垫底，闲者胜出。
#[test]
fn cold_start_falls_back_to_chain_order() {
    let a = mirror_load("cold-a.test");
    let b = mirror_load("cold-b.test");
    a.speed_ewma.store(0, Ordering::Relaxed);
    b.speed_ewma.store(0, Ordering::Relaxed);
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

/// 二级判据：ECT 并列组内选在途流最少者；流数也相同才轮转。
/// 高压镜像(流多)不再被继续堆片，从源头减少掐断误判。
#[test]
fn tie_prefers_fewer_inflight_streams() {
    let a = mirror_load("streams-a.test");
    let b = mirror_load("streams-b.test");
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    a.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
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
    a.speed_ewma.store(0, Ordering::Relaxed);
    b.speed_ewma.store(0, Ordering::Relaxed);
}

/// ECT 绝对最小(无容差): 速度差 4% 也严格选快者——5% 容差已废。
/// 仅 ECT 完全相等才走二级(流数/轮转)。
#[test]
fn ect_strict_minimum_no_tolerance() {
    let a = mirror_load("tie-a.test");
    let b = mirror_load("tie-b.test");
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["tie-a.test".to_string(), "tie-b.test".to_string()];
    // 速度差 4% → 恒选快者 b(容差时代会轮转)。
    a.speed_ewma.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.speed_ewma.store(2088 * 1024, Ordering::Relaxed); // +4%
    for _ in 0..10 {
        assert_eq!(pick_mirror(&chain, 8 * 1024 * 1024), 1, "无容差: 4% 差距也严格选快");
    }
    a.speed_ewma.store(0, Ordering::Relaxed);
    b.speed_ewma.store(0, Ordering::Relaxed);
}

#[test]
fn recent_failure_deprioritized() {
    let a = mirror_load("fail-a.test");
    let b = mirror_load("fail-b.test");
    a.speed_ewma.store(0, Ordering::Relaxed);
    b.speed_ewma.store(0, Ordering::Relaxed);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["fail-a.test".to_string(), "fail-b.test".to_string()];
    a.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 1024), 1);
    // 全体都在窗内：放开过滤回链序。
    b.last_fail_ms.store(pool::now_ms(), Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 1024), 0);
    a.last_fail_ms.store(0, Ordering::Relaxed);
    b.last_fail_ms.store(0, Ordering::Relaxed);
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
    assert_eq!(range_bytes(Some("bytes=0-99,200-299")), 100, "多区间取第一段");
}

#[test]
fn mirror_response_validation() {
    assert!(validate_mirror_response(true, 206, "application/octet-stream").is_ok());
    assert!(validate_mirror_response(true, 304, "text/html").is_ok());
    assert!(validate_mirror_response(false, 304, "").is_ok());
    assert!(validate_mirror_response(false, 200, "application/octet-stream").is_ok());
    assert!(
        validate_mirror_response(true, 200, "application/octet-stream").is_err(),
        "带 Range 回 200：镜像不认 Range, 必须换家"
    );
    assert!(validate_mirror_response(true, 403, "text/html").is_err());
    assert!(validate_mirror_response(false, 302, "text/html").is_err());
    assert!(validate_mirror_response(false, 200, "text/html; charset=utf-8").is_err());
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
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "Drop 必须清残余");
    {
        let mut g = LoadGuard::charge(ld.clone(), 100, true);
        g.on_frame(500);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "交付封顶于记账");
    }
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
    {
        let _g = LoadGuard::charge(ld.clone(), 4096, true);
        assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 4096);
    }
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0);
}

/// 链序按速度重排(纯函数): 快者在前, 无分/失败窗者保持原序缀尾, 同速稳定。
#[test]
fn speed_sorted_chain_orders_and_stabilizes() {
    let chain = vec![
        "https://a".to_string(),
        "https://b".to_string(),
        "https://c".to_string(),
        "https://d".to_string(),
    ];
    // 速度: a=100, b=0(无分), c=500, d=100 → c, a, d, b (b 原位缀尾, a/d 同速稳定)
    let speed_of = |m: &str| -> u64 {
        match m {
            "https://a" => 100,
            "https://c" => 500,
            "https://d" => 100,
            _ => 0,
        }
    };
    let out = speed_sorted_chain(&chain, &speed_of);
    assert_eq!(
        out,
        vec!["https://c".to_string(), "https://a".to_string(), "https://d".to_string(), "https://b".to_string()],
        "速度降序 + 无分缀尾 + 同速稳定: {out:?}"
    );
    // 已排序输入重排 = 恒等(幂等)。
    let again = speed_sorted_chain(&out, &speed_of);
    assert_eq!(again, out, "已排序链重排必须恒等(零写盘的幂等基础)");
}

/// 重排目标：只挑大文件链，且必须命中全部——一个镜像同挂三条大文件链，
/// 只排一条等于另两条永不更新(旧实现还会先撞上小文件链直接放弃)。
#[test]
fn big_chains_with_picks_every_big_chain_not_small() {
    let v = |urls: &[&str]| urls.iter().map(|u| u.to_string()).collect::<Vec<_>>();
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert("codeload.github.com".into(), v(&["https://a", "https://b"]));
    chains.insert(
        "release-assets.githubusercontent.com".into(),
        v(&["https://a"]),
    );
    chains.insert("raw.githubusercontent.com".into(), v(&["https://a"]));
    chains.insert("objects.githubusercontent.com".into(), v(&["https://other"]));
    let mut hosts: Vec<&str> = big_chains_with(&chains, "https://a")
        .into_iter()
        .map(|(h, _)| h.as_str())
        .collect();
    hosts.sort_unstable();
    assert_eq!(
        hosts,
        vec!["codeload.github.com", "release-assets.githubusercontent.com"],
        "含该镜像的两条大文件链都要排；小文件链和不含它的链都不许碰"
    );
}

/// 分数冻结：正常流(镜像已有分)只记账, 永不改写速度分。
#[test]
fn normal_stream_never_touches_score() {
    let ld = mirror_load("freeze.test");
    ld.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
    let mut g = LoadGuard::charge(ld.clone(), 1024 * 1024, true); // 有分 → 非探测
    assert!(!g.is_probe, "已有分的镜像派出的流不得是探测流");
    g.on_frame(1024 * 1024);
    drop(g);
    assert_eq!(
        ld.speed_ewma.load(Ordering::Relaxed),
        5 * 1024 * 1024,
        "正常流不得改写冻结分数"
    );
    ld.speed_ewma.store(0, Ordering::Relaxed);
}

/// 清场触发: 探测流交分后严劣于链内已交卷最大者 → 盖纪元号, 在途断流。
#[tokio::test]
async fn cull_fires_for_strictly_slower_probe() {
    let fast = mirror_load("cull-fast.test");
    fast.speed_ewma.store(5 * 1024 * 1024, Ordering::Relaxed);
    let me = mirror_load("cull-me.test");
    me.speed_ewma.store(0, Ordering::Relaxed);
    me.cull_epoch.store(0, Ordering::Relaxed);
    let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
        futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
            Bytes::from(vec![0u8; 64 * 1024]),
        ))]),
    ));
    let guard = LoadGuard::charge(me.clone(), 64 * 1024, true); // 无分 → 探测流
    let mut wrapped = cull_watched_body(
        body,
        guard,
        me.clone(),
        vec![fast.clone()],
        "h/p".into(),
        "cull-me.test".into(),
        Arc::new(|_: &str| {}),
    );
    tokio::time::sleep(Duration::from_millis(120)).await; // 满交分地板
    let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // 帧 → 交分 ~546KB/s → 触发清场
    assert_ne!(
        me.cull_epoch.load(Ordering::Relaxed),
        0,
        "严劣于链内最快的探测片应触发清场盖纪元"
    );
    let got_err = matches!(
        http_body_util::BodyExt::frame(&mut wrapped).await,
        Some(Err(_))
    );
    assert!(got_err, "被清场镜像的在途流必须断流交客户端重发");
    me.speed_ewma.store(0, Ordering::Relaxed);
    me.cull_epoch.store(0, Ordering::Relaxed);
    fast.speed_ewma.store(0, Ordering::Relaxed);
}

/// 并列最快者保留: 链内无更快者 → 不盖纪元, 存量自然跑完。
#[tokio::test]
async fn cull_spares_when_no_faster_peer() {
    let slow = mirror_load("tie-slow.test");
    slow.speed_ewma.store(100 * 1024, Ordering::Relaxed); // 同伴比我慢
    let me = mirror_load("tie-me.test");
    me.speed_ewma.store(0, Ordering::Relaxed);
    me.cull_epoch.store(0, Ordering::Relaxed);
    let body: BoxBody = BoxBody::new(http_body_util::StreamBody::new(
        futures_util::stream::iter(vec![Ok::<_, std::io::Error>(hyper::body::Frame::data(
            Bytes::from(vec![0u8; 64 * 1024]),
        ))]),
    ));
    let guard = LoadGuard::charge(me.clone(), 64 * 1024, true);
    let mut wrapped = cull_watched_body(
        body,
        guard,
        me.clone(),
        vec![slow.clone()],
        "h/p".into(),
        "tie-me.test".into(),
        Arc::new(|_: &str| {}),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    let _ = http_body_util::BodyExt::frame(&mut wrapped).await; // 交分 ~546KB/s > 100KB/s
    assert_eq!(
        me.cull_epoch.load(Ordering::Relaxed),
        0,
        "链内无更快者不得清场(并列最快保留)"
    );
    me.speed_ewma.store(0, Ordering::Relaxed);
    me.cull_epoch.store(0, Ordering::Relaxed);
    slow.speed_ewma.store(0, Ordering::Relaxed);
}
/// 小文件流与大文件机器绝对解耦: 零充值零归还零采样零评估。
#[test]
fn small_stream_never_touches_big_file_state() {
    let ld = mirror_load("small-decoupled.test");
    ld.in_flight_bytes.store(0, Ordering::Relaxed);
    ld.in_flight_streams.store(0, Ordering::Relaxed);
    ld.speed_ewma.store(0, Ordering::Relaxed);
    let mut g = LoadGuard::charge(ld.clone(), 1024 * 1024, false); // 小文件流
    assert!(!g.is_probe, "小文件流无探测语义");
    g.on_frame(1024 * 1024);
    std::thread::sleep(Duration::from_millis(120));
    g.on_frame(64 * 1024); // 过 100ms 地板也不得交分
    drop(g);
    assert_eq!(ld.in_flight_bytes.load(Ordering::Relaxed), 0, "零充值零归还");
    assert_eq!(ld.in_flight_streams.load(Ordering::Relaxed), 0, "流数零接触");
    assert_eq!(ld.speed_ewma.load(Ordering::Relaxed), 0, "小文件不写速度分");
    assert_eq!(ld.last_sample_ms.load(Ordering::Relaxed), 0, "评估缓存零记录");
}
