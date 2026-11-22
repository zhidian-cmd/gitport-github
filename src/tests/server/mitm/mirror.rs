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

/// 纯直连耗尽(零镜像)不给镜像链上熔断——链没参与，别连坐。
#[tokio::test]
async fn direct_only_exhaustion_spares_chain_breaker() {
    let log: LogFn = Arc::new(|_: &str| {});
    let host = "cred-brk.test";
    pool::MIRROR_BREAKER.clear(host);
    let req = hyper::Request::builder()
        .uri("https://cred-brk.test/f")
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
    assert!(err.contains("镜像链全灭"), "零镜像耗尽应报链全灭: {err}");
    assert!(
        !pool::MIRROR_BREAKER.open(host),
        "直连独走耗尽不得触发镜像链熔断"
    );
}

/// 审计 #3 回归: 熔断只拦有镜像候选的请求——零镜像时直连独走, 不得撞为镜像设的熔断(哪怕熔断正开着)。
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
    assert!(err.contains("镜像链全灭"), "零镜像应报链全灭: {err}");
    pool::MIRROR_BREAKER.clear(host);
}

/// 探片直连先行：大文件域 bytes=N-N 探测起轮点在直连腿（旧序从链头镜像起轮），镜像全程不被碰。
#[tokio::test]
async fn probe_range_starts_at_direct_leg() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // 隔离：serial_load 会把链上镜像收编进注册表并跨测试持久化，先清空。
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = std::env::temp_dir().join("gitport_probe_direct_seed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "hosts": {"objects.githubusercontent.com": {"content": true, "big": true}},
  "mirrors_big": ["https://127.0.0.1:1"]
}"#,
    )
    .unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);
    pool::MIRROR_BREAKER.clear("objects.githubusercontent.com");

    let lines: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let log: LogFn = {
        let lines = lines.clone();
        Arc::new(move |s: &str| lines.lock().unwrap().push(s.to_string()))
    };
    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri("https://objects.githubusercontent.com/big.bin")
        .header("range", "bytes=0-0")
        .body(protocol::empty_body())
        .unwrap();
    let resp = chain_fetch(
        &log,
        &req,
        "objects.githubusercontent.com",
        Box::pin(async {
            Ok::<_, String>(
                hyper::Response::builder()
                    .status(http::StatusCode::PARTIAL_CONTENT)
                    .header("content-range", "bytes 0-0/12345678")
                    .body(protocol::empty_body())
                    .unwrap(),
            )
        }),
        &Default::default(),
        &None,
    )
    .await
    .unwrap();
    assert_eq!(
        resp.extensions().get::<&'static str>().copied(),
        Some("direct"),
        "探片响应应来自直连腿"
    );
    let got = lines.lock().unwrap().join("\n");
    assert!(got.contains("探片直连"), "直连第一棒应有探片直连标签: {got}");
    assert!(
        !got.contains("127.0.0.1:1"),
        "镜像只兜底, 探片不应触碰镜像: {got}"
    );
    crate::settings::save_worker_mirrors(Vec::new());
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
    Box::pin(async { Err::<hyper::Response<BoxBody>, String>("test: direct unavailable".into()) })
}

/// 单窗结算规则：只有分配窗(5ms)，零收一律沿用（速率估计，卡死语义归收尸管）——零 sleep 确定性验证。
#[test]
fn single_window_snapshot_rules() {
    let ld = mirror_load("ect-slot.test");
    let mut g = LoadGuard::charge(ld.clone(), 8 * 1024 * 1024, true);
    g.on_frame(3 * 1024 * 1024);
    ect_sweep();
    assert_eq!(
        ld.alloc_prev.load(Ordering::Relaxed),
        3 * 1024 * 1024,
        "分配窗本拍快照"
    );
    assert_eq!(
        ld.alloc_bytes.load(Ordering::Relaxed),
        0,
        "快照后本窗清零重开"
    );
    // 零收（有债也在内）：沿用旧值——卡死语义归收尸管。
    ect_sweep();
    assert_eq!(
        ld.alloc_prev.load(Ordering::Relaxed),
        3 * 1024 * 1024,
        "零收沿用"
    );
    // 恢复出货：换新值。
    g.on_frame(4 * 1024 * 1024);
    ect_sweep();
    assert_eq!(ld.alloc_prev.load(Ordering::Relaxed), 4 * 1024 * 1024);
    ld.alloc_prev.store(0, Ordering::Relaxed);
}

/// 爬坡 EMA：首样直入、二次平滑；用 note_ramp 直接验证记账公式（打点在 LoadGuard::on_frame 首帧）。
#[test]
fn ramp_note_ema() {
    let ld = mirror_load("https://ramp-ema.test");
    ld.ramp_ms.store(0, Ordering::Relaxed);
    note_ramp(&ld, 800);
    assert_eq!(ld.ramp_ms.load(Ordering::Relaxed), 800, "首样直入");
    note_ramp(&ld, 200);
    assert_eq!(
        ld.ramp_ms.load(Ordering::Relaxed),
        650,
        "EMA 800×3/4 + 200×1/4 = 650"
    );
    ld.ramp_ms.store(0, Ordering::Relaxed);
}

/// ECT 派发把本家 ramp 加进分数：同排水下爬坡小的胜；ramp 足够大时能翻盘。
#[test]
fn ect_adds_ramp_to_score() {
    let fast = mirror_load("ect-ramp-a.test");
    fast.alloc_prev.store(1024 * 1024, Ordering::Relaxed); // 排空 5ms
    fast.ramp_ms.store(400, Ordering::Relaxed); // 总分 405
    let slow = mirror_load("ect-ramp-b.test");
    slow.alloc_prev.store(1024 * 1024, Ordering::Relaxed); // 排空 5ms
    slow.ramp_ms.store(100, Ordering::Relaxed); // 总分 105
    let chain = vec!["ect-ramp-a.test".to_string(), "ect-ramp-b.test".to_string()];
    assert_eq!(pick_mirror(&chain, 1024), 1, "同排水下爬坡小的胜");
    // 翻盘：A 排水略快但 ramp 巨大 → 选 B。
    fast.alloc_prev.store(4 * 1024 * 1024, Ordering::Relaxed); // 排空 ~1ms
    fast.ramp_ms.store(2000, Ordering::Relaxed); // 总分 ~2001
    assert_eq!(pick_mirror(&chain, 1024), 1, "ramp 项能翻转排序");
    fast.alloc_prev.store(0, Ordering::Relaxed);
    fast.ramp_ms.store(0, Ordering::Relaxed);
    slow.alloc_prev.store(0, Ordering::Relaxed);
    slow.ramp_ms.store(0, Ordering::Relaxed);
}

/// 先验退役：未交卷候选在 ECT 里按无穷大垫底——已交卷的慢腿也胜过它。
#[test]
fn ect_after_retirement_unprobed_loses_to_probed_slow() {
    let slow = mirror_load("retire-slow.test");
    slow.alloc_prev.store(100 * 1024, Ordering::Relaxed); // 100KB/5ms 已交卷
    let unprobed = mirror_load("retire-unprobed.test");
    unprobed.alloc_prev.store(0, Ordering::Relaxed);
    let chain = vec![
        "retire-slow.test".to_string(),
        "retire-unprobed.test".to_string(),
    ];
    assert_eq!(
        pick_mirror(&chain, 1024),
        0,
        "未交卷者 ECT 无穷大, 已交卷的慢腿也胜出(先验不再掺和)"
    );
    slow.alloc_prev.store(0, Ordering::Relaxed);
}

/// 直连同台：candidates = 镜像 + direct/{host}，ECT 统一派发。
#[test]
fn direct_competes_as_candidate() {
    let chain = vec!["cand-m.test".to_string()];
    let cands = [chain.as_slice(), &[direct_load_key("cand-host.test")][..]];
    let all: Vec<String> = cands.concat();
    // 直连快(8MB/s 实测) 镜像未交卷(ECT 无穷大垫底): 直连胜出。
    let d = mirror_load(&direct_load_key("cand-host.test"));
    d.alloc_prev.store(8 * 1024 * 1024, Ordering::Relaxed);
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
    d.alloc_prev.store(0, Ordering::Relaxed);
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
    a.alloc_prev.store(5 * 1024 * 1024, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    b.alloc_prev.store(512 * 1024, Ordering::Relaxed);
    let chain = vec!["ect-a.test".to_string(), "ect-b.test".to_string()];
    // A (0.5+10)/5 ≈ 2s < B 10/0.5 = 20s → A。
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 0);
    // A (100+10)/5 = 22 > B 20 → B。
    a.in_flight_bytes
        .store(100 * 1024 * 1024, Ordering::Relaxed);
    assert_eq!(pick_mirror(&chain, 10 * 1024 * 1024), 1);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    a.alloc_prev.store(0, Ordering::Relaxed);
    b.alloc_prev.store(0, Ordering::Relaxed);
}

/// 段级派发无视 ttfb（h2 复用后镜像/直连首字节对称，ttfb 只进探针排序）：快镜像 ttfb 600ms 仍按纯排水胜出。
/// 谁把 ttfb 加回段级谁挂（620ms > 160ms 时会错选慢腿）。
#[test]
fn ect_ignores_ttfb_for_segments() {
    let fast = mirror_load("ect-fast.test");
    fast.alloc_prev.store(8 * 1024 * 1024, Ordering::Relaxed);
    fast.ttfb_ms.store(600, Ordering::Relaxed);
    let slow = mirror_load("ect-slow.test");
    slow.alloc_prev.store(1024 * 1024, Ordering::Relaxed);
    let chain = vec!["ect-fast.test".to_string(), "ect-slow.test".to_string()];
    assert_eq!(
        pick_mirror(&chain, 2 * 1024 * 1024),
        0,
        "纯排水 20ms < 160ms, 快镜像胜"
    );
    fast.alloc_prev.store(0, Ordering::Relaxed);
    fast.ttfb_ms.store(0, Ordering::Relaxed);
    slow.alloc_prev.store(0, Ordering::Relaxed);
}

/// ttfb 入账语义：首样直入，之后 EMA α=1/4 平滑；直连键永不入账恒 0。
#[test]
fn ttfb_note_ema_and_direct_free() {
    let m = mirror_load("https://ema.test");
    note_ttfb("https://ema.test", 800);
    assert_eq!(m.ttfb_ms.load(Ordering::Relaxed), 800, "首样直入");
    note_ttfb("https://ema.test", 200);
    assert_eq!(
        m.ttfb_ms.load(Ordering::Relaxed),
        650,
        "EMA 800×3/4 + 200×1/4 = 650"
    );
    let d = mirror_load(&direct_load_key("ema.test"));
    assert_eq!(d.ttfb_ms.load(Ordering::Relaxed), 0, "直连腿不入账恒 0");
    m.ttfb_ms.store(0, Ordering::Relaxed);
}

/// 实网验尸：gh-proxy.org(CF) 协商 h2 拉带 Range 的真文件段，体必须读满 content-length。
/// 当年 h2 被关的坑是"头正常、体 0B EOF"，此探针即其回归测试。网络测试，#[ignore]：
/// `cargo test mirror_h2_body_probe -- --ignored` 单独验。
#[tokio::test]
#[ignore]
async fn mirror_h2_body_probe() {
    let mut tls = None;
    for attempt in 1..=3 {
        match crate::pool::dial::dial_tls_simple("gh-proxy.org").await {
            Ok(t) => {
                tls = Some(t);
                break;
            }
            Err(e) => eprintln!("探针拨号第 {attempt} 次未成: {e}"),
        }
    }
    let tls = tls.expect("3 次探针拨号全失败");
    assert_eq!(
        tls.ssl().selected_alpn_protocol(),
        Some(b"h2".as_slice()),
        "CF 系应协商出 h2"
    );
    drop(tls);
    let log: LogFn = Arc::new(|_| {});
    let client = crate::server::upstream::mirror_client(&log);
    let mut resp = None;
    for attempt in 1..=3 {
        let req = hyper::Request::builder()
            .uri("https://gh-proxy.org/https://raw.githubusercontent.com/torvalds/linux/master/README")
            .header("user-agent", MIRROR_UA)
            .header("range", "bytes=0-65535")
            .body(protocol::empty_body())
            .unwrap();
        match tokio::time::timeout(Duration::from_secs(15), client.request(req)).await {
            Ok(Ok(r)) => {
                resp = Some(r);
                break;
            }
            other => eprintln!("拨号/请求第 {attempt} 次未成: {other:?}"),
        }
    }
    let resp = resp.expect("3 次尝试全失败");
    // raw 路径部分镜像忽略 Range 回 200 全量（gh-proxy.org 实测），与 h2 无关——靶子是体完整性：
    // 旧坑"头正常、体 0B EOF"的回归点 = 体读不满 content-length。
    let status = resp.status().as_u16();
    assert!(
        status == 206 || status == 200,
        "镜像应回 206/200, 拿到 {status}"
    );
    let cl: usize = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or_default();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(
        !body.is_empty(),
        "h2 体必须非空——旧坑'头正常体 0B EOF'回归即在此挂"
    );
    if cl > 0 {
        assert_eq!(
            body.len(),
            cl,
            "h2 体必须读满 content-length({cl})——旧坑'头正常体 0B EOF'回归即在此挂"
        );
    }
    eprintln!(
        "[探针] h2 体验证通过: status={status} cl={cl} body={}B 前16字节={:02x?}",
        body.len(),
        &body[..16.min(body.len())]
    );
}

/// 全未交卷(ECT 同为无穷大、并列) → 轮转均摊；在途越深越垫底，闲者胜出。
#[test]
fn cold_start_falls_back_to_chain_order() {
    let a = mirror_load("cold-a.test");
    let b = mirror_load("cold-b.test");
    a.alloc_prev.store(0, Ordering::Relaxed);
    b.alloc_prev.store(0, Ordering::Relaxed);
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
    a.alloc_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.alloc_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
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
    a.alloc_prev.store(0, Ordering::Relaxed);
    b.alloc_prev.store(0, Ordering::Relaxed);
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
    a.alloc_prev.store(2 * 1024 * 1024, Ordering::Relaxed);
    b.alloc_prev.store(2088 * 1024, Ordering::Relaxed); // +4%
    for _ in 0..10 {
        assert_eq!(
            pick_mirror(&chain, 8 * 1024 * 1024),
            1,
            "无容差: 4% 差距也严格选快"
        );
    }
    a.alloc_prev.store(0, Ordering::Relaxed);
    b.alloc_prev.store(0, Ordering::Relaxed);
}

#[test]
fn recent_failure_deprioritized() {
    let a = mirror_load("fail-a.test");
    let b = mirror_load("fail-b.test");
    a.alloc_prev.store(0, Ordering::Relaxed);
    b.alloc_prev.store(0, Ordering::Relaxed);
    a.in_flight_bytes.store(0, Ordering::Relaxed);
    b.in_flight_bytes.store(0, Ordering::Relaxed);
    let chain = vec!["fail-a.test".to_string(), "fail-b.test".to_string()];
    mark_fail(&a, false);
    assert_eq!(pick_mirror(&chain, 1024), 1);
    // 全体都在窗内：放开过滤，ECT 照常按吞吐选（b 有历史胜过零历史的 a）。
    mark_fail(&b, false);
    b.alloc_prev.store(1024 * 1024, Ordering::Relaxed);
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

/// {url_enc} 转义口径：字母数字与 . - _ ~ 保留，其余（含中文与 ://）逐字节 %XX。
#[test]
fn fill_template_url_enc_keeps_unreserved_only() {
    let url = "https://raw.githubusercontent.com/a/b/main/文件 name.png?q=1";
    let out = fill_template("{mirror}/{url_enc}".to_string(), "https://m.example", url);
    assert_eq!(
        out,
        "https://m.example/https%3A%2F%2Fraw.githubusercontent.com%2Fa%2Fb%2Fmain%2F%E6%96%87%E4%BB%B6%20name.png%3Fq%3D1"
    );
    let plain = fill_template("{mirror}/{url}".to_string(), "https://m.example", url);
    assert_eq!(plain, "https://m.example/".to_string() + url, "{url} 原样拼接");
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

/// 整包 GET(没带 Range)收到 206 分片：按这家失败处理，绝不当完整文件交出去（静默截断）。
#[test]
fn stream_start_rejects_206_without_range() {
    let resp = |status: u16, cr: &str| {
        hyper::Response::builder()
            .status(status)
            .header("content-range", cr)
            .body(protocol::empty_body())
            .unwrap()
    };
    assert_eq!(
        stream_start_mismatch(None, &resp(206, "bytes 0-99/1000")),
        Some("未请求 Range 却回 206".to_string()),
        "没要 Range 却回 206 必须判失败"
    );
    assert_eq!(stream_start_mismatch(None, &resp(200, "")), None, "200 全量照旧放行");
    assert_eq!(
        stream_start_mismatch(Some("bytes=0-99"), &resp(206, "bytes 0-99/1000")),
        None,
        "带 Range 且起点对齐照旧放行"
    );
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
    ld.alloc_prev.store(0, Ordering::Relaxed);
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
        ld.alloc_bytes.load(Ordering::Relaxed),
        0,
        "小文件不进时间槽"
    );
    assert_eq!(ld.alloc_prev.load(Ordering::Relaxed), 0, "零历史保持垫底");
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
            Ok(FilledSeg {
                body,
                owner: "fake".to_string(),
                ramp: 0,
            })
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

/// 测试段：四元组补成生产六元组（owner/ramp 默认 0）。
fn t(s: u64, e: u64, at: Instant, b: BoxBody) -> (u64, u64, Instant, BoxBody, String, u64) {
    (s, e, at, b, "test".to_string(), 0)
}

/// 队首段早断：驱动自己起新流补上，整条河走完，绝不提前 EOF。
#[tokio::test]
async fn driver_rescues_early_eof_and_finishes() {
    let now = Instant::now();
    // 段 1 [0,10) 只给 4B 就 EOF；段 2 [10,20) 完整。
    let mb = MergeBody::new(
        vec![
            t(0, 10, now, body_of(b"AAAA")),
            t(10, 20, now, body_of(b"BBBBBBBBBB")),
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
    let mb = MergeBody::new(vec![t(0, 10, now, dead)], 10);
    let fetch: Fetch = Arc::new(|_, _| Box::pin(async { Err("起流失败".to_string()) }));
    let res = http_body_util::BodyExt::collect(drive_split(mb, ctx_with(fetch))).await;
    assert!(res.is_err(), "补不起来必须报错，不能假装下完");
}

/// 供 prefix 字节后永久 Pending（不注册 waker）：模拟静默装死的上游。
fn silent_body(prefix: &'static [u8]) -> BoxBody {
    struct Silent {
        left: Option<Bytes>,
    }
    impl hyper::body::Body for Silent {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            let me = self.get_mut();
            match me.left.take() {
                Some(b) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b)))),
                None => std::task::Poll::Pending,
            }
        }
    }
    BoxBody::new(Silent {
        left: Some(Bytes::from_static(prefix)),
    })
}

/// 静默装死的上游不许永久挂死（直连切片搬来的回归钉子）：waker 注册进静默上游永不触发，
/// drive_split 的 500ms Tick 是唯一唤醒源——停滞收尸 → 补发 → 连续空手 → 错误上抛。
#[tokio::test]
async fn driver_silent_upstream_wakes_and_errors() {
    let now = Instant::now();
    let mb = MergeBody::new(vec![t(0, 10, now, silent_body(b"abc"))], 10);
    let fetch: Fetch = Arc::new(|_, _| Box::pin(async { Err("起流失败".to_string()) }));
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        http_body_util::BodyExt::collect(drive_split(mb, ctx_with(fetch))),
    )
    .await;
    let collected = res.expect("静默停滞不许永久挂死: collect 必须限时收场");
    assert!(collected.is_err(), "补发连续空手必须错误上抛, 而非无声挂起");
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
