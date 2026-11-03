use super::*;

/// 造一条合法 H2Upstream：h2 握手用本机 duplex 对拉（无需真网），server 端由 h2::server 回 SETTINGS 即完成。
async fn mk_up(ip: &str, slot: u8) -> H2Upstream {
    let (client_io, server_io) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = h2::server::handshake(server_io).await;
    });
    let (send, conn) = h2::client::handshake(client_io).await.expect("duplex 握手");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    H2Upstream {
        ip: ip.to_string(),
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        slot,
        send,
        ping: None,
    }
}

#[tokio::test]
async fn slot_filter_pins_search_to_primary() {
    let host = "test-slot-filter.github.com";
    store_h2(host, mk_up("9.9.9.2", 2).await); // 第二通道先入池
    store_h2(host, mk_up("9.9.9.1", 1).await); // 主通道后入
    for _ in 0..4 {
        let up = cached_h2_in(host, Some(1)).expect("主通道应在池");
        assert_eq!(up.ip, "9.9.9.1", "Some(1) 永远拿主通道,轮转计数不动");
    }
    // 主通道被摘后:Some(1) -> None(交拨号按主键重建),绝不误用第二通道
    drop_h2_id(host, {
        let g = lock(conn_pool());
        g.get(host)
            .unwrap()
            .conns
            .iter()
            .find(|c| c.up.slot == 1)
            .unwrap()
            .up
            .id
    });
    assert!(
        cached_h2_in(host, Some(1)).is_none(),
        "主通道被摘后应回 None 走重建,不得回落第二通道"
    );
    // None = 原语义:池里剩下的第二通道照常服务
    let up = cached_h2_in(host, None).expect("无过滤应命中");
    assert_eq!(up.ip, "9.9.9.2");
    let _ = lock(conn_pool()).remove(host);
}

/// 借道用例要装一张路由表（donor 标记现在由数据给，不再看域名后缀）。
fn install_borrow_routes() {
    let specs = [
        r#"{"key":"githubassets.com","donor":true}"#,
        r#"{"key":"*.githubusercontent.com","content":true,"fallback":"mirror"}"#,
    ];
    let rows = specs
        .iter()
        .map(|s| {
            crate::pool::route::RouteRow::new(serde_json::from_str(s).expect("spec"))
                .expect("行合法")
        })
        .collect();
    crate::pool::route::install(rows);
}

/// 造一条真能用的 donor：对端是本地 h2 服务，回 200 并把收到的 `:authority` 回显到响应头，
/// 用它才能断言"借来的连接确实按目标 host 路由"。
async fn live_donor(ip: &str) -> H2Upstream {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let Ok(mut conn) = h2::server::handshake(server_io).await else {
            return;
        };
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let auth = req
                .uri()
                .authority()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let resp = http::Response::builder()
                .status(200)
                .header("x-seen-authority", auth)
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
            }
        }
    });
    let (send, conn) = h2::client::handshake(client_io).await.expect("client 握手");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    H2Upstream {
        ip: ip.to_string(),
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        slot: 1,
        send,
        ping: None,
    }
}

/// 借道三步契约（顺序执行，避免并行抢全局连接池）：只认 assets 域现成连接；`:authority` 保持目标 host；借失败进冷却后直接回落。
// 用例独占全局路由表与连接池，串行锁必须跨 await 持有；生产路径不这么用。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn borrow_contract_end_to_end() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_borrow_routes();
    let target = "avatars.test-borrow.githubusercontent.com";
    let donor_host = "github.test-borrow.githubassets.com";
    let content_host = "raw.test-borrow.githubusercontent.com";
    let log: LogFn = Arc::new(|_: &str| {});

    // 1) 选择
    store_h2(content_host, mk_up("9.9.7.1", 1).await); // 内容域连接：不在候选里
    store_h2(donor_host, live_donor("9.9.7.2").await);
    let (h, up) = borrow_donor(target).expect("应有 assets donor");
    assert_eq!(h, donor_host, "只能借 assets 域已有的连接");
    assert_eq!(up.ip, "9.9.7.2", "借到的应是那条 donor");
    assert!(borrow_donor(donor_host).is_none(), "不能把 donor 借给自己");

    // 2) 接线：借到的连接直接把请求发出去，:authority 不变
    let out = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{target}/u/1?s=40"))
        .body(empty_body())
        .unwrap();
    let info = crate::server::mitm::UpstreamInfo::default();
    let got = crate::server::mitm::try_borrow(&log, &out, target, &info, &None)
        .await
        .expect("有 donor 就该尝试借道")
        .expect("借道应成功");
    assert_eq!(got.status(), 200);
    assert_eq!(
        got.headers()
            .get("x-seen-authority")
            .and_then(|v| v.to_str().ok()),
        Some(target),
        "借来的连接上 :authority 必须仍是目标 host"
    );
    assert_eq!(*info.lock().unwrap(), "9.9.7.2", "响应标记记真实出口");

    // 3) 失败进冷却：对端已消失的 donor 试一次就够
    let dead_host = "github.test-borrow-dead.githubassets.com";
    let dead_target = "camo.test-borrow.githubusercontent.com";
    let _ = lock(conn_pool()).remove(donor_host);
    store_h2(dead_host, mk_up("9.9.7.3", 1).await); // 握手后对端即走：一借就失败
    let out2 = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{dead_target}/x"))
        .body(empty_body())
        .unwrap();
    let dead_info = crate::server::mitm::UpstreamInfo::default();
    let first = crate::server::mitm::try_borrow(&log, &out2, dead_target, &dead_info, &None).await;
    assert!(
        matches!(first, Some(Err(_))),
        "借失败要如实报错, 不能假装成功"
    );
    let second = crate::server::mitm::try_borrow(&log, &out2, dead_target, &dead_info, &None).await;
    assert!(second.is_none(), "冷却期内不再空试, 直接交回退路径");

    for h in [content_host, dead_host] {
        let _ = lock(conn_pool()).remove(h);
    }
    assert!(
        borrow_donor(target).is_none(),
        "池空时借不到, 必须回 None 而不是新建"
    );
}

/// 两条通道要摊开：前一条已经挂着借出的流，下一条请求就该走另一条；
/// 归还后计数必须回到 0，否则那条连接会一直"在忙"，再也挑不中。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn borrow_spreads_over_two_channels() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_borrow_routes();
    let target = "avatars.test-spread.githubusercontent.com";
    let donor_host = "github.test-spread.githubassets.com";
    let a = live_donor("9.9.4.1").await;
    let b = live_donor("9.9.4.2").await;
    let (aid, bid) = (a.id, b.id);
    store_h2(donor_host, a);
    store_h2(donor_host, b);

    let (_, first) = borrow_donor(target).expect("第一条应借到");
    let (_, second) = borrow_donor(target).expect("第二条应借到");
    assert_ne!(
        first.id, second.id,
        "两条都空闲时，第二条请求要换另一条通道，不能全堆在一根 TCP 上"
    );
    borrow_done(donor_host, first.id);
    borrow_done(donor_host, second.id);
    let (_, third) = borrow_donor(target).expect("归还后应还能借到");
    assert!(
        third.id == aid || third.id == bid,
        "归还后计数应清零，池里还是那两条"
    );
    borrow_done(donor_host, third.id);
    let _ = lock(conn_pool()).remove(donor_host);
}

/// 一条通道坏了不该拖死请求：同一次调用里换另一条，响应照拿；
/// 借出的配额在响应体丢弃时要还回去。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn borrow_fails_over_to_second_channel() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    install_borrow_routes();
    let target = "avatars.test-failover.githubusercontent.com";
    let donor_host = "github.test-failover.githubassets.com";
    // 先入池的先被选中：坏的那条排前面，才能真的走到"换一条再试"。
    store_h2(donor_host, mk_up("9.9.3.1", 1).await); // 握手后对端即走
    store_h2(donor_host, live_donor("9.9.3.2").await);

    let log: LogFn = Arc::new(|_: &str| {});
    let out = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{target}/u/1?s=40"))
        .body(empty_body())
        .unwrap();
    let info = crate::server::mitm::UpstreamInfo::default();
    let got = crate::server::mitm::try_borrow(&log, &out, target, &info, &None)
        .await
        .expect("有 donor 就该尝试借道")
        .expect("一条坏了要自动换另一条，不能让请求陪它一起失败");
    assert_eq!(got.status(), 200);
    assert_eq!(*info.lock().unwrap(), "9.9.3.2", "响应应来自健康的那条通道");

    drop(got); // 体丢弃 -> 借出配额归还
    let (_, again) = borrow_donor(target).expect("健康通道应已归还配额");
    assert_eq!(again.ip, "9.9.3.2", "还回来的应是那条健康的");
    borrow_done(donor_host, again.id);
    let _ = lock(conn_pool()).remove(donor_host);
}

/// 纯连接级契约（不碰全局池，可与上面并行）：换连接不换 `:authority`。
#[tokio::test]
async fn borrowed_stream_keeps_target_authority() {
    let target = "avatars.test-authority.githubusercontent.com";
    let donor = live_donor("9.9.6.1").await;
    let out = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{target}/u/1?s=40"))
        .body(empty_body())
        .unwrap();
    let resp = h2_send(&donor, &out, &None).await.expect("借道请求应成功");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-seen-authority")
            .and_then(|v| v.to_str().ok()),
        Some(target),
        "借来的连接上 :authority 必须仍是目标 host"
    );
}

#[tokio::test]
async fn slot_filter_prefers_fastest_primary() {
    let host = "test-slot-ewma.github.com";
    let slow = mk_up("9.9.8.1", 1).await;
    let fast = mk_up("9.9.8.2", 1).await;
    let (sid, fid) = (slow.id, fast.id);
    store_h2(host, slow);
    store_h2(host, fast);
    // 灌 EWMA 样本(>=3 次才参与择优):慢的 300ms,快的 50ms
    for _ in 0..4 {
        note_latency(host, sid, 300);
        note_latency(host, fid, 50);
    }
    let up = cached_h2_in(host, Some(1)).expect("主通道应在池");
    assert_eq!(up.id, fid, "槽位过滤应在主通道内取 EWMA 最快者");
    let _ = lock(conn_pool()).remove(host);
}
