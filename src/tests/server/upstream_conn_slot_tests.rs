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
        g.get(host).unwrap().conns.iter().find(|c| c.up.slot == 1).unwrap().up.id
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

/// 借道三步契约，顺序执行：三段都要看全局连接池，拆成并行用例会互相抢候选。
/// 1) 只认 assets 域现成连接，内容域自己的连接和 donor 自身都不算；
/// 2) 借来的流 `:authority` 仍是目标 host（服务端按它路由，这才是能取到内容域的原因）；
/// 3) 借失败要进冷却，后续请求直接回落，不再逐条空等。
#[tokio::test]
async fn borrow_contract_end_to_end() {
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
    let first =
        crate::server::mitm::try_borrow(&log, &out2, dead_target, &dead_info, &None).await;
    assert!(
        matches!(first, Some(Err(_))),
        "借失败要如实报错, 不能假装成功"
    );
    let second =
        crate::server::mitm::try_borrow(&log, &out2, dead_target, &dead_info, &None).await;
    assert!(second.is_none(), "冷却期内不再空试, 直接交回退路径");

    for h in [content_host, dead_host] {
        let _ = lock(conn_pool()).remove(h);
    }
    assert!(
        borrow_donor(target).is_none(),
        "池空时借不到, 必须回 None 而不是新建"
    );
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
