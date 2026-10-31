use super::*;

/// 造一条合法 H2Upstream:h2 握手用本机 duplex 对拉(无需真网络),
/// server 端由 h2::server 驱动回 SETTINGS,client 端即完成。
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
        let g = pool::lock(conn_pool());
        g.get(host).unwrap().conns.iter().find(|c| c.up.slot == 1).unwrap().up.id
    });
    assert!(
        cached_h2_in(host, Some(1)).is_none(),
        "主通道被摘后应回 None 走重建,不得回落第二通道"
    );
    // None = 原语义:池里剩下的第二通道照常服务
    let up = cached_h2_in(host, None).expect("无过滤应命中");
    assert_eq!(up.ip, "9.9.9.2");
    let _ = pool::lock(conn_pool()).remove(host);
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
    let _ = pool::lock(conn_pool()).remove(host);
}
