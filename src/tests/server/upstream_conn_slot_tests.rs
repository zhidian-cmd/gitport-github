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
        owner: None,
        max_streams: 100,
        inflight: Arc::new(AtomicU32::new(0)),
        send,
    }
}

/// 造一条能回 200 并把 `:authority` 回显到响应头的活连接：v2 共享连接上发谁就路由谁的核心证据。
async fn live_conn(ip: &str) -> H2Upstream {
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
        owner: None,
        max_streams: 100,
        inflight: Arc::new(AtomicU32::new(0)),
        send,
    }
}

/// 硬约束：同一个 IP 永远只有一条通道。后到的连接当场作废、返回池里已有的那条。
/// 顺带验证槽位过滤：主通道被摘后不回落到别的槽位，且登记随之撤销允许重拨。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn one_ip_one_channel_and_slot_filter() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "9.9.9.1";
    pool::inflight::clear();
    let first = mk_up(ip, 1).await;
    let first_id = first.id;
    assert_eq!(store_h2(ip, first).id, first_id, "第一条应入库");

    let second = mk_up(ip, 2).await;
    let second_id = second.id;
    let kept = store_h2(ip, second);
    assert_eq!(kept.id, first_id, "同 IP 的第二条必须作废, 返回已有连接");
    assert_ne!(kept.id, second_id);
    {
        let g = lock(conn_pool());
        assert_eq!(g.get(ip).unwrap().conns.len(), 1, "池里该 IP 只能有一条");
    }
    assert!(pool::inflight::live(ip), "入库即登记'这个 IP 已有通道'");

    for _ in 0..4 {
        let up = cached_h2_in(&[ip.to_string()], Some(1)).expect("主通道应在池");
        assert_eq!(up.slot, 1, "Some(1) 永远拿主通道,轮转计数不动");
    }
    drop_h2_id(ip, first_id);
    assert!(
        cached_h2_in(&[ip.to_string()], Some(1)).is_none(),
        "主通道被摘后应回 None 走重建"
    );
    assert!(
        cached_h2_in(&[ip.to_string()], None).is_none(),
        "同 IP 不该还留着第二条通道"
    );
    assert!(!pool::inflight::live(ip), "最后一条摘除后应允许重拨");
    let _ = lock(conn_pool()).remove(ip);
}

/// 只有 filling 标记（没连接）的 IP 不算"已有通道"。把它算进去会让候选被误判为
/// 全被占住、请求原地重试到死（实测 api.github.com 连刷 24 行同样的失败）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn filling_mark_is_not_an_occupied_channel() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ip = "9.9.9.4";
    {
        let mut g = lock(conn_pool());
        g.entry(ip.to_string()).or_default().filling = true;
    }
    assert!(
        occupied_ips(&[ip.to_string()]).is_empty(),
        "filling 只是补第二条的防重入标记，不是可用通道"
    );
    store_h2(ip, mk_up(ip, 1).await);
    assert_eq!(
        occupied_ips(&[ip.to_string()]),
        vec![ip.to_string()],
        "真正有连接才算占用"
    );
    let _ = lock(conn_pool()).remove(ip);
    pool::inflight::clear();
}

/// 会话域优先用自己建的通道：池里另有公共连接时也不去蹭，没有自己的才退回任意。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn session_host_prefers_own_channel_over_public() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let own_ip = "9.9.7.1";
    let public_ip = "9.9.7.2";
    let mut own = mk_up(own_ip, 1).await;
    own.owner = Some("api.github.com".into());
    let own_id = own.id;
    store_h2(own_ip, own);
    let mut public = mk_up(public_ip, 1).await;
    public.owner = Some("raw.githubusercontent.com".into());
    store_h2(public_ip, public);

    let ips = vec![own_ip.to_string(), public_ip.to_string()];
    let up = cached_h2_own("api.github.com", &ips, None).expect("应有连接");
    assert_eq!(up.id, own_id, "会话域先认自己建的通道");

    // 自己没建过：入口不抢公共，返回 None，让调用方去自建。
    let ips_public_first = vec![public_ip.to_string(), own_ip.to_string()];
    assert!(
        cached_h2_own("gist.github.com", &ips_public_first, None).is_none(),
        "入口只认自己的通道；公共连接留给拨号失败后的兜底"
    );

    let _ = lock(conn_pool()).remove(own_ip);
    let _ = lock(conn_pool()).remove(public_ip);
    pool::inflight::clear();
}

/// 选路看空闲：一条顶到并发上限，请求该落到另一条闲着的，哪怕它慢一点。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn pool_prefers_idle_channel_over_full_one() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let full_ip = "9.9.4.1";
    let idle_ip = "9.9.4.2";
    let mut full = mk_up(full_ip, 1).await;
    full.max_streams = 4;
    full.inflight
        .store(4, std::sync::atomic::Ordering::Relaxed);
    let full_id = full.id;
    store_h2(full_ip, full);
    let mut idle = mk_up(idle_ip, 1).await;
    idle.max_streams = 4;
    let idle_id = idle.id;
    store_h2(idle_ip, idle);
    // 把"满的那条"灌成明显更快：只看 EWMA 会选它，看空闲就该让给另一条。
    for _ in 0..4 {
        note_latency(full_ip, full_id, 10);
        note_latency(idle_ip, idle_id, 300);
    }
    let ips = vec![full_ip.to_string(), idle_ip.to_string()];
    let up = cached_h2_in(&ips, None).expect("应有一条可用");
    assert_eq!(up.id, idle_id, "满了的通道不该再接新流");
    let _ = lock(conn_pool()).remove(full_ip);
    let _ = lock(conn_pool()).remove(idle_ip);
    pool::inflight::clear();
}

/// 在途计数跟着响应体走：body 没消费完算占用，丢弃后必须归还，不能留幽灵占位。
#[tokio::test]
async fn inflight_count_follows_response_body_lifecycle() {
    let ip = "9.9.4.3";
    let up = live_conn(ip).await;
    let order = std::sync::atomic::Ordering::Relaxed;
    assert_eq!(up.inflight.load(order), 0);
    let req = hyper::Request::builder()
        .method("GET")
        .uri("https://probe.example/")
        .body(empty_body())
        .unwrap();
    let resp = h2_send(&up, &req, &None).await.expect("请求应成功");
    assert_eq!(up.inflight.load(order), 1, "响应体还在，槽位算占用");
    drop(resp);
    assert_eq!(up.inflight.load(order), 0, "body 丢弃后必须归还槽位");
}

/// 两个 host 同时把新连接交上来，池里也只能留下一条；两条通道只能分落在两个不同 IP。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn concurrent_hosts_never_share_two_channels_on_one_ip() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let same = "9.9.9.2";
    let other = "9.9.9.3";
    let a = mk_up(same, 1).await;
    let b = mk_up(same, 2).await;
    let (ra, rb) = tokio::join!(
        async move { store_h2(same, a) },
        async move { store_h2(same, b) },
    );
    assert_eq!(ra.id, rb.id, "两边最终必须用同一条连接");
    {
        let g = lock(conn_pool());
        assert_eq!(g.get(same).unwrap().conns.len(), 1);
    }
    // 第二条通道落在另一个 IP：仍然允许， EWMA 轮转也照旧。
    store_h2(other, mk_up(other, 2).await);
    let ips = vec![same.to_string(), other.to_string()];
    assert_eq!(
        lock(conn_pool())
            .iter()
            .filter(|(k, _)| ips.contains(k))
            .map(|(_, h)| h.conns.len())
            .sum::<usize>(),
        2,
        "两条通道 = 两个不同 IP 各一条"
    );
    assert!(cached_h2_in(&ips, None).is_some());
    let _ = lock(conn_pool()).remove(same);
    let _ = lock(conn_pool()).remove(other);
    pool::inflight::clear();
}

/// v2 复用单元 = IP：给定候选 IP 集合，池里任一命中都可复用，:authority 保持目标 host。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn shared_conn_keeps_target_authority_across_hosts() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "9.9.6.1";
    let donor = live_conn(ip).await;
    store_h2(ip, donor);
    // 同一 IP 先后服务两个不同的目标 host——v1 要借道，v2 是常态路径。
    for target in [
        "avatars.test-authority.githubusercontent.com",
        "raw.test-authority.githubusercontent.com",
    ] {
        let out = hyper::Request::builder()
            .method("GET")
            .uri(format!("https://{target}/u/1?s=40"))
            .body(empty_body())
            .unwrap();
        let resp = h2_send(&cached_h2_in(&[ip.to_string()], None).unwrap(), &out, &None)
            .await
            .expect("共享连接请求应成功");
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-seen-authority")
                .and_then(|v| v.to_str().ok()),
            Some(target),
            "共享连接上 :authority 必须仍是目标 host"
        );
    }
    let _ = lock(conn_pool()).remove(ip);
}

/// 候选集合跨两个 IP 时：EWMA 快的胜出（样本 >=3 才参与）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn pool_prefers_fastest_across_ips() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let slow_ip = "9.9.8.1";
    let fast_ip = "9.9.8.2";
    let slow = mk_up(slow_ip, 1).await;
    let fast = mk_up(fast_ip, 1).await;
    let (sid, fid) = (slow.id, fast.id);
    store_h2(slow_ip, slow);
    store_h2(fast_ip, fast);
    // 灌 EWMA 样本(>=3 次才参与择优):慢的 300ms,快的 50ms
    for _ in 0..4 {
        note_latency(slow_ip, sid, 300);
        note_latency(fast_ip, fid, 50);
    }
    let ips = vec![slow_ip.to_string(), fast_ip.to_string()];
    let up = cached_h2_in(&ips, Some(1)).expect("主通道应在池");
    assert_eq!(up.id, fid, "应在候选集合内取 EWMA 最快者");
    let _ = lock(conn_pool()).remove(slow_ip);
    let _ = lock(conn_pool()).remove(fast_ip);
}

/// 样本决定择优：EWMA 快的恒赢（探索计数器先对齐到非探索相位，概率不进断言）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn pool_no_samples_takes_first_candidate() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let slow_ip = "9.9.5.1";
    let fast_ip = "9.9.5.2";
    let slow = mk_up(slow_ip, 1).await;
    let fast = mk_up(fast_ip, 1).await;
    let (sid, fid) = (slow.id, fast.id);
    store_h2(slow_ip, slow);
    store_h2(fast_ip, fast);
    let ips = vec![slow_ip.to_string(), fast_ip.to_string()];
    // 全零样本：取首条（确定性）
    for _ in 0..3 {
        let up = cached_h2_in(&ips, None).expect("应有连接");
        assert_eq!(up.ip, slow_ip, "全零样本时恒取首条");
    }
    // 灌样本：快的恒赢
    for _ in 0..4 {
        note_latency(slow_ip, sid, 300);
        note_latency(fast_ip, fid, 50);
    }
    for _ in 0..3 {
        let up = cached_h2_in(&ips, None).expect("应有连接");
        assert_eq!(up.ip, fast_ip, "有样本后 EWMA 快者恒胜");
    }
    let _ = lock(conn_pool()).remove(slow_ip);
    let _ = lock(conn_pool()).remove(fast_ip);
}

/// 全局"正在拨"登记按 IP 粒度：抢占期间别人看得到，同一 IP 只能有一个拨号者，释放后立刻可拨。
#[test]
fn inflight_registry_claim_blocks_and_release_frees() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "198.51.100.7";
    pool::inflight::clear();
    assert!(!pool::inflight::busy(ip));
    let guard = pool::inflight::try_claim(ip).expect("首个应抢到");
    assert!(pool::inflight::busy(ip), "认领后应显示在拨");
    assert!(
        pool::inflight::try_claim(ip).is_none(),
        "同一 IP 第二个必须抢不到"
    );
    assert!(
        pool::inflight::try_claim("203.0.113.9").is_some(),
        "别的 IP 不受影响"
    );
    drop(guard);
    assert!(!pool::inflight::busy(ip), "释放后应立刻可拨");
}

/// 一次性探针（手动跑，走真网络）：实测 185.199 段每个边缘 IP 对每个内容域名的服务支持。
/// 每条边 = 用该节点自己的 verify 锚点建一条 h2 连接，再对它发 HEAD 看状态码。
/// 用法：cargo test probe_content_edges -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn probe_content_edges() {
    use crate::pool::dial::dial_one;
    use crate::server::protocol::empty_body;
    use crate::server::upstream::{h2_from_dialed, h2_send};
    use std::sync::Arc;
    use std::time::Duration;

    // 真实资源路径：只有能取到内容才算"支持"，根路径的 404/302 说明不了问题。
    let domains = [
        ("avatars.githubusercontent.com", "/u/1?v=4"),
        ("raw.githubusercontent.com", "/git/git/master/README.md"),
        ("docs.github.com", "/en/get-started"),
        ("octocat.github.io", "/"),
        ("github.com", "/"),
    ];
    let log: crate::util::LogFn = Arc::new(|_: &str| {});
    for last in ["133", "153", "154", "215"] {
        for third in 108..=111 {
            let ip = format!("185.199.{third}.{last}");
            let verify = if last == "133" || last == "153" {
                "github.com"
            } else {
                "githubassets.com"
            };
            let dialed = match tokio::time::timeout(
                Duration::from_secs(12),
                dial_one(&ip, "baidu.com", verify, true),
            )
            .await
            {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => {
                    println!("PROBE\t{ip}\t{verify}\tTLS\tERR {e}");
                    continue;
                }
                Err(_) => {
                    println!("PROBE\t{ip}\t{verify}\tTLS\tTIMEOUT");
                    continue;
                }
            };
            let up = match h2_from_dialed("probe", dialed, &ip, 1, &log).await {
                Ok(u) => u,
                Err(e) => {
                    println!("PROBE\t{ip}\t{verify}\th2\tERR {e}");
                    continue;
                }
            };
            for (d, path) in domains {
                let req = hyper::Request::builder()
                    .method("HEAD")
                    .uri(format!("https://{d}{path}"))
                    .body(empty_body())
                    .unwrap();
                let r =
                    tokio::time::timeout(Duration::from_secs(10), h2_send(&up, &req, &None)).await;
                let s = match r {
                    Ok(Ok(resp)) => {
                        let code = resp.status().as_u16();
                        let loc = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .map(|l| format!(" -> {}", &l[..l.len().min(70)]))
                            .unwrap_or_default();
                        let ty = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        format!("{code} {ty}{loc}")
                    }
                    Ok(Err(e)) => format!("ERR {e}"),
                    Err(_) => "TIMEOUT".to_string(),
                };
                println!("PROBE\t{ip}\t{verify}\t{d}{path}\t{s}");
            }
        }
    }
}

/// 一次性探针（手动跑，走真网络）：为 4 个无边域名实测候选 IP 与证书锚点。
/// 用法：cargo test probe_new_hosts -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn probe_new_hosts() {
    use crate::pool::dial::dial_one;
    use crate::server::protocol::empty_body;
    use crate::server::upstream::{h2_from_dialed, h2_send};
    use std::sync::Arc;
    use std::time::Duration;

    let hosts = [
        "api.mcp.github.com",
        "githubapp.com",
        "objects-origin.githubusercontent.com",
        "viewscreen.githubusercontent.com",
    ];
    let ips = [
        "140.82.112.21",
        "140.82.112.22",
        "140.82.113.21",
        "140.82.113.22",
        "140.82.114.21",
        "140.82.114.22",
        "140.82.112.29",
        "140.82.112.30",
        "140.82.113.29",
        "140.82.113.30",
        "140.82.114.29",
        "140.82.114.30",
    ];
    let log: crate::util::LogFn = Arc::new(|_: &str| {});
    for host in hosts {
        // 证书锚点：先按域名本身，其次回落到基础域（GitHub 证书常见多 SAN）。
        let anchors: Vec<&str> = match host {
            "api.mcp.github.com" => vec![host, "github.com"],
            "githubapp.com" => vec!["githubapp.com"],
            _ => vec![host, "githubusercontent.com"],
        };
        for ip in ips {
            let mut chosen: Option<(String, crate::pool::dial::Dialed)> = None;
            let mut last_err = String::new();
            for anchor in &anchors {
                match tokio::time::timeout(
                    Duration::from_secs(8),
                    dial_one(ip, "baidu.com", anchor, true),
                )
                .await
                {
                    Ok(Ok(d)) => {
                        chosen = Some(((*anchor).to_string(), d));
                        break;
                    }
                    Ok(Err(e)) => last_err = e.to_string(),
                    Err(_) => last_err = "TLS 超时".to_string(),
                }
            }
            let Some((anchor, dialed)) = chosen else {
                println!("HOSTPROBE\t{ip}\t{host}\t-\tERR {last_err}");
                continue;
            };
            let up = match h2_from_dialed(host, dialed, ip, 1, &log).await {
                Ok(u) => u,
                Err(e) => {
                    println!("HOSTPROBE\t{ip}\t{host}\t{anchor}\th2 ERR {e}");
                    continue;
                }
            };
            let req = hyper::Request::builder()
                .method("HEAD")
                .uri(format!("https://{host}/"))
                .body(empty_body())
                .unwrap();
            let r = tokio::time::timeout(Duration::from_secs(8), h2_send(&up, &req, &None)).await;
            let s = match r {
                Ok(Ok(resp)) => {
                    let srv = resp
                        .headers()
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-");
                    format!("{} server={srv}", resp.status().as_u16())
                }
                Ok(Err(e)) => format!("ERR {e}"),
                Err(_) => "TIMEOUT".to_string(),
            };
            println!("HOSTPROBE\t{ip}\t{host}\t{anchor}\t{s}");
        }
    }
}

/// 一次性探针：同一连接（SNI=api.mcp）改发其它 :authority，看服务端是否 421。
/// 决定连接池能否按 IP 复用不同 SNI 的节点。
/// 用法：cargo test probe_cross_sni_reuse -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn probe_cross_sni_reuse() {
    use crate::pool::dial::dial_one;
    use crate::server::protocol::empty_body;
    use crate::server::upstream::{h2_from_dialed, h2_send};
    use std::sync::Arc;
    use std::time::Duration;

    let ip = "140.82.112.21";
    let log: crate::util::LogFn = Arc::new(|_: &str| {});
    let dialed = dial_one(ip, "api.mcp.github.com", "api.mcp.github.com", true)
        .await
        .expect("api.mcp 握手应成功");
    let up = h2_from_dialed("api.mcp.github.com", dialed, ip, 1, &log)
        .await
        .expect("h2 握手");
    for host in [
        "api.mcp.github.com",
        "objects-origin.githubusercontent.com",
        "viewscreen.githubusercontent.com",
        "githubapp.com",
        "github.com",
    ] {
        let req = hyper::Request::builder()
            .method("HEAD")
            .uri(format!("https://{host}/"))
            .body(empty_body())
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(8), h2_send(&up, &req, &None)).await;
        let s = match r {
            Ok(Ok(resp)) => resp.status().as_u16().to_string(),
            Ok(Err(e)) => format!("ERR {e}"),
            Err(_) => "TIMEOUT".to_string(),
        };
        println!("REUSE\t{ip}\tSNI=api.mcp\t{host}\t{s}");
    }
}

/// 一次性探针：验证基线节点（SNI=baidu, verify=actions.githubusercontent.com）是否服务三个域名。
/// 用法：cargo test probe_baseline_actions -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn probe_baseline_actions() {
    use crate::pool::dial::dial_one;
    use crate::server::protocol::empty_body;
    use crate::server::upstream::{h2_from_dialed, h2_send};
    use std::sync::Arc;
    use std::time::Duration;

    let log: crate::util::LogFn = Arc::new(|_: &str| {});
    for ip in ["140.82.112.21", "140.82.113.22", "140.82.114.21"] {
        let dialed = match tokio::time::timeout(
            Duration::from_secs(8),
            dial_one(ip, "baidu.com", "actions.githubusercontent.com", true),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                println!("BASE\t{ip}\tTLS ERR {e}");
                continue;
            }
            Err(_) => {
                println!("BASE\t{ip}\tTLS TIMEOUT");
                continue;
            }
        };
        let up = match h2_from_dialed("baseline", dialed, ip, 1, &log).await {
            Ok(u) => u,
            Err(e) => {
                println!("BASE\t{ip}\th2 ERR {e}");
                continue;
            }
        };
        for host in [
            "api.mcp.github.com",
            "objects-origin.githubusercontent.com",
            "viewscreen.githubusercontent.com",
        ] {
            let req = hyper::Request::builder()
                .method("HEAD")
                .uri(format!("https://{host}/"))
                .body(empty_body())
                .unwrap();
            let r = tokio::time::timeout(Duration::from_secs(8), h2_send(&up, &req, &None)).await;
            let s = match r {
                Ok(Ok(resp)) => resp.status().as_u16().to_string(),
                Ok(Err(e)) => format!("ERR {e}"),
                Err(_) => "TIMEOUT".to_string(),
            };
            println!("BASE\t{ip}\t{host}\t{s}");
        }
    }
}

/// 拨号权抢占必须是原子的：释放后能重新抢到（前半段见 inflight_registry_claim_blocks_and_release_frees）。
#[test]
fn inflight_try_claim_is_exclusive() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "198.51.100.21";
    pool::inflight::clear();
    let first = pool::inflight::try_claim(ip).expect("第一枪应成功");
    assert!(
        pool::inflight::try_claim(ip).is_none(),
        "同一 IP 第二个必须抢不到"
    );
    drop(first);
    assert!(
        pool::inflight::try_claim(ip).is_some(),
        "释放后应能重新抢到"
    );
}

/// 通道自己断掉必须自己除名：池同时是「这个 IP 已有通道」的登记表（`inflight::live`），
/// 留一条僵尸会让该 IP 一直占着名额——下次请求先撞一次死连接、白付一次发送，日志里还
/// 多一行「复用连接已断」。对端回收空闲连接（边缘 50~65s 静默）天天发生，这条路必须静默收尾。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn conn_end_removes_itself_from_pool() {
    use std::time::Duration;

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ip = "9.9.9.5";

    // 内存 duplex 对拉：server 端只完成握手就收摊 = 对端回收连接（客户端读到 EOF）。
    // 握手没赶上也不要紧：任务一 abort 就连 socket 一起丢，客户端照样读到 EOF。
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut server = tokio::spawn(async move {
        let _ = h2::server::handshake(server_io).await;
    });
    let (send, conn) = h2::client::handshake(client_io)
        .await
        .expect("client 握手");

    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let up = H2Upstream {
        ip: ip.to_string(),
        id,
        slot: 1,
        owner: None,
        max_streams: 100,
        inflight: Arc::new(AtomicU32::new(0)),
        send,
    };
    assert_eq!(store_h2(ip, up).id, id, "第一条应入库");
    assert!(pool::inflight::live(ip), "入库即登记'这个 IP 已有通道'");

    spawn_conn_driver(
        ip.to_string(),
        id,
        conn,
        None,
        Arc::new(|_| {}),
        Duration::from_secs(30),
    );
    // 给 server 端一点时间把握手走完，再掐掉它；没走完也一样，abort 会连 socket 一起丢。
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
    server.abort();

    // 不拿固定 sleep 赌时序：轮询到登记撤销为止。
    let mut gone = false;
    for _ in 0..100 {
        if !pool::inflight::live(ip) {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(gone, "连接结束后应撤销'已有通道'登记，该 IP 才能重新拨号");
    assert!(
        cached_h2_in(&[ip.to_string()], None).is_none(),
        "死连接不该还留在池里被复用"
    );
    assert!(lock(conn_pool()).get(ip).is_none(), "池里不该留这条僵尸");
    let _ = lock(conn_pool()).remove(ip);
}

/// 「停 ping」的那一刻，每个 IP 就该各自从「已有通道」表里滚出去。
/// 改前：全局保活任务超窗只 `break` 回睡，池里的连接和 live 登记都原样留着 →
/// 5 分钟后回来的第一个请求撞尸体、烧满 4s 预算，内容域还会误判「直连全灭」转镜像。
/// 现在每条连接是自己的任务，任务一停就在出口按 id 摘自己，谁建得早谁先走。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn idle_window_end_retires_each_ip_from_its_own_task() {
    use std::time::Duration;

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ips = ["9.9.9.10", "9.9.9.11"];
    for ip in ips {
        let (client_io, server_io) = tokio::io::duplex(4096);
        // server 端握完手就攥着不放：客户端不会读到 EOF，任务只能因「停保活」退出。
        tokio::spawn(async move {
            if let Ok(_c) = h2::server::handshake(server_io).await {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        let (send, mut conn) = h2::client::handshake(client_io).await.expect("client 握手");
        let ping = conn
            .ping_pong()
            .map(|p| Arc::new(tokio::sync::Mutex::new(p)));
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let up = H2Upstream {
            ip: ip.to_string(),
            id,
            slot: 1,
            owner: None,
            max_streams: 100,
            inflight: Arc::new(AtomicU32::new(0)),
            send,
        };
        store_h2(ip, up);
        assert!(pool::inflight::live(ip), "入库即登记");
        // 空闲窗按每条连接自己的最后使用算：把它回拨 6 分钟，模拟"建好后无人问津"。
        // 全局 LAST_ACTIVITY 不再参与——别的连接忙不代表这条有人用。
        {
            let mut g = lock(conn_pool());
            if let Some(h) = g.get_mut(ip) {
                if let Some(c) = h.conns.iter_mut().find(|c| c.up.id == id) {
                    c.last_used = now_secs() - 400;
                }
            }
        }
        spawn_conn_driver(
            ip.to_string(),
            id,
            conn,
            ping,
            Arc::new(|_| {}),
            Duration::from_millis(20),
        );
    }

    let mut all_gone = false;
    for _ in 0..100 {
        if ips.iter().all(|ip| !pool::inflight::live(ip)) {
            all_gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(all_gone, "静默超窗后每个 IP 的任务都应自行除名");
    assert!(
        ips.iter().all(|ip| lock(conn_pool()).get(*ip).is_none()),
        "池里不该留没任务管的连接"
    );
    assert!(
        cached_h2_in(&ips.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None).is_none(),
        "表里不该还有可取用的尸体"
    );
    LAST_ACTIVITY.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// 机器睡眠 / 进程被冻住：这一段时间里**没有任何任务跑过**，等各任务自己的
/// 定时节拍来摘已经晚了——醒来第一个请求会先撞上去。请求入口必须同步逐条除名。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn wake_after_suspend_retires_unprobed_before_any_reuse() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ips = ["9.9.9.12", "9.9.9.13", "9.9.9.14"];
    for ip in ips {
        let up = mk_up(ip, 1).await;
        store_h2(ip, up);
        assert!(pool::inflight::live(ip));
    }
    // 睡前最后一次活动，进程冻结 28 分钟，池里三条都成了没人验过活的登记。
    LAST_ACTIVITY.store(now_secs() - 28 * 60, std::sync::atomic::Ordering::Relaxed);

    note_activity(); // 请求处理的第一行

    assert!(
        ips.iter().all(|ip| !pool::inflight::live(ip)),
        "空窗后的第一个请求到达前，每个 IP 的「已有通道」登记都要撤销，才允许重新拨号"
    );
    assert!(lock(conn_pool()).is_empty(), "池里不该留任何尸体");
    assert!(
        cached_h2_in(&ips.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None).is_none(),
        "取用时看不到尸体，本次请求会直接新建"
    );
    LAST_ACTIVITY.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// 别把「正常连续使用」也当成空窗。这条防的是同步除名写宽了、每次请求都清池。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn normal_activity_keeps_channels_registered() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ip = "9.9.9.15";
    store_h2(ip, mk_up(ip, 1).await);
    LAST_ACTIVITY.store(now_secs(), std::sync::atomic::Ordering::Relaxed);

    note_activity();

    assert!(pool::inflight::live(ip), "刚活动过的通道不该被摘");
    assert!(lock(conn_pool()).get(ip).is_some());
    LAST_ACTIVITY.store(0, std::sync::atomic::Ordering::Relaxed);
    let _ = lock(conn_pool()).remove(ip);
}

/// 判定边界：一轮探测内的正常抖动不摘；漏了一整轮（进程被挂起）或静默超窗才摘。
#[test]
fn probe_expired_only_when_missed_or_window_elapsed() {
    let probe = 30_000;
    let window = 300;
    assert!(!probe_expired(probe, probe, 10, window));
    assert!(!probe_expired(probe + PROBE_SLACK_MS, probe, 10, window));
    assert!(probe_expired(probe + PROBE_SLACK_MS + 1, probe, 10, window));
    assert!(probe_expired(28 * 60 * 1000, probe, 10, window));
    assert!(probe_expired(probe, probe, window + 1, window));
    assert!(!probe_expired(probe, probe, window, window));
}

/// 一条 CONNECT 隧道会连着跑几十个请求，TCP 只在建隧道时经过 handle。
/// 只在那里打点，隧道越忙越会被误判「静默超窗」，把健康通道全摘光。
/// 钉住：每个解密请求都刷新「最后活动」，池里的通道一直留着可复用。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn busy_tunnel_requests_keep_channels_alive() {
    use std::time::Duration;

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    pool::inflight::clear();
    let ip = "9.9.9.16";
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        if let Ok(_c) = h2::server::handshake(server_io).await {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    let (send, conn) = h2::client::handshake(client_io)
        .await
        .expect("client 握手");
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    store_h2(
        ip,
        H2Upstream {
            ip: ip.to_string(),
            id,
            slot: 1,
            owner: None,
            max_streams: 100,
            inflight: Arc::new(AtomicU32::new(0)),
            send,
        },
    );
    LAST_ACTIVITY.store(now_secs(), std::sync::atomic::Ordering::Relaxed);
    spawn_conn_driver(
        ip.to_string(),
        id,
        conn,
        None,
        Arc::new(|_| {}),
        Duration::from_millis(20),
    );

    // 模拟隧道里连着来 30 个请求：每个都打点，中间不该出现任何假空窗。
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        note_activity();
    }

    assert!(
        pool::inflight::live(ip),
        "隧道一直在发请求，通道不该被当成静默超窗摘掉"
    );
    assert!(lock(conn_pool()).get(ip).is_some(), "池里的健康连接还在");
    assert!(
        cached_h2_in(&[ip.to_string()], None).is_some(),
        "后续请求仍可复用这条通道"
    );

    server.abort();
    LAST_ACTIVITY.store(0, std::sync::atomic::Ordering::Relaxed);
    let _ = lock(conn_pool()).remove(ip);
    pool::inflight::clear();
}
