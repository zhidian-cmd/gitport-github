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
        ping_tx: None,
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
        ping_tx: None,
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
    let _ = lock(conn_pool()).remove(ip);
}

/// 只有真连接才算"已有通道"；空壳条目不算占用（防的是"候选全被占住"的误判，
/// 实测 api.github.com 曾连刷 24 行同样的失败）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn empty_entry_is_not_an_occupied_channel() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let ip = "9.9.9.4";
    {
        let mut g = lock(conn_pool());
        g.entry(ip.to_string()).or_default();
    }
    assert!(
        occupied_ips(&[ip.to_string()]).is_empty(),
        "没有连接的条目不算占用"
    );
    store_h2(ip, mk_up(ip, 1).await);
    assert_eq!(
        occupied_ips(&[ip.to_string()]),
        vec![ip.to_string()],
        "真正有连接才算占用"
    );
    let _ = lock(conn_pool()).remove(ip);

}

/// 会话域优先用自己建的通道：池里另有公共连接时也不去蹭，没有自己的才退回任意。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn session_host_prefers_own_channel_over_public() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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

}

/// 选路看空闲：一条顶到并发上限，请求该落到另一条闲着的，哪怕它慢一点。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn pool_prefers_idle_channel_over_full_one() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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

/// 通道自己断掉必须自己除名：池就是「这个 IP 已有通道」的唯一登记处，
/// 留一条僵尸会让该 IP 一直占着名额——下次请求先撞一次死连接、白付一次发送，日志里还
/// 多一行「复用连接已断」。对端回收空闲连接（边缘 50~65s 静默）天天发生，这条路必须静默收尾。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn conn_end_removes_itself_from_pool() {
    use std::time::Duration;

    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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
        ping_tx: None,
    };
    assert_eq!(store_h2(ip, up).id, id, "第一条应入库");

    spawn_conn_driver(ConnDriver {
        ip: ip.to_string(),
        id,
        conn,
        ping: None,
        ping_rx: None,
        log: Arc::new(|_| {}),
    });
    // 给 server 端一点时间把握手走完，再掐掉它；没走完也一样，abort 会连 socket 一起丢。
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
    server.abort();

    // 不拿固定 sleep 赌时序：轮询到驱动任务把自己从池里摘走为止。
    let mut gone = false;
    for _ in 0..100 {
        if lock(conn_pool()).get(ip).is_none() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(gone, "连接结束后应把自己从池里摘除，该 IP 才能重新拨号");
    assert!(
        cached_h2_in(&[ip.to_string()], None).is_none(),
        "死连接不该还留在池里被复用"
    );
    assert!(lock(conn_pool()).get(ip).is_none(), "池里不该留这条僵尸");
    let _ = lock(conn_pool()).remove(ip);
}

/// 批窗外通道的就地除名：过窗且空闲的摘掉（跨批重建/睡眠唤醒共用这一条路），
/// 刚用过的留着；挂着在途流的（长下载 last_used 停在开流时刻）不按空闲论处；
/// 会话域通道归 ping 闸管，批窗摘除永远跳过。摘除连带撤销「已有通道」登记。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn evict_stale_removes_only_expired_idle_conns() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let fresh_ip = "9.9.9.20";
    let stale_ip = "9.9.9.21";
    let busy_ip = "9.9.9.22";
    let session_ip = "9.9.9.23";
    store_h2(fresh_ip, mk_up(fresh_ip, 1).await);
    store_h2(stale_ip, mk_up(stale_ip, 1).await);
    store_h2(busy_ip, mk_up(busy_ip, 1).await);
    let mut session_up = mk_up(session_ip, 1).await;
    session_up.owner = Some("github.com".to_string());
    store_h2(session_ip, session_up);
    // 除批内那条外全部回拨过窗，模拟跨批/睡眠唤醒。
    {
        let mut g = lock(conn_pool());
        for ip in [stale_ip, busy_ip, session_ip] {
            if let Some(h) = g.get_mut(ip) {
                for c in h.conns.iter_mut() {
                    c.last_used = now_secs() - crate::config::REUSE_WINDOW_SECS - 1;
                }
            }
        }
    }
    // busy 那条挂一个在途流：guard drop 时归还，断言前一直算「忙」。
    let inflight_arc = {
        let g = lock(conn_pool());
        g.get(busy_ip).unwrap().conns[0].up.inflight.clone()
    };
    let _busy = StreamGuard::new(inflight_arc);

    evict_stale(&[
        fresh_ip.to_string(),
        stale_ip.to_string(),
        busy_ip.to_string(),
        session_ip.to_string(),
    ]);

    assert!(lock(conn_pool()).get(fresh_ip).is_some(), "批内通道不摘");
    assert!(
        lock(conn_pool()).get(stale_ip).is_none(),
        "过窗且空闲的摘掉，该 IP 立刻可重拨"
    );
    assert!(
        lock(conn_pool()).get(busy_ip).is_some(),
        "挂着在途流的不按空闲论处"
    );
    assert!(
        lock(conn_pool()).get(session_ip).is_some(),
        "会话域归 ping 闸管，批窗摘除跳过"
    );
    let _ = lock(conn_pool()).remove(fresh_ip);
    let _ = lock(conn_pool()).remove(busy_ip);
    let _ = lock(conn_pool()).remove(session_ip);

}

/// 会话域取用闸：ping 端已死（驱动不在/全部句柄释放）= 通道必死，就地摘除返回 None；
/// 刚用过的通道跳过 ping 直接信——哪怕 ping 端也是死的，取用路径零额外延迟。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn session_pick_gates_on_ping_end_health() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let ip = "9.9.9.24";
    let mut up = mk_up(ip, 1).await;
    up.owner = Some("github.com".to_string());
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(1);
    drop(dead_rx); // 接收端没了 = 驱动任务不在，任何 ping 都发不进去
    up.ping_tx = Some(dead_tx);
    store_h2(ip, up);
    // 刚入库（last_used = 现在）：跳过 ping 直接信，死 ping 端轮不到出场。
    let fresh = session_pick("github.com", &[ip.to_string()], None).await;
    assert!(fresh.is_some(), "刚用过的会话通道不该被 ping 闸拦下");
    // 回拨过闸限：这次必须验活，ping 端已死 → 通道判死摘除。
    {
        let mut g = lock(conn_pool());
        if let Some(h) = g.get_mut(ip) {
            for c in h.conns.iter_mut() {
                c.last_used = now_secs() - crate::config::SESSION_PING_GATE_SECS - 1;
            }
        }
    }
    let gated = session_pick("github.com", &[ip.to_string()], None).await;
    assert!(gated.is_none(), "ping 端已死 = 通道必死");
    assert!(lock(conn_pool()).get(ip).is_none(), "池里不该留死通道");
}

// 看护任务不再做保活与补拨（批窗 + ping 闸取代），旧的隧道打点与补拨节流测试随之退役：
// 连接死亡一律由请求结果或批窗发现，通道重建是下一批请求自己的事。
