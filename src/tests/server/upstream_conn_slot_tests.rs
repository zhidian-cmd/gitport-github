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
        overflow: false,
        close: std::sync::Arc::new(tokio::sync::Notify::new()),
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
        overflow: false,
        close: std::sync::Arc::new(tokio::sync::Notify::new()),
        send,
    }
}

/// 会话域硬约束：同一 IP 只留一条通道。后到的当场作废、返回池里已有的那条。
/// 顺带验证槽位过滤：主通道被摘后不回落到别的槽位。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn one_ip_one_channel_and_slot_filter() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "9.9.9.1";
    let mut first = mk_up(ip, 1).await;
    first.owner = Some("github.com".to_string()); // 会话域 → cap 1
    let first_id = first.id;
    assert_eq!(store_h2(ip, first).id, first_id, "第一条应入库");

    let mut second = mk_up(ip, 2).await;
    second.owner = Some("github.com".to_string());
    let second_id = second.id;
    let kept = store_h2(ip, second);
    assert_eq!(kept.id, first_id, "会话域同 IP 的第二条必须作废, 返回已有连接");
    assert_ne!(kept.id, second_id);
    {
        let g = lock(conn_pool());
        assert_eq!(g.get(ip).unwrap().len(), 1, "会话域池里该 IP 只能有一条");
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

/// 竞速排名：按拨号耗时升序——通道即用即建几乎全新，拨号快慢是唯一速度先验。
#[tokio::test]
async fn race_ranks_by_dial_ms() {
    let legs = vec![
        RaceLeg {
            ip: "c".into(),
            dial_ms: 500,
            up: mk_up("9.9.9.33", 1).await,
            pooled: false,
        },
        RaceLeg {
            ip: "a".into(),
            dial_ms: 100,
            up: mk_up("9.9.9.31", 1).await,
            pooled: false,
        },
        RaceLeg {
            ip: "b".into(),
            dial_ms: 300,
            up: mk_up("9.9.9.32", 1).await,
            pooled: false,
        },
    ];
    let ranked = rank_legs(legs);
    let order: Vec<&str> = ranked.iter().map(|l| l.ip.as_str()).collect();
    assert_eq!(order, vec!["a", "b", "c"], "按拨号耗时升序");
}

/// 内容域：同 IP 只准一条通道——第二条拨出来当场作废，返回池里现成那条。
/// 要多通道就换 IP 另起（竞速建连按这个前提展开）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn content_ip_keeps_single_channel() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "9.9.9.2";
    let mut a = mk_up(ip, 1).await;
    a.owner = Some("raw.githubusercontent.com".to_string());
    let a_id = a.id;
    assert_eq!(store_h2(ip, a).id, a_id, "第一条应入库");

    let mut b = mk_up(ip, 2).await;
    b.owner = Some("raw.githubusercontent.com".to_string());
    let b_id = b.id;
    let kept = store_h2(ip, b);
    assert_ne!(kept.id, b_id, "同 IP 第二条必须作废");
    assert_eq!(kept.id, a_id, "作废时返回池里现成的那条");
    {
        let g = lock(conn_pool());
        assert_eq!(g.get(ip).unwrap().len(), 1, "同 IP 上限 1 条");
    }
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
    let _full_id = full.id;
    store_h2(full_ip, full);
    let mut idle = mk_up(idle_ip, 1).await;
    idle.max_streams = 4;
    let idle_id = idle.id;
    store_h2(idle_ip, idle);
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

/// 两个 host 并发入库同一 IP（内容域）：两条通道并存，不互斥。
/// 会话域仍然恒单通道（见 one_ip_one_channel_and_slot_filter）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn concurrent_content_hosts_coexist_on_one_ip() {
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
    // 内容域/其他（owner 无 session 标志）：两条并存
    assert_ne!(ra.id, rb.id, "内容域同 IP 两条通道并存");
    {
        let g = lock(conn_pool());
        assert_eq!(g.get(same).unwrap().len(), 2, "内容域同 IP 两条并存");
    }
    // 第二条通道落在另一个 IP：仍然允许， EWMA 轮转也照旧。
    store_h2(other, mk_up(other, 2).await);
    let ips = vec![same.to_string(), other.to_string()];
    assert_eq!(
        lock(conn_pool())
            .iter()
            .filter(|(k, _)| ips.contains(k))
            .map(|(_, h)| h.len())
            .sum::<usize>(),
        3,
        "同 IP 两条 + 另一 IP 一条 = 三条"
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
        overflow: false,
        close: std::sync::Arc::new(tokio::sync::Notify::new()),
        send: send.clone(),
    };
    assert_eq!(store_h2(ip, up).id, id, "第一条应入库");

    spawn_conn_driver(ConnDriver {
        ip: ip.to_string(),
        id,
        conn,
        session: false,
        close: std::sync::Arc::new(tokio::sync::Notify::new()),
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

/// 溢出临时通道语义：同 IP 溢出是拥挤时的临时加班——正编 + 一条溢出并存，
/// pick 与通道清单都不外发溢出句柄，第二条溢出拒收（递回正编），
/// 驱动按"在途流归零即焚"回收（conn_probe_state 露出标记给清扫拍判）。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn overflow_channel_handle_is_never_handed_out_again() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip_normal = "9.9.2.1";
    let mut normal = mk_up(ip_normal, 1).await;
    normal.owner = Some("raw.githubusercontent.com".to_string());
    let normal_id = normal.id;
    store_h2(ip_normal, normal);
    // 溢出通道：与正编同 IP（同 IP 溢出例外），标了 overflow。
    let mut temp = mk_up(ip_normal, 1).await;
    temp.owner = Some("raw.githubusercontent.com".to_string());
    temp.overflow = true;
    let temp_id = temp.id;
    store_h2(ip_normal, temp);
    // 第二条溢出拒收：每 IP 至多一条溢出，关掉新的、递回正编。
    let mut temp2 = mk_up(ip_normal, 1).await;
    temp2.owner = Some("raw.githubusercontent.com".to_string());
    temp2.overflow = true;
    let temp2_id = temp2.id;
    let back = store_h2(ip_normal, temp2);
    assert_ne!(back.id, temp2_id, "第二条溢出必须拒收");
    assert_eq!(back.id, normal_id, "拒收时递回正编通道");

    let ips = vec![ip_normal.to_string()];
    // pick 永远只给正常通道：溢出通道对后来者不存在。
    for _ in 0..3 {
        assert_eq!(
            cached_h2_in(&ips, None).expect("正常通道应在池").id,
            normal_id,
            "pick 不得外发溢出通道句柄"
        );
    }
    // 通道清单同理：只列正常的，摊段调用方拿不到溢出品。
    let listed = channels_for(&ips);
    assert_eq!(listed.len(), 1, "清单只含非溢出通道");
    assert_eq!(listed[0].id, normal_id);
    // 驱动看到的标记就位：在途流归零时清扫拍会焚毁它。
    let (_, inflight, overflow) = conn_probe_state(ip_normal, temp_id);
    assert!(overflow, "溢出标记应跟着句柄进池");
    assert_eq!(inflight, 0, "无在途流 = 下一个清扫拍回收");
    // 正常通道不带标记。
    assert!(!conn_probe_state(ip_normal, normal_id).2);
    let _ = lock(conn_pool()).remove(ip_normal);
}

/// get_or_build 步骤①：池里有闲通道就直接骑（fresh=false），绝不拨号。
/// 建造路径要真网，单测不碰；这里的断言是"取到池里那条且来源不是新拨"。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn get_or_build_rides_pool_channel_without_dialing() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    // 必须落在路由表候选里，pick 才看得见；表外 IP 会被当成池空去真拨号。
    let ip = crate::pool::route::dial_targets("github.com")
        .expect("种子表必有 github.com 行")[0]
        .ip
        .clone();
    let mut up = mk_up(&ip, 1).await;
    up.owner = Some("github.com".to_string());
    let id = up.id;
    store_h2(&ip, up);
    let log: LogFn = Arc::new(|_| {});
    let (got, fresh) = crate::pool::get_or_build("github.com", None, "", &log)
        .await
        .expect("池里有通道应直接返回");
    assert_eq!(got.id, id, "应骑池里现成的那条");
    assert!(!fresh, "骑池不算新拨，失败记账走不罚分支");
    let _ = lock(conn_pool()).remove(&ip);
}

// 看护任务不再做保活与补拨（即用即建取代），旧的隧道打点与补拨节流
// 测试随之退役：连接死亡由请求结果发现，通道重建是下一个请求自己的事。
