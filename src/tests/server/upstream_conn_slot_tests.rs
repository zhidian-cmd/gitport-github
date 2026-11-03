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
        send,
        ping: None,
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn slot_filter_pins_search_to_primary() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let ip = "9.9.9.1";
    store_h2(ip, mk_up(ip, 2).await); // 第二通道先入池
    store_h2(ip, mk_up(ip, 1).await); // 主通道后入
    for _ in 0..4 {
        let up = cached_h2_in(&[ip.to_string()], Some(1)).expect("主通道应在池");
        assert_eq!(up.slot, 1, "Some(1) 永远拿主通道,轮转计数不动");
    }
    // 主通道被摘后:Some(1) -> None(交拨号按主键重建),绝不误用第二通道
    drop_h2_id(ip, {
        let g = lock(conn_pool());
        g.get(ip)
            .unwrap()
            .conns
            .iter()
            .find(|c| c.up.slot == 1)
            .unwrap()
            .up
            .id
    });
    assert!(
        cached_h2_in(&[ip.to_string()], Some(1)).is_none(),
        "主通道被摘后应回 None 走重建,不得回落第二通道"
    );
    // None = 原语义:池里剩下的第二通道照常服务
    let up = cached_h2_in(&[ip.to_string()], None).expect("无过滤应命中");
    assert_eq!(up.slot, 2);
    let _ = lock(conn_pool()).remove(ip);
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
    align_explore_to_sampled_phase();
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
    align_explore_to_sampled_phase();
    for _ in 0..3 {
        let up = cached_h2_in(&ips, None).expect("应有连接");
        assert_eq!(up.ip, fast_ip, "有样本后 EWMA 快者恒胜");
    }
    let _ = lock(conn_pool()).remove(slow_ip);
    let _ = lock(conn_pool()).remove(fast_ip);
}

/// 全局"正在拨"登记：认领期间别的 host 能看到，候选组有交集即命中；释放后立刻可拨。
#[test]
fn inflight_registry_claim_blocks_and_release_frees() {
    let ips = vec!["198.51.100.7".to_string()];
    assert!(!inflight_busy(&ips));
    let guard = DialingGuard::claim(&ips);
    assert!(inflight_busy(&ips), "认领后应显示在拨");
    assert!(
        inflight_busy(&["203.0.113.9".to_string(), "198.51.100.7".to_string()]),
        "候选组有交集即算命中"
    );
    drop(guard);
    assert!(!inflight_busy(&ips), "释放后应立刻可拨");
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
            let up = match h2_from_dialed("probe", dialed, &ip, "probe", 1, &log).await {
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
            let up = match h2_from_dialed(host, dialed, ip, "probe", 1, &log).await {
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
    let up = h2_from_dialed("api.mcp.github.com", dialed, ip, "probe", 1, &log)
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
        let up = match h2_from_dialed("baseline", dialed, ip, "probe", 1, &log).await {
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
