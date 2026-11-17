use super::*;

#[test]
fn host_only_strips_port() {
    assert_eq!(host_only("github.com:443"), "github.com");
    assert_eq!(host_only("[::1]:443"), "[::1]");
    assert_eq!(host_only("github.com"), "github.com");
}

#[test]
fn split_target_parses_and_defaults() {
    assert_eq!(
        split_target("github.com:443", 443),
        ("github.com".into(), 443)
    );
    assert_eq!(split_target("github.com", 80), ("github.com".into(), 80));
    assert_eq!(split_target("[::1]:8443", 443), ("[::1]".into(), 8443));
    assert_eq!(split_target("[::1]", 443), ("[::1]".into(), 443));
    assert_eq!(
        split_target("github.com:notaport", 80),
        ("github.com:notaport".into(), 80)
    );
}

/// 明文 HTTP 分发：与头同包到达的请求体必须原样续传（曾把体当头转发致真体丢失）；受管域名+种子表走假上游，非受管目标被开放代理闸 502。
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn plain_http_post_body_forwarded_intact() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // 自建路由表：github.com → 127.0.0.1（串发池 tls_handshake=false 纯 TCP，拨号端口指假上游）；种子表是真 GitHub IP 拨不进本进程。
    let dir = std::env::temp_dir().join(format!("gitport_srv_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("routes.json"),
        r#"{"ips":[{"ip":"127.0.0.1","sni":"a.example","hosts":["github.com"]}], "hosts": {}}"#,
    )
    .unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);
    // 假上游：读满 头 + Content-Length 体，校验体原样、头无混入，然后回 200。
    let up_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up_ln.local_addr().unwrap().port();
    crate::pool::dial::set_dial_port(up_port);
    let up_task = tokio::spawn(async move {
        let (mut sock, _) = up_ln.accept().await.unwrap();
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let (head_end, body_len) = loop {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head_text = String::from_utf8_lossy(&raw[..pos]);
                let cl = head_text
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if !k.trim().eq_ignore_ascii_case("content-length") {
                            return None;
                        }
                        v.trim().parse::<usize>().ok()
                    })
                    .unwrap_or(0);
                if raw.len() >= pos + 4 + cl {
                    break (pos, cl);
                }
            }
            let n = tokio::time::timeout_at(deadline, sock.read(&mut chunk))
                .await
                .expect("上游读超时: 请求体未被转发")
                .unwrap();
            assert!(n > 0, "上游连接被提前关闭");
            raw.extend_from_slice(&chunk[..n]);
        };
        let head_text = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let body = &raw[head_end + 4..head_end + 4 + body_len];
        assert_eq!(body, b"hello", "体应原样出现在头块之后");
        assert!(!head_text.contains("hello"), "体被当头转发: {head_text}");
        assert_eq!(
            head_text.matches("Content-Length: 5").count(),
            1,
            "Content-Length 不应重复: {head_text}"
        );
        // 逐跳头不过上游：客户端发来的 connection 必须在转发前剥掉（connection 白名单里的逐跳头与 proxy-*/host 一并在此兜底）。
        assert!(
            !head_text.to_lowercase().contains("connection:"),
            "connection 逐跳头泄漏到上游: {head_text}"
        );
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });

    // 代理本体：起在随机端口，直接复用 serve()（不经 start_proxy_with 免端口腾挪）。
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = ln.local_addr().unwrap().port();
    let log: LogFn = Arc::new(|_: &str| {});
    let srv = Arc::new(ProxyServer {
        log,
        authority: None,
    });
    let ctx = CancellationToken::new();
    let serve_task = tokio::spawn(serve(srv, ln, ctx.clone()));

    let mut cli = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    // 一次 write：头体同包（当年被吞的形态）；明文代理用绝对 URI，并带 Connection/Keep-Alive 供假上游断言逐跳头被剥。目标受管域+443 进串发池。
    let req = format!(
        "POST http://github.com:443/x HTTP/1.1\r\nHost: github.com\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"
    );
    cli.write_all(req.as_bytes()).await.unwrap();

    let mut resp: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !(resp.windows(4).any(|w| w == b"\r\n\r\n") && resp.ends_with(b"ok")) {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline, cli.read(&mut chunk))
            .await
            .expect("客户端读超时: 未收到响应")
            .unwrap();
        assert!(n > 0, "代理提前关闭客户端连接");
        resp.extend_from_slice(&chunk[..n]);
    }
    assert!(resp.starts_with(b"HTTP/1.1 200 OK"));

    crate::pool::dial::set_dial_port(0); // 复位，别影响别的测试
    up_task.await.unwrap();
    ctx.cancel();
    let _ = serve_task.await;
}

/// 开放代理闸：非受管目标一律 502——防借本机代理扫内网、读云元数据、摸自家管理端口。
#[tokio::test]
async fn unmanaged_targets_are_rejected() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = ln.local_addr().unwrap().port();
    // 日志要留底：拨不通时删闸也回 502（TCP 层失败同款），只有非受管域名拒绝日志能区分被闸拦还是拨不通。
    let logs: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = logs.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    let srv = Arc::new(ProxyServer {
        log,
        authority: None,
    });
    let ctx = CancellationToken::new();
    let serve_task = tokio::spawn(serve(srv, ln, ctx.clone()));

    let mut cli = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    // CONNECT 到云元数据地址：不得建隧道。
    cli.write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
        .await
        .unwrap();
    let mut resp: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline, cli.read(&mut chunk))
            .await
            .expect("读超时: 闸未回包")
            .unwrap();
        assert!(n > 0, "连接被静默关闭");
        resp.extend_from_slice(&chunk[..n]);
    }
    assert!(
        resp.starts_with(b"HTTP/1.1 502"),
        "非受管 CONNECT 应 502: {}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        !resp
            .windows(b"200 Connection".len())
            .any(|w| w == b"200 Connection"),
        "不得回隧道建立成功: {}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        logs
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.contains("非受管域名")),
        "闸必须留下「非受管域名」拒绝日志——is_managed 闸被删时这里要红"
    );

    // 明文 HTTP 打内网地址：同样 502。
    let mut cli2 = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    cli2.write_all(b"GET http://10.0.0.5:8080/ HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n")
        .await
        .unwrap();
    let mut resp2: Vec<u8> = Vec::new();
    while !resp2.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline, cli2.read(&mut chunk))
            .await
            .expect("读超时: 明文闸未回包")
            .unwrap();
        assert!(n > 0, "连接被静默关闭");
        resp2.extend_from_slice(&chunk[..n]);
    }
    assert!(
        resp2.starts_with(b"HTTP/1.1 502"),
        "非受管明文目标应 502: {}",
        String::from_utf8_lossy(&resp2)
    );

    ctx.cancel();
    let _ = serve_task.await;
}

/// 兜底腿地址保险：hosts 劫持把受管域名指进环回/私网/链路本地时必须拒拨。
#[test]
fn bogon_filter_blocks_loopback_and_private_ranges() {
    let p = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    for bad in [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.9",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fd00::9",
        "ff02::1",
    ] {
        assert!(super::bogon_addr(p(bad)), "{bad} 必须判为保留地址");
    }
    // v4-mapped 的内网地址折回 v4 判，不能因为"是 v6 形状"漏过
    assert!(super::bogon_addr(p("::ffff:127.0.0.1")));
    assert!(super::bogon_addr(p("::ffff:10.0.0.5")));
    for ok in ["140.82.121.3", "185.199.110.133", "2606:50c0:8000::153"] {
        assert!(!super::bogon_addr(p(ok)), "{ok} 是合法 GitHub 边缘地址");
    }
}

/// 地址保险补段：CGNAT / 0/8 / 组播 / 240/4 / IETF 保留段 / 内嵌 v4 的 v6；只靠 is_private() 会漏企业/运营商内网段。
#[test]
fn bogon_filter_blocks_cgnat_and_reserved_ranges() {
    let p = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    for bad in [
        "100.64.0.1",
        "100.127.255.254", // 100.64.0.0/10 CGNAT
        "0.0.0.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "192.0.0.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.255.1",
        "::7f00:1",                    // IPv4-compatible 内嵌 127.0.0.1
        "2002:0a00:0001::1",           // 6to4 内嵌 10.0.0.1
        "2001:0:808:808:0:0:80ff:fffe", // Teredo 客户端内嵌 127.0.0.1
    ] {
        assert!(super::bogon_addr(p(bad)), "{bad} 必须判为内网/保留地址");
    }
    for ok in [
        "8.8.8.8",
        "140.82.121.3",
        "185.199.110.133",
        "2606:50c0:8000::153",
    ] {
        assert!(!super::bogon_addr(p(ok)), "{ok} 是合法公网地址");
    }
}

/// 非受管域名的 443 不再一刀切：走到系统 DNS 兜底腿后由地址保险拒拨本机；删掉 && port != 443 会退回闸处拒绝日志，删掉 bogon 过滤会连上本机。
#[tokio::test]
async fn unmanaged_443_reaches_dns_fallback_and_bogon() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let proxy_port = ln.local_addr().unwrap().port();
    let logs: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = logs.clone();
    let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
    let srv = Arc::new(ProxyServer {
        log,
        authority: None,
    });
    let ctx = CancellationToken::new();
    let serve_task = tokio::spawn(serve(srv, ln, ctx.clone()));

    let mut cli = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    cli.write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let mut resp: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline, cli.read(&mut chunk))
            .await
            .expect("读超时: 兜底腿未回包")
            .unwrap();
        assert!(n > 0, "连接被静默关闭");
        resp.extend_from_slice(&chunk[..n]);
    }
    assert!(
        resp.starts_with(b"HTTP/1.1 502"),
        "本机 443 必须被地址保险拒拨: {}",
        String::from_utf8_lossy(&resp)
    );
    let snapshot = logs.lock().unwrap().clone();
    assert!(
        !snapshot.iter().any(|m| m.contains("非受管域名且非 443")),
        "443 不该被闸拦(放行条件被删?): {snapshot:?}"
    );
    assert!(
        snapshot
            .iter()
            .any(|m| m.contains("解析到内网/保留地址")),
        "必须留下地址保险的拒绝原因(bogon 过滤被删?): {snapshot:?}"
    );
    ctx.cancel();
    let _ = serve_task.await;
}

/// 首字节判死后两路一起收：只 shutdown 写半部时客户端不关自己写半部会让 join! 永远 pending，task+TCP+fd 永久挂着。
#[tokio::test]
async fn first_byte_timeout_closes_both_directions() {
    let (mut client, mut relay_a) = tokio::io::duplex(4096);
    let (mut relay_b, upstream) = tokio::io::duplex(4096);
    // 客户端发一点数据后故意不关写半部；上游侧也保持连接但不发任何字节。
    let holder = tokio::spawn(async move {
        client.write_all(b"hello").await.unwrap();
        std::future::pending::<()>().await;
    });
    let hold_upstream = tokio::spawn(async move {
        let _keep = upstream;
        std::future::pending::<()>().await;
    });
    let (sent, recv) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        bidir_copy(
            &mut relay_a,
            &mut relay_b,
            Some(std::time::Duration::from_millis(120)),
            false,
            CancellationToken::new(),
        ),
    )
    .await
    .expect("首字节超时后 bidir_copy 必须返回，不能等另一路 EOF");
    assert_eq!(sent, 5, "客户端那 5 字节应在判死前转发出去");
    assert_eq!(recv, 0, "上游一个字节都没发");
    holder.abort();
    hold_upstream.abort();
}

/// 明文 HTTP 分块体：识别出来就走 501，不把块长度行当正文喂给上游。
#[test]
fn chunked_request_body_is_refused() {
    assert!(headers_have_chunked(
        b"Host: a\r\nTransfer-Encoding: chunked\r\n"
    ));
    assert!(headers_have_chunked(
        b"transfer-encoding: gzip, chunked\r\n"
    ));
    assert!(!headers_have_chunked(
        b"Content-Length: 5\r\nConnection: close\r\n"
    ));
    assert!(!headers_have_chunked(b""));
}

/// 分片门槛：TLS 握手(0x16)且够长才拆；SSH/HTTP/过短流不拆。拆分形态：2~3 段、无缝覆盖全量、首刀 1..=16。
#[test]
fn hello_split_ranges_gate() {
    let tls_long: Vec<u8> = std::iter::once(0x16u8)
        .chain(std::iter::repeat_n(0u8, 300))
        .collect();
    let ranges = hello_split_ranges(&tls_long).expect("TLS 握手应拆");
    assert!(
        ranges.len() == 2 || ranges.len() == 3,
        "段数应在 2~3: {ranges:?}"
    );
    assert_eq!(ranges.first().unwrap().start, 0);
    assert!(!ranges.first().unwrap().is_empty());
    assert!(ranges.first().unwrap().len() <= config::HELLO_SPLIT_FIRST_MAX);
    let mut cursor = 0usize;
    for r in &ranges {
        assert_eq!(r.start, cursor, "切点应无缝衔接: {ranges:?}");
        cursor = r.end;
    }
    assert_eq!(cursor, tls_long.len(), "应覆盖整个首段: {ranges:?}");

    let tls_short = vec![0x16u8, 0x03, 0x01];
    assert!(hello_split_ranges(&tls_short).is_none(), "过短流不拆");

    let ssh: Vec<u8> = b"SSH-2.0-OpenSSH".to_vec();
    assert!(hello_split_ranges(&ssh).is_none(), "非 TLS 流不拆");

    assert!(hello_split_ranges(&[]).is_none(), "空流不拆");
}

/// 随机化：同一载荷多次拆分，首刀位置必须出现变化（防退化成固定形态被签名）。
#[test]
fn hello_split_randomizes_cuts() {
    let tls_long: Vec<u8> = std::iter::once(0x16u8)
        .chain(std::iter::repeat_n(0u8, 600))
        .collect();
    let mut firsts = std::collections::HashSet::new();
    let mut seg_counts = std::collections::HashSet::new();
    for _ in 0..40 {
        let ranges = hello_split_ranges(&tls_long).expect("应拆");
        firsts.insert(ranges[0].len());
        seg_counts.insert(ranges.len());
    }
    assert!(
        firsts.len() >= 3,
        "40 次拆分首刀位置应多变(随机化失效?): {firsts:?}"
    );
    assert!(seg_counts.len() >= 2, "段数应在 2~3 间变化: {seg_counts:?}");
}

/// 首包分片不丢字节：TLS 握手载荷经分片转发后必须完整到达对端。
#[tokio::test]
async fn tunnel_hello_split_relays_all_bytes() {
    let (mut client, mut relay_in) = tokio::io::duplex(4096);
    let (mut relay_out, mut upstream) = tokio::io::duplex(4096);
    let payload: Vec<u8> = std::iter::once(0x16u8)
        .chain((0u8..=255).cycle().take(400))
        .collect();

    let writer = {
        let payload = payload.clone();
        tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            drop(client); // EOF：让拷贝循环收尾
        })
    };
    let copier = tokio::spawn(async move {
        copy_with_first_byte_timeout(
            &mut relay_in,
            &mut relay_out,
            None,
            true,
            CancellationToken::new(),
        )
        .await
    });

    writer.await.unwrap();
    let sent = copier.await.unwrap();
    assert_eq!(sent, payload.len() as u64, "转发字节数应与载荷一致");

    let mut received = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        upstream.read_to_end(&mut received),
    )
    .await
    .expect("读超时：分片转发未收尾")
    .unwrap();
    assert_eq!(received, payload, "分片不得丢改字节");
}
