use super::*;

#[test]
fn host_only_strips_port() {
    assert_eq!(host_only("github.com:443"), "github.com");
    assert_eq!(host_only("[::1]:443"), "[::1]");
    assert_eq!(host_only("github.com"), "github.com");
}

#[test]
fn split_target_parses_and_defaults() {
    assert_eq!(split_target("github.com:443", 443), ("github.com".into(), 443));
    assert_eq!(split_target("github.com", 80), ("github.com".into(), 80));
    assert_eq!(split_target("[::1]:8443", 443), ("[::1]".into(), 8443));
    assert_eq!(split_target("[::1]", 443), ("[::1]".into(), 443));
    assert_eq!(
        split_target("github.com:notaport", 80),
        ("github.com:notaport".into(), 80)
    );
}

/// 明文 HTTP 分发：与头同包到达的请求体必须原样续传（曾把体当头转发、真体丢失）。
/// 127.0.0.1 非池域名走系统直连腿，恰好落在本进程起的假上游上，全程无外网。
#[tokio::test]
async fn plain_http_post_body_forwarded_intact() {
    // 假上游：读满 头 + Content-Length 体，校验体原样、头无混入，然后回 200。
    let up_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up_ln.local_addr().unwrap().port();
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
        // 逐跳头不过上游：客户端发来的 connection 必须在转发前剥掉
        // （connection 白名单里的逐跳头与 proxy-*/host 一并在此兜底）。
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
    // 一次 write：头与体同包到达（正是当年被吞的形态）；明文走代理必须绝对 URI。
    // 顺带带 Connection/Keep-Alive 逐跳头：假上游断言它们被剥除（曾原样泄漏，
    // 上游收完即关导致代理转发语义被逐跳头带偏）。
    let req = format!(
        "POST http://127.0.0.1:{up_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"
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

    up_task.await.unwrap();
    ctx.cancel();
    let _ = serve_task.await;
}

/// 明文 HTTP 分块体：识别出来就走 501，不把块长度行当正文喂给上游。
#[test]
fn chunked_request_body_is_refused() {
    assert!(headers_have_chunked(
        b"Host: a\r\nTransfer-Encoding: chunked\r\n"
    ));
    assert!(headers_have_chunked(b"transfer-encoding: gzip, chunked\r\n"));
    assert!(!headers_have_chunked(
        b"Content-Length: 5\r\nConnection: close\r\n"
    ));
    assert!(!headers_have_chunked(b""));
}

/// 分片门槛：TLS 握手(0x16)且够长才拆；SSH/HTTP/过短流不拆。
/// 拆分形态：2~3 段、无缝覆盖全量、首刀 1..=16。
#[test]
fn hello_split_ranges_gate() {
    let tls_long: Vec<u8> = std::iter::once(0x16u8)
        .chain(std::iter::repeat_n(0u8, 300))
        .collect();
    let ranges = hello_split_ranges(&tls_long).expect("TLS 握手应拆");
    assert!(ranges.len() == 2 || ranges.len() == 3, "段数应在 2~3: {ranges:?}");
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
    assert!(
        seg_counts.len() >= 2,
        "段数应在 2~3 间变化: {seg_counts:?}"
    );
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
        copy_with_first_byte_timeout(&mut relay_in, &mut relay_out, None, true).await
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
