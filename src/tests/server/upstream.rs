use super::*;

/// gzip;q=0 是明确拒绝：别再把压缩体塞给手写客户端(浏览器不受影响)。
#[test]
fn accepts_gzip_respects_explicit_reject() {
    let mk = |ae: &str| {
        hyper::Request::builder()
            .header("accept-encoding", ae)
            .body(())
            .unwrap()
    };
    assert!(accepts_gzip(&mk("gzip, deflate")));
    assert!(accepts_gzip(&mk("GZIP")));
    assert!(accepts_gzip(&mk("br, gzip;q=1")));
    assert!(!accepts_gzip(&mk("gzip;q=0")));
    assert!(!accepts_gzip(&mk("br")));
    // 分号/等号两侧的空白合法(HTTP OWS)，照样是明确拒绝
    assert!(!accepts_gzip(&mk("gzip; q=0")));
    assert!(!accepts_gzip(&mk("gzip ; q=0")));
    assert!(!accepts_gzip(&mk("br, gzip;q=0")));
}

/// 上行泵（git push 的请求体通道）：2MB 体必须一字节不差送到对端。
/// 这条路径此前没有任何测试——窗口/背压改错不会让别的测试变红，只会让 push 卡住。
#[tokio::test]
async fn h2_body_pump_delivers_every_byte() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    // 假上游：h2 服务端，收满请求体后把字节数写回响应体。
    let srv = tokio::spawn(async move {
        let (sock, _) = ln.accept().await.unwrap();
        let svc = hyper::service::service_fn(
            |req: hyper::Request<hyper::body::Incoming>| async move {
                let n = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes().len())
                    .unwrap_or(0);
                Ok::<_, std::convert::Infallible>(hyper::Response::new(full_body(
                    Bytes::from(n.to_string()),
                )))
            },
        );
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(sock), svc)
            .await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (send, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut send = send.ready().await.unwrap();
    let head = http::Request::builder()
        .method("POST")
        .uri("https://example.test/upload")
        .body(())
        .unwrap();
    let (resp_fut, stream) = send.send_request(head, false).unwrap();

    let len = 2 * 1024 * 1024;
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let body = full_body(Bytes::from(payload));
    let log: LogFn = Arc::new(|_: &str| {});
    let pump = h2_spawn_pump(stream, body, log);

    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), resp_fut)
        .await
        .expect("10s 内上游没收到完整请求体（泵卡住了）")
        .unwrap();
    let mut recv = resp.into_body();
    let mut echoed = Vec::new();
    while let Some(chunk) = recv.data().await {
        echoed.extend_from_slice(&chunk.unwrap());
    }
    pump.await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&echoed),
        len.to_string(),
        "上游收到的字节数应与发送量一致"
    );
    srv.abort();
}

#[test]
fn forced_gzip_gated_on_client_accept() {
    let req = hyper::Request::builder()
        .uri("https://github.com/a")
        .header("accept-encoding", "gzip, deflate, br")
        .body(())
        .unwrap();
    let out = upstream_request(&req, "github.com").unwrap();
    assert_eq!(
        out.headers().get("accept-encoding").unwrap(),
        "gzip",
        "声明过 gzip 的客户端应被强制 gzip"
    );

    let req2 = hyper::Request::builder()
        .uri("https://github.com/a")
        .body(())
        .unwrap();
    let out2 = upstream_request(&req2, "github.com").unwrap();
    assert!(
        out2.headers().get("accept-encoding").is_none(),
        "未声明的客户端应回身份编码"
    );

    let req3 = hyper::Request::builder()
        .uri("https://raw.githubusercontent.com/a")
        .body(())
        .unwrap();
    let out3 = upstream_request(&req3, "raw.githubusercontent.com").unwrap();
    assert!(
        out3.headers().get("accept-encoding").is_none(),
        "非嗅探 host 不添加"
    );
}
