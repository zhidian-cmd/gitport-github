use super::*;

#[test]
fn ca_generate_and_leaf_ctx() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let dir = std::env::temp_dir().join(format!("gitport_cert_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    assert!(!a.cert_der.is_empty());
    let c1 = a.leaf_ctx("github.com").unwrap();
    let c2 = a.leaf_ctx("github.com").unwrap();
    assert!(Arc::ptr_eq(&c1, &c2), "同一主机的上下文应缓存复用");
    assert!(
        a.leaf_ctx("unmanaged.example").is_err(),
        "受管域名之外不得签发证书"
    );
}

#[test]
fn tls_acceptor_ok() {
    let dir = std::env::temp_dir().join(format!("gitport_tls_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    let _acc = tls_acceptor_of(&a);
}

// 用例独占路由表与本地监听端口，串行锁必须跨 await 持有；生产路径不这么用。
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn mitm_handshake_roundtrip() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    // rustls 客户端 ↔ boring 服务端：独立实现互验，本地终结栈换血后的互操作钉子。
    let dir = std::env::temp_dir().join(format!("gitport_hs_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    let acc = tls_acceptor_of(&a);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let tls = tokio_boring::accept(&acc, stream).await.unwrap();
        assert_eq!(
            tls.ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice()),
            "客户端提供 h2/http1.1 时应选中 h2"
        );
    });

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(a.cert_der.clone()))
        .unwrap();
    let mut cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
    let name = rustls_pki_types::ServerName::try_from("github.com".to_string()).unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector.connect(name, stream).await.unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "rustls 客户端侧也应确认选中 h2"
    );
    drop(tls);
    srv.await.unwrap();
}

/// 非受管域 SNI：服务端在 servername 回调直接 fatal alert，客户端握手必须失败。
#[tokio::test(flavor = "multi_thread")]
async fn mitm_rejects_unmanaged_sni() {
    let dir = std::env::temp_dir().join(format!("gitport_mitm_neg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    let acc = tls_acceptor_of(&a);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio_boring::accept(&acc, stream).await
    });

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(a.cert_der.clone()))
        .unwrap();
    let cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
    let name = rustls_pki_types::ServerName::try_from("unmanaged.example".to_string()).unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = connector.connect(name, stream).await;
    assert!(got.is_err(), "非受管域 SNI 不得握手成功");
    assert!(srv.await.unwrap().is_err(), "服务端应因拒签而握手失败");
}
