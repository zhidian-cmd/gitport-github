use super::*;

#[test]
fn ca_generate_and_leaf() {
    let dir = std::env::temp_dir().join(format!("gitport_cert_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    assert!(!a.cert_der.is_empty());
    let leaf = a.leaf("github.com").unwrap();
    assert_eq!(leaf.cert.len(), 2, "叶子应附带 CA 链");
    let leaf2 = a.leaf("github.com").unwrap();
    assert!(std::ptr::eq(Arc::as_ptr(&leaf), Arc::as_ptr(&leaf2)) || leaf.cert == leaf2.cert);
}

#[test]
fn tls_config_ok() {
    let dir = std::env::temp_dir().join(format!("gitport_tls_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    let _cfg = tls_config_of(&a);
}

#[tokio::test(flavor = "multi_thread")]
async fn mitm_handshake_roundtrip() {
    let dir = std::env::temp_dir().join(format!("gitport_hs_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir, None).unwrap();
    let cfg = tls_config_of(&a);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(cfg)
            .accept(stream)
            .await
            .unwrap();
        let _ = tls;
    });

    let roots = crate::pool::dial::system_roots();
    let mut roots = (*roots).clone();
    roots
        .add(rustls_pki_types::CertificateDer::from(a.cert_der.clone()))
        .unwrap();
    let cc = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
    let name = rustls_pki_types::ServerName::try_from("github.com".to_string()).unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector.connect(name, stream).await.unwrap();
    let _ = tls;
    srv.await.unwrap();
}
