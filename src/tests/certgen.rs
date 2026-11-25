use super::*;

#[test]
fn ca_generate_and_leaf_ctx() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let dir = std::env::temp_dir().join(format!("gitport_cert_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir).unwrap();
    assert!(!a.cert_der.is_empty());
    let c1 = a.leaf_ctx("github.com").unwrap();
    let c2 = a.leaf_ctx("github.com").unwrap();
    assert!(Arc::ptr_eq(&c1, &c2), "同一主机的上下文应缓存复用");
    assert!(
        a.leaf_ctx("unmanaged.example").is_err(),
        "受管域名之外不得签发证书"
    );
}

/// 叶子缓存超限淘汰：清签发时刻最旧的一张，总量守在 LEAVES_CAP。
#[test]
fn leaf_cache_evicts_oldest_at_cap() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let dir = std::env::temp_dir().join(format!("gitport_leafcap_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir).unwrap();
    let ctx = a.leaf_ctx("github.com").unwrap();
    {
        // 直填 511 条把表顶到上限（github.com 占第 1 条），t0 伪造为最旧。
        let mut leaves = a.leaves.lock().unwrap();
        let now = SystemTime::now();
        for i in 0..LEAVES_CAP - 1 {
            let t = if i == 0 {
                now - std::time::Duration::from_secs(3600)
            } else {
                now
            };
            leaves.insert(format!("t{i}.githubusercontent.com"), (t, ctx.clone()));
        }
    }
    let fresh = a.leaf_ctx("api.github.com").unwrap();
    let leaves = a.leaves.lock().unwrap();
    assert_eq!(leaves.len(), LEAVES_CAP, "总量应守在上限");
    assert!(
        !leaves.contains_key("t0.githubusercontent.com"),
        "最旧的一张应被淘汰"
    );
    assert!(leaves.contains_key("api.github.com"), "新签的应已入缓存");
    assert!(
        Arc::ptr_eq(&fresh, &leaves.get("api.github.com").unwrap().1),
        "缓存返回的应是刚签的同一上下文"
    );
}

#[test]
fn tls_acceptor_ok() {
    let dir = std::env::temp_dir().join(format!("gitport_tls_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir).unwrap();
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
    let a = load_or_generate(&dir).unwrap();
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
    let a = load_or_generate(&dir).unwrap();
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

/// 首握手并发去重：20 个线程同时要同一域名的叶子证书，只能真签一次。
/// 这条不是逻辑推演——签发计数器是测试期真实累加的，多签一次就会读到 20。
#[test]
fn leaf_sign_once_under_concurrency() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::install_seed_routes();
    let dir = std::env::temp_dir().join(format!("gitport_signonce_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = load_or_generate(&dir).unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(20));
    let mut hs = Vec::new();
    for _ in 0..20 {
        let a2 = a.clone();
        let b = barrier.clone();
        hs.push(std::thread::spawn(move || {
            b.wait(); // 尽量让 20 个线程同一时刻撞进 leaf_ctx
            a2.leaf_ctx("github.com").unwrap()
        }));
    }
    let ctxs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let n = a
        .sign_count
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(n, 1, "20 个并发首握手只应签发一次，实际签了 {n} 次");
    for c in &ctxs {
        assert!(Arc::ptr_eq(c, &ctxs[0]), "并发请求必须拿到同一份上下文");
    }
}

/// CA 私钥落盘后的 ACL：只应有当前用户与 SYSTEM，不能给 Everyone / Users / Authenticated Users。
/// 用 SID 判定而不是本地化组名，中英文 Windows 都成立。
#[test]
fn ca_key_acl_only_current_user_and_system() {
    let dir = std::env::temp_dir().join(format!("gitport_acl_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    load_or_generate(&dir).unwrap();
    let key = dir.join("ca.key");
    assert!(key.exists(), "ca.key 应已写入");
    assert!(
        std::fs::read_to_string(&key).unwrap().contains("PRIVATE KEY"),
        "私钥内容应完整写入"
    );

    let script = format!(
        "(Get-Acl -LiteralPath '{}').Access | ForEach-Object {{ $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }}",
        key.display()
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .expect("调用 powershell 读 ACL 失败");
    let sids = String::from_utf8_lossy(&out.stdout);
    for bad in ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"] {
        assert!(
            !sids.contains(bad),
            "ca.key 不应授予 {bad}（Everyone/Authenticated Users/Users）: {sids}"
        );
    }
    assert!(sids.contains("S-1-5-18"), "应保留 SYSTEM: {sids}");
}
