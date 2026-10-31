use super::*;
use boring::pkey::PKey;
use boring::ssl::SslAcceptor;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
fn tmp_seq() -> usize {
    TMP_SEQ.fetch_add(1, Ordering::SeqCst)
}

const OFFICIAL_HOST: &str = "foobar.com";

fn boring_test_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("BORING_TEST_DIR") {
        let p = std::path::PathBuf::from(d);
        return (p.join("cert.pem").exists()).then_some(p);
    }
    let home = std::env::var("CARGO_HOME")
        .or_else(|_| std::env::var("USERPROFILE").map(|h| format!("{h}\\.cargo")))
        .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.cargo")))
        .ok()?;
    let src = std::path::Path::new(&home).join("registry").join("src");
    for pair in std::fs::read_dir(src).ok()?.flatten() {
        for ver in std::fs::read_dir(pair.path()).ok()?.flatten() {
            if ver.file_name().to_string_lossy().starts_with("boring-") {
                let test = ver.path().join("test");
                if test.join("cert.pem").exists() {
                    return Some(test);
                }
            }
        }
    }
    None
}

fn official_material() -> Option<(String, String, String)> {
    let dir = boring_test_dir()?;
    let cert = std::fs::read_to_string(dir.join("cert.pem")).ok()?;
    let root = std::fs::read_to_string(dir.join("root-ca.pem")).ok()?;
    let key = std::fs::read_to_string(dir.join("key.pem")).ok()?;
    Some((root.clone(), format!("{cert}{root}"), key))
}

fn acceptor_for(chain_pem: &str, key_pem: &str) -> SslAcceptor {
    let dir = std::env::temp_dir();
    let chain_path = dir.join(format!(
        "gitport_test_chain_{}_{}.pem",
        std::process::id(),
        tmp_seq()
    ));
    std::fs::write(&chain_path, chain_pem).unwrap();
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_certificate_chain_file(&chain_path).unwrap();
    b.set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
        .unwrap();
    b.set_alpn_select_callback(|_, _| Ok(b"h2")); // 就地修改，返回 ()
    b.build()
}

#[derive(Debug, PartialEq)]
struct ClientHelloObs {
    sni: Option<String>,
    grease: bool,
}

fn analyze(buf: &[u8]) -> ClientHelloObs {
    let text = String::from_utf8_lossy(buf);
    let mut sni = None;
    for d in ["github.com", "baidu.com", OFFICIAL_HOST] {
        if text.contains(d) {
            sni = Some(d.to_string());
            break;
        }
    }
    let mut grease = false;
    for i in 0..buf.len().saturating_sub(1) {
        let v = u16::from_be_bytes([buf[i], buf[i + 1]]);
        if v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff) {
            grease = true;
            break;
        }
    }
    ClientHelloObs { sni, grease }
}

async fn handshake_probe(
    host: &str,
    mode: &str,
    material: &(String, String, String),
) -> std::io::Result<ClientHelloObs> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (ca_pem, chain_pem, key_pem) = material.clone();
    let server: tokio::task::JoinHandle<std::io::Result<Option<ClientHelloObs>>> =
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut buf = [0u8; 4096];
            let n = tcp.peek(&mut buf).await?;
            let obs = analyze(&buf[..n]);
            let acceptor = acceptor_for(&chain_pem, &key_pem);
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(mut stream) => {
                    stream.write_all(b"pong").await?;
                    Ok(Some(obs))
                }
                Err(e) => {
                    eprintln!("服务端 accept 失败: {e}");
                    Ok(None)
                }
            }
        });
    let tcp = TcpStream::connect(addr).await?;
    let mut ssl = client_ssl(host, mode, Some(&ca_pem))?;
    ssl.param_mut().set_time(1_577_836_800); // 2020-01-01 00:00:00 UTC
    let mut tls = tokio_boring::SslStreamBuilder::new(ssl, tcp)
        .connect()
        .await
        .map_err(|e| {
            let detail = format!("客户端握手失败: {e}");
            eprintln!("{detail}");
            io_err(detail)
        })?;
    let mut out = [0u8; 4];
    tls.read_exact(&mut out).await?;
    assert_eq!(&out, b"pong");
    let obs = server.await.map_err(|e| io_err(e.to_string()))??;
    obs.ok_or_else(|| io_err("服务端握手失败".into()))
}

#[tokio::test]
async fn real_mode_sends_host_sni_with_grease() {
    let Some(material) = official_material() else {
        eprintln!("跳过: 未找到 boring 测试证书目录(编译过 boring 后重试, 或设 BORING_TEST_DIR)");
        return;
    };
    let obs = handshake_probe(OFFICIAL_HOST, OFFICIAL_HOST, &material)
        .await
        .unwrap();
    assert_eq!(obs.sni.as_deref(), Some(OFFICIAL_HOST));
    assert!(obs.grease, "Chrome 指纹(GREASE)应存在: {obs:?}");
}

#[tokio::test]
async fn fake_mode_sends_fake_sni_but_verifies_host() {
    let Some(material) = official_material() else {
        eprintln!("跳过: 未找到 boring 测试证书目录(编译过 boring 后重试, 或设 BORING_TEST_DIR)");
        return;
    };
    let obs = handshake_probe(OFFICIAL_HOST, "baidu.com", &material)
        .await
        .unwrap();
    assert_eq!(obs.sni.as_deref(), Some("baidu.com"));
    assert!(obs.grease);
}

#[tokio::test]
#[ignore = "真实网络直连 GitHub，仅诊断用，非 CI 稳定项"]
async fn real_network_boring_dial_probe() {
    let host = "github.com";
    for (mode, ip) in [("fake:baidu.com", "140.82.114.4"), ("real", "140.82.112.3")] {
        match tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let tcp = TcpStream::connect((ip, 443))
                .await
                .map_err(|e| format!("TCP 连接失败: {e}"))?;
            let ssl = client_ssl(host, mode, None).map_err(|e| format!("client_ssl: {e}"))?;
            tokio_boring::SslStreamBuilder::new(ssl, tcp)
                .connect()
                .await
                .map_err(|e| format!("TLS 握手失败: {e}"))
        })
        .await
        {
            Ok(Ok(tls)) => {
                eprintln!(
                    "[{mode}] {ip} 拨号成功 h2={:?}",
                    tls.ssl().selected_alpn_protocol()
                );
            }
            Ok(Err(e)) => eprintln!("[{mode}] {ip} 失败: {e}"),
            Err(_) => eprintln!("[{mode}] {ip} 超时"),
        }
    }
}

#[tokio::test]
async fn fake_mode_rejects_wrong_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let Some(material) = official_material() else {
        eprintln!("跳过: 未找到 boring 测试证书目录(编译过 boring 后重试, 或设 BORING_TEST_DIR)");
        return;
    };
    let (ca_pem, chain_pem, key_pem) = material;
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let acceptor = acceptor_for(&chain_pem, &key_pem);
        let _ = tokio_boring::accept(&acceptor, tcp).await;
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut ssl = client_ssl("wrong.example", "fake:baidu.com", Some(&ca_pem)).unwrap();
    ssl.param_mut().set_time(1_577_836_800); // 同上：官方材料过期，回拨验证时间
    let r = tokio_boring::SslStreamBuilder::new(ssl, tcp)
        .connect()
        .await;
    assert!(
        r.is_err(),
        "校验名 wrong.example 与证书 CN=foobar.com 不匹配应失败"
    );
    let _ = server.await;
}

/// 会话恢复：第一次拨号完整握手并把 ticket 存入缓存，第二次注入后必须命中恢复。
/// SNI 用唯一键防与其他测试的缓存竞争；acceptor 复用同一个（ticket key 随 SSL_CTX
/// 随机生成，换 acceptor 旧 ticket 解不开会回落完整握手，测试就失去意义）。
#[tokio::test]
async fn session_resumed_on_second_dial() {
    let Some(material) = official_material() else {
        eprintln!("跳过: 未找到 boring 测试证书目录(编译过 boring 后重试, 或设 BORING_TEST_DIR)");
        return;
    };
    let (ca_pem, chain_pem, key_pem) = material;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = acceptor_for(&chain_pem, &key_pem);
    let server = tokio::spawn(async move {
        let mut reused = Vec::new();
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = tokio_boring::accept(&acceptor, tcp).await.unwrap();
            reused.push(s.ssl().session_reused());
            s.write_all(b"pong").await.unwrap();
        }
        reused
    });

    let sni = "sess-resume-test"; // 独立缓存键；校验名恒为 foobar.com 不受 SNI 影响
    let first = {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ssl = client_ssl(OFFICIAL_HOST, sni, Some(&ca_pem)).unwrap();
        ssl.param_mut().set_time(1_577_836_800);
        let mut tls = tokio_boring::SslStreamBuilder::new(ssl, tcp)
            .connect()
            .await
            .unwrap();
        let mut pong = [0u8; 4];
        tls.read_exact(&mut pong).await.unwrap(); // 读应用数据顺带解析 NewSessionTicket → 入缓存
        tls
    };
    assert!(
        !first.ssl().session_reused(),
        "首拨没有缓存可注入，必须是完整握手"
    );
    assert!(
        session_cache()
            .lock()
            .unwrap()
            .contains_key(sni),
        "NewSessionTicket 回调应已把 ticket 写入缓存"
    );

    let second = {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ssl = client_ssl(OFFICIAL_HOST, sni, Some(&ca_pem)).unwrap();
        ssl.param_mut().set_time(1_577_836_800);
        apply_cached_session(&mut ssl, sni);
        let mut tls = tokio_boring::SslStreamBuilder::new(ssl, tcp)
            .connect()
            .await
            .unwrap();
        let mut pong = [0u8; 4];
        tls.read_exact(&mut pong).await.unwrap();
        tls
    };
    assert!(
        second.ssl().session_reused(),
        "第二次拨号注入 ticket 后应走 PSK 恢复"
    );
    assert_eq!(server.await.unwrap(), [false, true], "服务端视角同判定");
}
