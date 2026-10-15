//! 握手执行器：串发表每个 (ip, sni 形态) 的实际拨号。
//! 2026-10-14 起流量形态恒为伪装（fake:x，如 baidu.com）；real 仅存留
//! 于诊断与测试（nosni 形态已随生产不可达删除, 旧表值由 serial_load 归一）。
//!
//! Go 版用 refraction-networking/utls 模拟 Chrome TLS 指纹；Rust 生态的
//! rquest（0x676e67/rquest）在 crates.io 上 152 个版本全部 yanked、仓库已改名
//! netty（纯协议客户端，无指纹能力），wreq 同为其 URL 级高层客户端，无法把
//! "拨号目标 IP"与"SNI"解耦（本项目生命线：对指定 IP 拨号但 SNI 用伪装域名/
//! 无 SNI，证书按目标 host 校验），故采用 boring（cloudflare/boring 4.22）——
//! BoringSSL 的 Rust 绑定，Chrome 同款 TLS 实现——自建三形态握手，语义与 Go 版
//! DialOne 完全一致：
//! - fake:x: SNI=x（伪装），证书按 host 校验（流量主形态）
//! - real:   SNI=host，证书按 host 校验（诊断）
//! SNI 与校验名解耦：SSL_set_tlsext_host_name（SslRef::set_hostname）只改 SNI
//! 扩展；X509_VERIFY_PARAM_set1_host（verify param 的 set_host）只改校验名。
//! 开启 GREASE（SSL_CTX_set_grease_enabled，Chrome 指纹标志）与 ALPN h2,http/1.1，
//! BoringSSL 默认密码套件/扩展顺序即 Chrome 同款 —— 指纹不再被风控按 JA3/JA4
//! 识别为库实现。

use crate::config::CONNECT_TIMEOUT_SECS;
use boring::ssl::{Ssl, SslContextBuilder, SslMethod, SslVerifyMode};
use boring::x509::verify::X509CheckFlags;
use boring::x509::X509;
use rustls_native_certs::CertificateResult;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 握手形态标识（拨号层内部用）。
pub const MODE_SNI: &str = "sni"; // BoringSSL 真 SNI
pub const MODE_FAKE_PFX: &str = "fake:"; // 表内裸域名(如 baidu.com)经 plan_mode 加上, 证书按 host 校验

/// BoringSSL(Tokio) TLS 流类型。
pub type BoringTls = tokio_boring::SslStream<TcpStream>;

/// 拨号形态 → 连接结果（TLS 已握手或裸 TCP）。
pub enum Dialed {
    Plain(TcpStream),
    Tls(BoringTls),
}

impl AsyncRead for Dialed {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_read(cx, buf),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Dialed {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_write(cx, buf),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_flush(cx),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_shutdown(cx),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_shutdown(cx),
        }
    }
}

/// hyper-util legacy 客户端的连接抽象（Dialed 直接可作连接用）。
/// ALPN 自动探测：tls_connect 强制 h2（池内直连腿），dial_tls_simple 不强制
/// （镜像腿随服务端协商）—— 按实际协商结果告知 hyper 走 h2/h1。
impl hyper_util::client::legacy::connect::Connection for Dialed {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let mut c = hyper_util::client::legacy::connect::Connected::new();
        if let Dialed::Tls(t) = self {
            if t.ssl().selected_alpn_protocol() == Some(b"h2") {
                c = c.negotiated_h2();
            }
        }
        c
    }
}

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

/// 系统根证书 PEM（BoringSSL set_ca_file 加载用）。等价 Go 的 x509.SystemCertPool 与
/// rustls 版 system_roots。加载失败返回 None（调用方回退 set_default_verify_paths）。
/// 惰性缓存（进程内一次加载）。
pub fn system_root_pem() -> Option<String> {
    static PEM: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let mut buf = String::new();
        let mut added = 0usize;
        match rustls_native_certs::load_native_certs() {
            CertificateResult { certs, .. } => {
                for c in certs {
                    // DER → PEM 用 boring 自带 X509::to_pem（无需外部 base64 依赖）
                    let x = X509::from_der(c.as_ref()).ok()?;
                    buf.push_str(&String::from_utf8_lossy(&x.to_pem().ok()?));
                    added += 1;
                }
            }
        }
        if added == 0 {
            None
        } else {
            Some(buf)
        }
    })
    .clone()
}

/// 写临时 CA 文件供 set_ca_file 加载（进程唯一名，幂等覆盖）。
fn ca_file_for(pem: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "gh_link_ca_{}_{}.pem",
        std::process::id(),
        tmp_seq()
    ));
    std::fs::write(&path, pem)?;
    Ok(path)
}

/// 临时文件唯一序号：并行测试各写各的 CA/链，防互覆盖（随机 CA 竞态会导致
/// 客户端信任锚与服务端链不匹配 → 误报 self-signed）。
static TMP_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn tmp_seq() -> usize {
    TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// 构建三形态的 BoringSSL 客户端连接（SNI 与校验名解耦）。
/// - Sni：SNI=host，校验名=host
/// - NoSni：不发 SNI（不调 set_hostname），校验名=host
/// - Fake(name)：SNI=name，校验名=host（先按 host 建，再覆盖 SNI 扩展）
/// roots 为注入的信任锚（测试用）；真实路径传 None → 系统根。
/// 开启 GREASE + ALPN h2,http/1.1（Chrome 指纹 + 上游必须 h2）。
fn client_ssl(host: &str, mode: &str, ca_pem: Option<&str>) -> std::io::Result<Ssl> {
    let mut ctx_b = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| io_err(format!("BoringSSL 上下文初始化失败: {e}")))?;
    match ca_pem {
        Some(pem) => {
            // 信任锚注入：官方客户端姿势 set_ca_file（SSL_CTX_load_verify_locations）
            let ca_file = ca_file_for(pem)?;
            ctx_b
                .set_ca_file(&ca_file)
                .map_err(|e| io_err(format!("CA 加载失败: {e}")))?;
        }
        None => {
            ctx_b
                .set_default_verify_paths()
                .map_err(|e| io_err(format!("默认证书路径失败: {e}")))?;
        }
    }
    ctx_b.set_verify(SslVerifyMode::PEER);
    ctx_b.set_grease_enabled(true); // Chrome GREASE（SSL_CTX_set_grease_enabled）
                                    // ALPN：Chrome 指纹自带 h2,http/1.1；边缘按此协商出 h2（缺 ALPN 会全灭，已实锤）
    ctx_b
        .set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(|e| io_err(format!("ALPN 配置失败: {e}")))?;
    let ctx = ctx_b.build();
    let mut ssl = Ssl::new(&ctx).map_err(|e| io_err(format!("Ssl 初始化失败: {e}")))?;

    match mode {
        MODE_SNI => {
            ssl.set_hostname(host)
                .map_err(|e| io_err(format!("SNI 设置失败: {e}")))?;
        }
        m if m.starts_with(MODE_FAKE_PFX) => {
            let fake = m.trim_start_matches(MODE_FAKE_PFX);
            if fake.is_empty() {
                return Err(io_err("非法伪装 SNI(空域名)".into()));
            }
            ssl.set_hostname(fake)
                .map_err(|e| io_err(format!("伪装 SNI 设置失败: {e}")))?;
        }
        other => {
            return Err(io_err(format!("未知握手形态 {other:?}")));
        }
    }
    // 校验名恒为目标 host（与 SNI 解耦；IP 形式走 set_ip）。对照 boring 官方
    // setup_verify_hostname：NO_PARTIAL_WILDCARDS + set_host/set_ip。
    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => param
            .set_ip(ip)
            .map_err(|e| io_err(format!("校验 IP 设置失败: {e}")))?,
        Err(_) => param
            .set_host(host)
            .map_err(|e| io_err(format!("校验名设置失败: {e}")))?,
    }
    Ok(ssl)
}

/// 对已建立的 TCP 连接按形态完成 BoringSSL 握手（Chrome 指纹）。
/// 末尾强制断言协商出 h2（对照 Go dialOne 的 ALPN 检查）。
pub async fn tls_connect(host: &str, mode: &str, tcp: TcpStream) -> std::io::Result<BoringTls> {
    let ssl = client_ssl(host, mode, system_root_pem().as_deref())?;
    let tls = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio_boring::SslStreamBuilder::new(ssl, tcp).connect(),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS 握手超时"))?
    .map_err(|e| io_err(format!("TLS 握手失败: {e}")))?;
    // 强制 h2：上游传输只会讲 h2
    let proto = tls.ssl().selected_alpn_protocol().unwrap_or_default();
    if proto != b"h2" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("上游未协商出 h2(得到 {:?})", String::from_utf8_lossy(proto)),
        ));
    }
    Ok(tls)
}

/// 流量拨号闸门：限真实流量拨号的总并发。
static DIAL_GATE: tokio::sync::OnceCell<Arc<tokio::sync::Semaphore>> =
    tokio::sync::OnceCell::const_new();

async fn gate_acquire() -> tokio::sync::SemaphorePermit<'static> {
    let gate = DIAL_GATE
        .get_or_init(|| async {
            Arc::new(tokio::sync::Semaphore::new(crate::config::DIAL_GATE_SIZE))
        })
        .await;
    gate.acquire().await.expect("信号量未关闭")
}

/// 对单个 IP 走指定握手形态拨号。成功返回已握手连接（强制 h2）；
/// tls_handshake=false 时只做裸 TCP 拨号（透传 CONNECT 隧道用）。
pub async fn dial_one(
    host: &str,
    ip: &str,
    mode: &str,
    tls_handshake: bool,
) -> std::io::Result<Dialed> {
    let _permit = gate_acquire().await;
    let addr = format!("{ip}:443");
    let tcp = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP 拨号超时"))??;
    let _ = tcp.set_nodelay(true);

    if !tls_handshake {
        return Ok(Dialed::Plain(tcp));
    }

    let tls = tls_connect(host, mode, tcp).await?;
    Ok(Dialed::Tls(tls))
}

/// 镜像腿（大文件赛马的非池域名）标准 TLS 直拨：boring 栈 + 系统解析，
/// 无表无阶梯 —— 镜像无风控；ALPN 由服务端选择（h1 镜像走 http/1.1，
/// 与上游 mitm_h1_client 对齐）。返回类型与 Dialed::Tls 一致（BoringTls），
/// 上游 MirrorConnector 可直接包入 Dialed。
pub async fn dial_tls_simple(host: &str) -> std::io::Result<BoringTls> {
    let ssl = client_ssl(host, MODE_SNI, system_root_pem().as_deref())?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect((host, 443)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "镜像拨号超时"))??;
    let _ = tcp.set_nodelay(true);
    let tls = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio_boring::SslStreamBuilder::new(ssl, tcp).connect(),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "镜像 TLS 握手超时"))?
    .map_err(|e| io_err(format!("镜像 TLS 握手失败: {e}")))?;
    Ok(tls)
}

/// 系统根证书（rustls 版，供 certgen 测试的 rustls 客户端验证 MITM 证书）。
/// 加载失败时退回空池（连接会因证书校验失败而快速失败，与 Go 版一致）。
#[cfg(test)]
pub fn system_roots() -> Arc<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        CertificateResult { certs, .. } => {
            for c in certs {
                let _ = roots.add(c);
            }
        }
    }
    Arc::new(roots)
}

/// 供 mitm 上游构造 http 请求时使用（host-only 解析用，等价 Go net.SplitHostPort）。
#[cfg(test)]
mod tests {
    use super::*;
    use boring::pkey::PKey;
    use boring::ssl::SslAcceptor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// boring 官方测试证书目录（BoringSSL 自带，链/根/密钥齐全）。
    /// 用官方材料而非 rcgen 自签链：官方材料能被 boring 客户端完整信任，
    /// rcgen 生成的链在 boring 的 X509 链构建下不被认（self-signed/unknown_ca，
    /// 已逐一实证：issued()=Ok、check_host=Ok 仍被 TLS 拒绝）——测试目标是
    /// 验证三形态 ClientHello 与证书按 host 校验，官方材料即真实自签链。
    /// 位置不写死：编译过 boring 后材料在 CARGO_HOME 注册表下自动出现
    /// （registry/src/*/boring-*/test），也可用 BORING_TEST_DIR 显式指定；
    /// 找不到 = 相关测试跳过（材料不随仓库分发）。
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

    /// 官方材料：(信任锚 PEM, 服务端链 PEM=leaf+root, leaf key PEM)。
    /// 材料缺失返回 None（调用方测试跳过）。
    fn official_material() -> Option<(String, String, String)> {
        let dir = boring_test_dir()?;
        let cert = std::fs::read_to_string(dir.join("cert.pem")).ok()?;
        let root = std::fs::read_to_string(dir.join("root-ca.pem")).ok()?;
        let key = std::fs::read_to_string(dir.join("key.pem")).ok()?;
        Some((root.clone(), format!("{cert}{root}"), key))
    }

    /// BoringSSL 服务端（自签完整链 + 强制协商 h2）。链写入临时文件走
    /// set_certificate_chain_file（boring 服务端发完整链的标准姿势）。
    fn acceptor_for(chain_pem: &str, key_pem: &str) -> SslAcceptor {
        let dir = std::env::temp_dir();
        let chain_path = dir.join(format!(
            "gh_link_test_chain_{}_{}.pem",
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

    /// 粗解析 ClientHello：SNI 域名在明文中出现即检出；GREASE 值为
    /// 0x?a?a 双字节（高低一致 + 低半字节 0x0a）——BoringSSL 开启 GREASE 后
    /// cipher/扩展区必有。
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

    /// 起官方自签链 TLS 服务端，客户端用注入根的 store 走指定形态握手，
    /// 抓 ClientHello 验证 SNI/GREASE，双向读写验证连接可用。
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
                // peek 不消费数据：先看 ClientHello，再交给 BoringSSL accept
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
        // 官方测试证书年代久远已过期：把验证时间设回证书有效期内
        // （X509_VERIFY_PARAM_set_time，仅测试用；生产走系统根不过期）。
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
        let obs = handshake_probe(OFFICIAL_HOST, MODE_SNI, &material)
            .await
            .unwrap();
        assert_eq!(obs.sni.as_deref(), Some(OFFICIAL_HOST));
        assert!(obs.grease, "Chrome 指纹(GREASE)应存在: {obs:?}");
    }

    #[tokio::test]
    async fn fake_mode_sends_fake_sni_but_verifies_host() {
        // 证书 CN=foobar.com；SNI=baidu.com；校验名=foobar.com → 握手必须成功
        let Some(material) = official_material() else {
            eprintln!("跳过: 未找到 boring 测试证书目录(编译过 boring 后重试, 或设 BORING_TEST_DIR)");
            return;
        };
        let obs = handshake_probe(OFFICIAL_HOST, "fake:baidu.com", &material)
            .await
            .unwrap();
        assert_eq!(obs.sni.as_deref(), Some("baidu.com"));
        assert!(obs.grease);
    }

    #[tokio::test]
    #[ignore = "真实网络直连 GitHub，仅诊断用，非 CI 稳定项"]
    async fn real_network_boring_dial_probe() {
        // 真实网络直连 GitHub IP（不经代理），三形态各试一次，打印错误定位。
        // 非 CI 稳定项：仅诊断用。
        let host = "github.com";
        for (mode, ip) in [("fake:baidu.com", "140.82.114.4"), ("real", "140.82.112.3")] {
            match tokio::time::timeout(std::time::Duration::from_secs(20), async {
                let tcp = TcpStream::connect((ip, 443))
                    .await
                    .map_err(|e| format!("TCP 连接失败: {e}"))?;
                let ssl = client_ssl(host, mode, system_root_pem().as_deref())
                    .map_err(|e| format!("client_ssl: {e}"))?;
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
        // 校验名=wrong.example（≠证书 CN=foobar.com）→ 客户端握手必须失败
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
}
