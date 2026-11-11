//! 握手执行器：SNI 与校验名解耦（SNI 骗墙，证书按组锚点校验）；BoringSSL 造 Chrome 指纹。

use crate::config::{TCP_CONNECT_TIMEOUT_MS, TLS_HANDSHAKE_TIMEOUT_MS};
use boring::ssl::{NameType, Ssl, SslContextBuilder, SslMethod, SslSession, SslVerifyMode};
use boring::x509::verify::X509CheckFlags;
use boring::x509::X509;
use rustls_native_certs::CertificateResult;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub type BoringTls = tokio_boring::SslStream<TcpStream>;

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

impl hyper_util::client::legacy::connect::Connection for Dialed {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let mut c = hyper_util::client::legacy::connect::Connected::new();
        let alpn = match self {
            Dialed::Tls(t) => t.ssl().selected_alpn_protocol(),
            Dialed::Plain(_) => None,
        };
        if alpn == Some(b"h2") {
            c = c.negotiated_h2();
        }
        c
    }
}

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

/// TLS 会话恢复缓存：按键存最近一张 ticket，重拨走 1-RTT；仅内存，不启用 0-RTT。
fn session_cache() -> &'static std::sync::Mutex<HashMap<String, SslSession>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, SslSession>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn apply_cached_session(ssl: &mut Ssl, mode: &str) {
    if mode.is_empty() {
        return; // 无 SNI 拨号从不进缓存，恒完整握手
    }
    let ticket = session_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(mode)
        .cloned();
    if let Some(s) = ticket {
        // SAFETY: 必须在握手开始前注入；SslSession 是 Send+Sync，跨任务共享安全。
        unsafe {
            let _ = ssl.set_session(&s);
        }
    }
}

fn system_root_certs() -> Option<&'static [X509]> {
    static CERTS: std::sync::OnceLock<Option<Vec<X509>>> = std::sync::OnceLock::new();
    CERTS
        .get_or_init(|| {
            let mut out = Vec::new();
            let CertificateResult { certs, .. } = rustls_native_certs::load_native_certs();
            for c in certs {
                if let Ok(x) = X509::from_der(c.as_ref()) {
                    out.push(x);
                }
            }
            (!out.is_empty()).then_some(out)
        })
        .as_deref()
}

fn build_ssl_context(roots: Option<Vec<X509>>) -> std::io::Result<boring::ssl::SslContext> {
    let mut ctx_b = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| io_err(format!("BoringSSL 上下文初始化失败: {e}")))?;
    match roots {
        Some(certs) => {
            let mut sb = boring::x509::store::X509StoreBuilder::new()
                .map_err(|e| io_err(format!("根证书 store 初始化失败: {e}")))?;
            for c in certs {
                sb.add_cert(c)
                    .map_err(|e| io_err(format!("根证书载入失败: {e}")))?;
            }
            ctx_b.set_cert_store_builder(sb);
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
    // 会话恢复：CLIENT 模式只为触发 new_session_cb，注入恒由 apply_cached_session 显式做。
    ctx_b.set_session_cache_mode(boring::ssl::SslSessionCacheMode::CLIENT);
    ctx_b.set_new_session_callback(|ssl, session| {
        if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
            if !sni.is_empty() {
                session_cache()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(sni.to_owned(), session);
            }
        }
    });
    Ok(ctx_b.build())
}

fn default_ssl_context() -> std::io::Result<&'static boring::ssl::SslContext> {
    static CTX: std::sync::OnceLock<boring::ssl::SslContext> = std::sync::OnceLock::new();
    if let Some(ctx) = CTX.get() {
        return Ok(ctx);
    }
    let built = build_ssl_context(system_root_certs().map(<[X509]>::to_vec))?;
    let _ = CTX.set(built);
    Ok(CTX.get().expect("上下文刚已写入"))
}

/// 构建客户端连接：SNI = mode（非空才发扩展），校验名 = verify；ca_pem 为测试用内存信任锚。
fn client_ssl(verify: &str, sni: &str, ca_pem: Option<&str>) -> std::io::Result<Ssl> {
    let mut ssl = match ca_pem {
        None => {
            Ssl::new(default_ssl_context()?).map_err(|e| io_err(format!("Ssl 初始化失败: {e}")))?
        }
        Some(pem) => {
            let certs = X509::stack_from_pem(pem.as_bytes())
                .map_err(|e| io_err(format!("CA PEM 解析失败: {e}")))?;
            let ctx = build_ssl_context(Some(certs))?;
            Ssl::new(&ctx).map_err(|e| io_err(format!("Ssl 初始化失败: {e}")))?
        }
    };

    // sni 透传:非空即作为 ClientHello SNI,空串 = 无 SNI 扩展;校验名 = verify(与 SNI 解耦)。
    if !sni.is_empty() {
        ssl.set_hostname(sni)
            .map_err(|e| io_err(format!("SNI 设置失败: {e}")))?;
    }
    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match verify.parse::<std::net::IpAddr>() {
        Ok(ip) => param
            .set_ip(ip)
            .map_err(|e| io_err(format!("校验 IP 设置失败: {e}")))?,
        Err(_) => param
            .set_host(verify)
            .map_err(|e| io_err(format!("校验名设置失败: {e}")))?,
    }
    Ok(ssl)
}

/// 限时 TLS 握手共用尾：label 进错误文案（镜像腿与池腿归因可分）。
async fn tls_handshake(ssl: Ssl, tcp: TcpStream, label: &str) -> std::io::Result<BoringTls> {
    tokio::time::timeout(
        Duration::from_millis(TLS_HANDSHAKE_TIMEOUT_MS),
        tokio_boring::SslStreamBuilder::new(ssl, tcp).connect(),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{label}TLS 握手超时")))?
    .map_err(|e| io_err(format!("{label}TLS 握手失败: {e}")))
}

async fn tls_connect(sni: &str, verify: &str, tcp: TcpStream) -> std::io::Result<BoringTls> {
    let mut ssl = client_ssl(verify, sni, None)?;
    apply_cached_session(&mut ssl, sni);
    let tls = tls_handshake(ssl, tcp, "").await?;
    let proto = tls.ssl().selected_alpn_protocol().unwrap_or_default();
    if proto != b"h2" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("上游未协商出 h2(得到 {:?})", String::from_utf8_lossy(proto)),
        ));
    }
    Ok(tls)
}

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

/// 拨号端口：生产恒 443；测试可覆盖，否则核心重试逻辑没法在本地跑。
#[cfg(not(test))]
fn dial_port() -> u16 {
    443
}

#[cfg(test)]
static TEST_DIAL_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

#[cfg(test)]
fn dial_port() -> u16 {
    match TEST_DIAL_PORT.load(std::sync::atomic::Ordering::SeqCst) {
        0 => 443,
        p => p,
    }
}

/// 测试专用：0 = 复位为 443。
#[cfg(test)]
pub fn set_dial_port(p: u16) {
    TEST_DIAL_PORT.store(p, std::sync::atomic::Ordering::SeqCst);
}

/// 拨一条：TCP → 可选 TLS（SNI=sni 骗墙，证书按 verify 锚点校验）。
pub async fn dial_one(
    ip: &str,
    sni: &str,
    verify: &str,
    tls_handshake: bool,
) -> std::io::Result<Dialed> {
    let _permit = gate_acquire().await;
    let addr = format!("{ip}:{}", dial_port());
    let tcp = tokio::time::timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP 拨号超时"))??;
    let _ = tcp.set_nodelay(true);

    if !tls_handshake {
        return Ok(Dialed::Plain(tcp));
    }

    let tls = tls_connect(sni, verify, tcp).await?;
    Ok(Dialed::Tls(tls))
}

pub async fn dial_tls_simple(host: &str) -> std::io::Result<BoringTls> {
    let mut ssl = client_ssl(host, host, None)?;
    // 镜像腿只谈 HTTP/1.1：Cloudflare 系（gh-proxy.org 实测）的 h2 响应体在本客户端
    // 读不出——头正常、体流立即 0B EOF，而同一 URL 走 h1.1 一切正常。镜像只拉文件，
    // h2 多路复用没有收益，直接不开，这一类兼容问题连根拔掉。
    ssl.set_alpn_protos(b"\x08http/1.1")
        .map_err(|e| io_err(format!("ALPN 配置失败: {e}")))?;
    apply_cached_session(&mut ssl, host);
    let tcp = tokio::time::timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect((host, 443)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "镜像拨号超时"))??;
    let _ = tcp.set_nodelay(true);
    tls_handshake(ssl, tcp, "镜像 ").await
}

#[cfg(test)]
#[path = "../tests/pool/dial.rs"]
mod tests;
