//! 握手执行器：SNI 与校验名解耦（set_hostname 只改 SNI，set_host 只改校验名），证书恒按目标 host 校验。
//! GREASE + ALPN + BoringSSL 默认序 = Chrome 指纹；Rust 无 utls 绑定（rquest 全 yanked、wreq 解耦不了拨号 IP 与 SNI），用 boring。

use crate::config::CONNECT_TIMEOUT_SECS;
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
/// 白名单腿：底层 TCP 套了分片器，ClientHello 分三段发出。
pub type BoringTlsSplit = tokio_boring::SslStream<SplitHello>;

/// ClientHello 分片器：只拦第一个写（首字节 0x16 = TLS 握手记录），
/// 按 `WHITELIST_SPLIT_SEGS` 段切开、段间等 `WHITELIST_SPLIT_GAP_MS` 再发下一段。
/// DPI 要拼出完整 ClientHello 才能读 SNI，段间隔超过它的重组窗口就拼不齐。
/// 握手完成后（`done`）一律直通，不碰应用数据帧。
pub struct SplitHello {
    inner: TcpStream,
    segs_left: usize,
    gap: Duration,
    /// 下一段的放行时刻；None = 立即可发。
    timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    done: bool,
    /// 分片已开：首写通过资格判定后置位，续传段不再重判首字节(那是 0x03)。
    splitting: bool,
    /// 实际发出的段数。握手后读它：>=2 说明分片真的生效了，
    /// 1（或 0）说明首包太短、分片器直接退场——这是唯一能看出掩体没上成的信号。
    segs_sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// 白名单分片统计：尝试次数 / 实际分片次数。两者长期对不上 = 分片没生效。
pub static SPLIT_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static SPLIT_DONE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl SplitHello {
    pub fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            segs_left: crate::config::WHITELIST_SPLIT_SEGS.max(1),
            gap: Duration::from_millis(crate::config::WHITELIST_SPLIT_GAP_MS),
            timer: None,
            done: false,
            splitting: false,
            segs_sent: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// 取一份计数句柄；句柄要在这条流被 move 进 TLS 之前拿。
    pub fn counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.segs_sent.clone()
    }
}

impl AsyncRead for SplitHello {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SplitHello {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;
        let me = self.get_mut();
        // 首写判资格：非 TLS 握手/过短 → 分片器退场。分片已开则不再重判——
        // write_all 续传段的首字节是 0x03(版本号)，重判会把剩余字节一口气
        // 直通、丢掉段间隔，掩体空转(2026-10-29 审计)。
        // done = 握手帧发完：之后的帧是应用数据，直通且不再进分段计数。
        if me.done || (!me.splitting && (buf.len() < 32 || buf[0] != 0x16)) {
            me.done = true;
            return std::pin::Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        // 段间隔未到：挂定时器等唤醒
        if let Some(mut timer) = me.timer.take() {
            match timer.as_mut().poll(cx) {
                std::task::Poll::Pending => {
                    me.timer = Some(timer);
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(()) => {}
            }
        }
        let segs = me.segs_left.max(1);
        let n = if segs == 1 {
            buf.len()
        } else {
            (buf.len() / segs).max(1).min(buf.len())
        };
        let written = futures_util::ready!(std::pin::Pin::new(&mut me.inner).poll_write(cx, &buf[..n]))?;
        if written == 0 {
            return std::task::Poll::Ready(Ok(0));
        }
        me.segs_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        me.splitting = true;
        me.segs_left = me.segs_left.saturating_sub(1);
        if me.segs_left == 0 {
            me.done = true;
        } else {
            me.timer = Some(Box::pin(tokio::time::sleep(me.gap)));
        }
        std::task::Poll::Ready(Ok(written))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub enum Dialed {
    Plain(TcpStream),
    Tls(BoringTls),
    TlsSplit(BoringTlsSplit),
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
            Dialed::TlsSplit(t) => std::pin::Pin::new(t).poll_read(cx, buf),
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
            Dialed::TlsSplit(t) => std::pin::Pin::new(t).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_flush(cx),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_flush(cx),
            Dialed::TlsSplit(t) => std::pin::Pin::new(t).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Dialed::Plain(t) => std::pin::Pin::new(t).poll_shutdown(cx),
            Dialed::Tls(t) => std::pin::Pin::new(t).poll_shutdown(cx),
            Dialed::TlsSplit(t) => std::pin::Pin::new(t).poll_shutdown(cx),
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for Dialed {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let mut c = hyper_util::client::legacy::connect::Connected::new();
        let alpn = match self {
            Dialed::Tls(t) => t.ssl().selected_alpn_protocol(),
            Dialed::TlsSplit(t) => t.ssl().selected_alpn_protocol(),
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

/// TLS 会话恢复缓存：键 = SNI 形态（伪装腿统一一个键，真名腿各 host 自键）。
/// BoringSSL 在 NewSessionTicket 到达时触发 new_session_cb（TLS 1.2 为握手完成时），
/// 每个 SNI 只留最近一张 ticket；重拨时经 set_session 走 1-RTT PSK 恢复——
/// 省掉整条证书链的重传与验签（跨洋链路一次握手少传 ~4KB）。恢复被服务器拒绝时
/// 协议自动回落完整握手，无副作用。仅存内存，进程重启自然失效；
/// 不启用 0-RTT（重放面大，且要侵入 hyper 的首包路径）。
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
        // SAFETY: SSL_set_session 前置条件是 ssl 尚未开始握手——Ssl::new 之后立即调用；
        // SslSession: Send+Sync（boring foreign_type_and_impl_send_sync），跨任务共享安全。
        // 返回 Err 仅表示本轮无法注入，走完整握手。
        unsafe {
            let _ = ssl.set_session(&s);
        }
    }
}

fn system_root_certs() -> Option<&'static [X509]> {
    static CERTS: std::sync::OnceLock<Option<Vec<X509>>> = std::sync::OnceLock::new();
    CERTS.get_or_init(|| {
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
    // 会话恢复：ticket 到手即入缓存（见 session_cache）。键取客户端实际发出的 SNI——
    // 伪装腿全是同一 SNI，一张 ticket 管整个伪装族；真名腿各自成键。
    // CLIENT 模式只为触发 new_session_cb（客户端默认 OFF，不开回调不触发）；
    // BoringSSL 客户端不会自动从内部缓存取会话，注入恒由 apply_cached_session 显式做。
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

/// 构建三形态 BoringSSL 客户端连接；ca_pem 为测试用内存信任锚。
fn client_ssl(host: &str, mode: &str, ca_pem: Option<&str>) -> std::io::Result<Ssl> {
    let mut ssl = match ca_pem {
        None => Ssl::new(default_ssl_context()?)
            .map_err(|e| io_err(format!("Ssl 初始化失败: {e}")))?,
        Some(pem) => {
            let certs = X509::stack_from_pem(pem.as_bytes())
                .map_err(|e| io_err(format!("CA PEM 解析失败: {e}")))?;
            let ctx = build_ssl_context(Some(certs))?;
            Ssl::new(&ctx).map_err(|e| io_err(format!("Ssl 初始化失败: {e}")))?
        }
    };

    // sni 透传:非空即作为 ClientHello SNI,空串 = 无 SNI 扩展;校验名恒为 host(下方 param)。
    if !mode.is_empty() {
        ssl.set_hostname(mode)
            .map_err(|e| io_err(format!("SNI 设置失败: {e}")))?;
    }
    // 校验名恒为目标 host（与 SNI 解耦；IP 形式走 set_ip）。
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

/// 限时 TLS 握手共用尾：label 进错误文案（镜像腿与池腿归因可分）。
async fn tls_handshake(ssl: Ssl, tcp: TcpStream, label: &str) -> std::io::Result<BoringTls> {
    tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio_boring::SslStreamBuilder::new(ssl, tcp).connect(),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("{label}TLS 握手超时"),
        )
    })?
    .map_err(|e| io_err(format!("{label}TLS 握手失败: {e}")))
}

pub async fn tls_connect(host: &str, mode: &str, tcp: TcpStream) -> std::io::Result<BoringTls> {
    let mut ssl = client_ssl(host, mode, None)?;
    apply_cached_session(&mut ssl, mode);
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

/// 白名单腿 TLS：真名 SNI（mode 恒为 host）+ ClientHello 分片 + 必须协商 h2。
/// IP 由 edge 池的白名单族选好，这里不再自己解析。
async fn tls_connect_split(host: &str, tcp: TcpStream) -> std::io::Result<BoringTlsSplit> {
    use std::sync::atomic::Ordering;
    let ssl = client_ssl(host, host, None)?;
    let io = SplitHello::new(tcp);
    let counter = io.counter();
    // 发起即计数：握不上也要算进分母，否则 attempt/done 分不清"没人连"和"连了没分片"。
    SPLIT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    let tls = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio_boring::SslStreamBuilder::new(ssl, io).connect(),
    )
    .await
    .map_err(|_| io_err(format!("白名单 TLS 握手超时: {host}")))?
    .map_err(|e| io_err(format!("白名单 TLS 握手失败: {host}: {e}")))?;

    // 分了 2 段以上才算掩体真的上成了。
    if counter.load(Ordering::Relaxed) >= 2 {
        SPLIT_DONE.fetch_add(1, Ordering::Relaxed);
    }

    let proto = tls.ssl().selected_alpn_protocol().unwrap_or_default();
    if proto != b"h2" {
        return Err(io_err(format!(
            "白名单上游未协商出 h2(得到 {:?})",
            String::from_utf8_lossy(proto)
        )));
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

/// 拨号端口：生产恒 443。串发重试引擎要能在本地监听上跑测试，才留这个可覆盖的出口——
/// 否则只能抢占本机 443，等于核心重试逻辑没法测。
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

pub async fn dial_one(
    host: &str,
    ip: &str,
    mode: &str,
    tls_handshake: bool,
) -> std::io::Result<Dialed> {
    let _permit = gate_acquire().await;
    let addr = format!("{ip}:{}", dial_port());
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

    // 白名单：不管条目自带的 sni 是什么，一律真名 + ClientHello 分片。
    // 这批域名靠真名换正确证书，伪装会被上游判非法（docs 实测 90ms 回 400 Whoa）。
    if crate::config::is_whitelist(host) {
        let tls = tls_connect_split(host, tcp).await?;
        return Ok(Dialed::TlsSplit(tls));
    }

    let tls = tls_connect(host, mode, tcp).await?;
    Ok(Dialed::Tls(tls))
}

pub async fn dial_tls_simple(host: &str) -> std::io::Result<BoringTls> {
    let mut ssl = client_ssl(host, host, None)?;
    apply_cached_session(&mut ssl, host);
    let tcp = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect((host, 443)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "镜像拨号超时"))??;
    let _ = tcp.set_nodelay(true);
    tls_handshake(ssl, tcp, "镜像 ").await
}

#[cfg(test)]
pub fn system_roots() -> Arc<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let CertificateResult { certs, .. } = rustls_native_certs::load_native_certs();
    for c in certs {
        let _ = roots.add(c);
    }
    Arc::new(roots)
}

/// 分片器单测：分片默认关掉线上验证就只剩"看日志猜"，这里直接量时间差。
#[cfg(test)]
#[path = "../tests/pool/dial_split_hello_tests.rs"]
mod split_hello_tests;

#[cfg(test)]
#[path = "../tests/pool/dial.rs"]
mod tests;
