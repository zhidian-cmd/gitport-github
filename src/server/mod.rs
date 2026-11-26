//! 代理服务：CONNECT 隧道（TLS 透传 / 池内域名 MITM）+ 明文 HTTP 转发。

pub mod mitm;
pub mod protocol;
pub mod status;
pub mod upstream;

use crate::certgen::Authority;
use crate::config::{self, HEAD_TIMEOUT_SECS};
use crate::pool::{self, dial::Dialed};
use crate::util::LogFn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// 读头一次读 8192B；多读的体首段存 prefix，先于 socket 交付，避免握手首段丢失。
struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.at);
            buf.put_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct ProxyServer {
    pub log: LogFn,
    pub authority: Option<Arc<Authority>>,
}

/// 代理运行状态（webui 读取）。
static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn running() -> bool {
    RUNNING.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_running(v: bool) {
    RUNNING.store(v, std::sync::atomic::Ordering::Relaxed);
}

static PROXY_CTX: std::sync::Mutex<Option<CancellationToken>> = std::sync::Mutex::new(None);
static PROXY_JOIN: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>> =
    std::sync::Mutex::new(None);

pub fn start_proxy_with(
    rt: &tokio::runtime::Runtime,
    srv: Arc<ProxyServer>,
    port: u16,
) -> Result<(), String> {
    rt.handle().block_on(async {
        let ln = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| format!("端口 {port} 绑定失败(被占用?): {e}"))?;
        let ctx = CancellationToken::new();
        let join = tokio::spawn(serve(srv, ln, ctx.clone()));
        *PROXY_CTX.lock().unwrap() = Some(ctx);
        *PROXY_JOIN.lock().unwrap() = Some(join);
        Ok(())
    })
}

pub fn stop_proxy(rt: &tokio::runtime::Runtime) {
    rt.handle().block_on(async {
        let ctx = PROXY_CTX.lock().unwrap().take();
        if let Some(c) = ctx {
            c.cancel();
        }
        let join = PROXY_JOIN.lock().unwrap().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    });
}

pub async fn serve(srv: Arc<ProxyServer>, ln: TcpListener, ctx: CancellationToken) {
    // 启动成功不出声（地址在概览页）。
    set_running(true);
    // 每连接占一个许可，防狂开 CONNECT 堆死常驻进程。
    let gate = Arc::new(tokio::sync::Semaphore::new(config::PROXY_MAX_CONNS));
    loop {
        let permit = tokio::select! {
            _ = ctx.cancelled() => {
                (srv.log)("代理已停止");
                set_running(false);
                return;
            }
            p = gate.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => return,
            },
        };
        let (conn, _) = tokio::select! {
            _ = ctx.cancelled() => {
                (srv.log)("代理已停止");
                set_running(false);
                return;
            }
            r = ln.accept() => match r {
                Ok(c) => c,
                Err(_) => {
                    if ctx.is_cancelled() {
                        (srv.log)("代理已停止");
                        set_running(false);
                        return;
                    }
                    // 持续性错误小睡 100ms 再试，防全速空转烧核。
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let srv = srv.clone();
        let cancel = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit; // 连接存活期占坑，drop 归还
            // 取消时 conn 被 drop 即关 socket，已 spawn 的隧道一并收。
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = srv.handle(conn, cancel.clone()) => {}
            }
        });
    }
}

impl ProxyServer {
    async fn handle(&self, mut client: TcpStream, cancel: CancellationToken) -> std::io::Result<()> {
        let _ = client.set_nodelay(true);
        let head = read_head(&mut client).await?;
        // 空行后的字节是同包体首段，须原样续传。
        let Some(end) = find_head_end(&head) else {
            return Ok(()); // 头块不完整：直接断开
        };
        let Some(idx) = find_crlf(&head[..end]) else {
            return Ok(());
        };
        let line = String::from_utf8_lossy(&head[..idx]).to_string();
        let headers = &head[(idx + 2).min(end)..end];
        let body_prefix = &head[end + 4..];
        let mut parts = line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        if method == "CONNECT" {
            self.handle_connect(client, &target, cancel, body_prefix.to_vec())
                .await;
        } else {
            self.handle_http(client, &method, &target, headers, body_prefix, cancel)
                .await;
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        client: TcpStream,
        target: &str,
        cancel: CancellationToken,
        body_prefix: Vec<u8>,
    ) {
        let mut client = Prefixed::new(body_prefix, client);
        let (host, port) = split_target(target, 443);
        // 开放代理闸：受管域名加速，其他域名仅放 443 透明隧道；非 443 一律 502，bogon 过滤。
        if !pool::route::is_managed(&host) && port != 443 {
            (self.log)(&format!(
                "[拒绝] {host}:{port} 非受管域名且非 443, 不做开放转发(仅加速 GitHub 系与 https 镜像隧道)"
            ));
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        // MITM 只拦 443；非 443 交普通 TCP 隧道。
        if port == 443 && mitm::mitm_scope(self.authority.as_ref(), &host) {
            mitm::handle_connect_mitm(self, client, &host).await;
            return;
        }
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(why) => {
                reject(&mut client, &self.log, &host, &why).await;
                return;
            }
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        if mitm::quiet::first_time("connect", &host) {
            (self.log)(&format!("[CONNECT] {host} via {ip} -> 200已发, 开始转发"));
        }

        let (sent, recv) = bidir_copy(
            &mut client,
            &mut upstream,
            Some(std::time::Duration::from_secs(
                config::TUNNEL_FIRST_BYTE_TIMEOUT_SECS,
            )),
            true,
            cancel,
        )
        .await;
        // 字节数每 host 只留首条（防刷满日志环）。
        if mitm::quiet::first_time("tunnel-bytes", &host) {
            (self.log)(&format!("[隧道] {host} via {ip}: ↑{sent} ↓{recv}B"));
        }

        if pool::route::is_managed(&host) && ip != "system-dns" {
            match (sent, recv) {
                (s, r) if s > 0 && r > 0 => pool::cursor_note(&host, &ip, true),
                (s, r) if s > 0 && r == 0 => {
                    pool::cursor_note(&host, &ip, false);
                    (self.log)(&format!(
                        "[串发] {host} 客户端已握手但没收到回包, 换下一个 IP"
                    ));
                }
                _ => {}
            }
            // 透传看不见状态码，不猜风控响应。
        }
    }

    async fn handle_http(
        &self,
        mut client: TcpStream,
        method: &str,
        target: &str,
        headers: &[u8],
        body_prefix: &[u8],
        cancel: CancellationToken,
    ) {
        let Some(rest_target) = target.strip_prefix("http://") else {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };
        let (authority, path) = match rest_target.find('/') {
            Some(i) => (&rest_target[..i], &rest_target[i..]),
            None => (rest_target, "/"),
        };
        let (host, port) = split_target(authority, 80);
        if host.is_empty() {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        // 开放代理闸：非受管目标一律 502。
        if !pool::route::is_managed(&host) {
            (self.log)(&format!(
                "[拒绝] {host} 非受管域名, 不做开放转发(仅加速 GitHub 系)"
            ));
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        // 分块体不支持，回 501（不静默改坏数据）。
        if headers_have_chunked(headers) {
            (self.log)(&format!("[拒绝] {host} 明文 HTTP 分块请求体不支持, 回 501"));
            let _ = client
                .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(why) => {
                reject(&mut client, &self.log, &host, &why).await;
                return;
            }
        };

        let head_text = String::from_utf8_lossy(headers);
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n");
        for l in head_text.lines() {
            let l = l.trim_end_matches('\r');
            let low = l.to_lowercase();
            // 逐跳头不过上游（connection: close 会带偏转发）。
            let name = low.split(':').next().unwrap_or("").trim();
            if name.is_empty()
                || name == "host"
                || name == "proxy-authorization"
                || upstream::is_hop_by_hop(name)
            {
                continue;
            }
            req.push_str(l);
            req.push_str("\r\n");
        }
        // 一次交换一条连接：第二个请求会被灌给第一个上游（错 Host），强制关闭。
        req.push_str("Connection: close\r\n");
        req.push_str("\r\n");
        // 先写重拼头，再补体首段，交双向泵。
        let mut head_sent = upstream.write_all(req.as_bytes()).await.is_ok();
        if head_sent && !body_prefix.is_empty() {
            head_sent = upstream.write_all(body_prefix).await.is_ok();
        }
        let recv = if head_sent {
            bidir_copy(&mut client, &mut upstream, None, false, cancel)
                .await
                .1
        } else {
            0
        };
        if pool::route::is_managed(&host) && ip != "system-dns" {
            pool::cursor_note(&host, &ip, recv > 0);
        }
    }
}

/// 无可用上游：502 + 原因日志；原因区分保险拦截与拨不通。
async fn reject<S: AsyncWrite + Unpin>(client: &mut S, log: &LogFn, host: &str, why: &str) {
    let _ = client
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        .await;
    log(&format!("[拒绝] {host} 无可用上游({why})"));
}

async fn read_head(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HEAD_TIMEOUT_SECS);
    loop {
        if buf.len() >= 65536 || find_head_end(&buf).is_some() {
            break;
        }
        let read = tokio::time::timeout_at(deadline, client.read(&mut chunk)).await;
        let n = match read {
            Err(_) => break,
            Ok(Err(_)) => {
                if buf.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "读请求头失败",
                    ));
                }
                break;
            }
            Ok(Ok(n)) => {
                if n == 0 {
                    if buf.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "连接关闭",
                        ));
                    }
                    break;
                }
                n
            }
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// 头块结束位置（\r\n\r\n 起点）；读头与拆头共用。
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 明文请求头是否声明分块体（本路径无法转发）。
fn headers_have_chunked(headers: &[u8]) -> bool {
    String::from_utf8_lossy(headers).lines().any(|l| {
        let low = l.to_ascii_lowercase();
        low.starts_with("transfer-encoding:") && low.contains("chunked")
    })
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// 剥 Host 的 :port（IPv6 字面量安全，不改大小写）。
pub fn host_only(h: &str) -> &str {
    if let Some(idx) = h.rfind(':') {
        if !h[idx..].contains(']') {
            return &h[..idx];
        }
    }
    h
}

/// 解析 CONNECT/绝对 URI 的 host:port，无端口时用 def。
pub fn split_target(target: &str, def: u16) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        if !p.contains(']') {
            if let Ok(v) = p.parse::<u16>() {
                if v > 0 {
                    return (h.to_lowercase(), v);
                }
            }
        }
    }
    (target.to_lowercase(), def)
}

/// 上游唯一入口：走池，池全灭落系统 DNS 真名透传。
pub async fn connect_upstream(host: &str, port: u16) -> Result<(Dialed, String), String> {
    // 非 443 不走 IP 表（串发恒拨 443）。
    if port == 443 && pool::route::is_managed(host) {
        // 按类分流：内容域 TCP 竞速；会话域/其他串发+游标。
        let dialed = if crate::server::upstream::host_class(host)
            == crate::server::upstream::HostClass::Content
        {
            pool::tcp_race_connect(host).await
        } else {
            pool::serial_dial_skip(
                pool::DialSkip {
                    host,
                    tls_handshake: false,
                    skip_ips: &[],
                },
                None,
            )
            .await
            .map(|(c, ip, _)| (c, ip))
        };
        if let Ok((conn, ip)) = dialed {
            return Ok((conn, ip));
        }
    }
    let addr = format!("{host}:{port}");
    // 先解析再过保险：拒环回/私网（白名单只保证名字像 GitHub）。
    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(&addr),
    )
    .await;
    let addrs: Vec<std::net::SocketAddr> = match lookup {
        Ok(Ok(it)) => it.filter(|a| !bogon_addr(a.ip())).collect(),
        Ok(Err(e)) => return Err(format!("系统 DNS 解析失败: {host}: {e}")),
        Err(_) => return Err(format!("系统 DNS 解析超时: {host}")),
    };
    if addrs.is_empty() {
        return Err(format!("{host} 解析到内网/保留地址, 拒拨"));
    }
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&addrs[..]),
    )
    .await
    .map_err(|_| format!("系统 DNS 拨号超时: {host}"))?
    .map_err(|e| format!("系统 DNS 拨号失败: {host}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    Ok((Dialed::Plain(tcp), "system-dns".to_string()))
}

/// 地址保险：环回/私网/链路本地/CGNAT/组播/保留段一律拒；内嵌 v4 的 v6 折回 v4 再判。
pub(crate) fn bogon_addr(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    fn v4_from(hi: u16, lo: u16) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(
            (hi >> 8) as u8,
            hi as u8,
            (lo >> 8) as u8,
            lo as u8,
        ))
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || o[0] == 0 // 0.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] & 0xf0) == 224 // 224.0.0.0/4 组播
                || (o[0] & 0xf0) == 240 // 240.0.0.0/4 保留
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 任播
                || (o[0] == 198 && matches!(o[1], 18 | 19)) // 198.18.0.0/15
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return bogon_addr(IpAddr::V4(m));
            }
            let s = v6.segments();
            if v6.is_loopback()
                || v6.is_unspecified()
                || s[0] & 0xffc0 == 0xfe80 // fe80::/10 链路本地
                || s[0] & 0xfe00 == 0xfc00 // fc00::/7 ULA
                || s[0] & 0xff00 == 0xff00 // ff00::/8 组播
            {
                return true;
            }
            // IPv4-compatible ::a.b.c.d
            if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 {
                return bogon_addr(v4_from(s[6], s[7]));
            }
            // 6to4 2002:<v4>::/48
            if s[0] == 0x2002 {
                return bogon_addr(v4_from(s[1], s[2]));
            }
            // Teredo 2001:0000::/32：服务端 v4 在 s[2],s[3]，客户端 v4 取反。
            if s[0] == 0x2001 && s[1] == 0 {
                return bogon_addr(v4_from(s[2], s[3])) || bogon_addr(v4_from(!s[6], !s[7]));
            }
            false
        }
    }
}

/// 双向透传，任一方向结束即关两侧；首字节判死掐断另一路（只 shutdown 写半部会永久 pending）。
async fn bidir_copy<A, B>(
    a: &mut A,
    b: &mut B,
    first_byte: Option<std::time::Duration>,
    split_hello: bool,
    cancel: CancellationToken,
) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    // 两路共用 gate：超时/停止一起收；正常 EOF 不取消，保留半关闭。
    let gate = CancellationToken::new();
    let pair = async {
        tokio::join!(
            copy_with_first_byte_timeout(&mut ar, &mut bw, None, split_hello, gate.clone()),
            copy_with_first_byte_timeout(&mut br, &mut aw, first_byte, false, gate.clone()),
        )
    };
    let flow = async {
        tokio::select! {
            _ = cancel.cancelled() => {
                gate.cancel();
                (0, 0)
            }
            v = pair => v,
        }
    };
    if first_byte.is_some() {
        // 透明隧道有总时长上限；明文 HTTP 不限。
        match tokio::time::timeout(
            std::time::Duration::from_secs(config::TUNNEL_MAX_LIFETIME_SECS),
            flow,
        )
        .await
        {
            Ok(v) => v,
            Err(_) => {
                gate.cancel();
                (0, 0)
            }
        }
    } else {
        flow.await
    }
}

/// 轻量随机（RandomState 技巧，无 rand 依赖）：每次值不同。
fn fresh_rand() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

fn split_delay() -> std::time::Duration {
    let span = config::HELLO_SPLIT_DELAY_MAX_MS - config::HELLO_SPLIT_DELAY_MIN_MS + 1;
    std::time::Duration::from_millis(config::HELLO_SPLIT_DELAY_MIN_MS + (fresh_rand() % span))
}

/// TLS 握手首段分片：2~3 段、切点随机；仅首字节为 0x16 才拆（非 TLS 流不碰）。
fn hello_split_ranges(first_read: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    if first_read.len() < 32 || first_read[0] != 0x16 {
        return None;
    }
    let n = first_read.len();
    let r = fresh_rand();
    // 首刀 1..=16 字节。
    let c1 = 1 + (r % config::HELLO_SPLIT_FIRST_MAX as u64) as usize;
    // 约 2/3 概率三段，二刀落在 n 的 1/3~2/3。
    let three = !(r >> 8).is_multiple_of(3);
    if !three {
        return Some(vec![0..c1, c1..n]);
    }
    let lo = (n / 3).max(c1 + 8);
    let hi = (n * 2 / 3).min(n - 8);
    if hi <= lo {
        return Some(vec![0..c1, c1..n]);
    }
    let c2 = lo + ((r >> 16) % ((hi - lo) as u64)) as usize;
    Some(vec![0..c1, c1..c2, c2..n])
}

/// 转发一路：可选首字节看门狗（超时判死），其后普通泵，收尾 shutdown 让对端见 EOF。
async fn copy_with_first_byte_timeout<R, W>(
    r: &mut R,
    w: &mut W,
    first_byte: Option<std::time::Duration>,
    split_tls_hello: bool,
    gate: CancellationToken,
) -> u64
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    let mut first = true;
    if let Some(dur) = first_byte {
        let read = tokio::select! {
            v = tokio::time::timeout(dur, r.read(&mut buf)) => v,
            _ = gate.cancelled() => {
                let _ = w.shutdown().await;
                return total;
            }
        };
        match read {
            Ok(Ok(n)) if n > 0 => {
                if w.write_all(&buf[..n]).await.is_err() {
                    return total;
                }
                total += n as u64;
                first = false;
            }
            _ => {
                // 黑洞判死：两路一起收，不留僵尸。
                gate.cancel();
                let _ = w.shutdown().await;
                return total;
            }
        }
    }
    loop {
        let n = tokio::select! {
            v = r.read(&mut buf) => v,
            _ = gate.cancelled() => break,
        };
        let n = match n {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // 只对第一条流判定。
        let ranges = if first && split_tls_hello {
            hello_split_ranges(&buf[..n])
        } else {
            None
        };
        first = false;
        if let Some(ranges) = ranges {
            let mut ok = true;
            let mut added = 0u64;
            for (idx, seg) in ranges.iter().enumerate() {
                if idx > 0 {
                    tokio::time::sleep(split_delay()).await;
                }
                if w.write_all(&buf[seg.clone()]).await.is_err() {
                    ok = false;
                    break;
                }
                added += seg.len() as u64;
            }
            total += added;
            if !ok {
                break;
            }
            continue;
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
    }
    let _ = w.shutdown().await;
    total
}

#[cfg(test)]
#[path = "../tests/server/mod.rs"]
mod tests;
