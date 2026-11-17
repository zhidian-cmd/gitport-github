//! 代理服务：CONNECT 隧道（TLS 透传 / 池内域名 MITM）+ 明文 HTTP 转发。

pub mod mitm;
pub mod protocol;
pub mod status;
pub mod upstream;

use crate::certgen::Authority;
use crate::config::{self, HEAD_TIMEOUT_SECS};
use crate::pool::{self, dial::Dialed};
use crate::util::LogFn;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

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
    // 启动成功不出声：端口和工作台地址在概览页，日志只留事故。
    set_running(true);
    // 每连接占一个许可，满了就等；否则狂开 CONNECT 能把常驻进程堆死。
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
                    // 持续性错误(句柄耗尽/socket 失效等)立即重试会全速空转烧核: 小睡再试
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let srv = srv.clone();
        let cancel = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit; // 连接活着期间占坑，drop 时归还
            // 停止代理要连已 spawn 的隧道一起收：select 一取消 conn 被 drop 即关 socket，MITM 分支也覆盖。
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
        // 头块以空行收尾，之后的字节是同包到达的体首段，必须原样续传。
        let Some(end) = find_head_end(&head) else {
            return Ok(()); // 头块不完整(超时/EOF 截断): 成不了包, 直接断开
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
            self.handle_connect(client, &target, cancel).await;
        } else {
            self.handle_http(client, &method, &target, headers, body_prefix, cancel)
                .await;
        }
        Ok(())
    }

    async fn handle_connect(&self, mut client: TcpStream, target: &str, cancel: CancellationToken) {
        let (host, port) = split_target(target, 443);
        // 开放代理闸：受管域名全速加速，其他域名只放 443 透明隧道（拼接镜像 clone URL 用）；非 443 一律 502，bogon 过滤堵内网/元数据/非 HTTPS。
        if !pool::route::is_managed(&host) && port != 443 {
            (self.log)(&format!(
                "[拒绝] {host}:{port} 非受管域名且非 443, 不做开放转发(仅加速 GitHub 系与 https 镜像隧道)"
            ));
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        // MITM 只拦 443；非 443 是明文协议，交普通 TCP 隧道，端口照用。
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
        // 字节数每 host 只留首条：每连接两行会刷满日志环，异常(零回包)另有专门记录。
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
            // 曾经按“双向都小于 8KB”猜风控响应——304 也符合，每开一页就把驻留记号挪一格；透传看不见状态码，这种猜测注定误判。
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
        // 开放代理闸（与 CONNECT 同款）：非受管目标一律 502。
        if !pool::route::is_managed(&host) {
            (self.log)(&format!(
                "[拒绝] {host} 非受管域名, 不做开放转发(仅加速 GitHub 系)"
            ));
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        // 分块体过不去：块长度行会被上游当成正文，宁可 501 也不静默改坏数据。
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
            // 逐跳头不过上游（与 MITM 路径同一份名单）：connection: close 会带偏转发语义。
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
        req.push_str("\r\n");
        // 先写重拼后的头，再补同包到达的体首段，之后交给双向泵。
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

/// 无可用上游：502 + 带原因的日志（CONNECT 与明文 HTTP 共用），原因能区分被保险拦与拨不通。
async fn reject(client: &mut TcpStream, log: &LogFn, host: &str, why: &str) {
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

/// 头块结束位置（\r\n\r\n 的起点）：读头和拆头共用同一份查找。
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 明文 HTTP 请求头里是否声明了分块体（该编码在本路径无法原样转发）。
fn headers_have_chunked(headers: &[u8]) -> bool {
    String::from_utf8_lossy(headers).lines().any(|l| {
        let low = l.to_ascii_lowercase();
        low.starts_with("transfer-encoding:") && low.contains("chunked")
    })
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// 剥掉 Host 里的 :port（IPv6 字面量安全，不动大小写 —— 调用方按需 Lower）。
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

/// 上游唯一入口：按 routes.json 走池，池全灭落系统 DNS 真名透传（兜底不是加速，git clone 不能一上来 502）。
pub async fn connect_upstream(host: &str, port: u16) -> Result<(Dialed, String), String> {
    // 非 443 不走 IP 表：串发恒拨 443，git:// 与 SSH 会被连错端口。
    if port == 443 && pool::route::is_managed(host) {
        // 按类分流：内容域 TCP 竞速（MITM 关的隧道用）；会话域/其他串发+游标（跨 IP 并发 SYN 是风控画像）。
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
    // 先解析再过保险：hosts 把受管域名指进环回/私网时照连就是送信，白名单只保证名字像 GitHub。
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

/// 兜底腿地址保险：环回/私网/链路本地/CGNAT/组播/保留段一律拒；内嵌 v4 的 v6 先折回 v4 再判，MITM DNS 直拨腿也用。
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
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT（企业/运营商内网常用）
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
            // IPv4-compatible ::a.b.c.d（:: 与 ::1 已在上一步拦掉）
            if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 {
                return bogon_addr(v4_from(s[6], s[7]));
            }
            // 6to4 2002:<v4>::/48
            if s[0] == 0x2002 {
                return bogon_addr(v4_from(s[1], s[2]));
            }
            // Teredo 2001:0000::/32：服务端 v4 在 s[2],s[3]，客户端 v4 在后 32 位（取反）
            if s[0] == 0x2001 && s[1] == 0 {
                return bogon_addr(v4_from(s[2], s[3])) || bogon_addr(v4_from(!s[6], !s[7]));
            }
            false
        }
    }
}

/// 双向透传，任一方向结束即关两侧；首字节判死掐断另一路——只 shutdown 写半部会让 join! 永久 pending，task+TCP+fd 全挂着。
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
    // 两路共用 gate：超时/停止一起收；正常 EOF 不取消，保留 TCP 半关闭（客户端先 shutdown 时另一半仍传完）。
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
        // 透明隧道再给一条总时长上限；明文 HTTP 可能传大文件，不限。
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

/// 轻量随机（stdlib RandomState 技巧，避免引入 rand 依赖）：每次调用值不同。
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
    // 首刀：1..=16 字节（覆盖 TLS 记录头一带，具体位置随机）
    let c1 = 1 + (r % config::HELLO_SPLIT_FIRST_MAX as u64) as usize;
    // 约 2/3 概率三段：二刀落在 n 的 1/3 ~ 2/3 处（SNI 通常在这一带）
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
                // 黑洞判死：两路一起收，别只关半条连接留僵尸
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
        // 只对第一条流做判定：后再读到的都是数据段，不该拆。
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
