//! 代理服务 —— CONNECT 隧道（TLS 原样透传 / 池内域名 MITM）+ 明文 HTTP 转发。
//! 上游一律按 plans.json 串发（按表重试）；非池域名交系统 DNS 直接连接。

pub mod mitm;
pub mod upstream;

use crate::certgen::Authority;
use crate::config::{self, HEAD_TIMEOUT_SECS};
use crate::pool::{self, dial::Dialed, LogFn};
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
    (srv.log)("代理已启动");
    set_running(true);
    loop {
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
        tokio::spawn(async move {
            let _ = srv.handle(conn).await;
        });
    }
}

impl ProxyServer {
    async fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        let _ = client.set_nodelay(true);
        upstream::note_activity();
        let head = read_head(&mut client).await?;
        // 头块以 \r\n\r\n 收尾；之后的字节是同包到达的请求体首段，必须原样续传。
        // 明文 HTTP 分发前先切开：体混进头重拼会把体当头行转发、真体丢失。
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
            self.handle_connect(client, &target).await;
        } else {
            self.handle_http(client, &method, &target, headers, body_prefix)
                .await;
        }
        Ok(())
    }

    async fn handle_connect(&self, mut client: TcpStream, target: &str) {
        let (host, port) = split_target(target, 443);
        if mitm::mitm_scope(self.authority.as_ref(), &host) {
            mitm::handle_connect_mitm(self, client, &host).await;
            return;
        }
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(_) => {
                reject(&mut client, &self.log, &host).await;
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
        (self.log)(&format!("[CONNECT] {host} via {ip} -> 200已发, 开始转发"));

        let (sent, recv) = bidir_copy(
            &mut client,
            &mut upstream,
            Some(std::time::Duration::from_secs(
                config::TUNNEL_FIRST_BYTE_TIMEOUT_SECS,
            )),
            true,
        )
        .await;
        (self.log)(&format!("[隧道] {host} via {ip}: ↑{sent} ↓{recv}B"));

        let name = config::pool_for(&host);
        if !name.is_empty() && ip != "system-dns" {
            match (sent, recv) {
                (s, r) if s > 0 && r > 0 => pool::cursor_note(name, &host, &ip, true),
                (s, r) if s > 0 && r == 0 => {
                    pool::cursor_note(name, &host, &ip, false);
                    (self.log)(&format!("[串发] {host} 客户端已握手但零回包, 垫底换下一个"));
                }
                _ => {}
            }
            // 曾经这里按"双向都 <8KB"猜风控小响应并垫底换 IP——304 与任意小响应都符合，
            // 每开一个页面就把驻留记号挪一格（还带一次 settings 落盘）。透传看不见状态码，
            // 这种猜测注定误判；风控页化解只在 MITM 下做。
        }
    }

    async fn handle_http(
        &self,
        mut client: TcpStream,
        method: &str,
        target: &str,
        headers: &[u8],
        body_prefix: &[u8],
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
        // 分块体过不去：transfer-encoding 是逐跳头，转发前就被剥掉，
        // 块长度行会被上游当成正文——宁可 501 也不静默改坏数据。
        if headers_have_chunked(headers) {
            (self.log)(&format!("[拒绝] {host} 明文 HTTP 分块请求体不支持, 回 501"));
            let _ = client
                .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(_) => {
                reject(&mut client, &self.log, &host).await;
                return;
            }
        };

        let head_text = String::from_utf8_lossy(headers);
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n");
        for l in head_text.lines() {
            let l = l.trim_end_matches('\r');
            let low = l.to_lowercase();
            // 逐跳头不过上游（与 MITM 路径同一份名单）：客户端转来的
            // connection: close 会让上游收完即关，转发语义被带偏。
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
        // 先写重拼后的头，再补"与头同包到达"的体首段（无则跳过），之后交给双向泵。
        // 写失败 = 上游已坏，按 recv=0 垫底；与正常收尾共用同一条记账路径。
        let mut head_sent = upstream.write_all(req.as_bytes()).await.is_ok();
        if head_sent && !body_prefix.is_empty() {
            head_sent = upstream.write_all(body_prefix).await.is_ok();
        }
        let recv = if head_sent {
            bidir_copy(&mut client, &mut upstream, None, false).await.1
        } else {
            0
        };
        let name = config::pool_for(&host);
        if !name.is_empty() && ip != "system-dns" {
            pool::cursor_note(name, &host, &ip, recv > 0);
        }
    }
}

/// 无可用上游：502 + 一行日志（CONNECT 与明文 HTTP 共用出口）。
async fn reject(client: &mut TcpStream, log: &LogFn, host: &str) {
    let _ = client
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        .await;
    log(&format!("[拒绝] {host} 无可用上游"));
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

/// 上游唯一入口：串发池域名(core/api/edge)按 plans.json 串发（按表重试）；
/// 非串发池域名(fastly/codeload 等纯镜像池)与非池域名交系统 DNS 直接连接。
pub async fn connect_upstream(host: &str, port: u16) -> Result<(Dialed, String), String> {
    let name = config::pool_for(host);
    if pool::SERIAL_POOLS.contains(&name) {
        let (conn, ip, _shape) =
            pool::serial_dial_skip(name, host, CancellationToken::new(), false, None, None).await?;
        return Ok((conn, ip));
    }
    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("系统 DNS 拨号超时: {host}"))?
        .map_err(|e| format!("系统 DNS 拨号失败: {host}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    Ok((Dialed::Plain(tcp), "system-dns".to_string()))
}

/// 双向透传，任一方向结束即关闭两侧。返回 (a→b, b→a) 字节数。
/// b→a 可选首字节看门狗（ClientHello 黑洞判死）；a→b 可选 TLS 握手首包分片（隧道反 SNI RST）。
async fn bidir_copy<A, B>(
    a: &mut A,
    b: &mut B,
    first_byte: Option<std::time::Duration>,
    split_hello: bool,
) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    // 同一任务内交替轮询两拷贝循环；任一方向 EOF/错误即收尾。
    let (up, down) = tokio::join!(
        copy_with_first_byte_timeout(&mut ar, &mut bw, None, split_hello),
        copy_with_first_byte_timeout(&mut br, &mut aw, first_byte, false),
    );
    (up, down)
}

/// 轻量随机（stdlib RandomState 技巧，避免引入 rand 依赖）：每次调用值不同。
fn fresh_rand() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new().build_hasher().finish()
}

fn split_delay() -> std::time::Duration {
    let span = config::HELLO_SPLIT_DELAY_MAX_MS - config::HELLO_SPLIT_DELAY_MIN_MS + 1;
    std::time::Duration::from_millis(
        config::HELLO_SPLIT_DELAY_MIN_MS + (fresh_rand() % span),
    )
}

/// TLS 握手首段分片方案：返回切点列表（升序无缝，2~3 段，切点每连接随机）。
/// 仅当总闸开启、首字节为 0x16(TLS 握手)且长度足够才拆——SSH/HTTP/过短流一律不碰。
fn hello_split_ranges(first_read: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    if !config::HELLO_SPLIT_ENABLED || first_read.len() < 32 || first_read[0] != 0x16 {
        return None;
    }
    let n = first_read.len();
    let r = fresh_rand();
    // 首刀：1..=16 字节（覆盖 TLS 记录头一带，具体位置随机）
    let c1 = 1 + (r % config::HELLO_SPLIT_FIRST_MAX as u64) as usize;
    // 约 2/3 概率三段：二刀落在 n 的 1/3 ~ 2/3 处（SNI 通常在这一带）
    let three = (r >> 8) % 3 != 0;
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

/// 转发一路：可选首字节看门狗（超时 = 判死），其后普通泵；收尾 shutdown 让对端见 EOF。
/// a→b 方向可拆 TLS 握手首包：记录头单独成段 + 间隔 + 余下，DPI 拼不齐 SNI（见 config 常量）。
async fn copy_with_first_byte_timeout<R, W>(
    r: &mut R,
    w: &mut W,
    first_byte: Option<std::time::Duration>,
    split_tls_hello: bool,
) -> u64
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    let mut first = true;
    if let Some(dur) = first_byte {
        match tokio::time::timeout(dur, r.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                if w.write_all(&buf[..n]).await.is_err() {
                    return total;
                }
                total += n as u64;
                first = false;
            }
            _ => {
                let _ = w.shutdown().await;
                return total;
            }
        }
    }
    loop {
        let n = match r.read(&mut buf).await {
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
mod tests {
    use super::*;

    #[test]
    fn host_only_strips_port() {
        assert_eq!(host_only("github.com:443"), "github.com");
        assert_eq!(host_only("[::1]:443"), "[::1]");
        assert_eq!(host_only("github.com"), "github.com");
    }

    #[test]
    fn split_target_parses_and_defaults() {
        assert_eq!(split_target("github.com:443", 443), ("github.com".into(), 443));
        assert_eq!(split_target("github.com", 80), ("github.com".into(), 80));
        assert_eq!(split_target("[::1]:8443", 443), ("[::1]".into(), 8443));
        assert_eq!(split_target("[::1]", 443), ("[::1]".into(), 443));
        assert_eq!(
            split_target("github.com:notaport", 80),
            ("github.com:notaport".into(), 80)
        );
    }

    /// 明文 HTTP 分发：与头同包到达的请求体必须原样续传（曾把体当头转发、真体丢失）。
    /// 127.0.0.1 非池域名走系统直连腿，恰好落在本进程起的假上游上，全程无外网。
    #[tokio::test]
    async fn plain_http_post_body_forwarded_intact() {
        // 假上游：读满 头 + Content-Length 体，校验体原样、头无混入，然后回 200。
        let up_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up_ln.local_addr().unwrap().port();
        let up_task = tokio::spawn(async move {
            let (mut sock, _) = up_ln.accept().await.unwrap();
            let mut raw: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            let (head_end, body_len) = loop {
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head_text = String::from_utf8_lossy(&raw[..pos]);
                    let cl = head_text
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if !k.trim().eq_ignore_ascii_case("content-length") {
                                return None;
                            }
                            v.trim().parse::<usize>().ok()
                        })
                        .unwrap_or(0);
                    if raw.len() >= pos + 4 + cl {
                        break (pos, cl);
                    }
                }
                let n = tokio::time::timeout_at(deadline, sock.read(&mut chunk))
                    .await
                    .expect("上游读超时: 请求体未被转发")
                    .unwrap();
                assert!(n > 0, "上游连接被提前关闭");
                raw.extend_from_slice(&chunk[..n]);
            };
            let head_text = String::from_utf8_lossy(&raw[..head_end]).to_string();
            let body = &raw[head_end + 4..head_end + 4 + body_len];
            assert_eq!(body, b"hello", "体应原样出现在头块之后");
            assert!(!head_text.contains("hello"), "体被当头转发: {head_text}");
            assert_eq!(
                head_text.matches("Content-Length: 5").count(),
                1,
                "Content-Length 不应重复: {head_text}"
            );
            // 逐跳头不过上游：客户端发来的 connection 必须在转发前剥掉
            // （connection 白名单里的逐跳头与 proxy-*/host 一并在此兜底）。
            assert!(
                !head_text.to_lowercase().contains("connection:"),
                "connection 逐跳头泄漏到上游: {head_text}"
            );
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        // 代理本体：起在随机端口，直接复用 serve()（不经 start_proxy_with 免端口腾挪）。
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = ln.local_addr().unwrap().port();
        let log: LogFn = Arc::new(|_: &str| {});
        let srv = Arc::new(ProxyServer {
            log,
            authority: None,
        });
        let ctx = CancellationToken::new();
        let serve_task = tokio::spawn(serve(srv, ln, ctx.clone()));

        let mut cli = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .unwrap();
        // 一次 write：头与体同包到达（正是当年被吞的形态）；明文走代理必须绝对 URI。
        // 顺带带 Connection/Keep-Alive 逐跳头：假上游断言它们被剥除（曾原样泄漏，
        // 上游收完即关导致代理转发语义被逐跳头带偏）。
        let req = format!(
            "POST http://127.0.0.1:{up_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"
        );
        cli.write_all(req.as_bytes()).await.unwrap();

        let mut resp: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !(resp.windows(4).any(|w| w == b"\r\n\r\n") && resp.ends_with(b"ok")) {
            let mut chunk = [0u8; 1024];
            let n = tokio::time::timeout_at(deadline, cli.read(&mut chunk))
                .await
                .expect("客户端读超时: 未收到响应")
                .unwrap();
            assert!(n > 0, "代理提前关闭客户端连接");
            resp.extend_from_slice(&chunk[..n]);
        }
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));

        up_task.await.unwrap();
        ctx.cancel();
        let _ = serve_task.await;
    }

    /// 明文 HTTP 分块体：识别出来就走 501，不把块长度行当正文喂给上游。
    #[test]
    fn chunked_request_body_is_refused() {
        assert!(headers_have_chunked(
            b"Host: a\r\nTransfer-Encoding: chunked\r\n"
        ));
        assert!(headers_have_chunked(b"transfer-encoding: gzip, chunked\r\n"));
        assert!(!headers_have_chunked(
            b"Content-Length: 5\r\nConnection: close\r\n"
        ));
        assert!(!headers_have_chunked(b""));
    }

    /// 分片门槛：TLS 握手(0x16)且够长才拆；SSH/HTTP/过短流不拆。
    /// 拆分形态：2~3 段、无缝覆盖全量、首刀 1..=16。
    #[test]
    fn hello_split_ranges_gate() {
        let tls_long: Vec<u8> = std::iter::once(0x16u8)
            .chain(std::iter::repeat(0u8).take(300))
            .collect();
        let ranges = hello_split_ranges(&tls_long).expect("TLS 握手应拆");
        assert!(ranges.len() == 2 || ranges.len() == 3, "段数应在 2~3: {ranges:?}");
        assert_eq!(ranges.first().unwrap().start, 0);
        assert!(ranges.first().unwrap().len() >= 1);
        assert!(ranges.first().unwrap().len() <= config::HELLO_SPLIT_FIRST_MAX);
        let mut cursor = 0usize;
        for r in &ranges {
            assert_eq!(r.start, cursor, "切点应无缝衔接: {ranges:?}");
            cursor = r.end;
        }
        assert_eq!(cursor, tls_long.len(), "应覆盖整个首段: {ranges:?}");

        let tls_short = vec![0x16u8, 0x03, 0x01];
        assert!(hello_split_ranges(&tls_short).is_none(), "过短流不拆");

        let ssh: Vec<u8> = b"SSH-2.0-OpenSSH".to_vec();
        assert!(hello_split_ranges(&ssh).is_none(), "非 TLS 流不拆");

        assert!(hello_split_ranges(&[]).is_none(), "空流不拆");
    }

    /// 随机化：同一载荷多次拆分，首刀位置必须出现变化（防退化成固定形态被签名）。
    #[test]
    fn hello_split_randomizes_cuts() {
        let tls_long: Vec<u8> = std::iter::once(0x16u8)
            .chain(std::iter::repeat(0u8).take(600))
            .collect();
        let mut firsts = std::collections::HashSet::new();
        let mut seg_counts = std::collections::HashSet::new();
        for _ in 0..40 {
            let ranges = hello_split_ranges(&tls_long).expect("应拆");
            firsts.insert(ranges[0].len());
            seg_counts.insert(ranges.len());
        }
        assert!(
            firsts.len() >= 3,
            "40 次拆分首刀位置应多变(随机化失效?): {firsts:?}"
        );
        assert!(
            seg_counts.len() >= 2,
            "段数应在 2~3 间变化: {seg_counts:?}"
        );
    }

    /// 首包分片不丢字节：TLS 握手载荷经分片转发后必须完整到达对端。
    #[tokio::test]
    async fn tunnel_hello_split_relays_all_bytes() {
        let (mut client, mut relay_in) = tokio::io::duplex(4096);
        let (mut relay_out, mut upstream) = tokio::io::duplex(4096);
        let payload: Vec<u8> = std::iter::once(0x16u8)
            .chain((0u8..=255).cycle().take(400))
            .collect();

        let writer = {
            let payload = payload.clone();
            tokio::spawn(async move {
                client.write_all(&payload).await.unwrap();
                drop(client); // EOF：让拷贝循环收尾
            })
        };
        let copier = tokio::spawn(async move {
            copy_with_first_byte_timeout(&mut relay_in, &mut relay_out, None, true).await
        });

        writer.await.unwrap();
        let sent = copier.await.unwrap();
        assert_eq!(sent, payload.len() as u64, "转发字节数应与载荷一致");

        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream.read_to_end(&mut received),
        )
        .await
        .expect("读超时：分片转发未收尾")
        .unwrap();
        assert_eq!(received, payload, "分片不得丢改字节");
    }
}
