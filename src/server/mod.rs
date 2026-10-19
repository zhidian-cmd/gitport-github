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

// ---------- 代理启停（全局控制，main/webui 共用） ----------

static PROXY_CTX: std::sync::Mutex<Option<CancellationToken>> = std::sync::Mutex::new(None);
static PROXY_JOIN: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>> =
    std::sync::Mutex::new(None);

/// 同步绑定端口 + 启动服务。返回错误 = 端口被占用等真实失败。
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

/// 停止代理并等待端口释放（同步返回前端口已可复用）。
pub fn stop_proxy(rt: &tokio::runtime::Runtime) {
    rt.handle().block_on(stop_proxy_async());
}

pub async fn stop_proxy_async() {
    let ctx = PROXY_CTX.lock().unwrap().take();
    if let Some(c) = ctx {
        c.cancel();
    }
    let join = PROXY_JOIN.lock().unwrap().take();
    if let Some(j) = join {
        let _ = j.await;
    }
}

/// 在已绑定的 listener 上服务，ctx 取消时优雅退出。
pub async fn serve(srv: Arc<ProxyServer>, ln: TcpListener, ctx: CancellationToken) {
    let _ = ln.local_addr();
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
                    continue;
                }
            },
        };
        let srv = srv.clone();
        tokio::spawn(async move {
            // 单连接错误不致命
            let _ = srv.handle(conn).await;
        });
    }
}

impl ProxyServer {
    async fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        let _ = client.set_nodelay(true);
        // 活跃窗口计时: 保持上游 h2 保活
        upstream::note_activity();
        let head = read_head(&mut client).await?;
        let Some(idx) = find_crlf(&head) else {
            return Ok(());
        };
        let line = String::from_utf8_lossy(&head[..idx]).to_string();
        let rest = &head[idx + 2..];
        let mut parts = line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        if method == "CONNECT" {
            self.handle_connect(client, &target).await;
        } else {
            self.handle_http(client, &method, &target, rest).await;
        }
        Ok(())
    }

    /// CONNECT 隧道（纯透传路径）：上游 TCP 拨号（串发或系统 DNS）→ 200 →
    /// 双向转发。首字节看门狗 + 数据层结果回写串发表。
    async fn handle_connect(&self, mut client: TcpStream, target: &str) {
        let (host, port) = split_target(target, 443);
        // 池内域名且 MITM 开：本地终结 TLS
        if mitm::mitm_scope(self.authority.as_ref(), &host) {
            mitm::handle_connect_mitm(self, client, &host).await;
            return;
        }
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(_) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                (self.log)(&format!("[拒绝] {host} 无可用上游"));
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

        // 首字节看门狗：ClientHello 被黑洞时 8s 内判死
        let (sent, recv) = bidir_copy(
            &mut client,
            &mut upstream,
            Some(std::time::Duration::from_secs(
                config::TUNNEL_FIRST_BYTE_TIMEOUT_SECS,
            )),
        )
        .await;
        (self.log)(&format!("[隧道] {host} via {ip}: ↑{sent} ↓{recv}B"));

        let name = pool::pool_for(&host);
        if !name.is_empty() && ip != "system-dns" {
            // 数据层结果回写串发表
            match (sent, recv) {
                (s, r) if s > 0 && r > 0 => pool::serial_note(name, &ip, "ok"),
                (s, r) if s > 0 && r == 0 => {
                    pool::serial_note(name, &ip, "noreply");
                    (self.log)(&format!("[串发] {host} 客户端已握手但零回包, 垫底换下一个"));
                }
                _ => {}
            }
            // github.com 网页风控逃生（透传看不见状态码，用流量指纹记账）
            if host == "github.com" && sent > 0 && sent < 8192 && recv > 0 && recv < 8192 {
                pool::serial_note(name, &ip, "block");
                (self.log)(&format!(
                    "[串发] {host} 疑似风控小响应(↑{sent}↓{recv}B), 垫底换 IP"
                ));
            }
        }
    }

    /// 明文 HTTP 转发（非 CONNECT）：重写请求头后转发上游，双向透传。
    async fn handle_http(&self, mut client: TcpStream, method: &str, target: &str, rest: &[u8]) {
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
        let (mut upstream, ip) = match connect_upstream(&host, port).await {
            Ok(v) => v,
            Err(_) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                (self.log)(&format!("[拒绝] {host} 无可用上游"));
                return;
            }
        };

        // 重写请求头：origin-form + 真实 Host，剔除 hop 头
        let head_text = String::from_utf8_lossy(rest);
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n");
        for l in head_text.lines() {
            let l = l.trim_end_matches('\r');
            let low = l.to_lowercase();
            if low.starts_with("proxy-connection:")
                || low.starts_with("proxy-authorization:")
                || low.starts_with("host:")
            {
                continue;
            }
            req.push_str(l);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        if upstream.write_all(req.as_bytes()).await.is_err() {
            let name = pool::pool_for(&host);
            if !name.is_empty() && ip != "system-dns" {
                pool::serial_note(name, &ip, "other");
            }
            return;
        }
        let (_, recv) = bidir_copy(&mut client, &mut upstream, None).await;
        let name = pool::pool_for(&host);
        if !name.is_empty() && ip != "system-dns" {
            if recv == 0 {
                pool::serial_note(name, &ip, "noreply");
            } else {
                pool::serial_note(name, &ip, "ok");
            }
        }
    }
}

async fn read_head(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HEAD_TIMEOUT_SECS);
    loop {
        if buf.len() >= 65536 || contains_head_end(&buf) {
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

fn contains_head_end(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
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
    if pool::serial_pool(pool::pool_for(host)) {
        let (conn, ip, _shape) = pool::serial_dial(
            pool::pool_for(host),
            host,
            CancellationToken::new(),
            false,
            None,
        )
        .await?;
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
/// b→a 方向带首字节看门狗（可选）：第一次读到字节前设 dur 超时，
/// 超时 = 判死（上游 TCP 活着但 ClientHello 被黑洞的假节点）。
async fn bidir_copy<A, B>(
    a: &mut A,
    b: &mut B,
    first_byte: Option<std::time::Duration>,
) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    // 同一任务内交替轮询两拷贝循环；任一方向 EOF/错误即收尾。
    let (up, down) = tokio::join!(
        copy_with_first_byte_timeout(&mut ar, &mut bw, None),
        copy_with_first_byte_timeout(&mut br, &mut aw, first_byte),
    );
    (up, down)
}

/// 拷贝循环，可选首字节超时（None = 不限时）。超时/EOF/写失败即收尾。
async fn copy_with_first_byte_timeout<R, W>(
    r: &mut R,
    w: &mut W,
    first_byte: Option<std::time::Duration>,
) -> u64
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    let mut first = true;
    loop {
        let n = if first {
            first = false;
            match first_byte {
                Some(dur) => match tokio::time::timeout(dur, r.read(&mut buf)).await {
                    Err(_) => break, // 首字节看门狗超时：判死
                    Ok(Err(_)) => break,
                    Ok(Ok(n)) => n,
                },
                None => match r.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => break,
                },
            }
        } else {
            match r.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        if n == 0 {
            break;
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

    /// host_only：剥端口、IPv6 字面量安全、无端口原样返回。
    #[test]
    fn host_only_strips_port() {
        assert_eq!(host_only("github.com:443"), "github.com");
        assert_eq!(host_only("[::1]:443"), "[::1]");
        assert_eq!(host_only("github.com"), "github.com");
    }
}
