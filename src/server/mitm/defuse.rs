//! gh_defuse：GitHub 风控拦截页(403 restricted / 400 Whoa)本地嗅探与 IP 轮换化解。
use super::{get_direct, BoxBody, PeekRaw, UpstreamInfo};
use crate::server::upstream;
use crate::pool::{self, LogFn};
use bytes::Bytes;

/// 上游强制 gzip 后边收边解压判前 4KB，已消费原始压缩帧原样保留（PeekRaw）。
async fn is_gh_block_page(resp: &mut hyper::Response<BoxBody>) -> bool {
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if !ct.contains("text/html") {
        return false;
    }
    let enc = resp
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !enc.is_empty() && enc != "identity" && enc != "gzip" {
        return false;
    }
    let gz = enc == "gzip";
    let mut raw: Vec<Bytes> = Vec::new();
    let mut comp: Vec<u8> = Vec::new();
    let mut plain: Vec<u8> = Vec::new();
    let body = resp.body_mut();
    while plain.len() < 4096 && raw.len() < 8 {
        match http_body_util::BodyExt::frame(body).await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if gz {
                        comp.extend_from_slice(&data);
                        plain = gunzip_partial(&comp, 8192);
                    } else {
                        plain.extend_from_slice(&data);
                    }
                    raw.push(data);
                    if gz && comp.len() > 128 * 1024 {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    if raw.is_empty() {
        return false;
    }
    resp.extensions_mut().insert(PeekRaw(raw));
    if plain.is_empty() {
        return false;
    }
    let chunk = String::from_utf8_lossy(&plain[..plain.len().min(4096)]).to_lowercase();
    chunk.contains("has been restricted")
        || chunk.contains("whoa there")
        || (resp.status() == http::StatusCode::BAD_REQUEST && chunk.contains("bad request"))
}

/// 解风控循环的单步决策（纯函数，便于测试）：
/// 归属缺失 → 重试上限 3 次；同 IP 再现 = 全员拦截页 → 交回真实响应。
fn defuse_retry(ip_empty: bool, empty_retries: u8, ip_seen: bool) -> bool {
    if ip_empty {
        return empty_retries <= 3;
    }
    !ip_seen
}

/// 解 gzip 的前 max 字节（page_cache 的未登录页检测共用：主站正文恒压缩）。
pub(super) fn gunzip_partial(data: &[u8], max: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(data)
        .take(max as u64)
        .read_to_end(&mut out);
    out
}

pub(super) async fn gh_defuse(
    log: &LogFn,
    host: &str,
    info: &UpstreamInfo,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let name = crate::config::pool_for(host);
    let is_simple = true;
    let mut resp = get_direct(log, out, host, info, is_simple, body).await?;
    let mut tried = 0; // 已垫底重试候选数(仅日志)
    let mut seen = std::collections::HashSet::new(); // 本轮已试 IP
    let mut empty_ip_retries = 0u8; // 归属缺失分支的重试上限
    loop {
        if !is_gh_block_page(&mut resp).await {
            return Ok(resp);
        }
        let ip = info.lock().unwrap().clone();
        if name.is_empty() {
            return Ok(resp); // 非池域名: 无表可换, 诚实透传
        }
        if ip.is_empty() {
            empty_ip_retries += 1;
            if !defuse_retry(true, empty_ip_retries, false) {
                return Ok(resp);
            }
            resp = match get_direct(log, out, host, info, is_simple, body).await {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            continue;
        }
        pool::cursor_note(name, host, &ip, false); // 数据层失败: 记号前移, 重试自动跳过该 IP
                                               // 风控页 = 该 IP 的连接不可信(HTTP 层成功所以连接活着) —— 必须同步
                                               // 清复用槽, 否则下一个请求缓存命中又拿到坏连接: 垫底→重拨→再命中→
                                               // 再垫底乒乓死循环(2026-10-15 实锤: 单 IP 重试计数刷到 129, 每个请求
                                               // 白烧一次完整往返, 搜索/进仓库全部变慢)
        upstream::drop_h2(host, &ip);
        // 2026-10-14 起直连腿每请求新拨号(fresh), 无共享连接池可丢 ——
        // 垫底后下一 attempt 的 serial_dial 必然跳过该 IP
        tried += 1;
        // 整表轮换完一圈(同 IP 再现) = 全员拦截页: 再转只会重复, 交回 GitHub
        // 真实拦截响应终止。垫底+拔连接必须发生在终止判定之前 —— 否则交付时
        // 坏连接仍挂在复用缓存, 下个请求乒乓(2026-10-17 复审补充)
        let ip_seen = !seen.insert(ip.to_string());
        if !defuse_retry(false, empty_ip_retries, ip_seen) {
            (log)(&format!(
                "[MITM] {host} 全部可用边缘均返回拦截页({tried}), 交付真实响应"
            ));
            return Ok(resp);
        }
        (log)(&format!(
            "[MITM] {host} 边缘 {ip} 返回风控拦截页, 垫底换 IP 重试({tried})"
        ));
        resp = match get_direct(log, out, host, info, is_simple, body).await {
            Ok(r) => r,
            Err(e) => return Err(e), // 重试全灭(所有候选试遍): 交回错误
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defuse_retry_decision() {
        // 空归属：重试上限 3 次
        assert!(defuse_retry(true, 0, false));
        assert!(defuse_retry(true, 3, false));
        assert!(!defuse_retry(true, 4, false));
        // 有归属：新 IP 重试，同 IP 再现 = 全灭终止
        assert!(defuse_retry(false, 0, false));
        assert!(!defuse_retry(false, 0, true));
    }

    #[tokio::test]
    async fn gzip_sniff_detects_block_and_keeps_raw_prefix() {
        use std::io::Write;
        fn gzip(data: &[u8]) -> Vec<u8> {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        let mut html = b"<!doctype html><html><body><h1>".to_vec();
        html.extend_from_slice(&vec![b'a'; 2000]);
        html.extend_from_slice(b"</h1><p>Whoa there, pardner!</p></body></html>");
        let compressed = gzip(&html);
        let body = upstream::full_body(Bytes::from(compressed.clone()));
        let (parts, _) = hyper::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let mut resp = hyper::Response::from_parts(parts, body);
        assert!(is_gh_block_page(&mut resp).await, "gzip 压缩的拦截页应被判定");
        let raw = resp
            .extensions()
            .get::<PeekRaw>()
            .expect("必须保留原始压缩帧")
            .0
            .clone();
        let joined: Vec<u8> = raw.iter().flat_map(|b| b.to_vec()).collect();
        assert!(!joined.is_empty());
        assert!(
            compressed.starts_with(&joined),
            "写回前缀必须是原始压缩流的真前缀"
        );
        let normal = gzip(b"<!doctype html><html><body>hello</body></html>");
        let body2 = upstream::full_body(Bytes::from(normal));
        let (parts2, _) = hyper::Response::builder()
            .header("content-type", "text/html")
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let mut resp2 = hyper::Response::from_parts(parts2, body2);
        assert!(!is_gh_block_page(&mut resp2).await);
    }
}
