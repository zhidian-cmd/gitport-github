//! gh_defuse：GitHub 风控拦截页(403 restricted / 400 Whoa)本地嗅探与 IP 轮换化解。
use crate::server::protocol::BoxBody;
use super::{get_direct, PeekRaw, UpstreamInfo};
use crate::server::upstream;
use crate::pool;
use crate::util::LogFn;
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

/// 解风控单步决策（纯函数）：归属缺失最多重试 3 次；同 IP 再现 = 全员拦截页，交回真实响应。
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
        if !pool::route::is_managed(host) {
            return Ok(resp); // 非受管域名: 无表可换, 诚实透传
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
        pool::cursor_note(host, &ip, false, 1); // 数据层失败: 记号前移, 重试自动跳过该 IP
                                               // 风控页说明该 IP 的连接不可信，必须同步清复用槽，否则下个请求又拿到坏连接，垫底/重拨乒乓死循环。
        upstream::drop_h2(host, &ip);
        // 直连腿每请求新拨号，无共享池可丢；垫底后下一轮串发自然跳过该 IP。
        tried += 1;
        // 同 IP 再现 = 全员拦截页，再转只会重复；垫底与拔连接必须在终止判定之前，否则坏连接还挂在缓存里。
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
#[path = "../../tests/server/mitm/defuse.rs"]
mod tests;
