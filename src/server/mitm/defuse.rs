//! gh_defuse：GitHub 风控拦截页(403 restricted / 400 Whoa)本地嗅探与 IP 轮换化解。
use super::{get_direct, PeekRaw, UpstreamInfo};
use crate::pool;
use crate::server::protocol::BoxBody;
use crate::server::upstream;
use crate::util::{lock, LogFn};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 换尽 IP 仍风控的落盘限频：同 host 30s 只留首条。
static LAST_GIVEUP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn giveup_logged_recently(host: &str) -> bool {
    let map = LAST_GIVEUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = lock(map);
    let now = Instant::now();
    g.retain(|_, t| now - *t < Duration::from_secs(30));
    g.insert(host.to_string(), now).is_some()
}

/// 边收边解压判前 4KB（br/gzip），原始压缩帧留作 PeekRaw。
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
    if !enc.is_empty() && enc != "identity" && enc != "gzip" && enc != "br" {
        return false;
    }
    let compressed = !enc.is_empty() && enc != "identity";
    let mut raw: Vec<Bytes> = Vec::new();
    let mut comp: Vec<u8> = Vec::new();
    let mut plain: Vec<u8> = Vec::new();
    let body = resp.body_mut();
    while plain.len() < 4096 && raw.len() < 8 {
        match http_body_util::BodyExt::frame(body).await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if compressed {
                        comp.extend_from_slice(&data);
                        plain = decompress_partial(&comp, &enc, 8192);
                    } else {
                        plain.extend_from_slice(&data);
                    }
                    raw.push(data);
                    if compressed && comp.len() > 128 * 1024 {
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
    // 400 只认 GitHub 风控文案（"has been restricted"/"whoa there"）；通用 400 不换 IP。
    chunk.contains("has been restricted") || chunk.contains("whoa there")
}

/// 风控重试上限 24 ≈ 路由候选全试一遍；后续请求共享边冷却不重扫。
const DEFUSE_MAX_TRIES: usize = 24;

/// 解风控单步：归属缺失最多重试 3 次，正常分支试满 DEFUSE_MAX_TRIES。
fn defuse_retry(ip_empty: bool, empty_retries: u8, tried: usize) -> bool {
    if ip_empty {
        return empty_retries <= 3;
    }
    tried < DEFUSE_MAX_TRIES
}

/// 解压缩前 max 字节：gzip→GzDecoder，br→BrotliDecoder，其余原样截取。
pub(super) fn decompress_partial(data: &[u8], enc: &str, max: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    match enc {
        "gzip" => {
            let _ = flate2::read::GzDecoder::new(data)
                .take(max as u64)
                .read_to_end(&mut out);
        }
        "br" => {
            let dec = brotli_decompressor::Decompressor::new(data, 4096);
            let _ = dec.take(max as u64).read_to_end(&mut out);
        }
        _ => out.extend_from_slice(&data[..data.len().min(max)]),
    }
    out
}

pub(super) async fn gh_defuse(
    log: &LogFn,
    host: &str,
    info: &UpstreamInfo,
    out: &hyper::Request<BoxBody>,
    body: &Option<Bytes>,
) -> Result<hyper::Response<BoxBody>, String> {
    let mut resp = get_direct(log, out, host, info, body).await?;
    let mut tried = 0; // 已重试候选数（仅日志）
    let mut seen: Vec<String> = Vec::new(); // 本轮已试 IP（仅日志链）
    let mut empty_ip_retries = 0u8; // 归属缺失分支重试计数
    loop {
        if !is_gh_block_page(&mut resp).await {
            return Ok(resp);
        }
        let ip = info.lock().unwrap().clone();
        if !pool::route::is_managed(host) {
            return Ok(resp); // 非受管域名：无表可换，透传
        }
        if ip.is_empty() {
            empty_ip_retries += 1;
            if !defuse_retry(true, empty_ip_retries, tried) {
                return Ok(resp);
            }
            resp = match get_direct(log, out, host, info, body).await {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            continue;
        }
        pool::cursor_note(host, &ip, false); // 数据层失败：前移游标，重试跳过该 IP
                                                // 风控页记 10 分钟边冷却，免疫成功回写。
        if let Some(row) = pool::route::route_for(host) {
            pool::edges::mark_risk(&ip, &row.key);
        }
        upstream::drop_h2(&ip);
        // 垫底后下一轮串发跳过该 IP。
        tried += 1;
        // 垫底+拔连接须在判定前；seen 仅用于日志 IP 链。
        seen.push(ip.to_string());
        if !defuse_retry(false, empty_ip_retries, tried) {
            // 这是 GitHub 对本机出口 IP 的人机验证，不是本程序故障。
            if !giveup_logged_recently(host) {
                (log)(&format!(
                    "[MITM] {host} 连换 {tried} 个 IP({}) 都是 GitHub 风控页, 原样返回该请求(后台请求页面未必看得见)",
                    seen.join("→")
                ));
            }
            return Ok(resp);
        }
        // 静默重试（物理换 IP 有拨号日志）。
        resp = match get_direct(log, out, host, info, body).await {
            Ok(r) => r,
            Err(e) => return Err(e), // 重试全灭：交回错误
        };
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/defuse.rs"]
mod tests;
