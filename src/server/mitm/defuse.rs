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

/// 「换尽 IP 仍是风控页」的落盘限频：同 host 30s 内只留首条。
/// 风控风暴时十几个并发请求会各自走到这里，连刷十几行像系统出大事，实际只是同一个风控窗。
static LAST_GIVEUP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn giveup_logged_recently(host: &str) -> bool {
    let map = LAST_GIVEUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = lock(map);
    let now = Instant::now();
    g.retain(|_, t| now - *t < Duration::from_secs(30));
    g.insert(host.to_string(), now).is_some()
}

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

/// 风控重试记号上限：≈把路由表里的候选全试一遍。风控页偶尔换边缘真能通，
/// 不替 GitHub 提前放弃；同一波并发的后续请求共享边冷却，不会各自重扫成请求风暴。
const DEFUSE_MAX_TRIES: usize = 24;

/// 解风控单步决策（纯函数）：归属缺失最多重试 3 次；正常分支试满 DEFUSE_MAX_TRIES 才停。
/// 旧版"同 IP 再现 = 全员拦截页"不成立：3 轮就回头的根因是风控冷却被并发的"成功"回写洗掉
/// （edges::clear 已改为只清短冷却），不是"所有 IP 都风控"。
fn defuse_retry(ip_empty: bool, empty_retries: u8, tried: usize) -> bool {
    if ip_empty {
        return empty_retries <= 3;
    }
    tried < DEFUSE_MAX_TRIES
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
    let mut seen: Vec<String> = Vec::new(); // 本轮已试 IP，保序只为日志链
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
            if !defuse_retry(true, empty_ip_retries, tried) {
                return Ok(resp);
            }
            resp = match get_direct(log, out, host, info, is_simple, body).await {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            continue;
        }
        pool::cursor_note(host, &ip, false, 1); // 数据层失败: 记号前移, 重试自动跳过该 IP
                                                // 风控页记 10 分钟边冷却, 免疫"成功"回写(否则会被并发的 block 页当场洗掉)。
        if let Some(row) = pool::route::route_for(host) {
            pool::edges::mark_risk(&ip, &row.key);
        }
        upstream::drop_h2(&ip);
        // 直连腿每请求新拨号，无共享池可丢；垫底后下一轮串发自然跳过该 IP。
        tried += 1;
        // 垫底与拔连接必须在判定之前，否则坏连接还挂在缓存里。
        // seen 只为交付日志的 IP 链：正常应无重复，链尾重复 = 风控冷却又被洗掉了（留证）。
        seen.push(ip.to_string());
        if !defuse_retry(false, empty_ip_retries, tried) {
            // 语气按真实严重度来：不是本程序故障，是 GitHub 对本机出口 IP 弹人机验证。
            if !giveup_logged_recently(host) {
                (log)(&format!(
                    "[MITM] {host} 连换 {tried} 个 IP({}) 都是 GitHub 风控页, 原样返回该请求(后台请求页面未必看得见)",
                    seen.join("→")
                ));
            }
            return Ok(resp);
        }
        // 每请求命中拦截页都打一条会在风控风暴时同秒刷十几行（看着像"一 IP 多通道"失效），
        // 物理换 IP 有 [上游] 拨号日志，这里静默重试。
        resp = match get_direct(log, out, host, info, is_simple, body).await {
            Ok(r) => r,
            Err(e) => return Err(e), // 重试全灭(所有候选试遍): 交回错误
        };
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/defuse.rs"]
mod tests;
