//! githubassets 资产库：immutable 资产按"资产名"一存长用（同资产不同哈希只保留最新），本地透明回放。
//! 落盘槽位按资产名寻址（URL 文件名去内容哈希）；条目 = [4B 头长][头 json(key/status/headers)][体]。
//! 只收 js/css/字体；URL 一个字符不改地回放，CSP/SRI 天然完好。容量 25MB，超限按文件年龄淘汰。
//! 时代中立：取侧校验条目 key 与请求 URL 精确相等——同资产换哈希 = miss = 回源拉新覆盖，永不跨发版给错内容。

use crate::server::protocol::{self, BoxBody};
use crate::server::upstream;
use crate::util::LogFn;
use bytes::Bytes;
use http::StatusCode;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub(super) const ASSET_HOST: &str = "github.githubassets.com";

/// FNV-1a 64：URL → 文件名，跨进程确定，零依赖。
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 资产库容量上限：超限按文件年龄从旧到新淘汰（被新版本取代的旧代条目天然最老，先走；
/// 误淘汰热资产无害——下次请求重拉入库，时间戳变新自动排到最后）。
const ASSET_MAX_BYTES: u64 = 25 * 1024 * 1024;
const ASSET_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const ASSET_DIR: &str = "assets";

/// 只收 js/css/字体（GitHub 资产的内容类型族），其余透传不存。
fn content_type_allowed(ct: &str) -> bool {
    let ct = ct.trim().to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("css") || ct.contains("font")
}

/// 从 URL 文件名提取"资产名"（去内容哈希）：同资产不同哈希归并到同一落盘槽位，
/// 写新版本 = 覆盖旧版本（只保留最新）。两族命名：
/// JS `[名字]-[哈希].js`（哈希 = 最后一个 '-' 之后的段，8..=16 位 [A-Za-z0-9_-]）；
/// CSS module `[名字].[16位hex].module.css`。不匹配 = None（按完整 URL 落盘，不参与归并，无害）。
fn asset_logical_name(url: &str) -> Option<String> {
    let filename = url.rsplit('/').next()?;
    let dot = filename.rfind('.')?;
    let stem = &filename[..dot];
    // CSS module 族：[名字].[16位hex].module.css
    if let Some(rest) = stem.strip_suffix(".module") {
        return match rest.rsplit_once('.') {
            Some((name, hash))
                if hash.len() == 16 && hash.bytes().all(|c| c.is_ascii_hexdigit()) =>
            {
                Some(format!("{name}.module"))
            }
            _ => None,
        };
    }
    // JS 族：[名字]-[哈希]
    let (name, hash) = stem.rsplit_once('-')?;
    ((8..=16).contains(&hash.len())
        && hash
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
    .then(|| name.to_string())
}

fn asset_path(dir: &std::path::Path, url: &str) -> std::path::PathBuf {
    // 同资产（名字相同）不同哈希共用一个槽位：写新版本覆盖旧版本（只保留最新）。
    let key = asset_logical_name(url).unwrap_or_else(|| url.to_string());
    dir.join(ASSET_DIR).join(format!("{:016x}", fnv1a(key.as_bytes())))
}

/// 资产库键：完整 URL（含查询串）。
pub(super) fn asset_request_url<B>(req: &hyper::Request<B>, host: &str) -> String {
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    format!("https://{host}{pq}")
}

/// 日志用：资产 URL 只露文件名。
pub(super) fn asset_dbg_name(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

/// 容量强制：总量超限则按修改时间从旧到新删，删到限额以内为止。返回淘汰条数。
fn enforce_cap(dir: &std::path::Path, max: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(dir.join(ASSET_DIR)) else {
        return 0;
    };
    let mut files: Vec<(std::time::SystemTime, u64, std::path::PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            Some((md.modified().ok()?, md.len(), e.path()))
        })
        .collect();
    let mut total: u64 = files.iter().map(|(_, len, _)| *len).sum();
    if total <= max {
        return 0;
    }
    files.sort_by_key(|(t, _, _)| *t);
    let mut evicted = 0usize;
    for (_, len, path) in files {
        if total <= max {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
            evicted += 1;
        }
    }
    evicted
}

/// 本地命中：按 URL 读回条目并重建响应（头原样带回，浏览器拿到 immutable 后自会停问）。
pub(super) fn take(dir: &std::path::Path, url: &str) -> Option<axum::response::Response<BoxBody>> {
    let raw = std::fs::read(asset_path(dir, url)).ok()?;
    if raw.len() < 4 {
        return None;
    }
    let hlen = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let end = 4usize.checked_add(hlen)?;
    if raw.len() < end {
        return None;
    }
    let header: serde_json::Value = serde_json::from_slice(&raw[4..end]).ok()?;
    if header.get("key").and_then(|k| k.as_str()) != Some(url) {
        return None; // 哈希碰撞不服务错文件
    }
    let st = header.get("status").and_then(|v| v.as_u64())?;
    if st != StatusCode::OK.as_u16() as u64 {
        return None;
    }
    let arr = header.get("headers").and_then(|v| v.as_array())?;
    let mut hdrmap = hyper::HeaderMap::new();
    for pair in arr {
        let (Some(k), Some(v)) = (
            pair.get(0).and_then(|x| x.as_str()),
            pair.get(1).and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            hdrmap.insert(name, val);
        }
    }
    let body = Bytes::copy_from_slice(&raw[end..]);
    let mut resp = hyper::Response::builder()
        .status(StatusCode::OK)
        .body(protocol::full_body(body))
        .ok()?;
    *resp.headers_mut() = hdrmap;
    Some(resp)
}

/// 入库（管家线程调用）：tmp 写全量 + rename 原子覆盖。
pub(super) fn persist_blocking(
    dir: &std::path::Path,
    url: &str,
    bytes: &[u8],
    hdrs: &[Vec<String>],
) -> Result<(), String> {
    std::fs::create_dir_all(dir.join(ASSET_DIR)).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("tmp")).map_err(|e| e.to_string())?;
    let header = serde_json::json!({
        "key": url,
        "status": StatusCode::OK.as_u16(),
        "headers": hdrs,
    });
    let hbytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(4 + hbytes.len() + bytes.len());
    buf.extend_from_slice(&(hbytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&hbytes);
    buf.extend_from_slice(bytes);
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = dir
        .join("tmp")
        .join(format!("{}.{uniq:x}", fnv1a(url.as_bytes())));
    std::fs::write(&tmp_path, &buf).map_err(|e| e.to_string())?;
    let final_path = asset_path(dir, url);
    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        e.to_string()
    })?;
    // 容量强制：超限淘汰最旧（新写入的时间戳最新，天然排最后）
    enforce_cap(dir, ASSET_MAX_BYTES);
    Ok(())
}

/// 入库准入门（collect 侧调用）：200 + 白名单类型 + 体积上限。
pub(super) fn storable(status: StatusCode, content_type: &str, body_len: usize) -> bool {
    status == StatusCode::OK
        && content_type_allowed(content_type)
        && body_len <= ASSET_MAX_BODY_BYTES
}

// ---------- 强绑定服务：资产请求只问资产库 ----------

/// 同 URL 在途拉取的等待者登记表：首个 miss 发起独立拉取，后续 miss 排队等同一份结果。
static INFLIGHT: OnceLock<Mutex<HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>>> =
    OnceLock::new();

fn inflight() -> &'static Mutex<HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 登记：返回 (完成通知接收端, 是否发起者)。发起者负责拉取并在完成后逐个唤醒。
fn register_waiter(url: &str) -> (tokio::sync::oneshot::Receiver<()>, bool) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut g = crate::util::lock(inflight());
    let v = g.entry(url.to_string()).or_default();
    let initiator = v.is_empty();
    v.push(tx);
    (rx, initiator)
}

/// 完成通知：逐个唤醒等待者并撤销登记。
fn signal_done(url: &str) {
    let waiters = crate::util::lock(inflight()).remove(url);
    if let Some(v) = waiters {
        for tx in v {
            let _ = tx.send(());
        }
    }
}

/// 资产请求强绑定入口：命中本地回放；miss 独立拉取（与浏览器连接解耦——浏览器中途放弃，
/// 拉取继续完成并入库）。返回 None = 独立拉取失败，调用方回落既有 switchboard 路径。
pub(super) async fn serve_or_fetch<B>(
    log: &LogFn,
    req: &hyper::Request<B>,
    host: &str,
) -> Option<axum::response::Response<BoxBody>> {
    let url = asset_request_url(req, host);
    let dir = super::page_cache::page_cache_dir();
    // ① 命中：本地回放
    if let Some(resp) = take(&dir, &url) {
        if super::quiet::first_time("assethit", &url) {
            (log)(&format!("[资产] 命中 {}", asset_dbg_name(&url)));
        }
        return Some(resp);
    }
    // ② miss：登记等待者；发起者拉起独立拉取任务（浏览器断开不影响）
    let (rx, initiator) = register_waiter(&url);
    if initiator {
        spawn_detached_fetch(dir.clone(), log.clone(), url.clone());
    }
    // ③ 等完成（发起者与后续等待者都等同一份结果）
    rx.await.ok()?;
    // ④ 从库出：命中 = 交付；没有 = 拉取失败/不可收录 → None 回落
    take(&dir, &url)
}

/// 独立拉取任务：向通道池申请通道拉取资产，门检通过即入库。与浏览器连接解耦——
/// 浏览器断开只影响 oneshot 接收端，任务持有发送端继续跑完。
fn spawn_detached_fetch(dir: std::path::PathBuf, log: LogFn, url: String) {
    tokio::spawn(async move {
        let ok = fetch_and_store(&dir, &log, &url).await;
        signal_done(&url);
        let _ = ok; // 结果已由 fetch_and_store 内部落日志
    });
}

/// 拉取 + 门检 + 入库。返回是否成功入库。
async fn fetch_and_store(dir: &std::path::Path, log: &LogFn, url: &str) -> bool {
    let name = asset_dbg_name(url);
    // ① 通道：池内现成通道，没有就拨（内容域竞速 IP）
    let (up, _) = match crate::pool::get_or_build(ASSET_HOST, "/", log).await {
        Ok(v) => v,
        Err(e) => {
            (log)(&format!("[资产] 独立拉取拨号失败({e}), {name} 本次不入库"));
            return false;
        }
    };
    // ② 请求
    let req = match hyper::Request::builder()
        .uri(url)
        .header("accept", "*/*")
        .header("user-agent", upstream::BROWSER_UA)
        .body(protocol::empty_body())
    {
        Ok(r) => r,
        Err(e) => {
            (log)(&format!("[资产] 请求构造失败({e}), {name} 本次不入库"));
            return false;
        }
    };
    // ③ 拉取收体
    let resp = match upstream::h2_send(&up, &req, &None::<Bytes>).await {
        Ok(r) => r,
        Err(e) => {
            (log)(&format!("[资产] 独立拉取失败({e}), {name} 本次不入库"));
            return false;
        }
    };
    let (parts, body) = resp.into_parts();
    if parts.status != StatusCode::OK {
        (log)(&format!(
            "[资产] 独立拉取上游 {}, {name} 不入库回落",
            parts.status.as_u16()
        ));
        return false;
    }
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let collected = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            (log)(&format!("[资产] 独立拉取收体失败({e}), {name} 本次不入库"));
            return false;
        }
    };
    // ④ 门检 + 入库
    if !storable(StatusCode::OK, &ct, collected.len()) {
        (log)(&format!("[资产] 不收录({ct} / {}B), {name} 回落", collected.len()));
        return false;
    }
    let hdrs: Vec<Vec<String>> = parts
        .headers
        .iter()
        .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
        .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
        .collect();
    match persist_blocking(dir, url, &collected, &hdrs) {
        Ok(_) => {
            (log)(&format!("[资产] 独立拉取入库 {name} ({}B)", collected.len()));
            true
        }
        Err(e) => {
            (log)(&format!("[资产] 独立拉取入库失败({e}), {name}"));
            false
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/asset_store_tests.rs"]
mod asset_store_tests;
