//! githubassets 资产库：按资产名寻址（同资产不同哈希只留最新），URL 原样回放；只收 js/css/字体，容量 20MB 按年龄淘汰。
//! 条目 = [4B 头长][头 json(key/status/headers)][体]；取侧校验 key 与 URL 精确相等，换哈希即 miss 回源覆盖。

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

/// 容量上限 20MB；超限按文件年龄从旧到新淘汰。
const ASSET_MAX_BYTES: u64 = 20 * 1024 * 1024;
const ASSET_DIR: &str = "assets";

/// 只收 js/css/字体，其余透传不存。
fn content_type_allowed(ct: &str) -> bool {
    let ct = ct.trim().to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("css") || ct.contains("font")
}

/// 资产名（去哈希）：JS `[名字]-[哈希]`（8..=16 位）或 CSS `[名字].[16位hex].module.css`；不匹配按完整 URL 落盘。
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
    // 同名不同哈希共用槽位，新版覆盖旧版。
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

/// 容量强制：超限按修改时间从旧到新删；返回淘汰条数。
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

/// 本地命中：按 URL 读回条目重建响应，头原样带回。
pub(super) fn take(dir: &std::path::Path, url: &str) -> Option<axum::response::Response<BoxBody>> {
    let raw = std::fs::read(asset_path(dir, url)).ok()?;
    let entry = super::entry::decode(&raw, url).ok()?;
    let mut hdrmap = hyper::HeaderMap::new();
    for (k, v) in entry.headers {
        hdrmap.insert(k, v);
    }
    let mut resp = hyper::Response::builder()
        .status(StatusCode::OK)
        .body(protocol::full_body(entry.body))
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
    let buf = super::entry::encode(url, StatusCode::OK.as_u16(), hdrs, bytes);
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
    // 超限淘汰最旧。
    enforce_cap(dir, ASSET_MAX_BYTES);
    Ok(())
}

/// 入库准入门（collect 侧调用）：200 + 白名单类型。
pub(super) fn storable(status: StatusCode, content_type: &str) -> bool {
    status == StatusCode::OK && content_type_allowed(content_type)
}

// ---------- 强绑定服务：资产请求只问资产库 ----------

/// 同 URL 在途等待者表：首个 miss 发起拉取，后续等同一份结果。
static INFLIGHT: OnceLock<Mutex<HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>>> =
    OnceLock::new();

fn inflight() -> &'static Mutex<HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 登记：返回 (完成通知接收端, 是否发起者)；发起者负责拉取并唤醒。
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

/// 资产请求入口：命中回放；miss 独立拉取（浏览器断开不影响）；None = 拉取失败，回落 switchboard。
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
    // ② miss：登记等待者，发起者拉起独立拉取。
    let (rx, initiator) = register_waiter(&url);
    if initiator {
        spawn_detached_fetch(dir.clone(), log.clone(), url.clone());
    }
    // ③ 等完成（所有等待者等同一份结果）。
    rx.await.ok()?;
    // ④ 命中交付；未入库 → None 回落。
    take(&dir, &url)
}

/// 停滞界 30s（发头/零帧）；慢滴流每帧重置，不设总时限。
const HEAD_STALL_SECS: u64 = 30;
const BODY_STALL_SECS: u64 = 30;

/// 独立拉取任务：与浏览器解耦；任何退出路径都必须 signal_done，否则等待者永久 pend。
fn spawn_detached_fetch(dir: std::path::PathBuf, log: LogFn, url: String) {
    tokio::spawn(async move {
        // 内层拉取有停滞界，外层收尾保证 signal_done 必达。
        let handle = tokio::spawn({
            let dir = dir.clone();
            let log = log.clone();
            let url = url.clone();
            async move { fetch_and_store(&dir, &log, &url).await }
        });
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_panic() => {
                (log)(&format!(
                    "[资产] 后台拉取 panic({e}), {} 等待者已释放回落",
                    asset_dbg_name(&url)
                ));
            }
            Err(e) => {
                (log)(&format!(
                    "[资产] 后台拉取任务异常结束({e}), {} 等待者已释放回落",
                    asset_dbg_name(&url)
                ));
            }
        }
        signal_done(&url);
    });
}

/// 逐帧收体：只设停滞界不设总时限；连续 stall 零帧判装死。
async fn collect_stall_bounded(
    mut body: BoxBody,
    stall: std::time::Duration,
) -> Result<Bytes, String> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(stall, http_body_util::BodyExt::frame(&mut body)).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(d) = frame.into_data() {
                    out.extend_from_slice(&d);
                }
            }
            Ok(Some(Err(e))) => return Err(e.to_string()),
            Ok(None) => return Ok(Bytes::from(out)),
            Err(_) => return Err(format!("体停滞超 {stall:?} 零帧, 判装死")),
        }
    }
}

/// 拉取 + 门检 + 入库，结果只落日志。
async fn fetch_and_store(dir: &std::path::Path, log: &LogFn, url: &str) {
    let name = asset_dbg_name(url);
    // ① 通道：池内现成通道或新拨。
    let (up, fresh) = match crate::pool::get_or_build(ASSET_HOST, log).await {
        Ok(v) => v,
        Err(e) => {
            (log)(&format!("[资产] 独立拉取拨号失败({e}), {name} 本次不入库"));
            return;
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
            return;
        }
    };
    // ③ 响应头（30s 不发头判装死）。
    let resp = match tokio::time::timeout(
        std::time::Duration::from_secs(HEAD_STALL_SECS),
        upstream::h2_send(&up, &req, &None::<Bytes>),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            (log)(&format!("[资产] 独立拉取失败({e}), {name} 本次不入库"));
            crate::pool::report_failure(&up, ASSET_HOST, fresh); // 通道失败交池子摘除/换血。
            return;
        }
        Err(_) => {
            (log)(&format!(
                "[资产] 独立拉取 {HEAD_STALL_SECS}s 不发响应头, 判装死, {name} 本次不入库"
            ));
            crate::pool::report_failure(&up, ASSET_HOST, fresh);
            return;
        }
    };
    let (parts, body) = resp.into_parts();
    if parts.status != StatusCode::OK {
        (log)(&format!(
            "[资产] 独立拉取上游 {}, {name} 不入库回落",
            parts.status.as_u16()
        ));
        return;
    }
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // 拿到响应头即判类型，白名单外立即回落。
    if !storable(StatusCode::OK, &ct) {
        (log)(&format!("[资产] 不收录({ct}), {name} 立即回落"));
        return;
    }
    // ④ 收体（逐帧停滞界）。
    let collected = match collect_stall_bounded(body, std::time::Duration::from_secs(BODY_STALL_SECS))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            (log)(&format!("[资产] 独立拉取收体失败({e}), {name} 本次不入库"));
            crate::pool::report_failure(&up, ASSET_HOST, fresh);
            return;
        }
    };
    // ⑤ 入库。
    let hdrs: Vec<Vec<String>> = parts
        .headers
        .iter()
        .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case("set-cookie"))
        .map(|(k, v)| vec![k.as_str().to_string(), v.to_str().unwrap_or("").to_string()])
        .collect();
    match persist_blocking(dir, url, &collected, &hdrs) {
        Ok(_) => (log)(&format!("[资产] 独立拉取入库 {name} ({}B)", collected.len())),
        Err(e) => (log)(&format!("[资产] 独立拉取入库失败({e}), {name}")),
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/asset_store_tests.rs"]
mod asset_store_tests;
