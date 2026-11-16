//! githubassets 资产库：immutable 资产按 URL 一存永逸，本地透明回放。
//! 键 = 完整 URL；条目 = [4B 头长][头 json(key/status/headers)][体]，tmp+rename 原子覆盖。
//! 只收 js/css/字体；URL 一个字符不改地回放，CSP/SRI 天然完好。容量攒够整库清空（资产可再生）。

use super::parse::fnv1a;
use crate::server::protocol::{self, BoxBody};
use bytes::Bytes;
use http::StatusCode;

pub(super) const ASSET_HOST: &str = "github.githubassets.com";

/// 资产库容量上限：攒够整库清空（资产可再生，不做淘汰排序）。
const ASSET_MAX_BYTES: u64 = 200 * 1024 * 1024;
const ASSET_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const ASSET_DIR: &str = "assets";

/// 只收 js/css/字体（GitHub 资产的内容类型族），其余透传不存。
fn content_type_allowed(ct: &str) -> bool {
    let ct = ct.trim().to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("css") || ct.contains("font")
}

fn asset_path(dir: &std::path::Path, url: &str) -> std::path::PathBuf {
    dir.join(ASSET_DIR).join(format!("{:016x}", fnv1a(url.as_bytes())))
}

static ASSET_BYTES_SINCE_WIPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 攒够上限整库清空（资产可再生，不做淘汰排序）。
fn maybe_wipe_assets(dir: &std::path::Path, written: usize) {
    use std::sync::atomic::Ordering;
    let pending =
        ASSET_BYTES_SINCE_WIPE.fetch_add(written as u64, Ordering::Relaxed) + written as u64;
    if pending >= ASSET_MAX_BYTES
        && ASSET_BYTES_SINCE_WIPE
            .compare_exchange(pending, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let _ = std::fs::remove_dir_all(dir.join(ASSET_DIR));
    }
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
    maybe_wipe_assets(dir, 4 + hbytes.len() + bytes.len());
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
    })
}

/// 入库准入门（collect 侧调用）：200 + 白名单类型 + 体积上限。
pub(super) fn storable(status: StatusCode, content_type: &str, body_len: usize) -> bool {
    status == StatusCode::OK
        && content_type_allowed(content_type)
        && body_len <= ASSET_MAX_BODY_BYTES
}

#[cfg(test)]
#[path = "../../tests/server/mitm/asset_store_tests.rs"]
mod asset_store_tests;
