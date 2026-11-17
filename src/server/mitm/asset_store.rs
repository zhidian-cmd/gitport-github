//! githubassets 资产库：immutable 资产按"资产名"一存长用（同资产不同哈希只保留最新），本地透明回放。
//! 落盘槽位按资产名寻址（URL 文件名去内容哈希）；条目 = [4B 头长][头 json(key/status/headers)][体]。
//! 只收 js/css/字体；URL 一个字符不改地回放，CSP/SRI 天然完好。容量 15MB，超限按文件年龄淘汰。
//! 时代中立：取侧校验条目 key 与请求 URL 精确相等——同资产换哈希 = miss = 回源拉新覆盖，永不跨发版给错内容。

use crate::server::protocol::{self, BoxBody};
use bytes::Bytes;
use http::StatusCode;

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
const ASSET_MAX_BYTES: u64 = 15 * 1024 * 1024;
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

#[cfg(test)]
#[path = "../../tests/server/mitm/asset_store_tests.rs"]
mod asset_store_tests;
