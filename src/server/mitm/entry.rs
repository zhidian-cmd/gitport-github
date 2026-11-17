//! 磁盘条目统一编解码：`[4B 头长][json{key,status,headers}][体]`——页面缓存与资产库共用一份盘上格式。
//! 断电安全（tmp 写全量 + rename 原子覆盖）与容量治理留在各自调用方，这里只管单条目的字节进出。

use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};

/// 解码后的条目：状态码 + 规范化响应头 + 体。
pub(super) struct DiskEntry {
    pub status: u16,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}

/// 编码单条目。headers 键值对与盘上 json 数组形态一一对应。
pub(super) fn encode(key: &str, status: u16, headers: &[Vec<String>], body: &[u8]) -> Vec<u8> {
    let header = serde_json::json!({
        "key": key,
        "status": status,
        "headers": headers,
    });
    let hbytes = serde_json::to_vec(&header).expect("JSON 序列化不会失败");
    let mut buf = Vec::with_capacity(4 + hbytes.len() + body.len());
    buf.extend_from_slice(&(hbytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&hbytes);
    buf.extend_from_slice(body);
    buf
}

/// 解码单条目：长度/截断/元数据/键/状态校验，拒绝原因串与命中侧日志逐字对应。
pub(super) fn decode(raw: &[u8], want_key: &str) -> Result<DiskEntry, &'static str> {
    if raw.len() < 4 {
        return Err("文件过短");
    }
    let hlen = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let end = 4usize.checked_add(hlen).ok_or("头部长度溢出")?;
    if raw.len() < end {
        return Err("条目截断"); // miss 自愈
    }
    let header: serde_json::Value = serde_json::from_slice(&raw[4..end]).map_err(|_| "元数据损坏")?;
    if header.get("key").and_then(|k| k.as_str()) != Some(want_key) {
        return Err("哈希碰撞"); // 不服务错页
    }
    let Some(st) = header.get("status").and_then(|v| v.as_u64()) else {
        return Err("状态码损坏");
    };
    let status = u16::try_from(st).map_err(|_| "状态码损坏")?;
    if status != 200 {
        return Err("条目非 200"); // 拦截页/304：当 miss
    }
    let Some(arr) = header.get("headers").and_then(|v| v.as_array()) else {
        return Err("头部字段损坏");
    };
    let mut headers = Vec::with_capacity(arr.len());
    for pair in arr {
        let (Some(k), Some(v)) = (
            pair.get(0).and_then(|x| x.as_str()),
            pair.get(1).and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            headers.push((name, val));
        }
    }
    Ok(DiskEntry {
        status,
        headers,
        body: Bytes::copy_from_slice(&raw[end..]),
    })
}
