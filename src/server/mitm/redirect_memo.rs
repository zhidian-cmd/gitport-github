//! 头像入口 302 记忆：跳转目标按用户稳定，记住后本地直答，省掉每次渲染的来回。

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 记忆上限：条目按看过的用户数增长，超限整表重来（目标可随时重新学到）。
const MEMO_CAP: usize = 4096;
/// 目标保质期：换头像后入口 URL 不变，过期重学一次，把旧图窗口限制在几小时内。
const MEMO_TTL: Duration = Duration::from_secs(6 * 60 * 60);

fn memo() -> &'static std::sync::Mutex<HashMap<String, (String, Instant)>> {
    static M: OnceLock<std::sync::Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// 头像入口形态：github.com 单段路径、以 .png 结尾（如 /Venkateshvenki404224.png）。
fn is_avatar_entry(path: &str) -> bool {
    let Some(name) = path.strip_prefix('/') else {
        return false;
    };
    !name.is_empty() && !name.contains('/') && name.to_ascii_lowercase().ends_with(".png")
}

fn memo_key(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// 命中 = 本地直答的 302 目标；未命中/过期 = None（照常走上游，顺手重学）。
pub(super) fn cached_location(host: &str, path: &str, query: Option<&str>) -> Option<String> {
    if host != "github.com" || !is_avatar_entry(path) {
        return None;
    }
    let k = memo_key(path, query);
    let mut g = memo().lock().unwrap_or_else(|p| p.into_inner());
    let (loc, at) = g.get(&k)?.clone();
    if at.elapsed() > MEMO_TTL {
        g.remove(&k);
        return None;
    }
    Some(loc)
}

/// 从上游响应学习 302 目标：拨号后与复用快路径两个分支共用，只挂一处会漏学（头像几乎都走复用）。
pub(super) fn observe_response(
    host: &str,
    uri: &http::Uri,
    status: http::StatusCode,
    headers: &http::HeaderMap,
) {
    if status != http::StatusCode::FOUND {
        return;
    }
    if let Some(loc) = headers.get("location").and_then(|v| v.to_str().ok()) {
        observe(host, uri.path(), uri.query(), loc);
    }
}

/// 上游回了 302 就记一笔（只认头像入口形态；非 302/空 Location 调用方自会过滤）。
pub(super) fn observe(host: &str, path: &str, query: Option<&str>, location: &str) {
    if host != "github.com" || !is_avatar_entry(path) || location.is_empty() {
        return;
    }
    let mut g = memo().lock().unwrap_or_else(|p| p.into_inner());
    let k = memo_key(path, query);
    if g.len() >= MEMO_CAP && !g.contains_key(&k) {
        g.clear();
    }
    g.insert(k, (location.to_string(), Instant::now()));
}

#[cfg(test)]
fn backdate(path: &str, query: Option<&str>) {
    let mut g = memo().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(v) = g.get_mut(&memo_key(path, query)) {
        v.1 = Instant::now() - MEMO_TTL - Duration::from_secs(1);
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/redirect_memo.rs"]
mod tests;
