//! 头像入口 302 记忆：跳转目标按用户稳定，记住后本地直答，省掉每次渲染的来回。

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 记忆上限 4096：超限整表重来。
const MEMO_CAP: usize = 4096;
/// 目标保质期 6h：过期重学。
const MEMO_TTL: Duration = Duration::from_secs(6 * 60 * 60);

fn memo() -> &'static std::sync::Mutex<HashMap<String, (String, Instant)>> {
    static M: OnceLock<std::sync::Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// 头像入口形态：github.com 单段路径、.png 结尾。
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

/// 302 落点须为已知头像域（user-images/private-user-images/avatars.*.githubusercontent.com）。
fn is_avatar_target(location: &str) -> bool {
    let host = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or("");
    let host = host
        .rsplit('@')
        .next()
        .unwrap_or(host) // 剥 userinfo
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    host == "user-images.githubusercontent.com"
        || host == "private-user-images.githubusercontent.com"
        || (host.starts_with("avatars") && host.ends_with(".githubusercontent.com"))
}

/// 命中 = 本地直答的 302 目标；未命中/过期 = None（走上游重学）。
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
    if !is_avatar_target(&loc) {
        g.remove(&k); // 异常落点当场清掉
        return None;
    }
    Some(loc)
}

/// 学习点：get_direct 成功路径（新拨与复用都经过）。
pub(super) fn observe_response(
    host: &str,
    uri: &http::Uri,
    status: http::StatusCode,
    headers: &http::HeaderMap,
) {
    // 301/302/307/308 都学；落点由 is_avatar_target 校验。
    if !matches!(
        status,
        http::StatusCode::MOVED_PERMANENTLY
            | http::StatusCode::FOUND
            | http::StatusCode::TEMPORARY_REDIRECT
            | http::StatusCode::PERMANENT_REDIRECT
    ) {
        return;
    }
    if let Some(loc) = headers.get("location").and_then(|v| v.to_str().ok()) {
        observe(host, uri.path(), uri.query(), loc);
    }
}

/// 记跳转（301/302/307/308；仅头像入口+头像域落点）。
pub(super) fn observe(host: &str, path: &str, query: Option<&str>, location: &str) {
    if host != "github.com"
        || !is_avatar_entry(path)
        || location.is_empty()
        || !is_avatar_target(location)
    {
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
