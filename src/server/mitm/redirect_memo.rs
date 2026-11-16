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

/// 302 落点必须是已知头像域：否则一次异常跳转会让该路径 6 小时内全部本地直答这个跳转。
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
    if !is_avatar_target(&loc) {
        g.remove(&k); // 历史遗留的异常落点：当场清掉
        return None;
    }
    Some(loc)
}

/// 从上游响应学习跳转目标：唯一学习点在 get_direct 成功路径——新拨与复用都经过它。
pub(super) fn observe_response(
    host: &str,
    uri: &http::Uri,
    status: http::StatusCode,
    headers: &http::HeaderMap,
) {
    // 头像入口偶尔走 301/307/308，只认 302 会漏学；落点仍由 is_avatar_target 严格校验。
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

/// 记一笔跳转（301/302/307/308；只认头像入口形态 + 头像域落点，其余不记）。
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
