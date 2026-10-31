//! github.com 头像入口的 302 记忆。
//!
//! `github.com/<user>.png?size=N` 是 GitHub 设计的「302 + no-cache」入口：
//! 浏览器每次渲染页面都必须重问一遍跳转（实测 20/20 头像恰好各 2 次 = 每看
//! 一遍页面一次，260-310ms/个，十几个并行就是退出/翻页后内容"逐渐蹦出来"
//! 的主要来源）。跳转目标按用户稳定，代理记住后本地直答 302——浏览器行为
//! 不变（照样跟随跳转、照样用本地缓存的真图），只是那个来回归零。

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 记忆上限：条目按看过的用户数增长，超限整表重来（目标可随时重新学到）。
const MEMO_CAP: usize = 4096;
/// 目标保质期：用户换头像后入口 URL 不变（跳转目标里的版本号才变），
/// 过期重学一次，把旧图的窗口限制在几小时内。
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

/// 从上游响应学习 302 目标：get_direct（拨号后）与 try_cached（复用快路径）
/// 两个成功分支共用——头像请求几乎总走复用路径，只挂一处会漏学。
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
