//! 仓库页解析模块（资产骨架胚）：抽取 / 换装。纯文本操作，不碰网络不碰盘。
//! GitHub 仓库页 = 静态壳 + embeddedData 数据 + 全站 immutable 资产。胚只冻结
//! 外链资产引用（githubassets 的 href/src 属性值，文档顺序），按模板位置对齐换装：
//! CSP 的 sha256 只钉内联脚本内容，外链引用冻结零副作用；body/数据/nonce/CSP
//! 全部随每次真拉新鲜交付，永不过期。GitHub 改版时改这里的扫描规则即可。

/// 冻结的资产骨架：文档顺序的外链引用 + importmap 指纹（模块图漂移即重剥）。
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Skeleton {
    pub refs: Vec<String>,
    pub import_fp: u64,
}

const ASSET_URL_PREFIX: &str = "\"https://github.githubassets.com/";
const SCRIPT_OPEN: &str = "<script";
const SCRIPT_CLOSE: &str = "</script>";
const IMPORTMAP_OPEN: &str = "<script type=\"importmap\">";

/// FNV-1a 64：跨进程确定，零依赖。
pub(super) fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 在 text 中找 needle 的下一处（从 from 起）。
fn find_from(text: &str, needle: &str, from: usize) -> Option<usize> {
    text[from..].find(needle).map(|p| p + from)
}

/// 把所有 <script> 体内文本按原长度置换成空格：属性扫描就不会吃进
/// importmap/embeddedData 里的 URL 字符串，且置换后的字节偏移与原文一致。
fn blank_script_bodies(html: &str) -> String {
    let b = html.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while let Some(open) = find_from(html, SCRIPT_OPEN, i) {
        // 开标签结束（src 属性在开标签上，必须保留）
        let Some(gt) = find_from(html, ">", open) else {
            break;
        };
        let Some(close) = find_from(html, SCRIPT_CLOSE, gt) else {
            break;
        };
        for slot in out.iter_mut().take(close).skip(gt + 1) {
            *slot = b' ';
        }
        i = close + SCRIPT_CLOSE.len();
        if i >= b.len() {
            break;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| html.to_string())
}

/// 扫描属性值形态的 githubassets 引用（文档顺序），返回 (原文偏移区间, URL)。
/// 在 blank 后的文本上扫，区间在原文上同样有效（等长置换）。
fn scan_refs(masked: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(pos) = find_from(masked, ASSET_URL_PREFIX, i) {
        let start = pos + 1; // 跳过开引号
        let Some(end_rel) = masked[start..].find('"') else {
            break;
        };
        let end = start + end_rel;
        out.push((start, end, masked[start..end].to_string()));
        i = end;
    }
    out
}

/// importmap 指纹：模块图（react 等基础库的哈希名）漂移 = 结构变化，触发重剥。
fn importmap_fp(html: &str) -> u64 {
    match find_from(html, IMPORTMAP_OPEN, 0) {
        Some(open) => {
            let body_start = open + IMPORTMAP_OPEN.len();
            let inner_end = find_from(html, SCRIPT_CLOSE, body_start).unwrap_or(html.len());
            fnv1a(html[body_start..inner_end].as_bytes())
        }
        None => fnv1a(b""),
    }
}

/// 抽取骨架。无任何 githubassets 引用 = None（非典型页不立胚）。
pub(super) fn extract_skeleton(html: &str) -> Option<Skeleton> {
    let masked = blank_script_bodies(html);
    let refs: Vec<String> = scan_refs(&masked)
        .into_iter()
        .map(|(_, _, url)| url)
        .collect();
    (!refs.is_empty()).then(|| Skeleton {
        refs,
        import_fp: importmap_fp(html),
    })
}

/// 换装：fresh 的资产引用按位置换成 frozen 的旧引用。
/// 数量不符 = 页面结构变化 = None（调用方重剥）。返回 (换装后 html, 换掉的数量)，0 = 同部署恒等。
pub(super) fn swap_asset_refs(html: &str, frozen: &[String]) -> Option<(String, usize)> {
    let masked = blank_script_bodies(html);
    let spans = scan_refs(&masked);
    if spans.len() != frozen.len() {
        return None;
    }
    let mut out = String::with_capacity(html.len() + 256);
    let mut last = 0usize;
    let mut swapped = 0usize;
    for ((s, e, fresh_url), frozen_url) in spans.iter().zip(frozen.iter()) {
        out.push_str(&html[last..*s]);
        if fresh_url != frozen_url {
            out.push_str(frozen_url);
            swapped += 1;
        } else {
            out.push_str(fresh_url);
        }
        last = *e;
    }
    out.push_str(&html[last..]);
    Some((out, swapped))
}

#[cfg(test)]
#[path = "../../tests/server/mitm/parse_tests.rs"]
mod parse_tests;
