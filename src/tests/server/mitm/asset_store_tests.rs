//! 资产库 fixture：入库/回放往返、白名单、哈希碰撞不串文件。

use super::*;

fn dir_tag(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gitport_asset_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn hdrs(ct: &str) -> Vec<Vec<String>> {
    vec![
        vec!["content-type".into(), ct.into()],
        vec!["cache-control".into(), "public, max-age=31536000, immutable".into()],
    ]
}

/// 入库/回放往返：头（含 immutable 缓存头）与体逐字节一致；同 URL 覆盖写取新。
#[tokio::test]
async fn give_take_roundtrip() {
    let dir = dir_tag("rt");
    let url = "https://github.githubassets.com/assets/core-cccc3333.js";
    persist_blocking(&dir, url, b"console.log(1)", &hdrs("application/javascript; charset=utf-8")).unwrap();
    let resp = take(&dir, url).expect("入库后必须命中");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=31536000, immutable",
        "缓存头必须原样带回（浏览器 immutable 依赖它）"
    );
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/javascript; charset=utf-8"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body.as_ref(), b"console.log(1)");
    // 覆盖写取新
    persist_blocking(&dir, url, b"console.log(2)", &hdrs("application/javascript")).unwrap();
    let body2 = http_body_util::BodyExt::collect(take(&dir, url).unwrap().into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body2.as_ref(), b"console.log(2)");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 未入库 URL 不命中；非 200 拒收；白名单外类型拒收；异 URL 异文件（碰撞由条目内 key 校验兜底）。
#[test]
fn gates_and_misses() {
    let dir = dir_tag("gate");
    let url = "https://github.githubassets.com/assets/app-aaaa1111.js";
    assert!(take(&dir, url).is_none(), "未入库必须 miss");
    assert!(
        !storable(StatusCode::NOT_FOUND, "application/javascript", 10),
        "非 200 不收"
    );
    assert!(
        !storable(StatusCode::OK, "image/png", 10),
        "白名单外类型不收（图片走原直连）"
    );
    assert!(
        storable(StatusCode::OK, "text/css; charset=utf-8", 10),
        "css 必须收"
    );
    assert!(storable(StatusCode::OK, "font/woff2", 10), "字体必须收");
    assert!(
        !storable(StatusCode::OK, "application/javascript", ASSET_MAX_BODY_BYTES + 1),
        "超体积上限不收"
    );
    persist_blocking(&dir, url, b"a", &hdrs("application/javascript")).unwrap();
    let other = "https://github.githubassets.com/assets/app-bbbb2222.js";
    assert!(take(&dir, other).is_none(), "异 URL 不得串文件");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 资产名提取：JS 族与 CSS module 族；不匹配 = None。
#[test]
fn logical_name_families() {
    let n = |u: &str| asset_logical_name(u).unwrap();
    assert_eq!(
        n("https://github.githubassets.com/assets/main-CqlHzPsd.js"),
        "main"
    );
    assert_eq!(
        n("https://github.githubassets.com/assets/chunk-8-fe01295fba3566d3.js"),
        "chunk-8",
        "16 位哈希：名字取到 chunk-8"
    );
    assert_eq!(
        n("https://github.githubassets.com/assets/11446.527c1baea995f0d6.module.css"),
        "11446.module",
        "CSS module 族按点分隔的 16 位 hex"
    );
    assert_eq!(
        n("https://github.githubassets.com/assets/blackbird-search.0a233d31de21b466.module.css"),
        "blackbird-search.module"
    );
    assert!(
        asset_logical_name("https://github.githubassets.com/assets/nohash.js").is_none(),
        "无哈希段不参与归并"
    );
}

/// 名字键：同资产新哈希入库覆盖旧版本（只留最新）；旧哈希 URL 因 key 不匹配当 miss（不服务陈旧占用）。
#[tokio::test]
async fn same_name_new_hash_overwrites_and_old_url_misses() {
    let dir = dir_tag("namekey");
    let old = "https://github.githubassets.com/assets/LocalTab-DpwmSdY8.css";
    let new = "https://github.githubassets.com/assets/LocalTab-XY98wv65.css";
    persist_blocking(&dir, old, b"old bytes", &hdrs("text/css")).unwrap();
    assert!(take(&dir, old).is_some(), "前提：旧版本已入库");
    persist_blocking(&dir, new, b"new bytes", &hdrs("text/css")).unwrap();
    // 新 URL 命中新字节
    let hit = take(&dir, new).expect("新版本必须命中");
    let body = http_body_util::BodyExt::collect(hit.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body.as_ref(), b"new bytes", "必须是新内容");
    // 旧 URL：key 不匹配 = miss（不服务陈旧占用）
    assert!(
        take(&dir, old).is_none(),
        "旧哈希 URL 不得命中新内容（防陈旧占用）"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 容量强制：超限从最旧的文件开始淘汰（mtime 顺序），删到限额以内即停。
#[test]
fn cap_evicts_oldest_first() {
    let dir = dir_tag("cap");
    let ua = "https://github.githubassets.com/assets/a-aaaa1111.js";
    let ub = "https://github.githubassets.com/assets/b-bbbb2222.js";
    let uc = "https://github.githubassets.com/assets/c-cccc3333.js";
    persist_blocking(&dir, ua, b"aaaa", &hdrs("application/javascript")).unwrap();
    persist_blocking(&dir, ub, b"bbbb", &hdrs("application/javascript")).unwrap();
    persist_blocking(&dir, uc, b"cccc", &hdrs("application/javascript")).unwrap();
    // 回拨 mtime：a 最老、b 次之、c 最新
    for (path, days) in [
        (asset_path(&dir, ua), 3),
        (asset_path(&dir, ub), 2),
        (asset_path(&dir, uc), 0),
    ] {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 24 * 3600);
        f.set_times(std::fs::FileTimes::new().set_modified(old)).unwrap();
    }
    // 上限卡在"总大小 − 最老一份"：恰好必须淘汰 a，且只淘汰 a
    let fsize = |u: &str| std::fs::metadata(asset_path(&dir, u)).unwrap().len();
    let total: u64 = [ua, ub, uc].iter().map(|u| fsize(u)).sum();
    let max = total - fsize(ua);
    enforce_cap(&dir, max);
    assert!(take(&dir, ua).is_none(), "最老的必须被淘汰");
    assert!(take(&dir, ub).is_some(), "次新的保留");
    assert!(take(&dir, uc).is_some(), "最新的保留");
    // 已在限额内：再强制一次不得误删
    enforce_cap(&dir, max);
    assert!(take(&dir, ub).is_some() && take(&dir, uc).is_some(), "限额内不得误删");
    let _ = std::fs::remove_dir_all(&dir);
}
