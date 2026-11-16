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
