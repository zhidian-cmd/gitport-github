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
        !storable(StatusCode::NOT_FOUND, "application/javascript"),
        "非 200 不收"
    );
    assert!(
        !storable(StatusCode::OK, "image/png"),
        "白名单外类型不收（图片走原直连）"
    );
    assert!(
        storable(StatusCode::OK, "text/css; charset=utf-8"),
        "css 必须收"
    );
    assert!(storable(StatusCode::OK, "font/woff2"), "字体必须收");
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

/// 等待者中继语义：首个=发起者、后续=等待者；signal_done 全员唤醒并撤销登记；之后重新武装。
/// （失败/panic 后若不撤销登记，同 URL 会永久楔死——发现 1/2 的反面钉子。）
#[tokio::test]
async fn waiter_relay_rearm_and_wake() {
    let url = "https://github.githubassets.com/relay-11112222.js";
    let (rx1, i1) = register_waiter(url);
    assert!(i1, "首个必须判发起者");
    let (rx2, i2) = register_waiter(url);
    assert!(!i2, "第二个必须判等待者");
    signal_done(url);
    assert!(
        rx1.await.is_ok() && rx2.await.is_ok(),
        "signal_done 必须唤醒全体等待者"
    );
    let (rx3, i3) = register_waiter(url);
    assert!(
        i3,
        "撤销登记后必须重新武装（否则失败/panic 后 URL 永久楔死）"
    );
    signal_done(url);
    let _ = rx3.await;
}

/// 发现 1 回归钉子：上游全灭时，并发 miss 的等待者必须限时拿到 None 且登记清空，
/// 绝不永久挂在 rx 上（装死上游曾让同 URL 楔死到重启）。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // TEST_LOCK 护全局路由表/串发表，跨 await 有意为之
async fn miss_dead_upstream_releases_waiters() {
    use std::sync::Arc;
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    crate::pool::edges::clear_all();
    crate::settings::save_worker_mirrors(Vec::new());
    let dir = std::env::temp_dir().join(format!("gitport_asset_miss_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // 自建路由表：ASSET_HOST → 回环 IP，不碰真网
    std::fs::write(
        dir.join("routes.json"),
        r#"{
  "ips": [
    {"ip": "127.0.0.1", "sni": "a.example", "hosts": ["github.githubassets.com"]},
    {"ip": "127.0.0.2", "sni": "a.example", "hosts": ["github.githubassets.com"]}
  ],
  "hosts": {"github.githubassets.com": {}}
}"#,
    )
    .unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);
    // dial_port 指向一个刚释放的端口：必然拒连，拨号秒败
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    crate::pool::dial::set_dial_port(port);

    let url = "https://github.githubassets.com/miss-33334444.js";
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        .body(protocol::empty_body())
        .unwrap();
    let log: LogFn = Arc::new(|_| {});
    let (ra, rb) = tokio::join!(
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            serve_or_fetch(&log, &req, ASSET_HOST)
        ),
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            serve_or_fetch(&log, &req, ASSET_HOST)
        ),
    );
    let ra = ra.expect("20s 内必须返回（等待者不许挂死）");
    let rb = rb.expect("20s 内必须返回（等待者不许挂死）");
    assert!(ra.is_none() && rb.is_none(), "拉取全灭必须回落 None");
    assert!(
        !inflight()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(url),
        "拉取结束后登记表必须清空该 URL"
    );
    crate::pool::dial::set_dial_port(0); // 复位，别影响别的测试
    let _ = std::fs::remove_dir_all(&dir);
}

/// 每隔 interval 吐一帧共 n 帧，吐完 EOF——慢滴流测试用。
fn slow_frames(data: &'static [u8], n: usize, interval: std::time::Duration) -> BoxBody {
    let stream = futures_util::stream::unfold(0usize, move |i| async move {
        if i >= n {
            return None;
        }
        tokio::time::sleep(interval).await;
        let b = Bytes::from_static(&data[i..i + 1]);
        Some((Ok::<_, std::io::Error>(hyper::body::Frame::data(b)), i + 1))
    });
    BoxBody::new(http_body_util::StreamBody::new(stream))
}

/// 吐一帧后永久 Pending——装死上游测试用。
fn silent_after(data: &'static [u8]) -> BoxBody {
    struct Silent {
        left: Option<Bytes>,
    }
    impl hyper::body::Body for Silent {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            let me = self.get_mut();
            match me.left.take() {
                Some(b) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b)))),
                None => std::task::Poll::Pending,
            }
        }
    }
    BoxBody::new(Silent {
        left: Some(Bytes::from_static(data)),
    })
}

/// 停滞界判据（发现 1 修复核心）：慢滴流拉多久都不杀，零帧停滞才判死。
#[tokio::test]
async fn collect_stall_bounded_slow_frames_pass_and_silence_fails() {
    // 慢帧：每 40ms 吐 3 帧（真实时钟 ~120ms < 200ms 界）→ 成功收集
    let body = slow_frames(b"abc", 3, std::time::Duration::from_millis(40));
    let got = collect_stall_bounded(body, std::time::Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(got.as_ref(), b"abc", "慢滴流必须完整收集");
    // 装死：吐 1 帧后永久沉默 → 停滞界报错
    let body = silent_after(b"ab");
    assert!(
        collect_stall_bounded(body, std::time::Duration::from_millis(60))
            .await
            .is_err(),
        "零帧停滞必须判死"
    );
}
