/// 审计 #1 回归：镜像胜出时直连 future 未钧即弃（charge 在 future 内）——零残留，账面不得出现幽灵在途字节/流数。
#[test]
fn direct_leg_unpolled_leaves_zero_debt() {
    let key = mirror::direct_load_key("debt.test");
    let load = mirror::mirror_load(&key);
    load.in_flight_bytes
        .store(0, std::sync::atomic::Ordering::Relaxed);
    load.in_flight_streams
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let out = hyper::Request::builder()
        .uri("https://debt.test/f")
        .body(protocol::empty_body())
        .unwrap();
    let log: LogFn = Arc::new(|_: &str| {});
    let info = UpstreamInfo::default();
    let leg = direct_leg(
        "debt.test",
        8 * 1024 * 1024,
        true,
        &log,
        &out,
        "debt.test",
        &info,
        &None,
    );
    drop(leg);
    assert_eq!(
        load.in_flight_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "未钧即弃不得留下幽灵在途字节"
    );
    assert_eq!(
        load.in_flight_streams
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "流数同样不得泄漏"
    );
}
use super::*;

#[test]
fn release_asset_path_gate() {
    use pool::route::{master_route, Route};
    // 断言依赖种子表的 hosts 声明；别的测试会换全局表，先锁住并装回种子再判。
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join("gitport_release_gate_seed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);
    let mirror = |host: &str, path: &str| matches!(master_route(host, "GET", path), Route::Mirror);
    let pool = |host: &str, path: &str| matches!(master_route(host, "GET", path), Route::Pool);
    let not_mirror =
        |host: &str, path: &str| !matches!(master_route(host, "GET", path), Route::Mirror);
    assert!(
        pool(
            "github.com",
            "/torvalds/linux/archive/refs/tags/v6.6.tar.gz"
        ),
        "archive 已迁池，不再走镜像"
    );
    assert!(mirror(
        "github.com",
        "/cli/cli/releases/download/v2.0.0/gh_2.0.0_windows_amd64.zip"
    ));
    assert!(mirror(
        "github.com",
        "/docmirror/dev-sidecar/releases/latest/download/DevSidecar.exe"
    ));
    assert!(not_mirror("github.com", "/torvalds/linux/releases"));
    assert!(not_mirror(
        "github.com",
        "/torvalds/linux/releases/tag/v6.6"
    ));
    assert!(not_mirror(
        "github.com",
        "/torvalds/linux/info/refs?service=git-upload-pack"
    ));
    assert!(not_mirror("github.com", "/torvalds/linux/git-upload-pack"));
    assert!(not_mirror("api.github.com", "/repos/x/y/releases/assets/1"));
    assert!(
        pool("codeload.github.com", "/x/y/legacy.tar.gz"),
        "codeload 命中 github.com 裸键走池"
    );
}

#[test]
fn telemetry_paths_intercepted_only() {
    assert!(is_telemetry(
        "api.github.com",
        "/_private/browser/rum?ddforward=x"
    ));
    assert!(is_telemetry("api.github.com", "/_private/browser/errors"));
    assert!(is_telemetry("collector.github.com", "/"));
    assert!(is_telemetry("alive.github.com", "/"));
    assert!(!is_telemetry("api.github.com", "/graphql"));
    assert!(!is_telemetry("api.github.com", "/search/suggestions"));
    assert!(!is_telemetry("github.com", "/_private/browser/rum"));
}

#[test]
fn stream_decision_contract() {
    use upstream::MAX_REPLAY_BODY;
    assert_eq!(
        stream_decision(
            &Method::POST,
            "/fastgh/fgit.git/git-receive-pack",
            Some(100)
        ),
        Some("git 智能协议")
    );
    assert_eq!(
        stream_decision(&Method::POST, "/fastgh/fgit.git/git-upload-pack", None),
        Some("git 智能协议")
    );
    assert_eq!(
        stream_decision(
            &Method::GET,
            "/fastgh/fgit.git/info/refs?service=git-receive-pack",
            None
        ),
        None
    );
    assert_eq!(
        stream_decision(
            &Method::PUT,
            "/some/upload",
            Some(MAX_REPLAY_BODY as u64 + 1)
        ),
        Some("声明超限")
    );
    assert_eq!(
        stream_decision(&Method::POST, "/api/x", Some(MAX_REPLAY_BODY as u64)),
        None
    );
    assert_eq!(stream_decision(&Method::POST, "/api/x", None), None);
    assert_eq!(stream_decision(&Method::GET, "/x", Some(u64::MAX)), None);
    assert_eq!(stream_decision(&Method::HEAD, "/x", Some(u64::MAX)), None);
}

/// 客户端掐断的文案只认断开类，真故障不能被静默吞掉。
#[test]
fn client_gone_text_only_matches_disconnects() {
    assert!(client_gone_text("error writing a body to connection"));
    assert!(client_gone_text("broken pipe (os error 32)"));
    assert!(client_gone_text("connection reset by peer"));
    assert!(client_gone_text("connection closed before message completed"));
    // 这些是代理侧/协议侧真问题，仍要打「服务层错误」。
    assert!(!client_gone_text("http2 handshake failed: unexpected frame"));
    assert!(!client_gone_text("TLS alert received"));
    assert!(!client_gone_text("service task panicked"));
}

/// 断开提示同 host 只留首条，第二个 host 不受影响；表满清空属既有行为。
#[test]
fn client_gone_log_is_first_per_host() {
    let a = quiet::first_time("client-gone", "gone-a.test");
    let again = quiet::first_time("client-gone", "gone-a.test");
    let b = quiet::first_time("client-gone", "gone-b.test");
    assert!(a, "首次应出声");
    assert!(!again, "同 host 第二次不再刷");
    assert!(b, "另一个 host 仍能出声");
    // 隧道解密用的是另一个 tag，不共用名额。
    assert!(quiet::first_time("tunnel", "gone-a.test"));
}

/// 被 301 踢回主站的死路径要认得出，正常的 archive 下载和别的主站路径不许误伤。
#[test]
fn codeload_alias_path_only_matches_kicked_back_zip() {
    assert!(is_codeload_alias_path(
        "/zhidian-cmd/gitport-github/zip/refs/heads/main"
    ));
    assert!(is_codeload_alias_path("/o/r/tar.gz/refs/tags/v1"));
    assert!(!is_codeload_alias_path(
        "/zhidian-cmd/gitport-github/archive/refs/heads/main.zip"
    ));
    assert!(!is_codeload_alias_path("/o/r/zipball/main"));
    assert!(!is_codeload_alias_path("/o/r/zip"));
    assert!(!is_codeload_alias_path("/"));
}

/// 死路径只在 github.com 上认；改 host 后路径一字不改发往 codeload，且不再回 3xx。
#[test]
fn codeload_alias_rewrites_host_keeps_path() {
    assert_eq!(
        codeload_alias_host("github.com", "/zhidian-cmd/gitport-github/zip/refs/heads/main"),
        Some("codeload.github.com")
    );
    assert_eq!(
        codeload_alias_host("github.com", "/o/r/tar.gz/refs/tags/v1"),
        Some("codeload.github.com")
    );
    // 已经在 codeload 域、正常 archive、别的内容域，都不触发，免得反复改或误伤。
    assert_eq!(
        codeload_alias_host("codeload.github.com", "/o/r/zip/refs/heads/main"),
        None
    );
    assert_eq!(
        codeload_alias_host("github.com", "/o/r/archive/refs/heads/main.zip"),
        None
    );
    assert_eq!(
        codeload_alias_host("raw.githubusercontent.com", "/o/r/zip/refs/heads/main"),
        None
    );

    let req = hyper::Request::builder()
        .uri("https://github.com/zhidian-cmd/gitport-github/zip/refs/heads/main")
        .body(protocol::empty_body())
        .unwrap();
    let alias = codeload_alias_host("github.com", req.uri().path()).unwrap();
    let out = upstream::upstream_request(&req, alias).unwrap();
    assert_eq!(
        out.uri().to_string(),
        "https://codeload.github.com/zhidian-cmd/gitport-github/zip/refs/heads/main"
    );
}

/// 复用失败的两种病不能混成一句话：超时要写明"响应超时(Ns)"，真断链才叫"连接已断"。
/// 线上曾把 4s 预算超时印成"复用连接已断"，看着像链路故障，实际是边缘不答。
#[test]
fn reuse_failure_text_keeps_timeout_and_broken_conn_apart() {
    assert_eq!(
        reuse_failure_text(ERR_BUDGET_TIMEOUT, Duration::from_secs(4)),
        "响应超时(4s) 放弃复用"
    );
    assert_eq!(
        reuse_failure_text("h2 发送: connection closed", Duration::from_secs(8)),
        "连接已断(h2 发送: connection closed)"
    );
}
