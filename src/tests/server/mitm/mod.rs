/// 审计 #1 回归: 镜像胜出时直连 future 未钧即弃——charge 在 future 内,
/// 零残留, 账面不得出现幽灵在途字节/流数。
#[test]
fn direct_leg_unpolled_leaves_zero_debt() {
    let key = mirror::direct_load_key("debt.test");
    let load = mirror::mirror_load_for(&key);
    load.in_flight_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
    load.in_flight_streams.store(0, std::sync::atomic::Ordering::Relaxed);
    let out = hyper::Request::builder()
        .uri("https://debt.test/f")
        .body(upstream::empty_body())
        .unwrap();
    let log: LogFn = Arc::new(|_: &str| {});
    let info = UpstreamInfo::default();
    let leg = direct_leg("debt.test", 8 * 1024 * 1024, true, &log, &out, "debt.test", &info, &None);
    drop(leg);
    assert_eq!(
        load.in_flight_bytes.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "未钧即弃不得留下幽灵在途字节"
    );
    assert_eq!(
        load.in_flight_streams.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "流数同样不得泄漏"
    );
}
use super::*;


#[test]
fn release_asset_path_gate() {
    use pool::route::{master_route, Route};
    let mirror = |host: &str, path: &str| {
        matches!(master_route(host, "GET", path), Route::Mirror)
    };
    let not_mirror = |host: &str, path: &str| {
        !matches!(master_route(host, "GET", path), Route::Mirror)
    };
    assert!(mirror(
        "github.com",
        "/torvalds/linux/archive/refs/tags/v6.6.tar.gz"
    ));
    assert!(mirror(
        "github.com",
        "/cli/cli/releases/download/v2.0.0/gh_2.0.0_windows_amd64.zip"
    ));
    assert!(mirror(
        "github.com",
        "/docmirror/dev-sidecar/releases/latest/download/DevSidecar.exe"
    ));
    assert!(not_mirror("github.com", "/torvalds/linux/releases"));
    assert!(not_mirror("github.com", "/torvalds/linux/releases/tag/v6.6"));
    assert!(not_mirror(
        "github.com",
        "/torvalds/linux/info/refs?service=git-upload-pack"
    ));
    assert!(not_mirror("github.com", "/torvalds/linux/git-upload-pack"));
    assert!(not_mirror(
        "api.github.com",
        "/repos/x/y/releases/assets/1"
    ));
    assert!(mirror("codeload.github.com", "/x/y/legacy.tar.gz"));
}


#[test]
fn telemetry_paths_intercepted_only() {
    assert!(is_telemetry("api.github.com", "/_private/browser/rum?ddforward=x"));
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
        stream_decision(&Method::PUT, "/some/upload", Some(MAX_REPLAY_BODY as u64 + 1)),
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
