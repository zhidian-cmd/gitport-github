use super::*;
use std::time::Duration;

fn git_resp(status: u16, ct: &str, body: &'static [u8]) -> hyper::Response<BoxBody> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(protocol::full_body(Bytes::from_static(body)))
        .unwrap()
}

/// 假腿：延时后交预设结果（网络无关，专测竞速判赢语义）。
fn leg(delay_ms: u64, resp: Result<hyper::Response<BoxBody>, String>) -> LegFut {
    Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        resp
    })
}

const ADV: &str = "application/x-git-upload-pack-advertisement";
const RESULT: &str = "application/x-git-upload-pack-result";

#[test]
fn classify_recognizes_fetch_direction_only() {
    assert_eq!(
        super::classify(
            &Method::GET,
            "/o/r.git/info/refs",
            Some("service=git-upload-pack")
        ),
        Some(GitKind::Advertisement)
    );
    assert_eq!(
        super::classify(&Method::POST, "/o/r.git/git-upload-pack", None),
        Some(GitKind::Result)
    );
    // push 方向不认：走原路
    assert_eq!(
        super::classify(
            &Method::GET,
            "/o/r.git/info/refs",
            Some("service=git-receive-pack")
        ),
        None
    );
    assert_eq!(
        super::classify(&Method::POST, "/o/r.git/git-receive-pack", None),
        None
    );
    assert_eq!(super::classify(&Method::GET, "/o/r", Some("tab=x")), None);
}

#[test]
fn invalid_heads_never_count_as_valid() {
    assert!(super::head_is_valid(GitKind::Advertisement, 200, ADV));
    assert!(super::head_is_valid(
        GitKind::Result,
        200,
        "application/x-git-upload-pack-result; charset=utf-8"
    ));
    assert!(super::head_is_valid(GitKind::Result, 200, RESULT));
    // 错误页/限流页/错类别：判负不判赢
    assert!(!super::head_is_valid(GitKind::Advertisement, 404, ADV));
    assert!(!super::head_is_valid(GitKind::Advertisement, 200, "text/html"));
    assert!(!super::head_is_valid(GitKind::Result, 200, ADV));
}

#[tokio::test]
async fn fast_valid_leg_wins_and_slow_ones_are_aborted() {
    let legs = vec![
        (
            "slow".to_string(),
            leg(300, Ok(git_resp(200, ADV, b"# service=git-upload-pack"))),
        ),
        (
            "fast".to_string(),
            leg(5, Ok(git_resp(200, ADV, b"# service=git-upload-pack"))),
        ),
    ];
    let win = super::run_race(legs, GitKind::Advertisement, Duration::from_secs(5))
        .await
        .expect("合法腿应判赢");
    assert_eq!(win.name, "fast");
    // 交付契约：前缀 + 剩余体 = 原体（小响应全部落在前缀里）。
    let rest = http_body_util::BodyExt::collect(win.body)
        .await
        .unwrap()
        .to_bytes();
    let mut got = win.prefix.to_vec();
    got.extend_from_slice(&rest);
    assert_eq!(got.as_slice(), b"# service=git-upload-pack");
}

#[tokio::test]
async fn error_head_leg_cannot_steal_the_race() {
    // 回得最快的坏镜像回 404：必须判负，让慢但合法的腿赢。
    let legs = vec![
        (
            "bad-404".to_string(),
            leg(5, Ok(git_resp(404, "text/html", b"nope"))),
        ),
        (
            "good-slow".to_string(),
            leg(60, Ok(git_resp(200, ADV, b"# service=git-upload-pack"))),
        ),
    ];
    let win = super::run_race(legs, GitKind::Advertisement, Duration::from_secs(5))
        .await
        .expect("合法腿应判赢");
    assert_eq!(win.name, "good-slow", "坏头不许抢赢");
}

#[tokio::test]
async fn all_failed_legs_report_reasons() {
    let legs = vec![
        ("e1".to_string(), leg(5, Err("拨号失败".to_string()))),
        (
            "e2".to_string(),
            leg(10, Ok(git_resp(403, "text/html", b"blocked"))),
        ),
    ];
    let errs = match super::run_race(legs, GitKind::Advertisement, Duration::from_secs(5)).await {
        Err(e) => e,
        Ok(_) => panic!("全灭必须报错"),
    };
    assert!(errs.iter().any(|e| e.contains("e1: 拨号失败")));
    assert!(errs.iter().any(|e| e.contains("e2: 非法头(403")));
}

#[tokio::test]
async fn race_budget_aborts_hanging_legs() {
    let legs = vec![(
        "hang".to_string(),
        Box::pin(std::future::pending::<
            Result<hyper::Response<BoxBody>, String>,
        >()) as LegFut,
    )];
    let errs = match super::run_race(legs, GitKind::Advertisement, Duration::from_millis(80)).await
    {
        Err(e) => e,
        Ok(_) => panic!("超窗必须放弃"),
    };
    assert!(errs.iter().any(|e| e.contains("超窗")));
}

#[tokio::test]
async fn small_body_wins_at_eof() {
    // 协商通告常 < 1KB：完整小响应先到 EOF 也算赢，前缀即全体。
    let legs = vec![(
        "tiny".to_string(),
        leg(5, Ok(git_resp(200, ADV, b"# service=git-upload-pack"))),
    )];
    let win = super::run_race(legs, GitKind::Advertisement, Duration::from_secs(5))
        .await
        .expect("小响应 EOF 也算赢");
    assert_eq!(win.prefix.as_ref(), b"# service=git-upload-pack");
}

#[test]
fn noscheme_placeholder_strips_scheme() {
    let url = crate::server::mitm::mirror::fill_template(
        "{mirror}/{noscheme}".to_string(),
        "https://m.example",
        "https://github.com/o/r.git/info/refs?service=git-upload-pack",
    );
    assert_eq!(
        url,
        "https://m.example/github.com/o/r.git/info/refs?service=git-upload-pack"
    );
}
