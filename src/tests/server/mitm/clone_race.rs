use super::*;
use futures_util::StreamExt;
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

/// 头合法但体永久静默（不发不关）：测速上限的靶子。
struct SilentBody;

impl hyper::body::Body for SilentBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Pending
    }
}

fn resp_with_silent_body(status: u16, ct: &str) -> hyper::Response<BoxBody> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(BoxBody::new(SilentBody))
        .unwrap()
}

/// 假腿：head_ms 后交合法头，体帧按"头后偏移"依次到达（sleep 携带正确 waker）。
fn timed_leg(head_ms: u64, frames: Vec<(u64, Bytes)>) -> LegFut {
    Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(head_ms)).await;
        let seq = futures_util::stream::iter(frames).then(|(ms, b)| async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok::<_, std::io::Error>(hyper::body::Frame::data(b))
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", RESULT)
            .body(BoxBody::new(http_body_util::StreamBody::new(seq)))
            .map_err(|e| e.to_string())
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
    assert!(super::head_is_valid(GitKind::Result, 200, RESULT));
    assert!(super::head_is_valid(
        GitKind::Result,
        200,
        "application/x-git-upload-pack-result; charset=utf-8"
    ));
    // 错误页/限流页/错类别：判负不判赢
    assert!(!super::head_is_valid(GitKind::Advertisement, 404, ADV));
    assert!(!super::head_is_valid(GitKind::Advertisement, 200, "text/html"));
    assert!(!super::head_is_valid(GitKind::Result, 200, ADV));
}

/// 全腿计速后比速度：同头延迟下，1KB 交付更快的腿速度更高、赢。
#[tokio::test]
async fn fastest_speed_wins() {
    let kb = Bytes::from(vec![b'x'; 1024]);
    let rest3 = Bytes::from(vec![b'y'; 3072]);
    let legs = vec![
        (
            "slow".to_string(),
            timed_leg(
                50,
                vec![(300, kb.clone()), (310, rest3.clone())],
            ),
        ),
        (
            "fast".to_string(),
            timed_leg(50, vec![(100, kb.clone()), (110, rest3.clone())]),
        ),
    ];
    let race = super::run_race(
        legs,
        GitKind::Result,
        Duration::from_secs(5),
        Duration::from_secs(3),
    )
    .await
    .expect("合法腿应判赢");
    assert_eq!(race.win.name, "fast", "speeds={:?}", race.speeds);
    assert!(!race.complete, "大响应路径不是 EOF 胜");
    assert_eq!(race.speeds.len(), 2, "两条腿都要有计速");
    let rest = http_body_util::BodyExt::collect(race.win.body)
        .await
        .unwrap()
        .to_bytes();
    let mut got = race.win.prefix.to_vec();
    got.extend_from_slice(&rest);
    assert_eq!(got.len(), 4096, "前缀+剩余必须逐字节等于原体");
}

/// 回得最快的坏镜像回 404：判负不判赢，让唯一有速度的合法腿赢。
#[tokio::test]
async fn error_head_leg_cannot_steal_the_race() {
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
    let race = super::run_race(
        legs,
        GitKind::Advertisement,
        Duration::from_secs(5),
        Duration::from_secs(3),
    )
    .await
    .expect("合法腿应判赢");
    assert_eq!(race.win.name, "good-slow", "坏头不许抢赢");
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
    let errs = match super::run_race(
        legs,
        GitKind::Advertisement,
        Duration::from_secs(5),
        Duration::from_secs(3),
    )
    .await
    {
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
    let errs = match super::run_race(
        legs,
        GitKind::Advertisement,
        Duration::from_millis(80),
        Duration::from_secs(3),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("超窗必须放弃"),
    };
    assert!(errs.iter().any(|e| e.contains("超窗")));
}

/// 完整收完（EOF）的腿直接赢——哪怕另一条腿先交满了 1KB：
/// 响应已全在手里，比速度没有意义（小响应的正确语义）。
#[tokio::test]
async fn eof_complete_beats_earlier_1kb() {
    let legs = vec![
        // mid-stream：先交满 1KB 但响应远没完（旧语义会误选它）
        (
            "mid-stream".to_string(),
            leg(50, Ok(git_resp(200, RESULT, &[b'x'; 4096]))),
        ),
        // complete：100ms 收完整份小响应
        (
            "complete".to_string(),
            leg(100, Ok(git_resp(200, ADV, b"# service=git-upload-pack"))),
        ),
    ];
    let race = super::run_race(
        legs,
        GitKind::Advertisement,
        Duration::from_secs(5),
        Duration::from_secs(3),
    )
    .await
    .expect("完整收完的腿应直接赢");
    assert_eq!(race.win.name, "complete", "EOF 完整收完优先于先到 1KB");
    assert!(race.complete, "必须标记为 EOF 胜");
}

/// 单腿测速上限：静默腿 3s（测试 120ms）出局不拖场，有速度的腿照常赢。
#[tokio::test]
async fn too_slow_leg_does_not_stall_the_race() {
    let t0 = std::time::Instant::now();
    let legs = vec![
        (
            "silent".to_string(),
            leg(10, Ok(resp_with_silent_body(200, RESULT))),
        ),
        (
            "worker".to_string(),
            timed_leg(
                10,
                vec![(80, Bytes::from(vec![b'x'; 1024])), (160, Bytes::from(vec![b'y'; 3072]))],
            ),
        ),
    ];
    let race = super::run_race(
        legs,
        GitKind::Result,
        Duration::from_secs(10),
        Duration::from_millis(120), // 测速窗压缩到 120ms
    )
    .await
    .expect("有速度的腿应赢");
    assert_eq!(race.win.name, "worker");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "静默腿出局不许拖满预算(实测 {:?})",
        t0.elapsed()
    );
    assert!(race.speeds.len() == 1, "只有 worker 有计速");
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
