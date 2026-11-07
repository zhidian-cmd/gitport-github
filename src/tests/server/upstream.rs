use super::*;
use crate::server::protocol::full_body;

/// gzip;q=0 是明确拒绝：别再把压缩体塞给手写客户端(浏览器不受影响)。
#[test]
fn accepts_gzip_respects_explicit_reject() {
    let mk = |ae: &str| {
        hyper::Request::builder()
            .header("accept-encoding", ae)
            .body(())
            .unwrap()
    };
    assert!(accepts_gzip(&mk("gzip, deflate")));
    assert!(accepts_gzip(&mk("GZIP")));
    assert!(accepts_gzip(&mk("br, gzip;q=1")));
    assert!(!accepts_gzip(&mk("gzip;q=0")));
    assert!(!accepts_gzip(&mk("br")));
    // 分号/等号两侧的空白合法(HTTP OWS)，照样是明确拒绝
    assert!(!accepts_gzip(&mk("gzip; q=0")));
    assert!(!accepts_gzip(&mk("gzip ; q=0")));
    assert!(!accepts_gzip(&mk("br, gzip;q=0")));
}

/// 上行泵（git push 请求体通道）：2MB 体必须一字节不差送达——此前无测试，窗口/背压改错只会让 push 卡住不会变红。
#[tokio::test]
async fn h2_body_pump_delivers_every_byte() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    // 假上游：h2 服务端，收满请求体后把字节数写回响应体。
    let srv = tokio::spawn(async move {
        let (sock, _) = ln.accept().await.unwrap();
        let svc =
            hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                let n = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes().len())
                    .unwrap_or(0);
                Ok::<_, std::convert::Infallible>(hyper::Response::new(full_body(Bytes::from(
                    n.to_string(),
                ))))
            });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(sock), svc)
            .await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (send, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut send = send.ready().await.unwrap();
    let head = http::Request::builder()
        .method("POST")
        .uri("https://example.test/upload")
        .body(())
        .unwrap();
    let (resp_fut, stream) = send.send_request(head, false).unwrap();

    let len = 2 * 1024 * 1024;
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let body = full_body(Bytes::from(payload));
    let log: LogFn = Arc::new(|_: &str| {});
    let pump = h2_spawn_pump(stream, body, log);

    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), resp_fut)
        .await
        .expect("10s 内上游没收到完整请求体（泵卡住了）")
        .unwrap();
    let mut recv = resp.into_body();
    let mut echoed = Vec::new();
    while let Some(chunk) = recv.data().await {
        echoed.extend_from_slice(&chunk.unwrap());
    }
    pump.await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&echoed),
        len.to_string(),
        "上游收到的字节数应与发送量一致"
    );
    srv.abort();
}

#[test]
fn forced_gzip_gated_on_client_accept() {
    let req = hyper::Request::builder()
        .uri("https://github.com/a")
        .header("accept-encoding", "gzip, deflate, br")
        .body(())
        .unwrap();
    let out = upstream_request(&req, "github.com").unwrap();
    assert_eq!(
        out.headers().get("accept-encoding").unwrap(),
        "gzip",
        "声明过 gzip 的客户端应被强制 gzip"
    );

    let req2 = hyper::Request::builder()
        .uri("https://github.com/a")
        .body(())
        .unwrap();
    let out2 = upstream_request(&req2, "github.com").unwrap();
    assert!(
        out2.headers().get("accept-encoding").is_none(),
        "未声明的客户端应回身份编码"
    );

    let req3 = hyper::Request::builder()
        .uri("https://raw.githubusercontent.com/a")
        .body(())
        .unwrap();
    let out3 = upstream_request(&req3, "raw.githubusercontent.com").unwrap();
    assert!(
        out3.headers().get("accept-encoding").is_none(),
        "非嗅探 host 不添加"
    );
}

/// 单通道日志必须说清是「会话域规则」还是「候选真的不够」，别再混成一行。
#[test]
fn single_channel_reason_separates_rule_from_shortage() {
    let rule = single_channel_reason(HostClass::Session, 26, 0);
    assert!(rule.contains("会话域"), "会话域优先，候选再多也按规则解释");
    assert!(rule.contains("不开第二条"), "规则单通道要说清是不开，不是没得开");

    let other = single_channel_reason(HostClass::Other, 5, 4);
    assert!(other.contains("大文件"), "大文件/文档站单通道要单独说");

    let short = single_channel_reason(HostClass::Content, 3, 1);
    assert!(short.contains("候选"), "候选不足单独说");
    assert!(!short.contains("会话域"), "候选不足不许冒充会话域规则");

    // 会话域即使只剩 1 家，也仍按规则归因。
    assert!(single_channel_reason(HostClass::Session, 1, 0).contains("会话域"));
    assert_ne!(rule, short, "两种原因不能印成同一句话");
    assert_ne!(other, rule);
}

/// 主副分工：主通道只开新坑，副通道先看有没有现成的可捡。
#[test]
fn leg_plan_primary_opens_new_vice_reuses_existing() {
    // 会话域：只有主通道，绝不跨 IP。
    assert_eq!(
        plan_legs(true, 5, true),
        LegPlan {
            primary: true,
            vice_dial: false,
            vice_reuse: false,
        }
    );
    // 池空、空 IP 够两家：主副都去拨。
    assert_eq!(
        plan_legs(false, 2, false),
        LegPlan {
            primary: true,
            vice_dial: true,
            vice_reuse: false,
        }
    );
    // 池里已有现成通道：副通道直接复用，只剩主通道去开新 IP。
    assert_eq!(
        plan_legs(false, 1, true),
        LegPlan {
            primary: true,
            vice_dial: false,
            vice_reuse: true,
        }
    );
    // 只剩一个空 IP、又没现成的：老实单通道，不硬凑。
    assert_eq!(
        plan_legs(false, 1, false),
        LegPlan {
            primary: true,
            vice_dial: false,
            vice_reuse: false,
        }
    );
    // 全被已有通道占住：只剩复用这一条路。
    assert_eq!(
        plan_legs(false, 0, true),
        LegPlan {
            primary: false,
            vice_dial: false,
            vice_reuse: true,
        }
    );
    // 全被占住又没有现成的：一条腿都发不出来，交给上层重查连接池。
    assert_eq!(
        plan_legs(false, 0, false),
        LegPlan {
            primary: false,
            vice_dial: false,
            vice_reuse: false,
        }
    );
}

/// host 三分类：内容域双通道；会话域单通道自建优先；大文件/docs 单通道复用优先。
#[test]
fn host_classes_split_content_session_and_other() {
    let _g = crate::pool::TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join("gitport_host_class_seed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::pool::serial_load(&dir, Vec::new(), None);

    assert_eq!(host_class("github.com"), HostClass::Session);
    assert_eq!(
        host_class("api.github.com"),
        HostClass::Session,
        "api 也是会话域"
    );
    // 会话域按风控面划界(主站族之外的数据不是主站): githubassets/github.io/githubapp
    // 一律批窗内容域语义——githubassets 的长寿命通道不再占据 185.199.154/215
    // 这 8 个三类横跨的共享 IP。
    assert_eq!(host_class("githubassets.com"), HostClass::Other);
    assert_eq!(host_class("github.githubassets.com"), HostClass::Other);
    assert_eq!(host_class("github.io"), HostClass::Other);
    assert_eq!(host_class("githubapp.com"), HostClass::Other);
    assert_eq!(host_class("codeload.github.com"), HostClass::Other);
    assert!(!prefer_own_channel("githubassets.com"));

    assert_eq!(host_class("raw.githubusercontent.com"), HostClass::Content);
    assert_eq!(
        host_class("avatars.githubusercontent.com"),
        HostClass::Content
    );

    // 大文件域从内容域里摘出来：单通道、复用优先，不再给直连两片。
    assert_eq!(
        host_class("objects.githubusercontent.com"),
        HostClass::Other
    );
    assert_eq!(
        host_class("release-assets.githubusercontent.com"),
        HostClass::Other
    );
    // 只去 Fastly 边缘、不走主站的子域：一个都不能漏（清单见 docs/CONFIG.md）。
    for h in [
        "docs.github.com",
        "support.github.com",
        "resources.github.com",
        "desktop.github.com",
        "pages.github.com",
        "skills.github.com",
        "archiveprogram.github.com",
        "socialimpact.github.com",
        "raw.github.com",
        "agent.github.com",
        "uploads.github.com",
        "api.mcp.github.com",
    ] {
        assert_eq!(host_class(h), HostClass::Other, "{h} 应归「其他」");
        assert!(!prefer_own_channel(h), "{h} 复用优先");
    }

    assert!(prefer_own_channel("github.com"), "会话域自建优先");
    assert!(prefer_own_channel("api.github.com"), "api 也是会话域");
    assert!(
        !prefer_own_channel("objects.githubusercontent.com"),
        "大文件：复用优先"
    );
    // raw.github.com 在「其他」，raw.githubusercontent.com 在内容域，别混。
    assert_eq!(host_class("raw.githubusercontent.com"), HostClass::Content);
    assert!(!prefer_own_channel("raw.githubusercontent.com"));
}
