use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 真网端到端：白名单域名必须走 TlsSplit（真名 + 分片），且分片计数真的涨了。
/// 默认不跑（要能连 GitHub）：`cargo test -- --ignored whitelist_e2e`
/// IP 取 docs 实测的 Fastly .154；若该 IP 失效，换 plans.json 里任一 185.199.x.154。
#[tokio::test]
#[ignore]
async fn whitelist_e2e_through_pool() {
    use std::sync::atomic::Ordering;
    let before = SPLIT_DONE.load(Ordering::Relaxed);
    let d = dial_one("docs.github.com", "185.199.108.154", "docs.github.com", true)
        .await
        .expect("白名单拨号应成功");
    assert!(
        matches!(d, Dialed::TlsSplit(_)),
        "白名单域名应走分片腿，实际不是 TlsSplit"
    );
    assert!(
        SPLIT_DONE.load(Ordering::Relaxed) > before,
        "分片计数没涨：首包太短导致分片器退场了"
    );
}

/// 300 字节假 ClientHello 必须分三段发出，首末段间隔 ≥ 两个段间隔。
/// TCP 可能把小段合并到一次 read，所以断言的是时间差不是段数——
/// 合并恰恰说明分片没生效（间隔够大时内核不会攒到一起）。
#[tokio::test]
async fn sends_segments_with_gap() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = ln.accept().await.unwrap();
        let mut stamps = Vec::new();
        let mut total = 0usize;
        let mut buf = [0u8; 2048];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    stamps.push(std::time::Instant::now());
                    if total >= 300 {
                        break;
                    }
                }
            }
        }
        (total, stamps)
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let _ = tcp.set_nodelay(true);
    let mut io = SplitHello::new(tcp);
    // 首字节 0x16 才会触发分片（TLS 握手记录）
    let hello = vec![0x16u8; 300];
    let mut written = 0;
    while written < hello.len() {
        let n = io.write(&hello[written..]).await.unwrap();
        assert!(n > 0, "分片器写返回 0，会卡死握手");
        written += n;
    }
    assert_eq!(written, 300, "写入字节数对不上");

    let (total, stamps) = server.await.unwrap();
    assert_eq!(total, 300, "对端收到的字节数对不上");
    assert!(stamps.len() >= 2, "只收到一段，分片没生效");
    let spread = *stamps.last().unwrap() - stamps[0];
    let want = Duration::from_millis(crate::config::WHITELIST_SPLIT_GAP_MS * 2 - 20);
    assert!(
        spread >= want,
        "首末段间隔 {:?}，不足 {:?}，分片被合并或间隔没生效",
        spread,
        want
    );
}
/// 真实 ClientHello 形态：续传段首字节是 0x03(版本号)，不是 0x16——
/// 曾因 poll_write 重判首字节，第二刀直接直通、段间隔全丢，掩体空转。
/// (旧实现跑这条必红：stamps 只有 1 个。)
#[tokio::test]
async fn splits_real_clienthello_prefix() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = ln.accept().await.unwrap();
        let mut stamps = Vec::new();
        let mut total = 0usize;
        let mut buf = [0u8; 2048];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    stamps.push(std::time::Instant::now());
                    if total >= 307 {
                        break;
                    }
                }
            }
        }
        (total, stamps)
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let _ = tcp.set_nodelay(true);
    let mut io = SplitHello::new(tcp);
    // 真实握手记录形态：0x16 类型 + 0x03 0x01 版本 + 载荷
    let mut hello = vec![0x16u8, 0x03, 0x01];
    hello.resize(300, 0xAB);
    let mut written = 0;
    while written < hello.len() {
        let n = io.write(&hello[written..]).await.unwrap();
        assert!(n > 0, "分片器写返回 0，会卡死握手");
        written += n;
    }
    assert_eq!(written, 300, "写入字节数对不上");

    // 握手帧之后的帧是应用数据：done 门应直通，分段计数不得再涨。
    let counter = io.counter();
    let sent_before = counter.load(std::sync::atomic::Ordering::Relaxed);
    io.write_all(b"appdata").await.unwrap();
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Relaxed),
        sent_before,
        "应用数据帧不得再进分段计数(done 门失效)"
    );
    drop(io);

    let (total, stamps) = server.await.unwrap();
    assert_eq!(total, 307, "对端收到的字节数对不上");
    assert!(stamps.len() >= 2, "续传段被直通吞掉，只发出一段");
    let spread = *stamps.last().unwrap() - stamps[0];
    let want = Duration::from_millis(crate::config::WHITELIST_SPLIT_GAP_MS * 2 - 20);
    assert!(
        spread >= want,
        "首末段间隔 {:?}，不足 {:?}，分片被合并或间隔没生效",
        spread,
        want
    );
}
