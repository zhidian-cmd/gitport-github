//! 镜像链：内容域回落链（直连全灭时兜底）+ 校准测速 + 链容量/凭据防护。
//! cookie 语义边界：镜像腿一律剥离 cookie/authorization（第三方镜像不认识会话）。
use super::{path_of, BoxBody};
use crate::pool::{self, LogFn};
use crate::server::upstream;
use bytes::Bytes;
use std::sync::Arc;
use http::Method;
use http_body_util::BodyExt;
use std::time::{Duration, Instant};

const MIRROR_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const MIRROR_CHAIN_CAP: usize = 5;


/// 内容域小文件镜像链限前 5 家（仍串行）；大文件与 github.com 用全链。
fn mirror_chain_cap(host: &str) -> Option<usize> {
    (host != "github.com" && !pool::route::is_big_file_host(host)).then_some(MIRROR_CHAIN_CAP)
}

pub(super) async fn chain_fetch(
    log: &LogFn,
    out: &hyper::Request<BoxBody>,
    host: &str,
) -> Result<hyper::Response<BoxBody>, String> {
    // 凭据查询串拒走镜像：signed URL 等价 bearer，交第三方镜像即外泄。
    if let Some(q) = out.uri().query() {
        if has_credential_query(q) {
            return Err(format!("{host} 查询串含凭据参数, 拒绝镜像(防外泄)"));
        }
    }
    let orig_url = format!(
        "https://{host}{}",
        out.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default()
    );
    let path = path_of(out.uri());
    // 链归属与请求 host 解耦：release 附件走 release-assets 专属链（github.com 链头慢且中断）。
    // URL 仍用原 host 构造（镜像自己跟随 302 落点），熔断/限长/链序按归属 host。
    let chain_host = pool::route::mirror_chain_host(host, &path);
    if chain_host != host {
        (log)(&format!(
            "[镜像] {host}{path} 归属链 {chain_host}（不用 {host} 自己的链）"
        ));
    }
    let range = out.headers().get("range").and_then(|v| v.to_str().ok());
    let cond = out
        .headers()
        .get("if-none-match")
        .or_else(|| out.headers().get("if-modified-since"))
        .and_then(|v| v.to_str().ok());
    if let Some(r) = range {
        (log)(&format!("[镜像] {host}{path} 客户端 Range: {r}"));
    }
    if let Some(c) = cond {
        (log)(&format!("[镜像] {host}{path} 客户端条件请求: {c}"));
    }
    let chain = pool::mirror_chain(chain_host);
    if chain.is_empty() {
        return Err(format!("{host} 无镜像链({chain_host})"));
    }
    if pool::MIRROR_BREAKER.open(chain_host) {
        return Err(format!("{host} 镜像链熔断中(60s 内快速失败)"));
    }
    let limit = mirror_chain_cap(chain_host)
        .unwrap_or(chain.len())
        .min(chain.len());
    for (i, m) in chain.iter().take(limit).enumerate() {
        let req = match mirror_request(out, m, &orig_url) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[镜像] {host} {m} 请求构造失败({e}), 链内下一个"));
                continue;
            }
        };
        let t0 = Instant::now();
        match mirror_do(req, m, log).await {
            Ok(resp) => {
                let skipped = if i == 0 {
                    String::new()
                } else {
                    format!(", 跳过前 {i} 个")
                };
                (log)(&format!(
                    "[镜像] {host}{path} via {m} (链位 {}/{len}{skipped}, 头 {ms}ms)",
                    i + 1,
                    len = chain.len(),
                    ms = t0.elapsed().as_millis()
                ));
                pool::MIRROR_BREAKER.clear(chain_host); // 链是活的: 清全灭熔断
                return Ok(resp);
            }
            Err(e) => {
                (log)(&format!(
                    "[镜像] {host} {m} 失败({e}, {}ms), 链内下一个",
                    t0.elapsed().as_millis()
                ));
            }
        }
    }
    pool::MIRROR_BREAKER.set(chain_host); // 整链烧完仍全灭: 熔断 60s, 后续图快速失败
    Err(format!("{host} 镜像链全灭({chain_host} 链 {limit} 个)"))
}
fn mirror_request(
    out: &hyper::Request<BoxBody>,
    mirror: &str,
    orig_url: &str,
) -> Result<hyper::Request<BoxBody>, String> {
    let url = format!("{mirror}/{orig_url}");
    let mut builder = hyper::Request::builder().method(out.method()).uri(url);
    for (k, v) in out.headers() {
        let low = k.as_str().to_lowercase();
        if upstream::is_hop_by_hop(&low)
            || matches!(
                low.as_str(),
                "cookie" | "authorization" | "host" | "referer" | "user-agent"
            )
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    // CF 系镜像的 Bot Fight Mode 拦非浏览器 UA：镜像腿恒定浏览器 UA（剥掉
    // 客户端原 UA 后统一注入，否则 builder.header 是追加会出现两个 UA），
    // 校准/无 UA 客户端也能过；对外特征一致（见 MIRROR_UA 注释）。
    builder = builder.header(http::header::USER_AGENT, http::HeaderValue::from_static(MIRROR_UA));
    let body =
        BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(|e| std::io::Error::other(e)));
    builder.body(body).map_err(|e| e.to_string())
}
/// 镜像腿单发：5s 响应头预算 + 假页拒判（≥400 或 text/html 不算成绩）。
async fn mirror_do(
    req: hyper::Request<BoxBody>,
    mirror: &str,
    log: &LogFn,
) -> Result<hyper::Response<BoxBody>, String> {
    let client = upstream::mirror_client(log);
    let timed = tokio::time::timeout(MIRROR_HEAD_TIMEOUT, client.request(req));
    let resp = match timed.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("镜像响应头预算超时".to_string()),
    };
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    // 镜像须直出内容：3xx=甩锅、HTML=假站、≥400=拒绝；304 例外（缓存热时合法响应，曾误判致整链全灭）。
    let st = resp.status().as_u16();
    if (st >= 300 && st != 304) || ct.contains("text/html") {
        return Err(format!("{mirror} 状态 {st}"));
    }
    let (parts, body) = resp.into_parts();
    let body = BoxBody::new(http_body_util::BodyExt::map_err(
        body,
        std::io::Error::other,
    ));
    Ok(hyper::Response::from_parts(parts, body))
}
fn has_credential_query(query: &str) -> bool {
    query.split('&').any(|kv| {
        let name = kv.split('=').next().unwrap_or("").to_lowercase();
        name == "token"
            || name == "sig"
            || name == "signature"
            || name == "jwt"
            || name == "auth"
            || name == "access_token"
            || name == "session_token"
            || name == "awsaccesskeyid"
            || name.starts_with("x-amz-")
    })
}

pub const CALIBRATE_TEMPLATES: &[(&str, &str)] = &[
    (
        "github.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.5.1/git-lfs-windows-amd64-v3.5.1.zip",
    ),
    (
        "raw.githubusercontent.com",
        "https://raw.githubusercontent.com/torvalds/linux/master/README",
    ),
    (
        "gist.githubusercontent.com",
        "https://gist.githubusercontent.com/octocat/6cad326836d38bd3a7ae/raw/db9c55113504e46fa076e7df3a04ce592e2e86d8/hello_world.rb",
    ),
    (
        "avatars.githubusercontent.com",
        "https://avatars.githubusercontent.com/u/1?v=4&size=64",
    ),
    (
        "user-images.githubusercontent.com",
        "https://user-images.githubusercontent.com/543273/64829357-7d195e00-d5ce-11e9-91f1-e58deb6e7bbf.png",
    ),
    (
        "codeload.github.com",
        "https://codeload.github.com/torvalds/linux/tar.gz/refs/tags/v2.6.11",
    ),
    (
        "objects.githubusercontent.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.5.1/git-lfs-windows-amd64-v3.5.1.zip",
    ),
    (
        "release-assets.githubusercontent.com",
        "https://github.com/git-lfs/git-lfs/releases/download/v3.0.2/git-lfs-windows-amd64-v3.0.2.zip",
    ),
    (
        "media.githubusercontent.com",
        "https://media.githubusercontent.com/media/torvalds/linux/master/README",
    ),
];
// 两模式：Throughput=大文件四链 11 家并发竞速（12s 窗口按实收字节排名）；Ttfb=内容域五链响应头测速。
// 铁律：host 间严格串行——同一镜像服务多条链，跨链并发互相污染测量；并发只在手动低频校准，常规流量竞速已废。
pub enum CalibMode {
    Throughput,
    Ttfb,
}

/// 校准互斥：webui 用 swap(true) 抢跑，跑完 store(false)。
pub static CALIB_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static CALIB_REPORT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn last_calibrate_report() -> String {
    CALIB_REPORT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

pub fn set_calibrate_report(r: Option<String>) {
    if let Ok(mut g) = CALIB_REPORT.lock() {
        *g = r;
    }
}

const CALIB_THROUGHPUT_WINDOW: Duration = Duration::from_secs(12);
const CALIB_THROUGHPUT_CAP: u64 = 5 * 1024 * 1024;

/// 镜像腿统一浏览器 UA：CF 系镜像的 Bot Fight Mode 会拦非浏览器 UA（裸
/// Mozilla/5.0 一律 403），校准等代理自发的请求没有 UA 更过不了——恒定注入
/// Chrome UA，浏览器/校准/命令行走镜像腿的对外特征完全一致。
const MIRROR_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

fn mirror_get(uri: http::Uri) -> Result<hyper::Request<BoxBody>, String> {
    hyper::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("user-agent", MIRROR_UA)
        .header("accept", "*/*")
        .body(BoxBody::new(
            http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
        ))
        .map_err(|e| e.to_string())
}

async fn throughput_probe(
    mirror: &str,
    tmpl: &str,
    log: &LogFn,
) -> Result<(u64, u128), String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let req = mirror_get(uri)?;
    let client = upstream::mirror_client(log);
    let start = tokio::time::Instant::now();
    let deadline = start + CALIB_THROUGHPUT_WINDOW;
    let resp = match tokio::time::timeout_at(deadline, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("窗口内未见响应头".to_string()),
    };
    let st = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if st >= 300 || ct.contains("text/html") {
        return Err(format!("{mirror} 状态 {st}"));
    }
    let mut body = resp.into_body();
    let mut n: u64 = 0;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() || n >= CALIB_THROUGHPUT_CAP {
            break;
        }
        match tokio::time::timeout(remain, http_body_util::BodyExt::frame(&mut body)).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(d) = frame.into_data() {
                    n += d.len() as u64;
                }
            }
            _ => break, // EOF / 上游错 / 窗口到
        }
    }
    let ms = start.elapsed().as_millis();
    Ok((n, ms))
}

/// 单 host 内 11 家并发竞速：同窗口起跑按字节数排名，失败(负)沉底。
async fn throughput_race(
    host: &str,
    chain: &[String],
    tmpl: &str,
    log: &LogFn,
) -> Vec<(String, i64)> {
    let host = host.to_string();
    let mut joins = tokio::task::JoinSet::new();
    for m in chain {
        let m = m.clone();
        let tmpl = tmpl.to_string();
        let host = host.clone();
        let log = log.clone();
        joins.spawn(async move {
            let r = throughput_probe(&m, &tmpl, &log).await;
            match &r {
                Ok((bytes, ms)) => {
                    (log)(&format!(
                        "[校准] {host} {m} 吞吐 {}KB ({ms}ms 内)",
                        bytes / 1024
                    ));
                }
                Err(e) => {
                    (log)(&format!("[校准] {host} {m} 失败({e})"));
                }
            }
            (m, r.map(|(b, _)| b as i64).unwrap_or(-1))
        });
    }
    let mut rows: Vec<(String, i64)> = Vec::new();
    while let Some(r) = joins.join_next().await {
        if let Ok(row) = r {
            rows.push(row);
        }
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1)); // 字节数降序，失败(负)沉底
    rows
}

async fn calibrate_one(mirror: &str, tmpl: &str, log: &LogFn) -> Result<u16, String> {
    let uri: http::Uri = format!("{mirror}/{tmpl}")
        .parse()
        .map_err(|e| format!("URL 解析失败: {e}"))?;
    let resp = mirror_do(mirror_get(uri)?, mirror, log).await?;
    Ok(resp.status().as_u16())
}
/// TTFB 排名：毫秒小者优；失败项记负数，一律排最后（同类之间按耗时）。
fn rank_by_ttfb(rows: &mut [(String, i64)]) {
    rows.sort_by_key(|(_, ms)| (*ms < 0, ms.unsigned_abs()));
}

pub async fn calibrate_chains(log: &LogFn, mode: CalibMode) -> String {
    let chains = pool::mirror_chains_snapshot();
    let mut report = String::new();
    for (host, chain) in chains {
        let big = pool::route::is_big_file_host(&host);
        let eligible = match mode {
            CalibMode::Throughput => big,
            CalibMode::Ttfb => !big,
        };
        if !eligible {
            continue;
        }
        let Some((_, tmpl)) = CALIBRATE_TEMPLATES.iter().find(|(h, _)| *h == host) else {
            continue;
        };
        let rows = match mode {
            CalibMode::Throughput => throughput_race(&host, &chain, tmpl, log).await,
            CalibMode::Ttfb => {
                let mut rows: Vec<(String, i64)> = Vec::new();
                for m in &chain {
                    let t0 = Instant::now();
                    let res = calibrate_one(m, tmpl, log).await;
                    let ms = t0.elapsed().as_millis() as i64;
                    match res {
                        Ok(st) => {
                            (log)(&format!("[校准] {host} {m} {ms}ms {st}"));
                            rows.push((m.clone(), ms));
                        }
                        Err(e) => {
                            (log)(&format!("[校准] {host} {m} 失败({e})"));
                            rows.push((m.clone(), -(ms.max(1)))); // 负数 = 失败，沉底
                        }
                    }
                }
                rank_by_ttfb(&mut rows);
                rows
            }
        };
        let new_chain: Vec<String> = rows.iter().map(|(m, _)| m.clone()).collect();
        let summary: Vec<String> = rows
            .iter()
            .map(|(m, v)| {
                if *v >= 0 {
                    let human = match mode {
                        CalibMode::Throughput => format!("{}KB", v / 1024),
                        CalibMode::Ttfb => format!("{}ms", v),
                    };
                    format!("{}({})", m.trim_start_matches("https://"), human)
                } else {
                    format!("{}(失败)", m.trim_start_matches("https://"))
                }
            })
            .collect();
        report.push_str(&format!("{host}\n  {}\n", summary.join(" -> ")));
        pool::set_mirror_chain(&host, &new_chain, "校准");
    }
    if report.is_empty() {
        "无可校准的镜像链".to_string()
    } else {
        report
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_chain_cap_scope() {
        for h in [
            "raw.githubusercontent.com",
            "camo.githubusercontent.com",
            "avatars.githubusercontent.com",
            "user-images.githubusercontent.com",
            "media.githubusercontent.com",
            "gist.githubusercontent.com",
        ] {
            assert_eq!(mirror_chain_cap(h), Some(5), "{h} 应限长 5 家");
        }
        for h in [
            "codeload.github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "github.com",
        ] {
            assert_eq!(mirror_chain_cap(h), None, "{h} 应用全链");
        }
    }

    #[test]
    fn mirror_request_strips_identity_and_hop_by_hop() {
        let out = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://raw.githubusercontent.com/a/b")
            .header("cookie", "logged_in=yes")
            .header("authorization", "Bearer tok")
            .header("connection", "close")
            .header("keep-alive", "timeout=5")
            .header("upgrade", "websocket")
            .header("te", "trailers")
            .header("range", "bytes=0-1023")
            .header("accept-encoding", "gzip")
            .header("user-agent", "UA/1.0")
            .body(BoxBody::new(
                http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other),
            ))
            .unwrap();
        let req = mirror_request(
            &out,
            "https://gh-proxy.com",
            "https://raw.githubusercontent.com/a/b",
        )
        .unwrap();
        let h = req.headers();
        for gone in [
            "cookie",
            "authorization",
            "host",
            "referer",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
        ] {
            assert!(h.get(gone).is_none(), "{gone} 应被剥除");
        }
        assert_eq!(h.get("range").unwrap(), "bytes=0-1023", "业务头必须保留");
        assert_eq!(h.get("accept-encoding").unwrap(), "gzip");
        assert_eq!(h.get("user-agent").unwrap(), MIRROR_UA);
        let uri = req.uri().to_string();
        assert!(
            uri.starts_with("https://gh-proxy.com/https://raw.githubusercontent.com/"),
            "拼 URL 形态: {uri}"
        );
    }

    #[test]
    fn calibrate_templates_cover_content_hosts() {
        for h in pool::CONTENT_HOSTS {
            assert!(
                CALIBRATE_TEMPLATES.iter().any(|(host, _)| host == h),
                "{h} 缺校准模板"
            );
        }
    }

    #[test]
    fn credential_query_detection() {
        for q in [
            "token=abc",
            "sig=1",
            "signature=1",
            "jwt=1",
            "auth=1",
            "access_token=x",
            "session_token=1",
            "AWSAccessKeyId=k",
            "X-Amz-Signature=abc",
            "x-amz-credential=1",
            "a=1&access_token=x",
        ] {
            assert!(has_credential_query(q), "{q} 应判含凭据");
        }
        for q in ["", "foo=token", "page=2&q=tokenize", "tokens=1"] {
            assert!(!has_credential_query(q), "{q} 不该误判（名字才参与，值不算）");
        }
    }

    #[test]
    fn ttfb_rank_fastest_first_failures_last() {
        let mut rows = vec![
            ("slow".to_string(), 900),
            ("fast".to_string(), 120),
            ("mid".to_string(), 300),
            ("dead".to_string(), -50),
        ];
        rank_by_ttfb(&mut rows);
        let order: Vec<&str> = rows.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(order, ["fast", "mid", "slow", "dead"], "{rows:?}");
    }


    #[tokio::test]
    async fn chain_fetch_refuses_credentialed_url() {
        let log: LogFn = Arc::new(|_: &str| {});
        let req = hyper::Request::builder()
            .uri("https://raw.githubusercontent.com/o/r/f?sig=abc")
            .body(BoxBody::new(
                http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}),
            ))
            .unwrap();
        let err = chain_fetch(&log, &req, "raw.githubusercontent.com")
            .await
            .unwrap_err();
        assert!(err.contains("拒绝镜像"), "签名 URL 不得交给第三方镜像: {err}");
    }

}
