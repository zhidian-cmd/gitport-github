//! git clone 独立加速科室：智能协议请求（协商 GET / 取包 POST）在克隆镜像链 + 直连腿
//! 之间做 1KB 竞速——最先交出「合法头 + 1KB 体」的独占整条流，其余当场掐断。
//! 克隆不可切分，与 ECT（为可切分下载选段派发）语义不同，故独立成科；
//! 链数据在 routes.json cloneMirrors，与大小文件链互不读写。
//! 全灭/超窗回退现有直连单流——行为底线与未开竞速时逐字节一致。

use super::super::protocol::{self, BoxBody};
use super::mirror;
use super::{get_direct, mitm_unavailable, path_of, write_upstream, UpstreamInfo};
use crate::server::upstream;
use crate::{pool, util::LogFn};
use bytes::Bytes;
use http::Method;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

/// 竞速预算：盖过镜像腿 5s 头预算 + 1KB 体余量；超窗整体放弃回退直连。
const RACE_BUDGET: Duration = Duration::from_secs(15);
/// 判赢阈值：先送出 1KB 体（或完整小响应先到 EOF）的腿赢。
const WIN_BYTES: usize = 1024;

/// git 智能协议请求类别（决定合法响应的 Content-Type）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum GitKind {
    /// GET /info/refs?service=git-upload-pack：协商通告。
    Advertisement,
    /// POST /git-upload-pack：取包结果流（clone/fetch 数据）。
    Result,
}

/// 认 git 克隆流量：只认 fetch 方向（push 的 receive-pack 原路不动）。
pub(super) fn classify(method: &Method, path: &str, query: Option<&str>) -> Option<GitKind> {
    if method == Method::GET
        && path.ends_with("/info/refs")
        && query.is_some_and(|q| q.contains("service=git-upload-pack"))
    {
        return Some(GitKind::Advertisement);
    }
    if method == Method::POST && path.ends_with("/git-upload-pack") {
        return Some(GitKind::Result);
    }
    None
}

/// 合法头：200 + git 协议专属 Content-Type。错误页/限流页/HTML 一律判负不判赢——
/// 否则回得最快的坏镜像会抢赢竞速，把 404 当克隆结果交出去。
fn head_is_valid(kind: GitKind, status: u16, ct: &str) -> bool {
    if status != 200 {
        return false;
    }
    let want = match kind {
        GitKind::Advertisement => "application/x-git-upload-pack-advertisement",
        GitKind::Result => "application/x-git-upload-pack-result",
    };
    ct.to_lowercase().contains(want)
}

/// 单腿的未来：交响应头 + 体流（由竞速核心统一验头、读 1KB 判赢）。
type LegFut = Pin<Box<dyn Future<Output = Result<hyper::Response<BoxBody>, String>> + Send>>;

/// 赢腿产出：合法头 + 已缓冲前缀体 + 剩余体流（前缀 + 剩余逐字节等于原体）。
struct LegWin {
    name: String,
    head: http::response::Parts,
    prefix: Bytes,
    body: BoxBody,
}

/// 腿裁判：等响应头 → 验头合法 → 读 1KB（或 EOF）→ LegWin；任一步不符 = Err(原因)。
async fn judge_leg(name: String, fut: LegFut, kind: GitKind) -> Result<LegWin, String> {
    let resp = fut.await.map_err(|e| format!("{name}: {e}"))?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !head_is_valid(kind, status, &ct) {
        return Err(format!("{name}: 非法头({status} {ct})"));
    }
    let (parts, body) = resp.into_parts();
    let (prefix, rest) = read_prefix(body, WIN_BYTES)
        .await
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(LegWin {
        name,
        head: parts,
        prefix,
        body: rest,
    })
}

/// 读前缀体：整帧攒到 1KB（帧大于阈值就整帧收下）或 EOF（完整小响应）。
async fn read_prefix(mut body: BoxBody, cap: usize) -> Result<(Bytes, BoxBody), String> {
    let mut buf: Vec<Bytes> = Vec::new();
    let mut n = 0usize;
    loop {
        match http_body_util::BodyExt::frame(&mut body).await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    n += d.len();
                    buf.push(d.clone());
                }
                if n >= cap {
                    break;
                }
            }
            Some(Err(e)) => return Err(format!("体流错误({e})")),
            None => break,
        }
    }
    let mut full = Vec::with_capacity(n);
    for b in &buf {
        full.extend_from_slice(b);
    }
    Ok((Bytes::from(full), body))
}

/// 竞速判赢核心（网络无关，可注入假腿单测）：每腿并发起跑，最先交出
/// 「合法头 + 1KB」者赢，其余腿当场 abort；非法头/错误只判负不判赢；
/// 全腿收场无一合法或预算耗尽 = Err(各腿失败原因)。
async fn run_race(
    legs: Vec<(String, LegFut)>,
    kind: GitKind,
    budget: Duration,
) -> Result<LegWin, Vec<String>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(legs.len());
    let mut handles = Vec::with_capacity(legs.len());
    for (name, fut) in legs {
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            // send 是异步的（容量满会等）：必须 await——裸调创建的发送 Future 落地即弃，
            // 值永远发不出去，竞速 recv 只会看到"通道已关"。
            let _ = tx.send(judge_leg(name, fut, kind).await).await;
        }));
    }
    drop(tx); // 全腿收场后 recv 返回 None，全灭不必等预算
    let mut fails: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => {
                for h in &handles {
                    h.abort();
                }
                fails.push(format!("竞速预算超窗({}s)", budget.as_secs()));
                return Err(fails);
            }
            Ok(Some(Ok(win))) => {
                for h in &handles {
                    h.abort();
                }
                return Ok(win);
            }
            Ok(Some(Err(e))) => fails.push(e),
            Ok(None) => return Err(fails),
        }
    }
}

/// 直连腿要进 spawned 任务，out 得变成 owned——头照抄、体按回放重建。
fn owned_out(out: &hyper::Request<BoxBody>, replay: &Option<Bytes>) -> hyper::Request<BoxBody> {
    let mut b = hyper::Request::builder()
        .method(out.method())
        .uri(out.uri().clone());
    for (k, v) in out.headers() {
        b = b.header(k, v);
    }
    let body = match replay {
        Some(x) => protocol::full_body(x.clone()),
        None => protocol::empty_body(),
    };
    b.body(body).expect("直连腿请求构造失败")
}

/// 克隆科室入口：镜像链 + 直连同台竞速；赢家续流交付，全灭回退现有直连单流。
#[allow(clippy::too_many_arguments)] // 与 mirror.rs 探测/切片函数同款：参数都是同链路借用，拆结构体只是搬运
pub(super) async fn handle(
    log: &LogFn,
    req: &hyper::Request<hyper::body::Incoming>,
    out: &hyper::Request<BoxBody>,
    host: &str,
    path: &str,
    kind: GitKind,
    replay: &Option<Bytes>,
    info: &UpstreamInfo,
) -> axum::response::Response<BoxBody> {
    let orig_url = match out.uri().query() {
        Some(q) => format!("https://{host}{}?{q}", path_of(out.uri())),
        None => format!("https://{host}{}", path_of(out.uri())),
    };
    let chain = pool::clone_chain();
    let mut legs: Vec<(String, LegFut)> = Vec::new();
    for m in &chain {
        let leg_body = match replay {
            Some(b) => protocol::full_body(b.clone()),
            None => protocol::empty_body(),
        };
        let req = match mirror::clone_request(out, m, &orig_url, leg_body) {
            Ok(r) => r,
            Err(e) => {
                (log)(&format!("[克隆] {m} 请求构造失败({e}), 剔出本轮"));
                continue;
            }
        };
        let log2 = log.clone();
        let m2 = m.clone();
        legs.push((
            m.clone(),
            Box::pin(async move { mirror::mirror_do(req, &m2, &log2).await }),
        ));
    }
    // 直连腿永远在场：镜像全坏时它就是今天的行为；克隆链为空不会进到这里。
    legs.push((
        "direct".to_string(),
        Box::pin({
            let out = owned_out(out, replay);
            let log2 = log.clone();
            let host2 = host.to_string();
            let info2 = info.clone();
            let replay2 = replay.clone();
            async move { get_direct(&log2, &out, &host2, &info2, &replay2).await }
        }),
    ));
    (log)(&format!(
        "[克隆] {host}{path} 竞速开跑({} 镜像 + 直连)",
        legs.len() - 1
    ));
    let t0 = Instant::now();
    match run_race(legs, kind, RACE_BUDGET).await {
        Ok(win) => {
            let ms = t0.elapsed().as_millis();
            (log)(&format!("[克隆] {host}{path} 赢家 {}({ms}ms)", win.name));
            let mut parts = win.head;
            // 体被重拼（前缀+剩余），content-length 剥掉交给 hyper 按实际分块；
            // 逐跳头照剥，其余原样转交（含 content-encoding——我们只是字节管道）。
            let drop: Vec<http::HeaderName> = parts
                .headers
                .keys()
                .filter(|k| {
                    upstream::is_hop_by_hop(k.as_str()) || k.as_str() == "content-length"
                })
                .cloned()
                .collect();
            for k in drop {
                parts.headers.remove(&k);
            }
            let resp = hyper::Response::from_parts(
                parts,
                crate::server::upstream::prepend_body(vec![win.prefix], win.body),
            );
            write_upstream(log, resp, "clone", info, host, path)
        }
        Err(fails) => {
            (log)(&format!(
                "[克隆] {host}{path} 竞速全灭({}), 回退直连单流",
                fails.join("; ")
            ));
            match get_direct(log, out, host, info, replay).await {
                Ok(r) => write_upstream(log, r, "direct", info, host, path),
                Err(e) => {
                    (log)(&format!(
                        "[MITM] {host}{path} 克隆竞速后直连也失败({e})"
                    ));
                    mitm_unavailable(
                        req,
                        host,
                        "克隆镜像与直连均不可用, 代理正在按表自动重试。",
                    )
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/clone_race.rs"]
mod tests;
