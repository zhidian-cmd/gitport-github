//! git clone 独立加速科室：智能协议请求（协商 GET / 取包 POST）在克隆链 + 直连腿之间竞速。
//! 计速语义（用户定版）：从连接建立（= 响应头到达，拨号/TLS 成本不计入）起微秒计时，
//! 每腿交满 1KB 记速度；先交满者**不**掐别人——等全部腿有速度（或出局）后再比速度，
//! 最快者独占整条流，其余掐断。完整收完（EOF）的腿直接赢——响应已全在手里，无比较意义。
//! 单腿 3s 测速上限防装死；全灭/超窗回退现有直连单流——行为底线与未开竞速时逐字节一致。
//! 克隆不可切分，与 ECT（为可切分下载选段派发）语义不同，故独立成科；
//! 链数据在 routes.json mirrors_clone，与大小文件链互不读写。

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

/// 竞速预算：盖过镜像腿 5s 头预算 + 3s 测速窗 + 余量；超窗整体放弃回退直连。
const RACE_BUDGET: Duration = Duration::from_secs(15);
/// 计速窗口：每腿交满 1KB 即计速（从响应头到达起算）。
const WIN_BYTES: usize = 1024;
/// 单腿测速上限：头到达后 3s 没交满 1KB 记"无速度"出局，不再等它。
const SPEED_WINDOW: Duration = Duration::from_secs(3);

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

/// 合法头：200 + git 协议专属 Content-Type。错误页/限流页/HTML 一律判负——
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

/// 单腿的未来：交响应头 + 体流（由竞速核心统一验头、计速）。
type LegFut = Pin<Box<dyn Future<Output = Result<hyper::Response<BoxBody>, String>> + Send>>;

/// 赢腿产出：合法头 + 已缓冲前缀体 + 剩余体流（前缀 + 剩余逐字节等于原体）。
struct LegWin {
    name: String,
    head: http::response::Parts,
    prefix: Bytes,
    body: BoxBody,
}

/// 单腿裁决结果。
enum LegOutcome {
    /// 交满 1KB：带速度（字节/秒，自响应头到达起算）参选。
    Speed {
        name: String,
        speed: f64,
        win: LegWin,
    },
    /// 完整响应已收完：直接赢。
    Complete(LegWin),
    /// 3s 没交满 1KB：无速度出局。
    TooSlow { name: String },
    /// 头错误/非法/体流错误（why 已含腿名）。
    Failed { why: String },
}

/// 腿 worker：等响应头 → 验头 → 计速（1KB 窗口，speed_window 上限）→ 出局别。
async fn leg_worker(
    name: String,
    fut: LegFut,
    kind: GitKind,
    speed_window: Duration,
) -> LegOutcome {
    let resp = match fut.await {
        Ok(r) => r,
        Err(e) => {
            return LegOutcome::Failed {
                why: format!("{name}: {e}"),
            }
        }
    };
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !head_is_valid(kind, status, &ct) {
        return LegOutcome::Failed {
            why: format!("{name}: 非法头({status} {ct})"),
        };
    }
    let (parts, mut body) = resp.into_parts();
    // 计时基点 = 响应头到达（通道必然已建立）：拨号/TLS/头等待不计入速度，
    // 热直连的"零握手"优势不再压人——这正是用户定版要剔除的不对称。
    let t0 = Instant::now();
    let mut buf: Vec<Bytes> = Vec::new();
    let mut n = 0usize;
    loop {
        let left = speed_window.saturating_sub(t0.elapsed());
        if left.is_zero() {
            return LegOutcome::TooSlow { name };
        }
        match tokio::time::timeout(left, http_body_util::BodyExt::frame(&mut body)).await {
            Err(_) => return LegOutcome::TooSlow { name },
            Ok(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    n += d.len();
                    buf.push(d.clone());
                }
                if n >= WIN_BYTES {
                    let speed = n as f64 / t0.elapsed().as_secs_f64();
                    let win = LegWin {
                        name: name.clone(),
                        head: parts,
                        prefix: concat_buf(&buf, n),
                        body,
                    };
                    return LegOutcome::Speed { name, speed, win };
                }
            }
            Ok(Some(Err(e))) => {
                return LegOutcome::Failed {
                    why: format!("{name}: 体流错误({e})"),
                };
            }
            Ok(None) => {
                // 完整响应已收完（小响应常 <1KB）：直接赢，无比较意义。
                return LegOutcome::Complete(LegWin {
                    name,
                    head: parts,
                    prefix: concat_buf(&buf, n),
                    body,
                });
            }
        }
    }
}

fn concat_buf(buf: &[Bytes], n: usize) -> Bytes {
    let mut full = Vec::with_capacity(n);
    for b in buf {
        full.extend_from_slice(b);
    }
    Bytes::from(full)
}

/// 竞速判赢核心（网络无关，可注入假腿单测）：
/// - 完整收完（EOF）的腿立即赢，其余掐断；
/// - 全腿计速（或出局）后比速度，最快者赢；
/// - 无任何速度（全灭/全太慢）= Err(各腿失败原因)。
async fn run_race(
    legs: Vec<(String, LegFut)>,
    kind: GitKind,
    budget: Duration,
    speed_window: Duration,
) -> Result<RaceWin, Vec<String>> {
    let total = legs.len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(total);
    let mut handles = Vec::with_capacity(total);
    for (name, fut) in legs {
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            // send 是异步的（容量满会等）：必须 await——裸调创建的发送 Future 落地即弃，
            // 值永远发不出去，竞速 recv 只会看到"通道已关"。
            let _ = tx
                .send(leg_worker(name, fut, kind, speed_window).await)
                .await;
        }));
    }
    drop(tx); // 全腿收场后 recv 返回 None，不必等预算
    let mut speeds: Vec<(String, f64)> = Vec::new();
    let mut wins: Vec<LegWin> = Vec::new();
    let mut fails: Vec<String> = Vec::new();
    let mut resolved = 0usize;
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let got = tokio::time::timeout_at(deadline, rx.recv()).await;
        match got {
            Err(_) => {
                for h in &handles {
                    h.abort();
                }
                fails.push(format!("竞速预算超窗({}s)", budget.as_secs()));
                return Err(fails);
            }
            Ok(None) => {
                fails.push("竞速通道异常收场".to_string());
                return Err(fails);
            }
            Ok(Some(outcome)) => {
                match outcome {
                    LegOutcome::Complete(win) => {
                        for h in &handles {
                            h.abort();
                        }
                        return Ok(RaceWin {
                            win,
                            speeds,
                            complete: true,
                        });
                    }
                    LegOutcome::Speed { name, speed, win } => {
                        speeds.push((name, speed));
                        wins.push(win);
                        resolved += 1;
                    }
                    LegOutcome::TooSlow { name } => {
                        fails.push(format!(
                            "{name}: {}ms 未交满 1KB",
                            speed_window.as_millis()
                        ));
                        resolved += 1;
                    }
                    LegOutcome::Failed { why } => {
                        fails.push(why);
                        resolved += 1;
                    }
                }
                if resolved == total {
                    for h in &handles {
                        h.abort();
                    }
                    // 全腿计速/出局：比速度，最快者赢。
                    let mut ranked: Vec<(String, f64)> = speeds.clone();
                    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    if let Some((wname, _)) = ranked.first() {
                        if let Some(pos) = wins.iter().position(|w| &w.name == wname) {
                            let win = wins.swap_remove(pos);
                            return Ok(RaceWin {
                                win,
                                speeds,
                                complete: false,
                            });
                        }
                    }
                    return Err(fails);
                }
            }
        }
    }
}

/// 竞速产出：赢腿 + 各腿计速（日志用）。
struct RaceWin {
    win: LegWin,
    speeds: Vec<(String, f64)>,
    /// true = EOF 完整收完赢（无比较）。
    complete: bool,
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

/// 速度人话：>=1MB/s 用 MB，否则 KB。
fn fmt_speed(s: f64) -> String {
    if s >= 1_048_576.0 {
        format!("{:.1}MB/s", s / 1_048_576.0)
    } else {
        format!("{:.0}KB/s", s / 1024.0)
    }
}

/// 克隆科室入口：镜像链 + 直连同台计速竞速；赢家续流交付，全灭回退现有直连单流。
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
    match run_race(legs, kind, RACE_BUDGET, SPEED_WINDOW).await {
        Ok(race) => {
            let ms = t0.elapsed().as_millis();
            let how = if race.complete {
                "完整收完".to_string()
            } else {
                "速度最快".to_string()
            };
            let mut detail: Vec<String> = race
                .speeds
                .iter()
                .map(|(n, s)| format!("{n} {}", fmt_speed(*s)))
                .collect();
            detail.sort();
            (log)(&format!(
                "[克隆] {host}{path} 赢家 {}({ms}ms, {how}); 计速: {}",
                race.win.name,
                detail.join(", ")
            ));
            let mut parts = race.win.head;
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
                upstream::prepend_body(vec![race.win.prefix], race.win.body),
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
