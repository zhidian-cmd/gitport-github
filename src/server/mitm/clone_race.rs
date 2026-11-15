//! git clone 独立加速科室：智能协议请求（协商 GET / 取包 POST）在克隆链 + 直连腿之间竞速。
//! 计速语义（用户定版）：测速窗锚在**首个体字节**（头只是元数据秒回；取包 POST 的
//! 首字节要等 GitHub 生成 pack 1~3s，头后干等不算腿的错），窗长 0.5s，
//! 速度 = 窗口实收字节 ÷ 窗长；先交满者**不**掐别人——等全部腿有速度（或出局）后
//! 再比速度，最快者独占整条流，其余掐断。完整收完（EOF）的腿直接赢——响应已全在
//! 手里，无比较意义。窗口内不足 1KB（=2KB/s）出局；全灭/超窗回退现有直连单流
//! （预算收口不丢已计速的胜者）。克隆不可切分，与 ECT（为可切分下载选段派发）
//! 语义不同，故独立成科；链数据在 routes.json mirrors_clone，与大小文件链互不读写。

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

/// 竞速预算：兜底线，必须盖过各腿内层头预算（镜像 5s / 直连 4s）+ 测速窗 0.5s——
/// 外层预算小于内层 = 慢首字节腿全灭（审计 #2 的数值越界），全灭又引发回退重发（#3）。
const RACE_BUDGET: Duration = Duration::from_secs(8);
/// 入选门槛：测速窗内收满 1KB 才算"有速度"（不足 = 不足 2KB/s，出局）；
/// 速度分子 = 窗口内**实收字节**（不是到 1KB 的耗时——那是调度噪声）。
const WIN_BYTES: usize = 1024;
/// 单腿测速上限：头到达后 0.5s 没交满 1KB 记"无速度"出局——
/// 1024B/0.5s = 2KB/s，"0.5s 没速度"与"不足 2KB/s"是同一道门，慢腿没有留的价值。
const SPEED_WINDOW: Duration = Duration::from_millis(500);
/// 单腿缓冲硬上限（审计 #1）：到顶停止消费，剩余字节留在 body 续传。
/// 天花板 = 2MB/0.5s = 4MB/s——超出的镜像并列，但全部远超直连，胜负语义不受损。
const BUF_CAP: usize = 2 * 1024 * 1024;

/// git 智能协议请求类别（决定合法响应的 Content-Type）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum GitKind {
    /// GET /info/refs?service=git-upload-pack：协商通告。
    Advertisement,
    /// POST /git-upload-pack：取包结果流（clone/fetch 数据）。
    Result,
}

/// 认 git 克隆流量：只认 fetch 方向（push 的 receive-pack 原路不动）。
/// 入参 = 完整 path_and_query（含 query）——生产入参就是这个形状，内部自己拆，
/// 调用方拼错形状也不会静默漏判（审计 #1：曾用 ends_with 认带 query 的串，GET 全漏）。
pub(super) fn classify(method: &Method, path_and_query: &str) -> Option<GitKind> {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
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

/// 合法头：200 + git 协议专属 Content-Type。CT 按 `;` 切开精确比 media type——
/// `text/plain; note=application/x-git-...` 这类挂名响应不得蒙混（审计 #5）；
/// 错误页/限流页/HTML 一律判负——否则回得最快的坏镜像会抢赢竞速，把 404 当克隆结果交出去。
fn head_is_valid(kind: GitKind, status: u16, ct: &str) -> bool {
    if status != 200 {
        return false;
    }
    let media = ct.split(';').next().unwrap_or("").trim().to_lowercase();
    let want = match kind {
        GitKind::Advertisement => "application/x-git-upload-pack-advertisement",
        GitKind::Result => "application/x-git-upload-pack-result",
    };
    media == want
}

/// 响应体形状校验（审计 #5/#3：坏镜像缓存投毒/限流页不得借"最快"抢赢）：
/// 协商通告 = 智能协议 banner；取包结果 = pkt-line **自洽**——长度字段 ≤ 实收字节、
/// payload 为 NAK/version/ack 之一，flush 后必须还有 pkt。
/// `0000<html>限流页` 这类伪造前缀（4 位十六进制撞大运）过不了。
fn body_looks_git(kind: GitKind, frames: &[Bytes]) -> bool {
    match kind {
        GitKind::Advertisement => {
            let flat: Vec<u8> = frames
                .iter()
                .flat_map(|b| b.iter())
                .take(256)
                .copied()
                .collect();
            flat.windows(25).any(|w| w == b"# service=git-upload-pack")
        }
        GitKind::Result => {
            let flat: Vec<u8> = frames
                .iter()
                .flat_map(|b| b.iter())
                .take(1024)
                .copied()
                .collect();
            if flat.len() < 4 {
                return false;
            }
            let Some(l1) = std::str::from_utf8(&flat[..4])
                .ok()
                .and_then(|s| usize::from_str_radix(s, 16).ok())
            else {
                return false;
            };
            if l1 < 4 || l1 > flat.len() {
                return false; // 长度字段必须自洽
            }
            if l1 > 4 {
                let p = &flat[4..l1];
                return p.starts_with(b"NAK")
                    || p.starts_with(b"version")
                    || p.starts_with(b"ack");
            }
            // flush（0000）：后面必须还有自洽 pkt，裸 flush + 非 pkt 内容 = 伪造
            if flat.len() < 8 {
                return false;
            }
            let Some(l2) = std::str::from_utf8(&flat[4..8])
                .ok()
                .and_then(|s| usize::from_str_radix(s, 16).ok())
            else {
                return false;
            };
            l2 > 4 && l2 <= flat.len() - 4
        }
    }
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
    /// 测速窗内没交满 1KB（不足 2KB/s）：无速度出局。
    TooSlow { name: String },
    /// 头错误/非法/体流错误（why 已含腿名）。
    Failed { why: String },
}

/// 窗口收口：n < 1KB = 不足 2KB/s 出局；体形状不过验 = 坏镜像出局；否则带速度参选。
/// 速度分母固定为窗长（实测经过时间带调度抖动 δ，会翻转同吞吐腿的排序，审计 #12）。
fn speed_outcome(
    name: String,
    kind: GitKind,
    buf: &[Bytes],
    n: usize,
    parts: http::response::Parts,
    body: BoxBody,
    window: Duration,
) -> LegOutcome {
    if n < WIN_BYTES {
        return LegOutcome::TooSlow { name };
    }
    if !body_looks_git(kind, buf) {
        return LegOutcome::Failed {
            why: format!("{name}: 响应体不是 git 协议"),
        };
    }
    let win = LegWin {
        name: name.clone(),
        head: parts,
        prefix: concat_buf(buf, n),
        body,
    };
    let speed = n as f64 / window.as_secs_f64();
    LegOutcome::Speed { name, speed, win }
}

/// 腿 worker：等响应头 → 验头 → 等**首个体字节**（GitHub 生成 pack 要 1~3s，头后干等
/// 不算腿的错——头只是 HTTP 元数据，秒回；锚在头上会把"头快体慢"的全部腿判死，
/// 实测 8 镜像全灭、慢拨号的直连唯一幸存）→ 首字节起 0.5s 测速窗累计字节 → 收口计速。
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
    let mut t0: Option<Instant> = None; // 首个体字节 = 测速窗起点
    let mut buf: Vec<Bytes> = Vec::new();
    let mut n = 0usize;
    loop {
        if let Some(t) = t0 {
            if t.elapsed() >= speed_window {
                return speed_outcome(name, kind, buf.as_slice(), n, parts, body, speed_window);
            }
        }
        // 缓冲到顶（审计 #1）：停止消费——剩余字节留在 body 里由 prepend 续传，零丢失；
        // 睡到窗口收口再计速。天花板 = BUF_CAP/窗长，超出的镜像并列（均远超直连，胜负已分）。
        if n >= BUF_CAP {
            let wait = match t0 {
                Some(t) => speed_window.saturating_sub(t.elapsed()),
                None => speed_window,
            };
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            return speed_outcome(name, kind, buf.as_slice(), n, parts, body, speed_window);
        }
        // 测速中必须用 timeout 包帧等待：窗口收口要靠它醒来——裸 await 的体 pending
        // 永不唤醒，窗口检查永远没机会跑（本文件第三次踩这个坑，教训：任何 Pending
        // 分支都得有定时器或外部唤醒源兜底）。首字节等待段不包：由竞速预算收口。
        let got = match t0 {
            Some(t) => {
                let left = speed_window.saturating_sub(t.elapsed());
                if left.is_zero() {
                    return speed_outcome(name, kind, buf.as_slice(), n, parts, body, speed_window);
                }
                match tokio::time::timeout(left, http_body_util::BodyExt::frame(&mut body)).await {
                    Err(_) => return speed_outcome(name, kind, buf.as_slice(), n, parts, body, speed_window),
                    Ok(v) => v,
                }
            }
            None => http_body_util::BodyExt::frame(&mut body).await,
        };
        match got {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    if t0.is_none() {
                        t0 = Some(Instant::now()); // 首个体字节：测速窗开始
                    }
                    n += d.len();
                    buf.push(d.clone());
                }
            }
            Some(Err(e)) => {
                return LegOutcome::Failed {
                    why: format!("{name}: 体流错误({e})"),
                };
            }
            None => {
                // 完整响应已收完（小响应常 <1KB）：直接赢，无比较意义——但 body 形状
                // 必须先过验，坏镜像的"完整限流页"不得借 EOF 抢赢（审计 #5）。
                if !body_looks_git(kind, &buf) {
                    return LegOutcome::Failed {
                        why: format!("{name}: 响应体不是 git 协议"),
                    };
                }
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
/// - 预算超窗时已计速的胜者不丢（有速度照样比），无任何速度 = Err(各腿失败原因)。
fn ranked_first(speeds: &[(String, f64)]) -> Option<String> {
    let mut ranked = speeds.to_vec();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.first().map(|(n, _)| n.clone())
}

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
                // 预算收口不丢已计速的合法胜者（审计存疑项落地）：有速度就比出最快，
                // 只有没有任何速度（全灭/全太慢）才回退重发。
                if let Some(wname) = ranked_first(&speeds) {
                    if let Some(pos) = wins.iter().position(|w| w.name == *wname) {
                        let win = wins.swap_remove(pos);
                        return Ok(RaceWin {
                            win,
                            speeds,
                            complete: false,
                        });
                    }
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
                    if let Some(wname) = ranked_first(&speeds) {
                        if let Some(pos) = wins.iter().position(|w| w.name == wname) {
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
/// 返回 None = 克隆链为空，调用方落回普通分诊（无竞速框架、无回退请求的额外成本）。
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
) -> Option<axum::response::Response<BoxBody>> {
    // orig_url 一次性拼接：path_of 返回的已是 path_and_query（含 query），
    // 再拼一遍 ?{q} 会产出双 query 的畸形镜像 URL（审计 #1 的连环雷）。
    let orig_url = format!("https://{host}{}", path_of(out.uri()));
    let chain = pool::clone_chain();
    // 克隆链空 = 用户关光了镜像：退回原路（无竞速框架、无回退请求的额外成本）。
    if chain.is_empty() {
        (log)(&format!("[克隆] {host}{path} 克隆链为空, 走原路"));
        return None;
    }
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
        // 头预算归各腿内层（镜像 5s / 直连 4s）——服务端生成 pack 首字节本就要 1~3s，
        // 外层再掐 1s 会把全部腿判死（审计 #2）；死镜像的拨号由内层 TCP 超时自然出局。
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
            // 逐跳头照剥；镜像回的 set-cookie/location 不得往 github.com 域种状态（审计 #5）；
            // 其余原样转交（含 content-encoding——我们只是字节管道）。
            let drop: Vec<http::HeaderName> = parts
                .headers
                .keys()
                .filter(|k| {
                    upstream::is_hop_by_hop(k.as_str())
                        || matches!(
                            k.as_str(),
                            "content-length" | "set-cookie" | "location"
                        )
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
            Some(write_upstream(log, resp, "clone", info, host, path))
        }
        Err(fails) => {
            (log)(&format!(
                "[克隆] {host}{path} 竞速全灭({}), 回退直连单流",
                fails.join("; ")
            ));
            match get_direct(log, out, host, info, replay).await {
                Ok(r) => Some(write_upstream(log, r, "direct", info, host, path)),
                Err(e) => {
                    (log)(&format!(
                        "[MITM] {host}{path} 克隆竞速后直连也失败({e})"
                    ));
                    Some(mitm_unavailable(
                        req,
                        host,
                        "克隆镜像与直连均不可用, 代理正在按表自动重试。",
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/clone_race.rs"]
mod tests;
