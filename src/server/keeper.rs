//! 通道管理层：门房（按 IP 列表挑通道的公式）与开流（请求头级别动作，字节不过这里）。
//! 通道的生死看护在连接驱动任务里（upstream::spawn_conn_driver）：30 秒 PING、5 分钟
//! 空闲窗（按每条连接自己的最后使用时间算）、PING 失败/对端关闭即按 id 自摘。本层只管"选"和"用"。

use crate::server::protocol::BoxBody;
use crate::server::upstream::{self, H2Upstream};
use crate::util::lock;
use bytes::Bytes;
use hyper::{Request, Response};
use std::time::{Duration, Instant};

pub(crate) const ERR_BUDGET_TIMEOUT: &str = "响应预算超时";

/// 门房公式：在给定 IP 集合里挑活连接——占用率 × 延迟，最闲且最快的胜出。
/// only_owner = 会话域只认自己建的通道；want_slot = 搜索路径固定骑主通道。
pub fn pick(
    ips: &[String],
    want_slot: Option<u8>,
    only_owner: Option<&str>,
) -> Option<H2Upstream> {
    let mut g = lock(upstream::conn_pool());
    // (分数, 是否顶到并发上限, 连接)
    let mut cands: Vec<(f64, bool, H2Upstream)> = Vec::new();
    for ip in ips {
        let Some(h) = g.get_mut(ip) else { continue };
        for c in &h.conns {
            if let Some(want) = want_slot {
                if c.up.slot != want {
                    continue;
                }
            }
            if let Some(owner) = only_owner {
                if c.up.owner.as_deref() != Some(owner) {
                    continue;
                }
            }
            let inflight = c.up.inflight.load(std::sync::atomic::Ordering::Relaxed);
            let cap = c.up.max_streams.max(1);
            // 占用率 × 延迟：闲着又快的分最小；都忙时也自然挑"最快腾出槽位"的那条。
            // 还没发过请求的连接 ewma=0，用 1ms 兜底，免得白捡成永远第一。
            let ewma = if c.ewma > 0.0 { c.ewma } else { 1.0 };
            let score = (inflight as f64 + 1.0) / cap as f64 * ewma;
            cands.push((score, inflight >= cap, c.up.clone()));
        }
    }
    if cands.is_empty() {
        return None;
    }
    // 优先没顶到上限的；全满时才按分数排在队首那条（h2 自己会在服务端配额上排队）。
    let any_free = cands.iter().any(|c| !c.1);
    let pick = cands
        .iter()
        .enumerate()
        .filter(|(_, c)| !any_free || !c.1)
        .min_by(|a, b| a.1.0.total_cmp(&b.1.0))
        .map_or(0, |(i, _)| i);
    Some(cands.remove(pick).2)
}

/// 门房开流：把请求递进通道。字节不过这里——hyper 的泵直接在请求体/响应体与
/// socket 之间搬运，本层加一跳都不该加；每次开流顺带刷新这条连接的空闲期。
pub async fn stream_on(
    up: &H2Upstream,
    out: &Request<BoxBody>,
    body: &Option<Bytes>,
    budget: Duration,
) -> Result<(Response<BoxBody>, u64), String> {
    let t0 = Instant::now();
    match tokio::time::timeout(budget, upstream::h2_send(up, out, body)).await {
        Ok(r) => r.map(|resp| (resp, t0.elapsed().as_millis() as u64)),
        Err(_) => Err(ERR_BUDGET_TIMEOUT.to_string()),
    }
}
