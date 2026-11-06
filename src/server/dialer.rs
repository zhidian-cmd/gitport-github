//! 拨号层：host 侧下订单，这里受理/驳回、一单一任务拨号、回执结果。
//! 防撞圈、黑边、游标、入库去重都在池里——本层只换"谁调用"，
//! 让"下单 → 拨号 → 回执"这段有独立的日志与计时，慢在哪一段一眼可见。

use crate::pool::{self, DialCrew};
use crate::server::upstream::{self, H2Upstream, ERR_NO_FREE_IP};
use crate::util::LogFn;
use std::sync::Arc;
use tokio::sync::mpsc;

/// 一张拨号订单。prefer_shared：Some(true) 共享档在前 / Some(false) 独占档在前 /
/// None 不分档（真名透传腿等保持旧行为）。
pub struct DialOrder {
    pub host: String,
    pub slot: u8,
    pub crew: Arc<DialCrew>,
    pub skip_ips: Vec<String>,
    pub prefer_shared: Option<bool>,
}

/// 受理一张订单。整单级预检：候选（扣 skip）全部已有通道 → 当场驳回、不白发任务；
/// 通过则一单一任务拨号，结果回执 tx。同 IP 并发拨不设仲裁：
/// 两条都建成，入库时 store_h2 按"每 IP 一条"去重。
pub async fn submit(
    order: DialOrder,
    log: &LogFn,
    tx: mpsc::Sender<Result<(H2Upstream, bool), String>>,
) {
    let targets = pool::route::dial_targets(&order.host).unwrap_or_default();
    let occupied = upstream::occupied_ips(&targets.iter().map(|t| t.ip.clone()).collect::<Vec<_>>());
    let dialable = targets
        .iter()
        .any(|p| !order.skip_ips.contains(&p.ip) && !occupied.contains(&p.ip));
    if !dialable {
        (log)(&format!(
            "[拨号] {} 订单驳回(候选全已有通道), 去门房问",
            order.host
        ));
        let _ = tx.send(Err(format!("{} {ERR_NO_FREE_IP}", order.host))).await;
        return;
    }
    let log2 = log.clone();
    tokio::spawn(async move {
        let r = upstream::h2_dial_slot(
            &order.host,
            &log2,
            &order.skip_ips,
            order.slot,
            Some(&order.crew),
            order.prefer_shared,
        )
        .await
        .map(|up| (up, true));
        let _ = tx.send(r).await;
    });
}
