//! 全局拨号仲裁（独立"机器人"）：共享 IP 的拨号使用权由这里统一发放。
//!
//! 规则：
//! - 只有装表时标成共享的 IP 才来申请；独占 IP 走 `try_claim` 的轻量登记，不进裁决。
//! - 同一瞬间已经入批的申请算一批：按内容优先级挑一个赢家，其余当场驳回、换别的 IP。
//!   晚一个节拍才到的申请看到 IP 已授出，直接驳回、不参与排序（有先后就先到先得）。
//! - 授权只在拨号那一瞬有效：通道建好即交棒给全局连接池，之后多个 host 随便复用同一条连接。

use crate::util::lock;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use tokio::sync::oneshot;

/// 一个申请者：谁申请、多重要、结果往哪回。
struct Applicant {
    host: String,
    prio: u8,
    tx: oneshot::Sender<Verdict>,
}

#[derive(Default)]
struct State {
    /// ip → 当前握着使用权的 host（凭据存活期间有效）。
    granted: HashMap<String, String>,
    /// ip → 同一波还没结算的申请。
    pending: HashMap<String, Vec<Applicant>>,
    /// 已经建好通道、交给连接池的 IP。不是"握着不放"：只是登记"这个 IP 别再拨第二次"，
    /// 连接本身仍由连接池随便复用。摘除最后一条连接时同步撤销。
    live: HashSet<String>,
}

static TABLE: OnceLock<Mutex<State>> = OnceLock::new();

fn table() -> &'static Mutex<State> {
    TABLE.get_or_init(|| Mutex::new(State::default()))
}

/// 这个 IP 此刻有没有人在拨（含同一波还在裁决中、且申请者还活着的）。
pub fn busy(ip: &str) -> bool {
    let g = lock(table());
    g.granted.contains_key(ip)
        || g.pending
            .get(ip)
            .is_some_and(|v| v.iter().any(|a| !a.tx.is_closed()))
}

/// 这个 IP 是否已经有建好的通道。拨号循环据此跳过，保证同一个 IP 永远不会被拨第二次。
/// 与 `busy` 分开：`busy` 只表示"暂时有人在建"，可以等；`live` 是长期状态，等也没用，
/// 该直接去连接池复用现成的那条。
pub fn live(ip: &str) -> bool {
    lock(table()).live.contains(ip)
}

/// 通道入库成功时登记。由连接池的唯一写入口调用。
pub fn mark_live(ip: &str) {
    lock(table()).live.insert(ip.to_string());
}

/// 该 IP 最后一条连接被摘除时撤销，之后才允许重新拨号。
pub fn unmark_live(ip: &str) {
    lock(table()).live.remove(ip);
}

/// 同批里挑谁赢：优先级高者胜；同档按入批顺序，先到先得。
/// 抽成纯函数，排序规则不依赖线程调度就能验。
pub(crate) fn pick_winner(prios: &[u8]) -> usize {
    let mut best = 0usize;
    for i in 1..prios.len() {
        if prios[i] > prios[best] {
            best = i;
        }
    }
    best
}

/// 内容优先级：主站 > api > 一般内容 > avatars。只在同批分不出先后时生效。
pub fn priority(host: &str) -> u8 {
    let h = host.to_ascii_lowercase();
    if h == "github.com" || h == "www.github.com" {
        3
    } else if h == "api.github.com" || h.starts_with("api.") || h.ends_with(".api.github.com") {
        2
    } else if h.contains("avatar") {
        0
    } else {
        1
    }
}

/// 仲裁结果：拿到凭据去拨号，或被驳回换下一个 IP。
pub enum Verdict {
    Granted(Guard),
    Rejected { winner: String },
}

/// 拨号使用权凭据：Drop 时自动交还（成功、失败、panic、请求取消都交还）。
pub struct Guard {
    ip: String,
}

/// 独占 IP 的轻量登记：不排序、不记 host、不走批次，只留"这个 IP 正在拨"的标记。
pub fn try_claim(ip: &str) -> Option<Guard> {
    let mut g = lock(table());
    // 已有通道的 IP 谁都不准再拨：和 mark_live 在同一把锁里，堵死"刚查完还没拨"的缝。
    if g.granted.contains_key(ip) || g.live.contains(ip) {
        return None;
    }
    g.granted.insert(ip.to_string(), String::new());
    Some(Guard {
        ip: ip.to_string(),
    })
}

/// 共享 IP 申请使用权。同一波同时到达的申请按优先级只放一个；已授出的直接驳回。
pub async fn apply(ip: &str, host: &str) -> Verdict {
    let (tx, rx) = oneshot::channel();
    {
        let mut g = lock(table());
        if let Some(owner) = g.granted.get(ip) {
            // 有先后：先到先得，后来者不参与排序，也不等。
            return Verdict::Rejected {
                winner: owner.clone(),
            };
        }
        if g.live.contains(ip) {
            // 通道已经建好交给池子了：直接去复用，不必再申请拨号权。
            return Verdict::Rejected {
                winner: String::new(),
            };
        }
        g.pending
            .entry(ip.to_string())
            .or_default()
            .push(Applicant {
                host: host.to_string(),
                prio: priority(host),
                tx,
            });
    }
    // 只让出一次调度，把已经同时到达的申请凑进同一批；不计时、不等还没来的。
    tokio::task::yield_now().await;
    let sends = {
        let mut g = lock(table());
        // 申请者中途被取消的，回执通道已关；剔掉再裁决，别让僵尸申请白占一个赢家名额。
        let batch: Vec<Applicant> = g
            .pending
            .remove(ip)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| !a.tx.is_closed())
            .collect();
        match batch.is_empty() {
            false => {
                // 这批申请还在等结算时，可能已有通道建好入库：整批驳回，谁都别再拨第二次。
                if g.live.contains(ip) {
                    Some(
                        batch
                            .into_iter()
                            .map(|a| {
                                (
                                    a.tx,
                                    Verdict::Rejected {
                                        winner: String::new(),
                                    },
                                )
                            })
                            .collect(),
                    )
                } else {
                    let prios: Vec<u8> = batch.iter().map(|a| a.prio).collect();
                    let best = pick_winner(&prios);
                    let winner = batch[best].host.clone();
                    // 结算与授权在同一把锁里完成，中间不留第二个授权挤进来的空档。
                    g.granted.insert(ip.to_string(), winner.clone());
                    let mut out = Vec::with_capacity(batch.len());
                    for (i, a) in batch.into_iter().enumerate() {
                        let v = if i == best {
                            Verdict::Granted(Guard {
                                ip: ip.to_string(),
                            })
                        } else {
                            Verdict::Rejected {
                                winner: winner.clone(),
                            }
                        };
                        out.push((a.tx, v));
                    }
                    Some(out)
                }
            }
            true => None, // 别人已把这批结算走，或整批都被取消：等自己的回执即可
        }
    };
    if let Some(sends) = sends {
        for (tx, v) in sends {
            let _ = tx.send(v);
        }
    }
    rx.await.unwrap_or(Verdict::Rejected {
        winner: String::new(),
    })
}

impl Drop for Guard {
    fn drop(&mut self) {
        lock(table()).granted.remove(&self.ip);
    }
}

#[cfg(test)]
pub(crate) fn clear() {
    let mut g = lock(table());
    g.granted.clear();
    g.pending.clear();
    g.live.clear();
}
