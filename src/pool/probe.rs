//! IP 串发测速：通道池驱动搭建机器人在全部节点 IP 上串发建通道（TCP+TLS），
//! 建连成功耗时即延迟，逐个掐断；结束后 latency 落盘 routes.json、清空游标——
//! 串发顺序此后完全由「latency 升序 + 同 IP 互避防串」接管（游标由运行时驻留自然重建）。
//! 通道搭建机器人只有通道池能叫：本模块是 pool 子模块，合法调度者。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use super::{dial, msg_is_tcp_dead, note_dead, route};
use crate::util::{lock, LogFn};

pub static PROBE_RUNNING: AtomicBool = AtomicBool::new(false);

static REPORT: Mutex<Option<String>> = Mutex::new(None);

pub fn set_probe_report(r: Option<String>) {
    *lock(&REPORT) = r;
}

pub fn probe_report() -> Option<String> {
    lock(&REPORT).clone()
}

/// 防重入守卫：panic/提前返回也复位（照校准的 CalibDone 模式）。
pub struct ProbeGuard;
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBE_RUNNING.store(false, Ordering::SeqCst);
    }
}

/// 获得执行权；false = 已有测速在跑。
pub fn probe_begin() -> bool {
    !PROBE_RUNNING.swap(true, Ordering::SeqCst)
}

/// 一条龙：全部节点 IP 串发建通道（TCP+TLS，建完即断）→ 计时写 latency
/// → 落盘 routes.json + 清空游标。前置条件：probe_begin() 已返回 true。
pub async fn probe_serial_domains(log: &LogFn) -> String {
    let targets = route::probe_targets();
    if targets.is_empty() {
        return "路由表未装载，无 IP 可测".into();
    }
    (log)(&format!(
        "[IP 测速] 开始：{} 个 IP 串发建通道（TCP+TLS，建完即断）",
        targets.len()
    ));
    let mut rows = Vec::with_capacity(targets.len());
    let mut ok = 0usize;
    let mut fail = 0usize;
    for t in &targets {
        let t0 = std::time::Instant::now();
        // sni 空串 = ClientHello 无 SNI 扩展（dial.rs 的既定语义），与代理拨号一致；显示口径对齐日志的「无SNI」。
        let sni_show = if t.sni.is_empty() { "无SNI".to_string() } else { t.sni.clone() };
        match dial::dial_one(&t.ip, &t.sni, &t.verify, true).await {
            Ok(_conn) => {
                let ms = t0.elapsed().as_millis() as u64;
                route::set_latency(&t.ip, ms);
                ok += 1;
                rows.push(format!("{} [{}] 通，{}ms", t.ip, sni_show, ms));
                (log)(&format!("[IP 测速] {} [{}] 通，{}ms", t.ip, sni_show, ms));
            }
            Err(e) => {
                route::set_latency(&t.ip, 0);
                // TCP 层失败 = IP 当下不通，进死亡退避（60s 内运行时绕行）；TLS 失败只清基线。
                if msg_is_tcp_dead(&e) {
                    note_dead(&t.ip);
                }
                fail += 1;
                rows.push(format!("{} [{}] 不通（{e}）", t.ip, sni_show));
                (log)(&format!("[IP 测速] {} [{}] 不通（{e}）", t.ip, sni_show));
            }
        }
    }
    save_results();
    let summary = format!(
        "完成：{ok} 通 / {fail} 不通；latency 已写 routes.json，游标已清空"
    );
    (log)(&format!("[IP 测速] {summary}"));
    format!(
        "IP 串发测速报告（{} 个 IP）\n{}\n{summary}",
        targets.len(),
        rows.join("\n")
    )
}

/// 测速结果落盘：latency 回流 routes.json + 游标全清（settings.json）。
fn save_results() {
    crate::pool::save_routes_now();
    crate::settings::set_last_ips(Vec::new());
}

#[cfg(test)]
#[path = "../tests/pool/probe.rs"]
mod tests;
