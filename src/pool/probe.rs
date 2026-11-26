//! IP 串发测速：全部节点 IP 串发建通道（TCP+TLS），建连耗时即延迟，逐个掐断。
//! latency 落盘 routes.json 并清游标；排序由 latency 升序 + 同 IP 互避接管。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use super::{clear_cursors, clear_dead, dial, msg_is_tcp_dead, note_dead, route};
use crate::util::{lock, LogFn};

pub static PROBE_RUNNING: AtomicBool = AtomicBool::new(false);

static REPORT: Mutex<Option<String>> = Mutex::new(None);

pub fn set_probe_report(r: Option<String>) {
    *lock(&REPORT) = r;
}

pub fn probe_report() -> Option<String> {
    lock(&REPORT).clone()
}

/// 防重入守卫：panic/提前返回也复位。
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

/// 串发建通道（TCP+TLS，建完即断）→ 写 latency → 落盘 routes.json + 清游标；前置 probe_begin() 为 true。
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
        // sni 空串 = ClientHello 无 SNI 扩展；显示记为「无SNI」。
        let sni_show = if t.sni.is_empty() { "无SNI".to_string() } else { t.sni.clone() };
        // 计时起点在拿到闸门名额后；排队不计入延迟。
        match dial::dial_one_timed(&t.ip, &t.sni, &t.verify, true).await {
            Ok((_conn, ms, queued_ms)) => {
                if queued_ms >= 50 {
                    (log)(&format!(
                        "[IP 测速] {} 闸门排队 {queued_ms}ms(不计入延迟)",
                        t.ip
                    ));
                }
                route::set_latency(&t.ip, ms);
                // 成功即清死亡退避。
                clear_dead(&t.ip);
                ok += 1;
                rows.push(format!("{} [{}] 通，{}ms", t.ip, sni_show, ms));
                (log)(&format!("[IP 测速] {} [{}] 通，{}ms", t.ip, sni_show, ms));
            }
            Err(e) => {
                route::set_latency(&t.ip, 0);
                // TCP 失败进死亡退避（60s 绕行）；TLS 失败只清基线。
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

/// 测速结果落盘：latency 回流 routes.json，游标全清（内存 + settings.json）。
fn save_results() {
    clear_cursors(); // 先清内存表，否则下次拨号又写回磁盘
    crate::pool::save_routes_now();
    crate::settings::set_last_ips(Vec::new());
}

#[cfg(test)]
#[path = "../tests/pool/probe.rs"]
mod tests;
