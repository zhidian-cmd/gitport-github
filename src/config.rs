//! 配置常量与域名分组（按表串发版）。

use std::sync::atomic::{AtomicU16, Ordering};

/// 默认端口（-port / -webui 可覆盖）。
pub const DEFAULT_PORT: u16 = 7810;
pub const WEBUI_PORT: u16 = 7811;

static PROXY_PORT: AtomicU16 = AtomicU16::new(DEFAULT_PORT);
static UI_PORT: AtomicU16 = AtomicU16::new(WEBUI_PORT);

pub fn proxy_port() -> u16 {
    PROXY_PORT.load(Ordering::Relaxed)
}

pub fn set_proxy_port(p: u16) {
    PROXY_PORT.store(p, Ordering::Relaxed);
}

pub fn webui_port() -> u16 {
    UI_PORT.load(Ordering::Relaxed)
}

pub fn set_webui_port(p: u16) {
    UI_PORT.store(p, Ordering::Relaxed);
}

pub const HEAD_TIMEOUT_SECS: u64 = 30;
/// 单阶段拨号上限（TCP 连接与 TLS 握手各自独立计时，各 2s）：黑洞型死 IP 不许拖住整轮串发。
/// 健康全流程实测 ~334ms，2s 是 5-10 倍余量；须 > DIAL_SLOW_MS(1500) 保住"慢成功"检测窗。
pub const CONNECT_TIMEOUT_SECS: u64 = 2;
/// h2 SETTINGS 握手限时：对端装死会永久持有 per-host 拨号锁，拖死整个域名。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 串发每请求总耗时预算，到期即停并按 host 冷却 30s。2s/IP 上限下 ≈ 走完 6 个候选就交镜像链。
pub const SERIAL_DIAL_BUDGET_SECS: u64 = 12;

/// 通道持续存在（无批窗）：健康由驱动探活保证，死了立即出池。
/// 内容域/其他探活间隔：闲置超此秒数的通道，驱动在现有连接上开 stream 发
/// GET Range:bytes=0-0（1 字节 Range 是正常 HTTP 请求，与真实流量无异）。
pub const PROBE_INTERVAL_SECS: u64 = 10;
/// 探活响应头等待上限：超时 = 连接已黑洞，当场自摘出池。
pub const PROBE_TIMEOUT_SECS: u64 = 2;
/// 会话域 PING 探活间隔（闲置超此秒数才探，驱动计时器驱动）。
pub const SESSION_PROBE_INTERVAL_SECS: u64 = 30;
/// 会话域按需 ping 的 PONG 等待上限（驱动任务侧计时）。
pub const SESSION_PING_TIMEOUT_SECS: u64 = 2;
/// 内容域/其他同 IP 通道上限：常态 2 条（主副双腿），两条顶满才同 IP 溢出补。
pub const MAX_CONNS_CONTENT: usize = 3;
/// 会话域同 IP 通道上限：恒 1 条（风控面不漂移，全忙骑现有连接排队）。
pub const MAX_CONNS_SESSION: usize = 1;
/// CONNECT 隧道首字节看门狗：上游 TCP 活着但被黑洞时，代理先于浏览器判死+垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;

/// 隧道首包分片：0x16 开头的 ClientHello 拆 2~3 段随机构造发出；DPI 拼不齐 SNI 就不会 RST，非 TLS 流不碰。
pub const HELLO_SPLIT_ENABLED: bool = true;
/// 首刀上限：1..=FIRST_MAX 字节随机（覆盖 TLS 记录头 5B 一带）。
pub const HELLO_SPLIT_FIRST_MAX: usize = 16;
/// 段间隔随机范围（毫秒），每段间隔独立抽取。
pub const HELLO_SPLIT_DELAY_MIN_MS: u64 = 20;
pub const HELLO_SPLIT_DELAY_MAX_MS: u64 = 70;
/// 真实流量拨号总并发闸（无它，开页面 30 并发会打爆自己）。
pub const DIAL_GATE_SIZE: usize = 48;
pub const LOG_BUFFER_SIZE: usize = 2000;
