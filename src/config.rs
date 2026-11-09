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
/// 拨号单阶段上限，TCP 与 TLS 各自独立计时：TCP 1.15s、TLS 1.35s。
/// 健康全流程实测 ~334ms，两项合计 2.5s 是 7 倍余量；合计仍 > DIAL_SLOW_MS(1500)，慢成功检测窗不变。
/// 不设整轮总预算：候选逐个试完为止，慢总比失败好。
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 1150;
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 1350;
/// h2 SETTINGS 握手限时：对端装死会永久持有 per-host 拨号锁，拖死整个域名。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 内容域/其他探活间隔：闲置超此秒数发 1 字节 Range 请求验活（PING 探不了黑洞）。
/// 须卡在边缘 50~65s 空闲回收窗内，保活才有效。
pub const PROBE_INTERVAL_SECS: u64 = 30;
/// 探活响应头等待上限：超时 = 连接已黑洞，当场自摘出池。
pub const PROBE_TIMEOUT_SECS: u64 = 2;
/// 会话域探活间隔（闲置超此秒数才探）。
pub const SESSION_PROBE_INTERVAL_SECS: u64 = 30;
/// 闲置（无真实流量）超此秒数主动放手，会话域/内容域一律适用——5 分钟没人用的
/// 连接没有留的价值，重拨有游标兜底（同 IP 驻留）；在途流不为零不算闲置。
pub const CONN_IDLE_RETIRE_SECS: u64 = 300;
/// 内容域/其他同 IP 通道上限：恒 1 条。同 IP 多通道实测是灾难（互相抢带宽、连接级窗口
/// 被几条流摊薄），要多通道就换 IP 另起一条——竞速建连取前二即按此展开。
pub const MAX_CONNS_CONTENT: usize = 1;
/// 会话域同 IP 通道上限：恒 1 条。
pub const MAX_CONNS_SESSION: usize = 1;
/// 直连切片 5s 界：没拉完的段由镜像链续传，段失败立即换镜像。
pub const MEDIA_RESCUE_WAIT_SECS: u64 = 5;
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
