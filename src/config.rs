//! 配置常量：端口、拨号/隧道/黑洞超时、通道与并发上限、首包分片参数。

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
/// 拨号单阶段上限：TCP 1.15s、TLS 1.35s（合计 2.5s，健康全流程 ~334ms 的 7 倍余量）；不设整轮总预算。
/// 合计必须 > upstream::DIAL_SLOW_MS(1500)——成功耗时不可能超过拨号上限，压到线内慢成功检测窗失效（编译期断言钉在 upstream.rs）。
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 1150;
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 1350;
/// h2 SETTINGS 握手限时：对端装死会永久持有 per-host 拨号锁，拖死整个域名。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 闲置（无在途流）超此秒数即焚通道，远短于对端 60~90s 静默掐死窗口，探活机制因此整体移除。
pub const CONN_IDLE_RETIRE_SECS: u64 = 10;
/// 直连切片 5s 界：没拉完的段由镜像链续传，段失败立即换镜像。
pub const MEDIA_RESCUE_WAIT_SECS: u64 = 5;
/// CONNECT 隧道首字节看门狗：上游 TCP 活着但被黑洞时，代理先于浏览器判死+垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;
/// 透明隧道总时长上限：兜僵死连接，1 小时足够最慢的大仓库 clone。
pub const TUNNEL_MAX_LIFETIME_SECS: u64 = 3600;
/// 代理并发连接上限：本机进程狂开 CONNECT 也不把常驻托盘进程拖垮。
pub const PROXY_MAX_CONNS: usize = 256;
/// 响应头到后 30s 无数据字节判黑洞：更短会误杀 1.1s 的 git 数据端点与 20~80s 的慢渲染接口；误判由 60s 暂缓过期兜底。
pub const BLACKHOLE_FIRST_BYTE_MS: u64 = 30_000;

/// 隧道首包分片：0x16 开头的 ClientHello 拆 2~3 段随机构造发出；DPI 拼不齐 SNI 就不会 RST，非 TLS 流不碰。
/// 首刀上限：1..=FIRST_MAX 字节随机（覆盖 TLS 记录头 5B 一带）。
pub const HELLO_SPLIT_FIRST_MAX: usize = 16;
/// 段间隔随机范围（毫秒），每段间隔独立抽取。
pub const HELLO_SPLIT_DELAY_MIN_MS: u64 = 20;
pub const HELLO_SPLIT_DELAY_MAX_MS: u64 = 70;
/// 真实流量拨号总并发闸（无它，开页面 30 并发会打爆自己）。
pub const DIAL_GATE_SIZE: usize = 48;
pub const LOG_BUFFER_SIZE: usize = 2000;
