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
/// 拨号上限：TCP 1.15s、TLS 1.35s（合计 2.5s）；不设整轮总预算，合计须 > upstream::DIAL_SLOW_MS(1500)（编译期断言在 upstream.rs）。
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 1150;
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 1350;
/// h2 SETTINGS 握手限时：防对端装死永久持有 per-host 拨号锁。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 闲置（无在途流）超 10s 即焚通道；无探活机制。
pub const CONN_IDLE_RETIRE_SECS: u64 = 10;
/// 直连切片 5s 界：未完段由镜像链续传。
pub const MEDIA_RESCUE_WAIT_SECS: u64 = 5;
/// CONNECT 隧道首字节看门狗 8s：黑洞时代理先判死并垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;
/// 透明隧道总时长上限 3600s（兜僵死连接）。
pub const TUNNEL_MAX_LIFETIME_SECS: u64 = 3600;
/// 代理并发连接上限：防狂开 CONNECT 拖垮常驻托盘进程。
pub const PROXY_MAX_CONNS: usize = 256;
/// 响应头后 30s 无数据判黑洞；误判由 60s 暂缓过期兜底。
pub const BLACKHOLE_FIRST_BYTE_MS: u64 = 30_000;

/// 隧道首包分片：0x16 开头的 ClientHello 拆 2~3 段随机发出，首刀 1..=FIRST_MAX 字节（覆盖 TLS 记录头 5B），非 TLS 流不碰。
pub const HELLO_SPLIT_FIRST_MAX: usize = 16;
/// 段间隔随机范围（毫秒），每段间隔独立抽取。
pub const HELLO_SPLIT_DELAY_MIN_MS: u64 = 20;
pub const HELLO_SPLIT_DELAY_MAX_MS: u64 = 70;
/// 真实流量拨号总并发闸：防开页面并发打爆自己。
pub const DIAL_GATE_SIZE: usize = 48;
pub const LOG_BUFFER_SIZE: usize = 2000;
