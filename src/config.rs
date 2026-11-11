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

/// 即用即建、用完就丢：闲置（无在途流）超此秒数即焚毁通道。10s 远短于对端/中间
/// 设备的静默掐死窗口（60~90s），「领到僵尸通道」在结构上不可能发生——探活机制
/// 因此整体移除（探活只能验尸不能续命，且总有漏检窗口）。在途流不为零不算闲置。
pub const CONN_IDLE_RETIRE_SECS: u64 = 10;
/// 内容域/其他同 IP 通道上限：恒 1 条。同 IP 多通道实测是灾难（互相抢带宽、连接级窗口
/// 被几条流摊薄），要多通道就换 IP 另起一条——竞速建连取前二即按此展开。
pub const MAX_CONNS_CONTENT: usize = 1;
/// 会话域同 IP 通道上限：恒 1 条。
pub const MAX_CONNS_SESSION: usize = 1;
/// 直连切片 5s 界：没拉完的段由镜像链续传，段失败立即换镜像。
pub const MEDIA_RESCUE_WAIT_SECS: u64 = 5;
/// CONNECT 隧道首字节看门狗：上游 TCP 活着但被黑洞时，代理先于浏览器判死+垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;
/// MITM 响应体黑洞判定：响应头到了但这个秒数内第一个数据字节没来 = 黑洞。
/// 8s 与隧道首字节看门狗统一（实战值）。500ms 实测是灾难：tree-commit-info 这类
/// git 数据端点总耗时可达 1.1s，线路抖一下头体间隔就过 500ms，看门狗把会话通道
/// 掐断，正在途中的 commit XHR 被误杀——每次页面加载都误伤同一个地方。
/// 误判由「暂缓 60s 自动过期 + 换血给出全部通道」兜底，不会永久冤枉一条通道。
/// 30s：8s 实测把"服务端慢渲染/单连接排队"误判成黑洞（overview-files 等接口
/// 20~80s 才回是常态，数据最终都到）——零字节满 30s 仍无数据才按黑洞处置。
pub const BLACKHOLE_FIRST_BYTE_MS: u64 = 30_000;

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
