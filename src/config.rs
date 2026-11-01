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
/// 单候选拨号超时（TCP 与 TLS 握手共用）：黑洞型死 IP 不许拖住整轮串发。
pub const CONNECT_TIMEOUT_SECS: u64 = 3;
/// h2 SETTINGS 握手限时：对端装死会永久持有 per-host 拨号锁，拖死整个域名。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 串发每请求总耗时预算，到期即停并按 host 冷却 30s。
pub const SERIAL_DIAL_BUDGET_SECS: u64 = 20;

/// h2 连接空闲 50-65s 被边缘回收，30s 探测可稳定续命。
pub const KEEPALIVE_PROBE_SECS: u64 = 30;
pub const KEEPALIVE_WINDOW_SECS: u64 = 300;
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
/// 域名分组：命中即按该池 plans.json 串发表拨号；IP 名单只住 plans.json。
pub struct Group {
    pub name: &'static str,
    pub patterns: &'static [&'static str],
}

pub const GROUPS: &[Group] = &[
    Group {
        name: "core",
        patterns: &["github.com", "*.github.com"],
    },
    Group {
        // api 走专用边缘（.5/.6）：与网站 IP 分服务互斥，落错返 404/301，必须精确优先拆池。
        name: "api",
        patterns: &["api.github.com"],
    },
    Group {
        name: "edge",
        patterns: &[
            "githubapp.com",
            "*.githubapp.com",
            "*.githubassets.com",
            "github.io",
            "*.github.io",
            "*.githubusercontent.com",
        ],
    },
];

/// `*.x` 匹配子域，否则全等。
pub fn pattern_match(host: &str, pat: &str) -> bool {
    match pat.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|h| h.ends_with('.')),
        None => host == pat,
    }
}

/// 直连白名单：不走池、不经代理——池的 IP 与伪装 SNI 对这些域会被上游判非法，系统 DNS 直连反而可用。
pub const DIRECT_HOSTS: &[&str] = &[
    "objects-origin.githubusercontent.com",
    "uploads.github.com",
    "viewscreen.githubusercontent.com",
    "api.mcp.github.com",
];

/// 主路由白名单：进 edge 池但按 seg 选段、握手用真名 + 分片；这些域不在老族的段上，落老族会被判 400。
pub struct WhitelistHost {
    pub host: &'static str,
    pub seg: &'static str,
}

pub const WHITELIST_HOSTS: &[WhitelistHost] = &[
    WhitelistHost { host: "docs.github.com", seg: "154" },
    WhitelistHost { host: "support.github.com", seg: "133" },
    WhitelistHost { host: "resources.github.com", seg: "133" },
    WhitelistHost { host: "desktop.github.com", seg: "153" },
    WhitelistHost { host: "pages.github.com", seg: "153" },
    WhitelistHost { host: "skills.github.com", seg: "153" },
    WhitelistHost { host: "archiveprogram.github.com", seg: "153" },
    WhitelistHost { host: "socialimpact.github.com", seg: "153" },
    WhitelistHost { host: "raw.github.com", seg: "133" },
    WhitelistHost {
        host: "copilot-proxy.githubusercontent.com",
        seg: "4.249",
    },
];

/// 白名单腿分片参数：固定 3 段、间隔 100ms——真名 SNI 一旦被拼齐就明文暴露，宁可多等。
pub const WHITELIST_SPLIT_SEGS: usize = 3;
pub const WHITELIST_SPLIT_GAP_MS: u64 = 100;

pub fn is_whitelist(host: &str) -> bool {
    whitelist_seg(host).is_some()
}

/// 白名单域名该落哪段 IP（Fastly 末段 / Azure 前缀）；不在白名单返回 None。
pub fn whitelist_seg(host: &str) -> Option<&'static str> {
    WHITELIST_HOSTS.iter().find(|w| w.host == host).map(|w| w.seg)
}

pub fn is_direct(host: &str) -> bool {
    DIRECT_HOSTS.contains(&host)
}

/// 域名 → 池名（"" = 非池）。精确 pattern 优先于通配符；总路由见 route::master_route。
pub fn pool_for(host: &str) -> &'static str {
    // 白名单必须先于 GROUPS 遍历：objects-origin 会被 edge 通配符吞掉（Fastly 500）。
    if is_direct(host) {
        return "";
    }
    // 白名单进 edge 池：池里靠白名单族按 seg 选 IP，握手由 dial_one 切成真名 + 分片。
    if is_whitelist(host) {
        return "edge";
    }
    for g in GROUPS {
        for pat in g.patterns {
            if *pat == host {
                return g.name;
            }
        }
    }
    for g in GROUPS {
        for pat in g.patterns {
            if pattern_match(host, pat) {
                return g.name;
            }
        }
    }
    ""
}

/// 全部受管域名的裸形（`*.x` 剥成 `x`），去重由调用方做一次（PAC 本身就是低频请求）。
pub fn pooled_domains() -> impl Iterator<Item = &'static str> {
    GROUPS
        .iter()
        .flat_map(|g| g.patterns.iter().map(|p| p.strip_prefix("*.").unwrap_or(p)))
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
