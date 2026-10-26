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
/// h2 SETTINGS 握手限时：TCP/TLS 已通但对端装死时快速垫底——裸等会永久持有
/// per-host 拨号锁，把该域名所有缓存未命中的请求一起拖死。
pub const H2_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// 串发每请求总耗时预算（整圈最坏 3.6 分钟）；到期即停并按 host 冷却 30s。
/// 与 ctx 分开：ctx = 整个请求的预算，这是圈内轮换预算。
pub const SERIAL_DIAL_BUDGET_SECS: u64 = 20;

/// h2 连接空闲 50-65s 被边缘回收，30s 探测可稳定续命。
pub const KEEPALIVE_PROBE_SECS: u64 = 30;
pub const KEEPALIVE_WINDOW_SECS: u64 = 300;
/// CONNECT 隧道首字节看门狗：上游 TCP 活着但被黑洞时，代理先于浏览器判死+垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;

/// 隧道模式 TLS 握手首包分片：客户端→上游的第一段若为 TLS 握手记录(0x16 开头)，
/// 拆成 2~3 段（切点/间隔每连接随机）发出。DPI 的 SNI 检测需要完整 ClientHello，
/// 拆段后重组窗口拼不齐 → 真名 SNI 免于 RST（byedpi/GoodbyeDPI 同款思路，纯用户态）；
/// 边缘的完整 TCP 栈不受影响。仅作用于 CONNECT 隧道首段——SSH/HTTP 流(非 0x16)不碰。
/// 随机化而非固定形态的原因：教科书式"5B 记录头 + 固定间隔"是公开知识，
/// 会被签名后针对性反制（2026-10-21 夜间窗口疑似即此）；随机让每条连接长得都不一样。
/// 总闸：A/B 对照时改 false 重编译即全关。
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
            .map_or(false, |h| h.ends_with('.')),
        None => host == pat,
    }
}

/// 直连白名单：不归任何池、不经代理（vhost→边缘映射只有 GitHub 的 DNS 知道，交给系统解析）。
/// - objects-origin：仅 GLB 族服务，主站边缘对其 301 无 CORS → 跨域预检失败、上传必败
/// - uploads.github.com：API 式上传源站，等价 gh CLI 可用路径
/// - viewscreen：mermaid 渲染，代理腿真名 SNI 被间歇掐断且无镜像兜底，浏览器直连反而可用（非 ECH）
/// - api.mcp：Copilot MCP 端点，core 池 IP 证书 SAN 不覆盖它（27 连败全 Hostname mismatch），
///   走池必然全灭，浏览器 DIRECT 即可
/// - docs / support / resources / desktop / pages / skills / archiveprogram / socialimpact / raw：
///   都托管在 Fastly 185.199.10x，被 `*.github.com` 通配送进 core 池后拿主站 IP + 伪装 SNI，
///   上游直接判非法。docs 实测 90ms 回 400 Whoa（2026-10-26），直连 200
/// - copilot-proxy：Azure 4.249.x，被 `*.githubusercontent.com` 吞进 edge 池，Fastly IP 连不上
pub const DIRECT_HOSTS: &[&str] = &[
    "objects-origin.githubusercontent.com",
    "uploads.github.com",
    "viewscreen.githubusercontent.com",
    "api.mcp.github.com",
];

/// 主路由白名单：进 edge 池，但**不走老族的筛 IP 规则**——按下面 seg 选段，
/// 握手用真名 + ClientHello 分片。
///
/// 为什么进池：单发拨号连不上就报错，进池后能自动换候选、按实测耗时重排、失败垫底。
/// 为什么不能落老族：它们托管在 Fastly 185.199.10x / Azure，老族只认 .133/.153/.154/.215
/// 且按域名后缀挂，这 10 个一个都落不到对的段上——docs 走 core 池实测 90ms 回 400 Whoa。
/// seg 语义：Fastly 系填末段（154/153/133），Azure 填前缀（4.249），由 route 层区分判断。
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

/// 白名单腿 ClientHello 分片：段数与段间隔（毫秒）。
/// 段间留够时间，DPI 的重组窗口拼不齐完整 SNI 就取不到域名。
///
/// 与上方 `HELLO_SPLIT_*`（透传腿）是**同一件事的两套参数，故意不同**：
/// - 透传腿：2~3 段、间隔 20~70ms 随机。历史实测值，靠随机形态躲签名化反制。
/// - 白名单腿：固定 3 段、间隔 100ms。更保守——这批域名走的是真名 SNI，
///   一旦被拼齐就是明文暴露，宁可多等 200ms 也要把重组窗口赌死。
/// 改任一侧前先看另一侧的注释，别只调一处。
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
    DIRECT_HOSTS.iter().any(|d| *d == host)
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
mod tests {
    use super::*;

    #[test]
    fn pattern_star_dot() {
        assert!(pattern_match("api.github.com", "*.github.com"));
        assert!(pattern_match("github.com", "github.com"));
        assert!(!pattern_match("xgithub.com", "*.github.com"));
        assert!(!pattern_match("github.com", "*.github.com"));
        assert!(!pattern_match("evilgithub.com", "*.github.com"));
    }

    #[test]
    fn pool_routing() {
        assert_eq!(pool_for("github.com"), "core");
        assert_eq!(pool_for("api.github.com"), "api");
        assert_eq!(pool_for("api.github.com.cn"), ""); // 不误伤非 api.github.com 后缀
        assert!(is_direct("objects-origin.githubusercontent.com"));
        assert_eq!(pool_for("objects-origin.githubusercontent.com"), "");
        assert!(is_direct("uploads.github.com"));
        assert_eq!(pool_for("uploads.github.com"), "");
        assert!(is_direct("viewscreen.githubusercontent.com"));
        assert_eq!(pool_for("viewscreen.githubusercontent.com"), "");
        assert!(is_direct("api.mcp.github.com")); // *.github.com 通配吞它，白名单精确短路
        assert_eq!(pool_for("api.mcp.github.com"), "");
        // 白名单：PAC 里故意不出现（要进代理才能分片），池名必须是 edge，且带段号。
        for w in WHITELIST_HOSTS {
            assert!(is_whitelist(w.host), "{} 应在白名单", w.host);
            assert!(
                !is_direct(w.host),
                "{} 不能进 DIRECT：那样流量被拦在代理外，拿不到分片",
                w.host
            );
            assert_eq!(pool_for(w.host), "edge", "{} 应判为 edge 池", w.host);
            assert_eq!(whitelist_seg(w.host), Some(w.seg), "{} 段号读不出", w.host);
        }
        // 段号必须覆盖四类：.154 / .153 / .133 / Azure 前缀
        assert_eq!(whitelist_seg("docs.github.com"), Some("154"));
        assert_eq!(whitelist_seg("pages.github.com"), Some("153"));
        assert_eq!(whitelist_seg("support.github.com"), Some("133"));
        assert_eq!(
            whitelist_seg("copilot-proxy.githubusercontent.com"),
            Some("4.249")
        );
        assert_eq!(pool_for("codeload.github.com"), "core");
        assert_eq!(pool_for("raw.githubusercontent.com"), "edge");
        assert_eq!(pool_for("avatars.githubusercontent.com"), "edge");
        assert_eq!(pool_for("camo.githubusercontent.com"), "edge");
        assert_eq!(pool_for("gist.githubusercontent.com"), "edge");
        assert_eq!(pool_for("github.githubassets.com"), "edge");
        assert_eq!(pool_for("foo.github.io"), "edge");
        assert_eq!(pool_for("github.io"), "edge");
        assert_eq!(pool_for("githubapp.com"), "edge");
        assert_eq!(pool_for("api.githubapp.com"), "edge");
        assert_eq!(pool_for("example.com"), "");
    }
}
