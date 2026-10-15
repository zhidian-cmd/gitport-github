//! 配置常量与域名分组（按表串发版）。

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::OnceLock;

/// 默认代理端口 / WebUI 端口（`-port` / `-webui` 可覆盖，避开被占用的 7810/7811）。
pub const DEFAULT_PORT: u16 = 7810;
pub const WEBUI_PORT: u16 = 7811;

static PROXY_PORT: AtomicU16 = AtomicU16::new(DEFAULT_PORT);
static UI_PORT: AtomicU16 = AtomicU16::new(WEBUI_PORT);

/// 当前生效的代理端口（命令行参数优先，默认 7810）。
pub fn proxy_port() -> u16 {
    PROXY_PORT.load(Ordering::Relaxed)
}

/// 设置代理端口（main 解析命令行后调用，仅在启动早期有效）。
pub fn set_proxy_port(p: u16) {
    PROXY_PORT.store(p, Ordering::Relaxed);
}

/// 当前生效的 WebUI 端口（默认 7811）。
pub fn webui_port() -> u16 {
    UI_PORT.load(Ordering::Relaxed)
}

/// 设置 WebUI 端口（main 解析命令行后调用，仅在启动早期有效）。
pub fn set_webui_port(p: u16) {
    UI_PORT.store(p, Ordering::Relaxed);
}

/// 读 CONNECT/请求头的超时（秒）。
pub const HEAD_TIMEOUT_SECS: u64 = 30;
/// 单候选拨号超时（TCP 与 TLS 握手共用）：3s 给 SYN 丢包一次重传机会，
/// 黑洞型死 IP 不许拖住整轮串发。
pub const CONNECT_TIMEOUT_SECS: u64 = 3;
/// CONNECT 隧道首字节看门狗：客户端已发 ClientHello 而上游 0 回包
/// （TCP 活着但被黑洞）时，代理先于浏览器 15~30s 超时判死 + 垫底。
pub const TUNNEL_FIRST_BYTE_TIMEOUT_SECS: u64 = 8;
/// 流量拨号闸门：限真实流量拨号的总并发 —— 没有它，打开一个页面
/// 30 并发请求会把自己打爆（实测踩过）。
pub const DIAL_GATE_SIZE: usize = 48;
/// 环形日志条数（供 WebUI 增量拉取）。
pub const LOG_BUFFER_SIZE: usize = 500;
/// 域名分组：命中规则的流量按该池的 plans.json 串发表拨号。
/// IP 名单不在此处 —— plans.json 是唯一权威（首次运行由 pool/seeds.json 初始化）。
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
        // api.github.com 走 API 专用边缘（140.82.112-114 的 .5/.6）：落到网站请求返
        // 404 JSON，反之网站 IP 落到 api 返 301，两族按 IP 分服务互斥，必须精确优先拆池。
        name: "api",
        patterns: &["api.github.com"],
    },
    Group {
        // 直连混合池 edge：auth 主机（OAuth/回调，凭据不能外泄第三方镜像）
        // + Fastly 静态边缘（CSS/JS、github.io、githubusercontent 内容域）。
        // avatars/camo/gist 直连 1s 内 200，镜像竞速则全灭 502（头像风暴还会
        // 打爆公共镜像）；raw 真名 SNI 被 GFW RST，直连失败由 mitm 回落镜像。
        // 条目 SNI 形态按 IP 族自动定（见 pool::shape_for_ip），serial_dial
        // 按 host 族选条目（IP 末段 133/153/154 对应域族），不对口不试不垫底。
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
    Group {
        // 纯镜像池（codeload 源码包）：同 fastly，不直连无表。
        name: "codeload",
        patterns: &["codeload.github.com"],
    },
];

/// `*.x` 匹配子域，否则全等。
pub fn pattern_match(host: &str, pat: &str) -> bool {
    if let Some(suffix) = pat.strip_prefix("*.") {
        // 必须卡点号边界：否则 "xgithub.com" 会被 "*.github.com" 误匹配
        return host.len() > suffix.len()
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            && host.ends_with(suffix);
    }
    host == pat
}

/// 域名 -> 所属池名（唯一路由真相，"" = 非池域名）。
/// 精确 pattern 优先于通配符 —— 否则 codeload.github.com 会被先遍历到的
/// core 组 "*.github.com" 抢走。
pub fn pool_for(host: &str) -> &'static str {
    for g in GROUPS {
        for pat in g.patterns {
            if *pat == host && pattern_match(host, pat) {
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

/// 池内全部域名（去重，PAC 脚本用）。
pub fn pooled_domains() -> &'static [&'static str] {
    static DOMAINS: OnceLock<Vec<&'static str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        let mut out: Vec<&'static str> = Vec::new();
        for g in GROUPS {
            for pat in g.patterns {
                let d = pat.strip_prefix("*.").unwrap_or(pat);
                if !out.contains(&d) {
                    out.push(d);
                }
            }
        }
        out
    })
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
        // api 池精确匹配优先于 core 的 "*.github.com"
        assert_eq!(pool_for("api.github.com"), "api");
        assert_eq!(pool_for("api.github.com.cn"), ""); // 不误伤非 api.github.com 后缀
                                                       // 精确 pattern 优先：codeload 不能落 core
        assert_eq!(pool_for("codeload.github.com"), "codeload");
        // 文件内容域 → edge 直连（avatars/camo/gist 实测直连 1s 内 200；
        // 镜像竞速全灭 502 是头像不显示的根源）+ 失败回落镜像在 mitm 侧
        assert_eq!(pool_for("raw.githubusercontent.com"), "edge");
        assert_eq!(pool_for("avatars.githubusercontent.com"), "edge");
        assert_eq!(pool_for("camo.githubusercontent.com"), "edge");
        assert_eq!(pool_for("gist.githubusercontent.com"), "edge");
        // CSS/JS 与 Pages → 直连池（镜像不路由，实测全 404）
        assert_eq!(pool_for("github.githubassets.com"), "edge");
        assert_eq!(pool_for("foo.github.io"), "edge");
        assert_eq!(pool_for("github.io"), "edge");
        // auth 主机与静态边缘合池 edge（凭据不外泄 + 镜像不路由）
        assert_eq!(pool_for("githubapp.com"), "edge");
        assert_eq!(pool_for("api.githubapp.com"), "edge");
        assert_eq!(pool_for("example.com"), "");
    }
}
