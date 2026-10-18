//! 路由细分：每池一张路由表，三池之上一张总路由（2026-10-19 用户裁定）。
//!
//! 细分前，路由知识散落四处：`config::GROUPS`（host→池）、`entry_serves`/
//! `host_family`（池内族筛选）、mitm 的 `is_big_file_host`/
//! `is_release_asset_path`（镜像 only）、`pool::CONTENT_HOSTS`（镜像链）。
//! 任何一处漏改都会出现"某类请求走到不该走的腿"类怪 bug —— 2026-10-17
//! objects-origin 落到 Fastly 500 Domain Not Found 即此类（白名单漏了
//! PAC 短路）。本表把四者合成一条决策链，唯一真相：
//!
//! ```text
//! master_route(host, method, path)
//!   → System   直连白名单（不代理，系统 DNS 真名）
//!   → Mirror   镜像 only（大文件域 / release 附件路径，仅 GET/HEAD）
//!   → Pool     串发池 + 族（族路由见 POOL_ROUTES）
//!   → Tunnel   非池域名（CONNECT 隧道直通，浏览器自连）
//! ```
//!
//! 池内：`POOL_ROUTES` 每池一张族表。族 = 一批条目（IP 末段 + SNI 形态）
//! + 服务的 host 判据 + 全灭兜底策略（`Fallback`）。core/api 单族 all；
//! edge 四族：content（.133 真名）/ assets（.154/.215 伪装）/
//! io（.153 伪装）/ auth（非 Fastly 伪装，githubapp.com 系）。
//! 冷却/健康状态全部按 host 或 IP 记账，不按池 —— 池级冷却会让一个域的
//! 全灭毒倒同池其他族的健康腿（2026-10-19 实测：camo 全灭 30s 内
//! assets/io/auth 全部快速失败落 502）。

use super::{plan_mode, SerialPlan};
use crate::config;

// ---------- 总路由 ----------

/// 总路由判定结果（`master_route`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// 直连白名单：不归任何池、不经代理（`config::DIRECT_HOSTS`）。
    System,
    /// 镜像 only：大文件域或 release 附件路径（GET/HEAD）。不试直连。
    Mirror,
    /// 串发池 + 族名（族路由见 `POOL_ROUTES`）。
    Pool {
        pool: &'static str,
        family: &'static str,
    },
    /// 非池域名：不进 MITM，CONNECT 隧道直通（浏览器自连系统 DNS）。
    Tunnel,
}

/// 大文件下载域（整域镜像）：codeload=源码包；objects/release-assets=
/// release 附件 302 的落点（新旧两代域名）。
pub fn is_big_file_host(host: &str) -> bool {
    matches!(
        host,
        "codeload.github.com"
            | "objects.githubusercontent.com"
            | "release-assets.githubusercontent.com"
    )
}

/// release 附件与源码包路径（/releases/download、/archive）一律走镜像；
/// git 智能协议路径不在此列 —— 镜像不认，必须走 core 池直连（伪装 SNI）。
fn is_release_asset_path(host: &str, path: &str) -> bool {
    if host != "github.com" {
        return false;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        [_owner, _repo, kind, ..] if *kind == "releases" => {
            // releases/download/...（releases 页面本身不拦，只拦下载）
            segs.len() >= 4 && segs[3] == "download"
        }
        [_owner, _repo, kind, ..] if *kind == "archive" => true,
        _ => false,
    }
}

/// 总路由：host → 处置。唯一真相（取代四处散落的判定）。
/// method/path 只影响 Mirror 分流（附件路径仅 GET/HEAD 镜像）。
pub fn master_route(host: &str, method: &str, path: &str) -> Route {
    // 白名单必须先于一切：objects-origin 会落到 edge 的
    // *.githubusercontent.com 通配符（Fastly 500），2026-10-17 16:53 错路
    if config::is_direct(host) {
        return Route::System;
    }
    if matches!(method, "GET" | "HEAD")
        && (is_big_file_host(host) || is_release_asset_path(host, path))
    {
        return Route::Mirror;
    }
    let pool = config::pool_for(host);
    if pool.is_empty() {
        return Route::Tunnel;
    }
    Route::Pool {
        pool,
        family: family_for(pool, host),
    }
}

// ---------- 池内族 ----------

/// 族全灭后的兜底策略。执行流在 mitm（`get_direct` 失败分支），
/// 策略以本表为准：改这里必须同步执行流，单测钉住两端一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// 镜像链（host 有链才走）→ 系统 DNS 直连腿。
    MirrorDns,
    /// 系统 DNS 直连腿 → 失败（无镜像可走：assets/io/auth）。
    Dns,
}

/// 池内族路由：一批条目 + 服务哪些 host + 兜底策略。
pub struct FamilyRoute {
    pub name: &'static str,
    /// host 是否归该族（总路由分族用）。
    pub host_of: fn(&str) -> bool,
    /// 条目是否服务该 host（串发筛选用：IP 末段族 + SNI 形态）。
    /// 不对口不试不垫底 —— 否则每类请求都把另一类 IP 试败沉底，
    /// 共享表顺序永久 ping-pong。
    pub serves: fn(&str, &SerialPlan) -> bool,
    pub fallback: Fallback,
}

/// 每池的路由表：池 → 有序族列表。
pub struct PoolRoute {
    pub pool: &'static str,
    pub families: &'static [FamilyRoute],
}

// --- host 判据 ---

fn host_is_content(host: &str) -> bool {
    host.ends_with("githubusercontent.com")
}
fn host_is_assets(host: &str) -> bool {
    host.ends_with("githubassets.com")
}
fn host_is_io(host: &str) -> bool {
    host == "github.io" || host.ends_with(".github.io")
}
fn host_is_auth(host: &str) -> bool {
    host == "githubapp.com" || host.ends_with(".githubapp.com")
}

// --- 条目判据 ---

/// Fastly 段 IP 的末段（108-111 段才认），非 Fastly 返回 None。
/// 末段即域族：133=githubusercontent 内容 / 153=github.io / 154=githubassets。
pub fn fastly_last_octet(ip: &str) -> Option<&str> {
    let mut o = ip.split('.');
    match (o.next(), o.next(), o.next(), o.next()) {
        (Some("185"), Some("199"), Some(n), Some(last))
            if matches!(n, "108" | "109" | "110" | "111") =>
        {
            Some(last)
        }
        _ => None,
    }
}

/// 非 Fastly 段 + 伪装形态（真名 MODE_SNI 只归 Fastly 内容族用）。
fn serves_non_fastly(_host: &str, p: &SerialPlan) -> bool {
    fastly_last_octet(&p.ip).is_none() && plan_mode(&p.sni) != plan_mode(super::dial::MODE_SNI)
}

/// core/api 通配族：全部条目服务全部 host。
const FAMILY_ALL: FamilyRoute = FamilyRoute {
    name: "all",
    host_of: |_| true,
    serves: serves_non_fastly,
    fallback: Fallback::Dns,
};

/// content：.133 真名（Fastly 校验 SNI==Host，伪装被挂起；真名抗不住
/// GFW 按域 RST —— raw 的直连腿基本随缘，兜底走镜像链）。
const FAMILY_CONTENT: FamilyRoute = FamilyRoute {
    name: "content",
    host_of: host_is_content,
    serves: |_host, p| fastly_last_octet(&p.ip) == Some("133"),
    fallback: Fallback::MirrorDns,
};

/// assets：.154/.215 伪装（抗 SNI 阻断；镜像不路由 CSS/JS）。
const FAMILY_ASSETS: FamilyRoute = FamilyRoute {
    name: "assets",
    host_of: host_is_assets,
    serves: |_host, p| matches!(fastly_last_octet(&p.ip), Some("154") | Some("215")),
    fallback: Fallback::Dns,
};

/// io：.153 伪装。github.io 裸域实测可服（2026-10-19 e2e 200）——
/// 早前"*.github.io 证书不覆盖 apex"的担心不影响代理腿（上游证书
/// 不参与客户端校验），登记在案免再审。
const FAMILY_IO: FamilyRoute = FamilyRoute {
    name: "io",
    host_of: host_is_io,
    serves: |_host, p| fastly_last_octet(&p.ip) == Some("153"),
    fallback: Fallback::Dns,
};

/// auth：githubapp.com 系，非 Fastly 段伪装。同时是 edge 的兜底族 ——
/// 未显式列族的 host（将来的新边缘主机）落这里，保持旧 entry_serves
/// "_" 分支的兼容语义。
const FAMILY_AUTH: FamilyRoute = FamilyRoute {
    name: "auth",
    host_of: host_is_auth,
    serves: serves_non_fastly,
    fallback: Fallback::Dns,
};

/// 三池路由表（顺序即 UI/落盘顺序，与 `SERIAL_POOLS` 恒一致）。
pub const POOL_ROUTES: &[PoolRoute] = &[
    PoolRoute {
        pool: "core",
        families: &[FAMILY_ALL],
    },
    PoolRoute {
        pool: "api",
        families: &[FAMILY_ALL],
    },
    PoolRoute {
        pool: "edge",
        families: &[FAMILY_CONTENT, FAMILY_ASSETS, FAMILY_IO, FAMILY_AUTH],
    },
];

/// 池路由表查找。
pub fn pool_route(pool: &str) -> Option<&'static PoolRoute> {
    POOL_ROUTES.iter().find(|pr| pr.pool == pool)
}

/// host 在该池所属族名（"" = 池无路由表）。edge 未显式列族的 host 归
/// auth（兜底族，见 FAMILY_AUTH 注释）。
pub fn family_for(pool: &str, host: &str) -> &'static str {
    let Some(pr) = pool_route(pool) else {
        return "";
    };
    for f in pr.families {
        if (f.host_of)(host) {
            return f.name;
        }
    }
    if pr.families.len() > 1 {
        return "auth"; // edge 兜底族
    }
    "all"
}

/// host 的兜底策略（族全灭后怎么走）。
pub fn fallback_for(pool: &str, host: &str) -> Fallback {
    let name = family_for(pool, host);
    for pr in POOL_ROUTES {
        if pr.pool == pool {
            for f in pr.families {
                if f.name == name {
                    return f.fallback;
                }
            }
        }
    }
    Fallback::Dns
}

/// 是否内容域 host（edge content 族）。镜像链板块只覆盖内容域。
pub fn is_content_host(host: &str) -> bool {
    host_is_content(host)
}

// ---------- 已下线 IP（种子与实表都不再保留） ----------

/// 2026-10-19 TCP 实测全超时的 IP。复活了就从清单删（别让清单腐化
/// 成永久真相——它只是"当前这批已知死 IP"的快照）。
pub const RETIRED_IPS: &[&str] = &[
    // core：140.82.115-120 段（116.x 实测存活，保留）
    "140.82.115.3",
    "140.82.115.4",
    "140.82.117.3",
    "140.82.117.4",
    "140.82.118.3",
    "140.82.118.4",
    "140.82.119.3",
    "140.82.119.4",
    "140.82.120.3",
    "140.82.120.4",
    // edge content：108/109/111.133（110.133 时通时断，保留作独苗）
    "185.199.108.133",
    "185.199.109.133",
    "185.199.111.133",
];

pub fn is_retired(ip: &str) -> bool {
    RETIRED_IPS.contains(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(ip: &str, sni: &str) -> SerialPlan {
        SerialPlan {
            ip: ip.into(),
            sni: sni.into(),
        }
    }

    // ---------- 总路由 ----------

    #[test]
    fn master_route_all_hosts() {
        use Route::*;
        // 白名单
        assert_eq!(
            master_route("objects-origin.githubusercontent.com", "PUT", "/x"),
            System
        );
        assert_eq!(master_route("uploads.github.com", "GET", "/"), System);
        assert_eq!(
            master_route("viewscreen.githubusercontent.com", "GET", "/"),
            System
        );
        // 镜像 only：大文件域（GET/HEAD）
        assert_eq!(
            master_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
            Mirror
        );
        assert_eq!(
            master_route("objects.githubusercontent.com", "HEAD", "/x"),
            Mirror
        );
        // 镜像 only：github.com 附件路径
        assert_eq!(
            master_route(
                "github.com",
                "GET",
                "/git-lfs/git-lfs/releases/download/v3.5.1/x.zip"
            ),
            Mirror
        );
        assert_eq!(master_route("github.com", "GET", "/o/r/archive/x.zip"), Mirror);
        // 同一路径非 GET 不镜像（POST 附件不存在，但语义必须钉住）
        assert_eq!(
            master_route("github.com", "POST", "/o/r/releases/download/x"),
            Pool {
                pool: "core",
                family: "all"
            }
        );
        // releases 页面本身不拦
        assert_eq!(
            master_route("github.com", "GET", "/o/r/releases"),
            Pool {
                pool: "core",
                family: "all"
            }
        );
        // 三池
        assert_eq!(
            master_route("github.com", "GET", "/"),
            Pool {
                pool: "core",
                family: "all"
            }
        );
        assert_eq!(
            master_route("gist.github.com", "GET", "/"),
            Pool {
                pool: "core",
                family: "all"
            }
        );
        assert_eq!(
            master_route("api.github.com", "GET", "/"),
            Pool {
                pool: "api",
                family: "all"
            }
        );
        // 非池域名
        assert_eq!(master_route("example.com", "GET", "/"), Tunnel);
        assert_eq!(master_route("githubstatus.com", "GET", "/"), Tunnel);
    }

    #[test]
    fn master_route_edge_families() {
        use Route::*;
        for (host, fam) in [
            ("raw.githubusercontent.com", "content"),
            ("avatars.githubusercontent.com", "content"),
            ("camo.githubusercontent.com", "content"),
            ("user-images.githubusercontent.com", "content"),
            ("media.githubusercontent.com", "content"),
            ("private-user-images.githubusercontent.com", "content"),
            ("github.githubassets.com", "assets"),
            ("assets.githubassets.com", "assets"),
            ("github.io", "io"),
            ("octocat.github.io", "io"),
            ("githubapp.com", "auth"),
            ("api.githubapp.com", "auth"),
        ] {
            assert_eq!(
                master_route(host, "GET", "/x"),
                Pool {
                    pool: "edge",
                    family: fam
                },
                "{host} 应归 edge/{fam}"
            );
        }
    }

    // ---------- 族筛选 ----------

    #[test]
    fn family_entry_serves() {
        // content 只认 .133 真名
        assert!(host_is_content("avatars.githubusercontent.com"));
        assert_eq!(fastly_last_octet("185.199.110.133"), Some("133"));
        // .154 不服务内容域（打错边缘 Host 被拒/404）
        assert_eq!(fastly_last_octet("185.199.110.154"), Some("154"));
        // 非 Fastly 段不服务内容域
        assert!(fastly_last_octet("140.82.112.3").is_none());
        // serves 判据逐族
        assert!((FAMILY_CONTENT.serves)("x", &mk("185.199.110.133", crate::pool::dial::MODE_SNI)));
        assert!(!(FAMILY_CONTENT.serves)("x", &mk("185.199.110.154", "baidu.com")));
        assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.215", "baidu.com")));
        assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.154", "baidu.com")));
        assert!(!(FAMILY_ASSETS.serves)(
            "x",
            &mk("185.199.110.133", crate::pool::dial::MODE_SNI)
        ));
        assert!((FAMILY_IO.serves)("x", &mk("185.199.110.153", "baidu.com")));
        assert!(!(FAMILY_IO.serves)("x", &mk("185.199.110.154", "baidu.com")));
        // auth/all：非 Fastly 伪装
        assert!((FAMILY_AUTH.serves)("x", &mk("140.82.112.29", "baidu.com")));
        assert!(!(FAMILY_AUTH.serves)(
            "x",
            &mk("185.199.110.133", crate::pool::dial::MODE_SNI)
        ));
        assert!((FAMILY_ALL.serves)("x", &mk("140.82.112.3", "baidu.com")));
        // Fastly 三段形态由 load 时按族强制归一（shape_for_ip），此处只验判据
    }

    #[test]
    fn family_for_and_fallback() {
        assert_eq!(family_for("core", "github.com"), "all");
        assert_eq!(family_for("api", "api.github.com"), "all");
        assert_eq!(family_for("edge", "raw.githubusercontent.com"), "content");
        assert_eq!(family_for("edge", "github.githubassets.com"), "assets");
        assert_eq!(family_for("edge", "octocat.github.io"), "io");
        assert_eq!(family_for("edge", "githubapp.com"), "auth");
        // edge 兜底族：未列明的新 host 归 auth（旧 entry_serves "_" 语义）
        assert_eq!(family_for("edge", "future.edge.host"), "auth");
        // 无路由表的池
        assert_eq!(family_for("codeload", "codeload.github.com"), "");
        // 兜底策略：内容域先镜像后 DNS；其余直接 DNS
        assert_eq!(
            fallback_for("edge", "raw.githubusercontent.com"),
            Fallback::MirrorDns
        );
        assert_eq!(
            fallback_for("edge", "camo.githubusercontent.com"),
            Fallback::MirrorDns
        );
        assert_eq!(fallback_for("edge", "github.githubassets.com"), Fallback::Dns);
        assert_eq!(fallback_for("edge", "octocat.github.io"), Fallback::Dns);
        assert_eq!(fallback_for("edge", "githubapp.com"), Fallback::Dns);
        assert_eq!(fallback_for("core", "github.com"), Fallback::Dns);
        assert_eq!(fallback_for("api", "api.github.com"), Fallback::Dns);
    }

    #[test]
    fn retired_ips_snapshot() {
        for ip in [
            "140.82.115.3",
            "140.82.120.4",
            "140.82.117.3",
            "185.199.108.133",
            "185.199.111.133",
        ] {
            assert!(is_retired(ip), "{ip} 应已下线");
        }
        // 实测存活的必须在清单外
        for ip in [
            "140.82.116.3",
            "140.82.116.4",
            "140.82.121.3",
            "185.199.110.133",
            "185.199.110.154",
            "185.199.110.153",
            "140.82.112.29",
        ] {
            assert!(!is_retired(ip), "{ip} 实测存活, 不应下线");
        }
    }
}
