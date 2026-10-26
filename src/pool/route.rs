//! 路由唯一真相：master_route（System→Mirror→Pool→Tunnel）+ POOL_ROUTES 每池族表。
//! 冷却/健康按 host 或 IP 记账不按池——池级冷却会让一个域的全灭毒倒同池其他族。

use super::SerialPlan;
use crate::config;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    System,
    Mirror,
    Pool,
    Tunnel,
}

/// 大文件下载域（整域镜像）：codeload=源码包；objects/release-assets=附件 302 落点。
pub fn is_big_file_host(host: &str) -> bool {
    matches!(
        host,
        "codeload.github.com"
            | "objects.githubusercontent.com"
            | "release-assets.githubusercontent.com"
    )
}

/// 走镜像的大文件路径类别：`/releases/download`（含 `latest/download`）与 `/archive`。
/// git 智能协议路径不在此列；一个解析器同时供路由与镜像链归属用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetKind {
    Release,
    Archive,
}

fn release_asset_kind(host: &str, path: &str) -> Option<AssetKind> {
    if host != "github.com" {
        return None;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (segs.get(2), segs.get(3), segs.get(4)) {
        (Some(&"archive"), ..) => Some(AssetKind::Archive),
        (Some(&"releases"), Some(&"download"), _) => Some(AssetKind::Release),
        (Some(&"releases"), Some(&"latest"), Some(&"download")) => Some(AssetKind::Release),
        _ => None,
    }
}

fn is_release_asset_path(host: &str, path: &str) -> bool {
    release_asset_kind(host, path).is_some()
}

/// 镜像链归属：请求 host → 实际内容 host 的专属链（与请求 host 解耦）。
/// release 附件必须用 release-assets 链——github.com 链头部实测慢且中断。
pub fn mirror_chain_host<'a>(host: &'a str, path: &'a str) -> &'a str {
    if is_big_file_host(host) {
        return host;
    }
    match release_asset_kind(host, path) {
        Some(AssetKind::Archive) => "codeload.github.com",
        Some(AssetKind::Release) => "release-assets.githubusercontent.com",
        None => host,
    }
}

/// 总路由：host → 处置。method/path 只影响 Mirror 分流（附件路径仅 GET/HEAD）。
pub fn master_route(host: &str, method: &str, path: &str) -> Route {
    // 白名单必须先于一切：objects-origin 落 edge 通配符会 Fastly 500。
    if config::is_direct(host) {
        return Route::System;
    }
    if matches!(method, "GET" | "HEAD")
        && (is_big_file_host(host) || is_release_asset_path(host, path))
    {
        return Route::Mirror;
    }
    // 池名由 `config::pool_for` 单一给出：枚举只表达"走池"，不再夹带第二份副本。
    if config::pool_for(host).is_empty() {
        return Route::Tunnel;
    }
    Route::Pool
}


/// 族全灭后的兜底策略；执行流在 mitm 的 get_direct 失败分支，单测钉住两端一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    MirrorDns,
    Dns,
}

pub struct FamilyRoute {
    pub name: &'static str,
    pub host_of: fn(&str) -> bool,
    pub serves: fn(&str, &SerialPlan) -> bool,
    pub fallback: Fallback,
}

pub struct PoolRoute {
    pub pool: &'static str,
    pub families: &'static [FamilyRoute],
}

pub fn host_is_content(host: &str) -> bool {
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


/// Fastly 段（185.199.108-111）IP 的末段；非 Fastly 返回 None。
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

/// 非 Fastly 段（族资格只看 IP 段；sni 是透传形态，不参与族判定）。
/// 排除 Azure 的 4.249：那是白名单专用的 Copilot 代理段，混进 githubapp 的兜底族
/// 会让 auth 族拿它当候选，连过去必失败（不同服务）。
fn serves_non_fastly(_host: &str, p: &SerialPlan) -> bool {
    fastly_last_octet(&p.ip).is_none() && !p.ip.starts_with("4.249.")
}

const FAMILY_ALL: FamilyRoute = FamilyRoute {
    name: "all",
    host_of: |_| true,
    serves: serves_non_fastly,
    fallback: Fallback::Dns,
};

/// content：.133 伪装（2026-10-19 切换：默认证书 SAN 覆盖 *.githubusercontent.com 且实测出内容，
/// 真名反遭 RST）；伪装若失效，应急回退 = plans.json 该条 sni 改回 "sni"（重启生效）；兜底走镜像链。
const FAMILY_CONTENT: FamilyRoute = FamilyRoute {
    name: "content",
    host_of: host_is_content,
    serves: |_host, p| fastly_last_octet(&p.ip) == Some("133"),
    fallback: Fallback::MirrorDns,
};

/// content 透传(真名)腿：额外放行 .154/.215。这三组都能出内容(2026-10-25 全表试探实测)，
/// 但只有 .133 的默认证书 SAN 覆盖 *.githubusercontent.com——MITM 假名腿验得过，.154/.215
/// 只剩 *.githubassets.com 验不过，混进假名池只会白拨+池序抖动；真名腿浏览器按 SNI 拿对
/// 证书，好窗口白捡 8 个候选，坏窗口(SNI 点名)反正全灭，无损。
const FAMILY_CONTENT_PASSTHROUGH: FamilyRoute = FamilyRoute {
    name: "content",
    host_of: host_is_content,
    serves: |_host, p| {
        matches!(
            fastly_last_octet(&p.ip),
            Some("133") | Some("154") | Some("215")
        )
    },
    fallback: Fallback::MirrorDns,
};

/// assets：.154/.215 伪装（抗 SNI 阻断）。
const FAMILY_ASSETS: FamilyRoute = FamilyRoute {
    name: "assets",
    host_of: host_is_assets,
    serves: |_host, p| matches!(fastly_last_octet(&p.ip), Some("154") | Some("215")),
    fallback: Fallback::Dns,
};

/// io：.153 伪装。
const FAMILY_IO: FamilyRoute = FamilyRoute {
    name: "io",
    host_of: host_is_io,
    serves: |_host, p| fastly_last_octet(&p.ip) == Some("153"),
    fallback: Fallback::Dns,
};

/// auth：githubapp.com 系，非 Fastly 段伪装；兼 edge 未列族 host 的兜底族。
const FAMILY_AUTH: FamilyRoute = FamilyRoute {
    name: "auth",
    host_of: host_is_auth,
    serves: serves_non_fastly,
    fallback: Fallback::Dns,
};

/// 白名单族：域名该落哪段 IP 由 config::whitelist_seg 定，这里只按段认 IP。
/// 必须排在各老族之前——copilot-proxy 的后缀是 githubusercontent.com，
/// 排在后面会被 content 族先认走，而 content 只认 .133，它的 Azure 段对不上。
/// 分四个族而不是一个：cursor_key 是 `{pool}/{family}`，混成一个会让 docs 的池序
/// 被 support 的失败带偏。
fn wl_seg(host: &str) -> Option<&'static str> {
    config::whitelist_seg(host)
}

const FAMILY_WL_154: FamilyRoute = FamilyRoute {
    name: "wl154",
    host_of: |h| matches!(wl_seg(h), Some("154")),
    serves: |_h, p| fastly_last_octet(&p.ip) == Some("154"),
    fallback: Fallback::Dns,
};

const FAMILY_WL_153: FamilyRoute = FamilyRoute {
    name: "wl153",
    host_of: |h| matches!(wl_seg(h), Some("153")),
    serves: |_h, p| fastly_last_octet(&p.ip) == Some("153"),
    fallback: Fallback::Dns,
};

const FAMILY_WL_133: FamilyRoute = FamilyRoute {
    name: "wl133",
    host_of: |h| matches!(wl_seg(h), Some("133")),
    serves: |_h, p| fastly_last_octet(&p.ip) == Some("133"),
    fallback: Fallback::Dns,
};

/// Azure 段：不是 Fastly 四段之一，按前缀认（4.249.x）。
const FAMILY_WL_AZURE: FamilyRoute = FamilyRoute {
    name: "wl_azure",
    host_of: |h| matches!(wl_seg(h), Some("4.249")),
    serves: |_h, p| p.ip.starts_with("4.249."),
    fallback: Fallback::Dns,
};

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
        // 白名单族在最前：先按 config 里的 seg 认领，认到了就不进老族。
        families: &[
            FAMILY_WL_154,
            FAMILY_WL_153,
            FAMILY_WL_133,
            FAMILY_WL_AZURE,
            FAMILY_CONTENT,
            FAMILY_ASSETS,
            FAMILY_IO,
            FAMILY_AUTH,
        ],
    },
];

pub fn pool_route(pool: &str) -> Option<&'static PoolRoute> {
    POOL_ROUTES.iter().find(|pr| pr.pool == pool)
}

/// 串发族筛选：池内按 host 选族，未列族 host 归末族兜底（edge 即 auth）。
/// passthrough = 真名腿（CONNECT 隧道 / 明文转发），content 族放宽到 .154/.215。
pub fn serial_family(pool: &str, host: &str, passthrough: bool) -> Option<&'static FamilyRoute> {
    let pr = pool_route(pool)?;
    let fam = pr
        .families
        .iter()
        .find(|f| (f.host_of)(host))
        .or_else(|| {
            if pr.families.len() > 1 {
                pr.families.last()
            } else {
                None
            }
        })?;
    if passthrough && fam.name == "content" {
        return Some(&FAMILY_CONTENT_PASSTHROUGH);
    }
    Some(fam)
}

/// host 的兜底策略（族全灭后怎么走）；族语义与 serial_family 单点一致。仅 MITM 消费。
pub fn fallback_for(pool: &str, host: &str) -> Fallback {
    serial_family(pool, host, false).map_or(Fallback::Dns, |f| f.fallback)
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

    /// 白名单四族：按 seg 认域名、按段认 IP。段号填错或族序排错都会在这里红。
    #[test]
    fn whitelist_families_route_by_seg() {
        for (host, fam, ip) in [
            ("docs.github.com", "wl154", "185.199.108.154"),
            ("pages.github.com", "wl153", "185.199.108.153"),
            ("support.github.com", "wl133", "185.199.108.133"),
        ] {
            let f = serial_family("edge", host, false)
                .unwrap_or_else(|| panic!("{host} 没有命中任何族"));
            assert_eq!(f.name, fam, "{host} 落错族");
            assert!((f.serves)(host, &mk(ip, "baidu.com")), "{host} 应认 {ip}");
        }

        // Azure 段不是 Fastly 四段之一，必须按前缀认
        let cp = "copilot-proxy.githubusercontent.com";
        let f = serial_family("edge", cp, false).unwrap();
        assert_eq!(f.name, "wl_azure", "copilot-proxy 被别的族抢走了");
        assert!((f.serves)(cp, &mk("4.249.131.160", "baidu.com")));

        // 反例一：githubapp 系的兜底族不能把 Azure 段当候选（连过去是别的服务）
        let auth = serial_family("edge", "api.githubapp.com", false).unwrap();
        assert_eq!(auth.name, "auth");
        assert!(!(auth.serves)(
            "api.githubapp.com",
            &mk("4.249.131.160", "baidu.com")
        ));

        // 反例二：老族行为不变，content 仍只认 .133
        let content = serial_family("edge", "avatars.githubusercontent.com", false).unwrap();
        assert_eq!(content.name, "content");
        assert!((content.serves)(
            "avatars.githubusercontent.com",
            &mk("185.199.110.133", "baidu.com")
        ));
        assert!(!(content.serves)(
            "avatars.githubusercontent.com",
            &mk("185.199.110.154", "baidu.com")
        ));
    }


    #[test]
    fn master_route_all_hosts() {
        use Route::*;
        assert_eq!(
            master_route("objects-origin.githubusercontent.com", "PUT", "/x"),
            System
        );
        assert_eq!(master_route("uploads.github.com", "GET", "/"), System);
        assert_eq!(
            master_route("viewscreen.githubusercontent.com", "GET", "/"),
            System
        );
        assert_eq!(
            master_route("api.mcp.github.com", "GET", "/x"),
            System,
            "core 池证书不覆盖 api.mcp，必须白名单短路"
        );
        assert_eq!(
            master_route("codeload.github.com", "GET", "/o/r/tar.gz/x"),
            Mirror
        );
        assert_eq!(
            master_route("objects.githubusercontent.com", "HEAD", "/x"),
            Mirror
        );
        assert_eq!(
            master_route(
                "github.com",
                "GET",
                "/git-lfs/git-lfs/releases/download/v3.5.1/x.zip"
            ),
            Mirror
        );
        assert_eq!(master_route("github.com", "GET", "/o/r/archive/x.zip"), Mirror);
        assert_eq!(
            master_route("github.com", "POST", "/o/r/releases/download/x"),
            Pool
        );
        assert_eq!(
            master_route("github.com", "GET", "/o/r/releases"),
            Pool
        );
        assert_eq!(
            master_route("github.com", "GET", "/"),
            Pool
        );
        assert_eq!(
            master_route("gist.github.com", "GET", "/"),
            Pool
        );
        assert_eq!(
            master_route("api.github.com", "GET", "/"),
            Pool
        );
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
                Pool,
                "{host} 应归 edge 池"
            );
            assert_eq!(
                serial_family("edge", host, false).map(|f| f.name),
                Some(fam),
                "{host} 的族应为 {fam}"
            );
        }
    }


    #[test]
    fn family_entry_serves() {
        assert!(host_is_content("avatars.githubusercontent.com"));
        assert_eq!(fastly_last_octet("185.199.110.133"), Some("133"));
        assert_eq!(fastly_last_octet("185.199.110.154"), Some("154"));
        assert!(fastly_last_octet("140.82.112.3").is_none());
        assert!((FAMILY_CONTENT.serves)("x", &mk("185.199.110.133", "baidu.com")));
        assert!(!(FAMILY_CONTENT.serves)("x", &mk("185.199.110.154", "baidu.com")));
        assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.215", "baidu.com")));
        assert!((FAMILY_ASSETS.serves)("x", &mk("185.199.110.154", "baidu.com")));
        assert!(!(FAMILY_ASSETS.serves)(
            "x",
            &mk("185.199.110.133", "baidu.com")
        ));
        assert!((FAMILY_IO.serves)("x", &mk("185.199.110.153", "baidu.com")));
        assert!(!(FAMILY_IO.serves)("x", &mk("185.199.110.154", "baidu.com")));
        assert!((FAMILY_AUTH.serves)("x", &mk("140.82.112.29", "baidu.com")));
        assert!(!(FAMILY_AUTH.serves)(
            "x",
            &mk("185.199.110.133", "baidu.com")
        ));
        assert!((FAMILY_ALL.serves)("x", &mk("140.82.112.3", "baidu.com")));
    }

    fn fam(pool: &str, host: &str) -> &'static str {
        serial_family(pool, host, false).map_or("", |f| f.name)
    }

    #[test]
    fn family_for_and_fallback() {
        assert_eq!(fam("core", "github.com"), "all");
        assert_eq!(fam("api", "api.github.com"), "all");
        assert_eq!(fam("edge", "raw.githubusercontent.com"), "content");
        assert_eq!(fam("edge", "github.githubassets.com"), "assets");
        assert_eq!(fam("edge", "octocat.github.io"), "io");
        assert_eq!(fam("edge", "githubapp.com"), "auth");
        assert_eq!(fam("edge", "future.edge.host"), "auth");
        assert_eq!(fam("codeload", "codeload.github.com"), "");
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
    fn serial_family_edge_fallback() {
        let f = serial_family("edge", "future.edge.host", false).unwrap();
        assert_eq!(f.name, "auth");
        assert!((f.serves)("x", &mk("140.82.112.29", "baidu.com")));
        assert!(!(f.serves)("x", &mk("185.199.110.133", "real")));
    }

    #[test]
    fn content_serves_splits_by_leg() {
        let mitm = serial_family("edge", "raw.githubusercontent.com", false).unwrap();
        let pt = serial_family("edge", "raw.githubusercontent.com", true).unwrap();
        assert_eq!(mitm.name, "content");
        assert_eq!(pt.name, "content", "游标键不随模式分裂");
        // MITM 假名腿：只有 .133（默认证书 SAN 覆盖内容族）
        assert!((mitm.serves)("x", &mk("185.199.110.133", "baidu.com")));
        // 透传真名腿：.133/.154/.215 全放行，.153(io 组)不放行
        for last in ["133", "154", "215"] {
            let ip = format!("185.199.110.{last}");
            assert!((pt.serves)("x", &mk(&ip, "baidu.com")), "透传应放行 {ip}");
        }
        for last in ["154", "215"] {
            let ip = format!("185.199.110.{last}");
            assert!(!(mitm.serves)("x", &mk(&ip, "baidu.com")), "MITM 仍拒绝 {ip}");
        }
        assert!(!(pt.serves)("x", &mk("185.199.110.153", "baidu.com")));
        // 非 content 族不受模式影响
        let assets = serial_family("edge", "github.githubassets.com", true).unwrap();
        assert_eq!(assets.name, "assets");
        assert!((assets.serves)("x", &mk("185.199.110.154", "baidu.com")));
    }

    #[test]
    fn mirror_chain_host_dedicated() {
        assert_eq!(
            mirror_chain_host("github.com", "/o/r/releases/download/v1/f.exe"),
            "release-assets.githubusercontent.com"
        );
        assert_eq!(
            mirror_chain_host("github.com", "/o/r/releases/latest/download/f.exe"),
            "release-assets.githubusercontent.com"
        );
        assert_eq!(
            mirror_chain_host("github.com", "/o/r/archive/refs/tags/v1.tar.gz"),
            "codeload.github.com"
        );
        assert_eq!(
            mirror_chain_host(
                "release-assets.githubusercontent.com",
                "/x?sig=abc"
            ),
            "release-assets.githubusercontent.com"
        );
        assert_eq!(
            mirror_chain_host("codeload.github.com", "/o/r/tar.gz/x"),
            "codeload.github.com"
        );
        assert_eq!(mirror_chain_host("raw.githubusercontent.com", "/o/r/f"), "raw.githubusercontent.com");
        assert_eq!(mirror_chain_host("github.com", "/o/r"), "github.com");
        assert_eq!(mirror_chain_host("github.com", "/o/r/releases"), "github.com");
        assert_eq!(
            master_route("github.com", "GET", "/o/r/releases/latest/download/f.exe"),
            Route::Mirror
        );
    }
}
