//! 路由唯一真相：master_route（System→Mirror→Pool{池,族}→Tunnel）+ POOL_ROUTES 每池族表。
//! 冷却/健康按 host 或 IP 记账不按池——池级冷却会让一个域的全灭毒倒同池其他族。

use super::SerialPlan;
use crate::config;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    System,
    Mirror,
    Pool { pool: &'static str },
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
    let pool = config::pool_for(host);
    if pool.is_empty() {
        return Route::Tunnel;
    }
    Route::Pool { pool }
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
fn serves_non_fastly(_host: &str, p: &SerialPlan) -> bool {
    fastly_last_octet(&p.ip).is_none()
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

pub fn pool_route(pool: &str) -> Option<&'static PoolRoute> {
    POOL_ROUTES.iter().find(|pr| pr.pool == pool)
}

/// 串发族筛选：池内按 host 选族，未列族 host 归末族兜底（edge 即 auth）。
pub fn serial_family(pool: &str, host: &str) -> Option<&'static FamilyRoute> {
    let pr = pool_route(pool)?;
    pr.families
        .iter()
        .find(|f| (f.host_of)(host))
        .or_else(|| {
            if pr.families.len() > 1 {
                pr.families.last()
            } else {
                None
            }
        })
}

/// host 的兜底策略（族全灭后怎么走）；族语义与 serial_family 单点一致。
pub fn fallback_for(pool: &str, host: &str) -> Fallback {
    serial_family(pool, host).map_or(Fallback::Dns, |f| f.fallback)
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
            Pool { pool: "core" }
        );
        assert_eq!(
            master_route("github.com", "GET", "/o/r/releases"),
            Pool { pool: "core" }
        );
        assert_eq!(
            master_route("github.com", "GET", "/"),
            Pool { pool: "core" }
        );
        assert_eq!(
            master_route("gist.github.com", "GET", "/"),
            Pool { pool: "core" }
        );
        assert_eq!(
            master_route("api.github.com", "GET", "/"),
            Pool { pool: "api" }
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
                Pool { pool: "edge" },
                "{host} 应归 edge 池"
            );
            assert_eq!(
                serial_family("edge", host).map(|f| f.name),
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
        serial_family(pool, host).map_or("", |f| f.name)
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
        let f = serial_family("edge", "future.edge.host").unwrap();
        assert_eq!(f.name, "auth");
        assert!((f.serves)("x", &mk("140.82.112.29", "baidu.com")));
        assert!(!(f.serves)("x", &mk("185.199.110.133", "real")));
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
