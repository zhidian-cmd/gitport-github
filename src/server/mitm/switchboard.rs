//! 总机：浏览器 ↔ GitHub 的第一接头人。host 级路由政策的单点——
//! 会话域/其他 → 直连串发；镜像回落域 → 镜像+直连同台；切片资格 → 多段并发；
//! 其余 → 直连单流。mitm_http 只管缓冲与响应善后（缓存失效/写路由），
//! 「谁该去哪个科室」只看这里。
use super::{
    direct_split, dns_direct_fetch, gh_defuse, get_direct, mirror, mirror_or_direct,
    mitm_unavailable, write_upstream, UpstreamInfo,
};
use super::super::protocol::BoxBody;
use crate::{pool, util::LogFn};
use bytes::Bytes;
use http::Method;

/// 简单请求判定：GET/HEAD 才有切片/镜像/直连竞速的响应体语义。
fn is_simple(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD)
}

/// 简单请求的全科室路由。Ok = 上游响应到手（调用方做缓存善后）；
/// Err = 兜底也已失败或不可用的最终应答（调用方直接返回）。
pub(super) async fn dispatch(
    log: &LogFn,
    req: &hyper::Request<hyper::body::Incoming>,
    out_body: &hyper::Request<BoxBody>,
    host: &str,
    path: &str,
    info: &UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<axum::response::Response<BoxBody>, axum::response::Response<BoxBody>> {
    let is_simple = is_simple(out_body.method());
    // 镜像回落域：镜像链 + 直连同台竞速，ECT 统一派发；全部候选耗尽才 502。
    if is_simple
        && matches!(
            pool::route::master_route(host, out_body.method().as_str(), path),
            pool::route::Route::Mirror
        )
    {
        let chain_host = pool::route::mirror_chain_host(host, path);
        let new_bytes = mirror::range_bytes(req.headers().get("range").and_then(|v| v.to_str().ok()));
        match mirror_or_direct(log, out_body, host, chain_host, new_bytes, info, replay).await {
            Ok(resp) => return Ok(resp),
            // 原因落日志：熔断中/凭据串仅直连/链全灭，一眼可辨，不再吞。
            Err(e) => (log)(&format!("[MITM] {host}{path} 镜像与直连均不可用({e})")),
        }
        return Err(mitm_unavailable(
            req,
            host,
            "镜像与直连均不可用, 疑似封锁窗口期, 代理正在按表自动重试。",
        ));
    }
    // 大文件切片：只用池里现成的伪装 SNI 直连连接，多段 Range 并发拉再按字节边界合流。
    // 不进镜像链、不扩 IP、不新拨连接；池冷或任一段没回 206 就交回下面的单流路径。
    if is_simple {
        if let Some(resp) = direct_split::try_direct_split(log, out_body, host, info).await {
            return Ok(write_upstream(resp, "direct-split", info));
        }
    }
    let mut resp = match get_direct(log, out_body, host, info, replay).await {
        Ok(r) => r,
        Err(e) => {
            match pool::route::fallback_for(host) {
                pool::route::Fallback::MirrorDns if is_simple => {
                    let chain_host = pool::route::mirror_chain_host(host, path);
                    let new_bytes =
                        mirror::range_bytes(req.headers().get("range").and_then(|v| v.to_str().ok()));
                    // 直连刚失败过会带 45s 降权，ECT 自动跳过它——语义就是兜底的最后一次机会。
                    match mirror_or_direct(log, out_body, host, chain_host, new_bytes, info, replay)
                        .await
                    {
                        Ok(resp) => return Ok(resp),
                        Err(_) => (log)(&format!("[MITM] {host}{path} 直连和镜像都试不通")),
                    }
                }
                _ => {
                    (log)(&format!("[MITM] {host}{path} 上游失败: {e}"));
                }
            }
            if is_simple {
                match dns_direct_fetch(log, out_body, host, info, replay).await {
                    Ok(r) => return Ok(write_upstream(r, "dns", info)),
                    Err(de) => {
                        (log)(&format!("[MITM] {host}{path} DNS 备用直连也失败({de})"));
                    }
                }
            }
            return Err(mitm_unavailable(
                req,
                host,
                "直连与镜像链均不可用, 疑似封锁窗口期, 代理正在按表自动重试。",
            ));
        }
    };
    // 会话域风控页：4xx/5xx 先试 gh_defuse 换血重放，仍拦就交给拦截页化解。
    if is_simple
        && (host == "github.com" || host == "api.github.com")
        && resp.status().as_u16() >= 400
    {
        match gh_defuse(log, host, info, out_body, replay).await {
            Ok(r) => resp = r,
            Err(e) => {
                (log)(&format!("[MITM] {host}{path} 风控页重试也失败: {e}"));
                return Err(mitm_unavailable(
                    req,
                    host,
                    "全部边缘均返回风控拦截页, 代理正在按表自动重试。",
                ));
            }
        }
    }
    Ok(resp)
}
