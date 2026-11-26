//! 总机：URL 级分诊单点；镜像回落域→镜像加速，切片资格域→直连切片，其余→直连；mitm_http 只管缓冲与善后。
use super::{
    direct_split, dns_direct_fetch, gh_defuse, get_direct, mirror, mirror_or_direct,
    mitm_unavailable, UpstreamInfo,
};
use super::super::protocol::BoxBody;
use crate::{pool, util::LogFn};
use bytes::Bytes;
use http::Method;

/// 简单请求判定：GET/HEAD 才有切片/镜像/竞速语义。
fn is_simple(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD)
}

/// 全科室路由：Ok = (响应, 真路由名)，包装交调用方；Err = 最终应答。
pub(super) async fn dispatch(
    log: &LogFn,
    req: &hyper::Request<hyper::body::Incoming>,
    out_body: &hyper::Request<BoxBody>,
    host: &str,
    path: &str,
    info: &UpstreamInfo,
    replay: &Option<Bytes>,
) -> Result<
    (axum::response::Response<BoxBody>, &'static str),
    axum::response::Response<BoxBody>,
> {
    let is_simple = is_simple(out_body.method());
    // 镜像回落域：镜像链 + 直连竞速，全部耗尽才 502。
    if is_simple
        && pool::route::is_mirror_route(host, out_body.method().as_str(), path)
    {
        let chain_host = pool::route::mirror_chain_host(host, path);
        let new_bytes =
            mirror::range_bytes(req.headers().get("range").and_then(|v| v.to_str().ok()));
        match mirror_or_direct(log, out_body, host, &chain_host, new_bytes, info, replay).await {
            Ok((resp, route)) => return Ok((resp, route)),
            // 失败原因落日志（熔断/链全灭）。
            Err(e) => (log)(&format!("[MITM] {host}{path} 镜像与直连均不可用({e})")),
        }
        return Err(mitm_unavailable(
            req,
            host,
            "镜像与直连均不可用, 疑似封锁窗口期, 代理正在按表自动重试。",
        ));
    }
    // 大文件切片：下发片数；不满足或段失败回单流。
    if is_simple {
        if let Some(resp) = direct_split::try_direct_split(log, out_body, host, info, 8).await {
            return Ok((resp, "direct-split"));
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
                    // 直连失败带降权（硬错 45s / 超时 15s），兜底最后一次机会。
                    match mirror_or_direct(log, out_body, host, &chain_host, new_bytes, info, replay)
                        .await
                    {
                        Ok((r, route)) => return Ok((r, route)),
                        Err(_) => (log)(&format!("[MITM] {host}{path} 直连和镜像都试不通")),
                    }
                }
                _ => {
                    (log)(&format!("[MITM] {host}{path} 上游失败: {e}"));
                }
            }
            if is_simple {
                match dns_direct_fetch(log, out_body, host, info, replay).await {
                    Ok(r) => return Ok((r, "dns")),
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
    // 风控页：4xx/5xx 先试 gh_defuse 换血重放。
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
    Ok((resp, "direct"))
}
