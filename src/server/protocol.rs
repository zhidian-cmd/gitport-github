//! 服务层共用类型：请求/响应体别名与构造器、请求预算；mitm 子模块与 upstream 由此取用，互不依赖对方实现。

use bytes::Bytes;
use http_body_util::BodyExt;

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
pub type Incoming = hyper::body::Incoming;

/// BoxBody 构造收口：全仓的 Empty/Full + io 错误映射统一走这两个入口。
pub fn empty_body() -> BoxBody {
    BoxBody::new(http_body_util::Empty::<Bytes>::new().map_err(std::io::Error::other))
}

pub fn full_body(b: Bytes) -> BoxBody {
    BoxBody::new(http_body_util::Full::new(b).map_err(std::io::Error::other))
}

/// 其他域（文档站/静态 CDN/杂项子域）响应头预算：静态内容 2s 无头基本可判该 IP 有问题。
pub const REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
