use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

pub trait HttpBody {
    fn poll_frame_mut(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>>;
}

impl HttpBody for BoxBody {
    fn poll_frame_mut(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        hyper::body::Body::poll_frame(self, cx)
    }
}

fn empty_err_body() -> BoxBody {
    // error 类型对齐: Empty<Bytes> 的 Error 是 Infallible, map_err 拉齐到 io::Error
    BoxBody::new(BodyExt::map_err(
        http_body_util::Empty::<Bytes>::new(),
        std::io::Error::other,
    ))
}

/// 统一装箱: 把任意 http Body(BoxBody 或其 map 变体)转成 RacingBody 可用的 BoxBody。
pub fn to_box<B>(b: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes, Error = std::io::Error> + Send + Sync + Unpin + 'static,
{
    BoxBody::new(b)
}

/// 交错双源 body: 两路上游流都从同一 delivered 偏移起拉同一 Range,
/// 字节内容一致——谁先到先用, 另一路的同段自然重复, 下载器按偏移落盘
/// 时覆盖/跳过(写文件本就随机寻址)。两路各自流式透传, 代理不攒整片。
/// 一路结束(含错误)不终止整体, 另一路继续; 两路都完才算完。
pub struct RacingBody {
    a: Pin<Box<BoxBody>>,
    b: Pin<Box<BoxBody>>,
    /// b 尚未产出首个帧(成功建流)前不启用——b 建流失败时退化为纯 a。
    b_alive: bool,
    a_done: bool,
}

impl hyper::body::Body for RacingBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // A 路优先轮询: 字节到达即透传。
        if !self.a_done {
            match self.a.as_mut().poll_frame_mut(cx) {
                Poll::Ready(Some(Ok(f))) => return Poll::Ready(Some(Ok(f))),
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    self.a_done = true;
                }
                Poll::Pending => {}
            }
        }
        // B 路: 活着就轮询; 出错/结束置死, 不影响 A。
        if self.b_alive {
            match self.b.as_mut().poll_frame_mut(cx) {
                Poll::Ready(Some(Ok(f))) => {
                    // 重复内容原样透传——下载器按偏移去重。
                    return Poll::Ready(Some(Ok(f)));
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    self.b_alive = false;
                }
                Poll::Pending => {}
            }
        }
        if self.a_done && !self.b_alive {
            return Poll::Ready(None);
        }
        Poll::Pending
    }
}

/// 组装: A = 主流(ECT 最小者已建), B = 陪跑流(第二镜像的响应体)。
/// B 头失败(镜像拒绝/超时)时传 None——纯 A, 行为等同现状。
pub fn racing_body(a: BoxBody, b: Option<BoxBody>) -> RacingBody {
    match b {
        Some(b) => RacingBody {
            a: Box::pin(a),
            b: Box::pin(b),
            b_alive: true,
            a_done: false,
        },
        None => RacingBody {
            a: Box::pin(a),
            b: Box::pin(empty_err_body()),
            b_alive: false,
            a_done: false,
        },
    }
}

#[cfg(test)]
mod racing_tests {
    use super::*;

    fn body_from(chunks: Vec<&'static [u8]>) -> BoxBody {
        let stream = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(c)))),
        );
        BoxBody::new(http_body_util::StreamBody::new(stream))
    }

    async fn collect(b: &mut RacingBody) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(f) = BodyExt::frame(&mut *b).await {
            if let Ok(f) = f {
                if let Some(d) = f.data_ref() {
                    out.extend_from_slice(d);
                }
            }
        }
        out
    }

    /// 双源同内容: 汇总字节量 = 两路之和(下载器按偏移去重, 代理透传不裁剪)。
    #[tokio::test]
    async fn racing_passes_both_streams() {
        let a = body_from(vec![b"AAAA", b"BBBB"]);
        let b = body_from(vec![b"CCCC"]);
        let mut r = racing_body(a, Some(b));
        let got = collect(&mut r).await;
        assert_eq!(got.len(), 12, "两路字节都透传: {got:?}");
    }

    /// B 路中途出错: A 继续到底, 整体不失败。
    #[tokio::test]
    async fn racing_survives_b_error() {
        let a = body_from(vec![b"AAAA"]);
        let err_stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"XX"))),
            Err(std::io::Error::other("b died")),
        ]);
        let b: BoxBody = BoxBody::new(http_body_util::StreamBody::new(err_stream));
        let mut r = racing_body(a, Some(b));
        let got = collect(&mut r).await;
        assert!(
            got.windows(4).any(|w| w == b"AAAA"),
            "A 路数据必须完整: {got:?}"
        );
    }

    /// B 建流失败(None): 退化为纯 A。
    #[tokio::test]
    async fn racing_none_b_is_pure_a() {
        let a = body_from(vec![b"ONLYA"]);
        let mut r = racing_body(a, None);
        let got = collect(&mut r).await;
        assert_eq!(got, b"ONLYA");
    }
}
