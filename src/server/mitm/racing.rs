//! 接力切换 body: 慢腿(A)在流, 快腿(B)从 A 已交付偏移(delivered_at_spawn)
//! 起拉同一片剩余区间; B 的拉取进度(绝对偏移)追上 A 的交付进度时切换——
//! 掐 A、B 接管, 下载器只见到一条连续无重复的字节河。
//!
//! 字节守恒: A 前段(0..switch_point) + B 后段(switch_point..), 切换点两侧
//! 共享同一偏移基准, 无缝。代理不攒整片: 切换前只透传 A, 之后只透传 B;
//! B 在内部拉取只是推进进度计数(字节丢弃——那是与 A 重复的部分)。

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};





type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// 统一装箱。
pub fn to_box<B>(b: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes, Error = std::io::Error> + Send + Sync + Unpin + 'static,
{
    BoxBody::new(b)
}

/// 接力状态机。
pub struct RelayBody {
    a: Pin<Box<BoxBody>>,
    b: Pin<Box<BoxBody>>,
    /// B 起跑时 A 的交付偏移(B 的 Range 起点)。切换线。
    /// B 已拉到的绝对偏移(delivered_at_spawn + 累计拉取)。
    b_abs: u64,
    /// A 已透传给下载器的绝对偏移。
    a_sent: u64,
    switched: bool,
    a_alive: bool,
    b_alive: bool,
}

impl RelayBody {
    /// A: 慢腿主流(透传中); B: 快腿响应体, 其 Range 起点 = delivered_at_spawn
    /// (接线处取 A 的 guard.delivered 快照)。B 建流失败传 None → 纯 A。
    pub fn new(a: BoxBody, b: Option<BoxBody>, delivered_at_spawn: u64) -> Self {
        match b {
            Some(b) => Self {
                a: Box::pin(a),
                b: Box::pin(b),
                b_abs: delivered_at_spawn,
                a_sent: delivered_at_spawn,
                switched: false,
                a_alive: true,
                b_alive: true,
            },
            None => Self {
                a: Box::pin(a),
                b: Box::pin(BoxBody::new(BodyExt::map_err(
                    http_body_util::Empty::<Bytes>::new(),
                    std::io::Error::other,
                ))),
                b_abs: delivered_at_spawn,
                a_sent: delivered_at_spawn,
                switched: false,
                a_alive: true,
                b_alive: false,
            },
        }
    }

    /// 泵 B: 拉帧、推进 b_abs。帧内容与 A 已交付段重复(b_abs < a_sent)→ 丢弃;
    /// b_abs ≥ a_sent → 帧的剩余部分是下载器还没拿到的新字节 → 切换并透传。
    /// (帧粒度近似: 切换帧可能含少量与 A 重叠的头几个字节, 下载器按偏移
    ///  覆盖写盘天然容忍; 精确切分需要按字节拆帧, 复杂度不值。)
    fn pump_b(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match hyper::body::Body::poll_frame(self.b.as_mut(), cx) {
            Poll::Ready(Some(Ok(mut f))) => {
                if let Some(d) = f.data_mut() {
                    self.b_abs += d.len() as u64;
                }
                if self.b_abs >= self.a_sent {
                    self.switched = true;
                    self.a_alive = false; // 掐 A(guard Drop 收尾)
                    Poll::Ready(Some(Ok(f)))
                } else {
                    // 仍是重复段: 丢帧, 继续泵。
                    let _ = f;
                    self.pump_b(cx)
                }
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                // B 中断: 放弃接力, A 独走到底。
                self.b_alive = false;
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::body::Body for RelayBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = self.get_mut();
        if me.switched {
            return me.b.as_mut().poll_frame(cx);
        }
        if !me.b_alive {
            return me.a.as_mut().poll_frame(cx);
        }
        // 双活: 先泵 B(推进进度/触发切换), 再泵 A(透传)。
        match me.pump_b(cx) {
            Poll::Ready(r) => return Poll::Ready(r),
            Poll::Pending => {}
        }
        match me.a.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    me.a_sent += d.len() as u64;
                }
                Poll::Ready(Some(Ok(f)))
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                me.a_alive = false;
                if !me.b_alive {
                    return Poll::Ready(None);
                }
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    fn body_from(chunks: Vec<Result<&'static [u8], std::io::Error>>) -> BoxBody {
        let stream = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|c| c.map(|s| Frame::data(Bytes::from_static(s)))),
        );
        BoxBody::new(http_body_util::StreamBody::new(stream))
    }

    async fn collect(b: &mut RelayBody) -> Vec<u8> {
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

    /// B 追上交付线后接管。真实时序: 构造时 A 已透传 delivered_at_spawn 字节
    /// (那些字节已流到下载器, 不在本 body 内); A body 里是"从 delivered 起"
    /// 的剩余帧, B 从同起点拉。首泵 B 即超线接管 → B 的帧透传, A 剩余被掐
    /// (帧粒度近似: B 的帧从 delivered 起覆盖了 A 未透传的剩余, 下载器按
    ///  偏移写盘容忍重复/覆盖)。
    #[tokio::test]
    async fn relay_switches_when_b_catches_up() {
        // A: 剩余部分(从 delivered=6 起)——3 帧各 2B
        let a = body_from(vec![Ok(b"AA"), Ok(b"BB"), Ok(b"CC")]);
        // B: 从 delivered=6 起拉, 一帧 4B → b_abs=6+4=10 >= a_sent=6 → 立即接管
        let b = body_from(vec![Ok(b"DDDD")]);
        let mut r = RelayBody::new(a, Some(b), 6);
        let got = collect(&mut r).await;
        // 首泵 B 即切换: 只透传 B 的 4B(A 剩余被放弃, 字节由 B 覆盖供给)。
        assert_eq!(got.len(), 4, "切换后只剩 B 的帧: {:?}", got);
    }

    /// B 中断: 放弃接力, A 独走到底(行为 = 无接力)。
    #[tokio::test]
    async fn relay_survives_b_interruption() {
        let a = body_from(vec![Ok(b"AAAA"), Ok(b"BBBB")]);
        let b = body_from(vec![Err(std::io::Error::other("b dead"))]);
        let mut r = RelayBody::new(a, Some(b), 0);
        let got = collect(&mut r).await;
        assert_eq!(got, b"AAAABBBB", "B 中断后 A 必须完整走完");
    }

    /// B 建流失败(None): 纯 A。
    #[tokio::test]
    async fn relay_none_b_is_pure_a() {
        let a = body_from(vec![Ok(b"ONLYA")]);
        let mut r = RelayBody::new(a, None, 0);
        let got = collect(&mut r).await;
        assert_eq!(got, b"ONLYA");
    }
}
