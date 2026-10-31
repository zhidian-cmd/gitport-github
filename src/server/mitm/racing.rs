//! 接力切换 body: 慢腿(A)在流, 快腿(B)同 Range 再拉一路(镜像请求无法从
//! A 的中途偏移续传, 重复段由丢帧吸收); B 的拉取进度(绝对偏移)追上 A 的
//! 交付进度时切换——掐 A、B 接管, 下载器只见到一条连续无重复的字节河。
//!
//! 字节守恒: A 前段(0..switch_point) + B 后段(switch_point..), 切换点两侧
//! 共享同一偏移基准, 无缝。代理不攒整片: 切换前只透传 A, 之后只透传 B;
//! B 在内部拉取只是推进进度计数(重复段整帧丢弃)。
//!
//! 接管帧必须剃除与 A 已交付段重叠的头部, 从交付线(a_sent)精确续流:
//! 下载器按连接流序写盘(第 n 字节 → Range 起点+n), 不读数据内的绝对偏移;
//! 整帧透传的重复头会把该连接后续字节整体后移, 越过线程 Range 边界 →
//! IDM 判「数据冲突」回退单线程。Bytes::advance 零拷贝剃除, 「帧粒度
//! 近似、下载器覆盖写盘容忍」的假设不成立。
//!
//! 接管判据固定为「首帧越线即接管」(b_abs ≥ a_sent), 不可加领先量门槛
//! (如「B 领先 1MB 才接管」): 零缓冲下, 终点落在交付线之上却不切换的 B 帧
//! 只能丢弃, 而切换帧的起点随之上移到高于交付线 → 字节河出现永久空洞,
//! 下载器流错位、文件损坏。字节守恒强制此判据; 防慢腿误接管的正确位置
//! 是 ECT 派发决策(选谁陪跑), 不在切换条件里。
use bytes::Buf;

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

    /// 泵 B: 拉帧、推进 b_abs。整帧终点不高于交付线 → 纯重复, 丢弃续泵;
    /// 越线帧 → 剃除与 A 已交付段重叠的头部后切换透传(见模块文档: 下载器
    /// 按流序写盘, 重复头会整体移位)。loop 而非递归, 防大量小帧爆栈。
    fn pump_b(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        loop {
            match hyper::body::Body::poll_frame(self.b.as_mut(), cx) {
                Poll::Ready(Some(Ok(mut f))) => {
                    let start = self.b_abs;
                    let len = f.data_ref().map(|d| d.len() as u64).unwrap_or(0);
                    self.b_abs = start + len;
                    if self.b_abs > self.a_sent {
                        // 越线: 交付线之前的头部是与 A 重复的字节, 剃除。
                        // 不变量 start ≤ a_sent → overlap < len, 剃后帧非空。
                        let overlap = (self.a_sent - start) as usize;
                        if overlap > 0 {
                            if let Some(d) = f.data_mut() {
                                d.advance(overlap);
                            }
                        }
                        self.switched = true;
                        self.a_alive = false; // 掐 A(guard Drop 收尾)
                        return Poll::Ready(Some(Ok(f)));
                    }
                    // 整帧在交付线下: 丢弃, 续泵。
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    // B 中断: 放弃接力, A 独走到底。
                    self.b_alive = false;
                    return Poll::Pending;
                }
                Poll::Pending => return Poll::Pending,
            }
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

    /// B 首帧起点恰在交付线上(重叠为零)→ 整帧透传。构造时 A 已透传
    /// delivered_at_spawn 字节(已流到下载器, 不在本 body 内); A body 是
    /// "从 delivered 起"的剩余帧, B 同起点拉。首泵 B 即越线接管, A 被掐。
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
    /// 首轮 poll 返回 Pending(模拟 B 的 TTFB 晚于 A 交付), 之后透传 inner。
    struct LazyBody {
        inner: BoxBody,
        primed: bool,
    }

    impl hyper::body::Body for LazyBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let me = self.get_mut();
            if !me.primed {
                me.primed = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut me.inner).poll_frame(cx)
        }
    }

    /// 接管帧剃除重复头(移位回归)。下载器按连接流序写盘: 整帧透传跨线帧时,
    /// 重复头会把该连接后续字节整体后移 → 越过线程 Range → IDM 判数据冲突。
    /// 全流必须精确等于 Range 原文, 无重复无移位。
    #[tokio::test]
    async fn relay_trims_overlap_at_switch() {
        // A: 12B 三帧; B: 同区间一帧 12B, 但首帧晚到——先让 A 交付 4B
        // (a_sent=4), B 的跨线帧 [0..12) 剃掉前 4B 后接管。
        let a = body_from(vec![Ok(b"AAAA"), Ok(b"BBBB"), Ok(b"CCCC")]);
        let b = to_box(LazyBody {
            inner: body_from(vec![Ok(b"AAAABBBBCCCC")]),
            primed: false,
        });
        let mut r = RelayBody::new(a, Some(b), 0);
        let got = collect(&mut r).await;
        assert_eq!(got, b"AAAABBBBCCCC", "全流必须精确无重复无移位: {:?}", got);
    }
}
