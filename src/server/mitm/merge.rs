//! 切片合并：一条请求按镜像数切段并发拉，按边界序泵成单条字节河。
//! 段是**可缩的边界**，不是一条命的连接：慢段把尾巴让给闲下来的镜像，
//! 断了从自己收到的位置续，绝不整段判死。交付线只认相对偏移，与边界同域。

use super::protocol::{self, BoxBody};
use bytes::Bytes;
use hyper::body::{Body as _, Frame};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// 单段缓冲上限：快段先到先存，超过就暂时不读它，等交付线推进再读。
const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 让位/补发的最小片：小到不值一次建连就不切。
pub(super) const MIN_PIECE: u64 = 512 * 1024;
/// 多久没收到字节算死。5s 忍得住 CDN 抖动，又不让死连接白占位置。
pub(super) const STALL_MS: u64 = 5_000;
/// 让位的收益门槛：接管方建连要花的秒数，折算成"值不值得抢"。
pub(super) const SPLIT_SETUP_SECS: f64 = 0.5;
/// 速率至少观察这么久才算样本，首包前的 0 不当慢。
const RATE_WARMUP: Duration = Duration::from_millis(400);
/// 同一段两次让位的最小间隔，防抖。
const CUT_COOLDOWN: Duration = Duration::from_millis(1_500);
/// 连续多少次补发一个字节都没下到就认输（有进展立刻清零）。
pub(super) const MAX_DEAD_FILLS: u32 = 6;
/// 轮询断档超过这么久，回来后重新起算停滞——那是我们自己在忙队首，不是上游死了。
const POLL_GAP: Duration = Duration::from_millis(1_500);
/// 体检间隔：停滞是 5s 判据，500ms 看一眼足够。
const TICK_MS: u64 = 500;

/// 平均切 [base, base+len) 为 n 段：相邻共享边界，零重叠零缝，余数归最后一段。
/// n 超过字节数时收缩到字节数，保证每段至少 1 字节。
pub(super) fn split_even(base: u64, len: u64, n: usize) -> Vec<(u64, u64)> {
    if len == 0 {
        return Vec::new();
    }
    let n = (n.max(1) as u64).min(len);
    let per = len / n;
    let mut out = Vec::with_capacity(n as usize);
    let mut s = base;
    for i in 0..n {
        let e = if i + 1 == n { base + len } else { s + per };
        out.push((s, e));
        s = e;
    }
    out
}

/// 客户端 Range 的 (起点, 终点含)。无 Range、多区间、畸形 → None。
pub(super) fn parse_range(range: Option<&str>) -> Option<(u64, Option<u64>)> {
    let spec = range?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // 多区间响应是 multipart/byteranges，切不了
    }
    let (a, b) = spec.trim().split_once('-')?;
    let a: u64 = a.trim().parse().ok()?;
    let b = match b.trim() {
        "" => None,
        s => Some(s.parse::<u64>().ok()?),
    };
    Some((a, b))
}

/// 单字节探片（bytes=N-N）：下载器先探文件大小，走链头直通，不切分也不记分。
pub(super) fn is_probe_range(range: Option<&str>) -> bool {
    matches!(parse_range(range), Some((a, Some(b))) if a == b)
}

/// 从 `Content-Range: bytes 0-0/2097152000` 取文件总长；`*` 或缺失/畸形 → None。
pub(super) fn content_range_total(v: Option<&str>) -> Option<u64> {
    let t = v?.trim().rsplit('/').next()?.trim();
    if t == "*" {
        return None;
    }
    t.parse().ok()
}

/// 让位时持有者该留多少：按两者速率反比切，使双方同时完成（DEMS），
/// 并把帮手的建连耗时折进分母——`helper × setup` 是它在建连期间白下的字节。
/// 结果钳在 [MIN_PIECE, remaining − MIN_PIECE]，保证两边都不是碎渣。
pub(super) fn split_keep(remaining: u64, holder: f64, helper: f64) -> u64 {
    if remaining < 2 * MIN_PIECE {
        return remaining / 2;
    }
    let keep = if holder > 0.0 && helper > 0.0 && holder.is_finite() && helper.is_finite() {
        holder * (SPLIT_SETUP_SECS * helper + remaining as f64) / (holder + helper)
    } else {
        remaining as f64 / 2.0
    };
    (keep as u64).clamp(MIN_PIECE, remaining - MIN_PIECE)
}

/// 一段：自己的响应体 + 自己的缓冲 + 自己的实测。边界可以被外面改小。
struct Seg {
    /// 段起点（相对区间）。
    start: u64,
    /// 段终点（相对区间），可被让位改小。
    end: u64,
    body: BoxBody,
    /// 先到先存的数据，按到达顺序排。
    buf: VecDeque<Bytes>,
    buffered: usize,
    /// 已收到的字节数（含缓冲里还没交付的）。
    got: u64,
    /// 起跑时刻（响应头到达），算速率用。
    begin: Instant,
    /// 最近一次被轮询的时刻。
    last_poll: Instant,
    /// 开始"推了没数据"的时刻；None = 有数据或没在看。
    stalled_since: Option<Instant>,
    /// 上次被让位的时刻，冷却用。
    last_cut: Option<Instant>,
    /// 上游已结束（正常收尾、出错、或被停滞收割）。
    done: bool,
    /// 结束原因（仅 done 时有意义）。
    err: Option<std::io::Error>,
}

impl Seg {
    fn new(start: u64, end: u64, at: Instant, body: BoxBody) -> Self {
        Seg {
            start,
            end,
            body,
            buf: VecDeque::new(),
            buffered: 0,
            got: 0,
            begin: at,
            last_poll: at,
            stalled_since: None,
            last_cut: None,
            done: false,
            err: None,
        }
    }

    /// 已收到的位置（= 已交付 + 缓冲）。
    fn pos(&self) -> u64 {
        self.start + self.got
    }

    /// 起跑至今的均速。样本不足时按 0 处理，不当成慢。
    fn rate(&self, now: Instant) -> f64 {
        let el = now.saturating_duration_since(self.begin);
        if el < RATE_WARMUP {
            return 0.0;
        }
        self.got as f64 / el.as_secs_f64().max(0.001)
    }
}

pub(super) struct MergeBody {
    /// 按段起点排序，交付线在其中穿行。
    segs: BTreeMap<u64, Seg>,
    /// 已交付字节（相对区间起点）。
    sent: u64,
    /// 本区间总长。
    total: u64,
    /// 待发请求的区间：缺口、被让位的尾巴。
    fill: VecDeque<(u64, u64)>,
    /// 干净收尾的段数 = 闲下来的连接数，让位得有活才干。
    idle_credit: u32,
    /// 连续"补发一个字节都没下到"的次数，有进展清零。
    dead_fills: u32,
    /// 上次体检时刻。
    last_tick: Instant,
    finished: bool,
}

impl MergeBody {
    /// segs: (start, end, 起跑时刻, 响应体)，必须连续覆盖 [0, total)。
    pub(super) fn new(segs: Vec<(u64, u64, Instant, BoxBody)>, total: u64) -> Self {
        MergeBody {
            segs: segs
                .into_iter()
                .map(|(s, e, at, b)| (s, Seg::new(s, e, at, b)))
                .collect(),
            sent: 0,
            total,
            fill: VecDeque::new(),
            idle_credit: 0,
            dead_fills: 0,
            last_tick: Instant::now(),
            finished: false,
        }
    }

    pub(super) fn sent(&self) -> u64 {
        self.sent
    }

    pub(super) fn total(&self) -> u64 {
        self.total
    }

    /// 连续补发都空手而归：再试只是烧时间。
    pub(super) fn exhausted(&self) -> bool {
        self.dead_fills >= MAX_DEAD_FILLS
    }

    /// 到体检点了吗。数据一直在流也要跑——涓流不触发超时，却一样拖死整条河。
    pub(super) fn tick_due(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_tick) < Duration::from_millis(TICK_MS) {
            return false;
        }
        self.last_tick = now;
        true
    }

    /// 取一个待发区间（缺口 / 让位尾巴）。
    pub(super) fn take_fill(&mut self) -> Option<(u64, u64)> {
        self.fill.pop_front()
    }

    /// 补发请求失败：记一次空手，下次换家再来。
    pub(super) fn fail_fill(&mut self) {
        self.dead_fills += 1;
    }

    /// 起流失败后把这段塞回队尾重试——不塞回去就再也没人管这个洞了。
    pub(super) fn retry_fill(&mut self, from: u64, to: u64) {
        self.fail_fill();
        self.queue_fill(from, to);
    }

    /// 接管一条流：把 [start, end) 交给它。
    pub(super) fn feed(&mut self, start: u64, end: u64, at: Instant, body: BoxBody) {
        self.segs.insert(start, Seg::new(start, end, at, body));
    }

    fn queue_fill(&mut self, from: u64, to: u64) {
        if to <= from || self.fill.iter().any(|&(f, t)| f == from && t == to) {
            return;
        }
        self.fill.push_back((from, to));
    }

    /// 把还在跑的段各推一轮，填进各自缓冲。返回是否有进展（拿到数据或某段结束）。
    /// 缓冲满的段暂时不推——它的 waker 也就不再注册；等交付线推进后自然会再推它。
    fn fill_all(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        let now = Instant::now();
        let mut progressed = false;
        let mut freed = 0u32;
        for seg in self.segs.values_mut() {
            if seg.done || seg.buffered >= SEG_BUFFER_MAX {
                continue;
            }
            // 轮询断档（我们在忙队首）：这段没被看着的时间不算停滞。
            if now.saturating_duration_since(seg.last_poll) > POLL_GAP {
                seg.stalled_since = Some(now);
            }
            seg.last_poll = now;
            match std::pin::Pin::new(&mut seg.body).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(f))) => {
                    progressed = true;
                    // 非数据帧（trailer 等）直接丢，只关心正文。
                    if let Ok(d) = f.into_data() {
                        let n = d.len() as u64;
                        seg.buffered += d.len();
                        seg.got += n;
                        seg.buf.push_back(d);
                        seg.stalled_since = None;
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    progressed = true;
                    seg.done = true;
                    seg.err = Some(e);
                }
                std::task::Poll::Ready(None) => {
                    progressed = true;
                    seg.done = true;
                    freed += 1; // 连接空出来了，可以接活
                }
                std::task::Poll::Pending => {
                    seg.stalled_since.get_or_insert(now);
                }
            }
        }
        self.idle_credit += freed;
        progressed
    }

    /// 收尸：真停滞的段，把已收到的留下、没收到的那截排进补发。
    /// 这是"缩边界"，不是"整段重下"——缓冲里的字节一个都不丢。
    pub(super) fn reap_stalled(&mut self, now: Instant) -> bool {
        let mut any = false;
        for seg in self.segs.values_mut() {
            if seg.done {
                continue;
            }
            let Some(since) = seg.stalled_since else {
                continue;
            };
            if now.saturating_duration_since(since) < Duration::from_millis(STALL_MS) {
                continue;
            }
            let pos = seg.pos();
            if pos >= seg.end {
                continue; // 收齐了，只等它自己 EOF
            }
            let old_end = seg.end;
            seg.end = pos;
            seg.body = protocol::empty_body();
            seg.done = true;
            seg.err = Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "段停滞，尾巴转补发",
            ));
            if self.fill.iter().all(|&(f, t)| f != pos || t != old_end) {
                self.fill.push_back((pos, old_end));
            }
            any = true;
        }
        any
    }

    /// 让位：把预计最晚完成的段切掉尾巴，交给闲下来的连接。
    /// 判据是「抢过来能提前多少」——剩余 ÷ 我的速度 对 剩余 ÷ 最快速度 + 建连。
    /// 返回被切出去的区间。
    pub(super) fn plan_cut(&mut self, now: Instant) -> Option<(u64, u64)> {
        if self.idle_credit == 0 || !self.fill.is_empty() {
            return None;
        }
        let mut best_rate: f64 = 0.0;
        let mut best_etc = f64::INFINITY;
        for s in self.segs.values() {
            // 没在看着的（我们在忙队首）和缓冲顶格的（我们自己不读）不算慢。
            if now.saturating_duration_since(s.last_poll) > POLL_GAP
                || s.buffered >= SEG_BUFFER_MAX
            {
                continue;
            }
            let r = s.rate(now);
            if r <= 0.0 {
                continue;
            }
            best_rate = best_rate.max(r);
            let pos = s.pos();
            if s.done || pos >= s.end {
                continue;
            }
            best_etc = best_etc.min((s.end - pos) as f64 / r);
        }
        if best_rate <= 0.0 || !best_etc.is_finite() {
            return None;
        }
        // 受害者：预计完成时间最大的那段。
        let mut victim: Option<(u64, u64, u64, f64)> = None;
        for s in self.segs.values() {
            if s.done || s.last_cut.is_some_and(|t| now - t < CUT_COOLDOWN) {
                continue;
            }
            if now.saturating_duration_since(s.last_poll) > POLL_GAP
                || s.buffered >= SEG_BUFFER_MAX
            {
                continue;
            }
            let pos = s.pos();
            if pos >= s.end {
                continue;
            }
            let remaining = s.end - pos;
            if remaining < 2 * MIN_PIECE {
                continue; // 已经碎到不值一次建连
            }
            let r = s.rate(now);
            if r <= 0.0 {
                continue;
            }
            let etc = remaining as f64 / r;
            if etc <= best_etc + SPLIT_SETUP_SECS {
                continue; // 抢过来也快不了多少
            }
            if victim.is_none_or(|(_, _, _, v)| etc > v) {
                victim = Some((s.start, pos, remaining, etc));
            }
        }
        let (start, pos, remaining, _) = victim?;
        let holder = self.segs.get(&start).map_or(best_rate, |s| s.rate(now));
        let cut = pos + split_keep(remaining, holder, best_rate);
        self.cut(start, cut, now)
    }

    /// 把某段的边界缩到 cut，尾巴排进补发。父流不必断，交到新边界自然放手。
    fn cut(&mut self, start: u64, cut: u64, now: Instant) -> Option<(u64, u64)> {
        let seg = self.segs.get_mut(&start)?;
        let old_end = seg.end;
        if cut <= seg.pos() || cut >= old_end {
            return None;
        }
        seg.end = cut;
        seg.last_cut = Some(now);
        self.idle_credit = self.idle_credit.saturating_sub(1);
        self.fill.push_back((cut, old_end));
        Some((cut, old_end))
    }
}

impl hyper::body::Body for MergeBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = self.get_mut();
        loop {
            if me.finished {
                return std::task::Poll::Ready(None);
            }
            let sent = me.sent;
            if sent >= me.total {
                me.finished = true;
                return std::task::Poll::Ready(None);
            }
            // 交付线所在的段：起点不晚于 sent、终点晚于 sent 的那个。
            let key = me
                .segs
                .range(..=sent)
                .next_back()
                .map(|(&k, _)| k)
                .filter(|k| me.segs.get(k).is_some_and(|s| sent < s.end));
            let Some(k) = key else {
                // 洞还没补上（补发在路上），定时器会来叫醒。
                return std::task::Poll::Pending;
            };
            // 缩边界后父流还在跑：交到新边界就放手，连接不必再读。
            if sent >= me.segs[&k].end {
                me.segs.remove(&k);
                continue;
            }
            let mut emit: Option<Bytes> = None;
            let mut hole: Option<u64> = None;
            {
                let seg = me.segs.get_mut(&k).expect("已判存在");
                if let Some(chunk) = seg.buf.pop_front() {
                    seg.buffered -= chunk.len();
                    let room = (seg.end - sent) as usize;
                    if room >= chunk.len() {
                        emit = Some(chunk);
                    } else if room > 0 {
                        // 越过边界的部分归接手的那条流，这里丢掉。
                        emit = Some(chunk.slice(..room));
                    } else {
                        continue; // 整块在边界外
                    }
                } else if seg.done {
                    hole = Some(seg.end);
                }
            }
            if let Some(chunk) = emit {
                if !chunk.is_empty() {
                    me.sent += chunk.len() as u64;
                    me.dead_fills = 0; // 有字节流动，补发不算白跑
                    return std::task::Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                continue;
            }
            if let Some(end) = hole {
                if sent < end {
                    // 这段没交完就断了：缩到交付线，剩下的排补发，本轮到此为止。
                    if me.segs[&k].got == 0 {
                        me.dead_fills += 1; // 一个字节都没给，算空手
                    }
                    me.segs.remove(&k);
                    me.queue_fill(sent, end);
                    return std::task::Poll::Ready(None);
                }
                me.segs.remove(&k);
                continue;
            }
            // 队首还没货：把其余段各推一轮（它们的数据先进各自缓冲），
            // 只要有进展就回头再看队首；全体没动静才是真的 Pending。
            if me.fill_all(cx) {
                continue;
            }
            return std::task::Poll::Pending;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server/mitm/merge.rs"]
mod tests;
