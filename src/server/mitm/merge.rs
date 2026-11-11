//! 切片合并：按镜像数切段并发拉，按边界泵成单条流；段是可缩的边界而非固定连接——慢段让尾、断点续拉，不整段判死。
//! 交付线只认相对偏移，与边界同域。

use super::protocol::{self, BoxBody};
use bytes::Bytes;
use hyper::body::{Body as _, Frame};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// 单段缓冲上限：快段先到先存，超过就暂时不读它，等交付线推进再读。
pub(super) const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 让位/补发的最小片：小到不值一次建连就不切。
pub(super) const MIN_PIECE: u64 = 512 * 1024;
/// 多久没收到字节算死。5s 忍得住 CDN 抖动，又不让死连接白占位置。
pub(super) const STALL_MS: u64 = 5_000;
/// 让位的收益门槛：接管方建连要花的秒数，折算成"值不值得抢"。
pub(super) const SPLIT_SETUP_SECS: f64 = 0.5;
/// 速率至少观察这么久才算样本，首包前的 0 不当慢。
const RATE_WARMUP: Duration = Duration::from_millis(400);
/// 同段两次让位最小间隔 1.5s，防抖。
const CUT_COOLDOWN: Duration = Duration::from_millis(1_500);
/// 两次让位之间的全局间隔：多段同时"偏慢"时轮着切就是抖动。
const CUT_ANY_COOLDOWN: Duration = Duration::from_millis(2_500);
/// 刀口上限 ≈ 帮手 3 秒的吞吐，钳在 [MIN_PIECE, 64MB]；上限定死会让快源被慢段尾巴拖住。
fn handoff_cap(best_rate: f64) -> u64 {
    ((best_rate * 3.0) as u64).clamp(MIN_PIECE, 64 * 1024 * 1024)
}
/// 帮手爬坡：新流慢启动到稳态要跨几个 RTT（跨境单程 0.2~0.4s），按 1s 空转折算；让位判据的建模参数，非测量值（测量只来自真实流）。
const HELPER_RAMP_SECS: f64 = 1.0;
/// 让位判据看近期速率：样本窗与 POLL_GAP 对齐（没在看的不算），历史慢启动/停顿不拖累当下判断。
const RECENT_WIN: Duration = Duration::from_millis(1_500);
/// 连续多少次补发一个字节都没下到就认输（有进展立刻清零）。
pub(super) const MAX_DEAD_FILLS: u32 = 6;
/// 轮询断档超过这么久，回来后重新起算停滞——那是我们自己在忙队首，不是上游死了。
const POLL_GAP: Duration = Duration::from_millis(1_500);
/// 体检间隔：停滞是 5s 判据，500ms 看一眼足够。
const TICK_MS: u64 = 500;

/// 平均切 [base, base+len) 为 n 段：相邻共享边界，零重叠零缝，余数归最后一段；n 超字节数时收缩到字节数，每段至少 1 字节。
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

/// 取 `bytes 262144-524287/1608296` 里的区间部分。标准头用空格，也容忍 "bytes=" 写法。
fn range_span(v: Option<&str>) -> Option<&str> {
    let s = v?.trim();
    s.strip_prefix("bytes ")
        .or_else(|| s.strip_prefix("bytes="))?
        .split('/')
        .next()
}

/// 本段起点。206 的起点必须等于请求段的起点，否则字节会错位拼进合并流。
pub(super) fn content_range_start(v: Option<&str>) -> Option<u64> {
    range_span(v)?.split('-').next()?.trim().parse().ok()
}

/// 本段闭区间终点。用于确认 206 没有越过请求的段边界。
pub(super) fn content_range_end(v: Option<&str>) -> Option<u64> {
    range_span(v)?.split_once('-')?.1.trim().parse().ok()
}

/// 206 起点校验（直连切片与镜像竞速共用一条规则）：起点必须等于本段请求起点，
/// 否则字节会错位拼进合并流——宁可当段失败走补发。
pub(super) fn check_segment_start(v: Option<&str>, start: u64) -> Result<(), String> {
    match content_range_start(v) {
        Some(got) if got == start => Ok(()),
        Some(got) => Err(format!("206 起点不符: 要 {start}, 拿到 {got}")),
        None => Err("206 缺 Content-Range".to_string()),
    }
}

/// 让位时持有者留多少：按双方速率反比切（DEMS），帮手的建连+爬坡折进分母；结果钳在 [MIN_PIECE, remaining−MIN_PIECE]。
pub(super) fn split_keep(remaining: u64, holder: f64, helper: f64, setup_secs: f64) -> u64 {
    if remaining < 2 * MIN_PIECE {
        return remaining / 2;
    }
    let keep = if holder > 0.0 && helper > 0.0 && holder.is_finite() && helper.is_finite() {
        holder * (setup_secs * helper + remaining as f64) / (holder + helper)
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
    /// 收尾时冻结的均速：断了之后 begin 还在走，现算会一路衰减成假慢。
    frozen_rate: Option<f64>,
    /// 近期速率样本 (时刻, 已收字节)：让位判据用滑窗，全片均速会被慢启动拖累。
    recent: VecDeque<(Instant, u64)>,
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
            frozen_rate: None,
            recent: VecDeque::new(),
        }
    }

    /// 已收到的位置（= 已交付 + 缓冲）。
    fn pos(&self) -> u64 {
        self.start + self.got
    }

    /// 收尾时把均速定格（begin 还在走，现算只会越来越"慢"）：优先取近期速率（最后 1.5s 实测），样本不足退回全片均速。
    fn freeze(&mut self, now: Instant) {
        if self.frozen_rate.is_none() {
            let r = self.recent_rate(now);
            self.frozen_rate = Some(if r > 0.0 { r } else { self.rate(now) });
        }
    }

    /// 起跑至今的均速。样本不足时按 0 处理，不当成慢；收尾后返回冻结值。
    fn rate(&self, now: Instant) -> f64 {
        if let Some(r) = self.frozen_rate {
            return r;
        }
        let el = now.saturating_duration_since(self.begin);
        if el < RATE_WARMUP {
            return 0.0;
        }
        self.got as f64 / el.as_secs_f64().max(0.001)
    }

    /// 近期速率（最后 RECENT_WIN 的实测）：让位判据用它，慢启动与历史停顿不进分母；样本不足 RATE_WARMUP 时退回全片均速——短段没有近期可言。
    fn recent_rate(&self, now: Instant) -> f64 {
        if let Some(r) = self.frozen_rate {
            return r;
        }
        let Some((t0, b0)) = self.recent.front() else {
            return self.rate(now);
        };
        let el = now.saturating_duration_since(*t0);
        if el < RATE_WARMUP {
            return self.rate(now);
        }
        let bytes = self.got.saturating_sub(*b0);
        bytes as f64 / el.as_secs_f64().max(0.001)
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
    /// 上次让位时刻（全局，不按段），用来给让位整体限速。
    last_cut_any: Option<Instant>,
    finished: bool,
    /// 生命周期钩子：随 body 一起丢弃（切片计划里登记的在途区间靠它注销）。
    _guard: Option<Box<dyn Send + Sync>>,
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
            last_cut_any: None,
            finished: false,
            _guard: None,
        }
    }

    /// 挂一个生命周期钩子：body 被丢弃时一起释放（用于注销在途区间登记）。
    pub(super) fn hold(mut self, g: Box<dyn Send + Sync>) -> Self {
        self._guard = Some(g);
        self
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

    /// 起流失败后把这段塞回队尾重试——不塞回去就再也没人管这个洞了。
    /// 补发失败 = 记一次空手（dead_fills），下次换家再来。
    pub(super) fn retry_fill(&mut self, from: u64, to: u64) {
        self.dead_fills += 1;
        self.queue_fill(from, to);
    }

    /// 接管一条流：把 [start, end) 交给它。
    pub(super) fn feed(&mut self, start: u64, end: u64, at: Instant, body: BoxBody) {
        self.segs.insert(start, Seg::new(start, end, at, body));
    }

    pub(super) fn queue_fill(&mut self, from: u64, to: u64) {
        if to <= from || self.fill.iter().any(|&(f, t)| f == from && t == to) {
            return;
        }
        self.fill.push_back((from, to));
    }

    /// 把还在跑的段各推一轮填进各自缓冲，返回是否有进展（拿到数据或某段结束）；缓冲满的段暂不推——waker 不再注册，等交付线推进后自然会再推它。
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
            // 记近期速率样本点：判让位用滑窗，全片均速的历史包袱不进判据。
            seg.recent.push_back((now, seg.got));
            while seg.recent.len() > 64
                || seg
                    .recent
                    .front()
                    .is_some_and(|(t, _)| now.saturating_duration_since(*t) > RECENT_WIN)
            {
                seg.recent.pop_front();
            }
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
                    seg.freeze(now);
                    seg.done = true;
                    seg.err = Some(e);
                }
                std::task::Poll::Ready(None) => {
                    progressed = true;
                    seg.freeze(now); // 定格这家的实测速度，供别人当"最快"基准
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

    /// 收尸真停滞的段：已收到的留下、没收到的那截排进补发——是"缩边界"不是"整段重下"，缓冲里的字节一个都不丢。
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
            seg.freeze(now);
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

    /// 让位：切掉最晚完成段的尾巴交给最快的镜像；判据是「抢过来能提前多少」，新建连与爬坡都折进成本。
    pub(super) fn plan_cut(&mut self, now: Instant) -> Option<(u64, u64)> {
        if !self.fill.is_empty() {
            return None;
        }
        // 全局节流：两次让位之间留足间隔，别让几段轮着抖。
        if self
            .last_cut_any
            .is_some_and(|t| now.saturating_duration_since(t) < CUT_ANY_COOLDOWN)
        {
            return None;
        }
        // 有闲连接就复用、不花建连；新流都要爬坡几个 RTT，折进 setup。
        let setup = if self.idle_credit > 0 {
            0.0
        } else {
            SPLIT_SETUP_SECS
        } + HELPER_RAMP_SECS;
        // 基准取「链内最快实测」：已收尾的段用冻结值，仍在跑的用近期速率。
        let mut best_rate: f64 = 0.0;
        for s in self.segs.values() {
            // 没在看着的（我们在忙队首）和缓冲顶格的（我们自己不读）不算慢；已收尾的段没有轮询了，冻结值就是最可信的证据。
            let watched = now.saturating_duration_since(s.last_poll) <= POLL_GAP
                && s.buffered < SEG_BUFFER_MAX;
            if s.done || watched {
                best_rate = best_rate.max(s.recent_rate(now));
            }
        }
        if best_rate <= 0.0 {
            return None;
        }
        // 受害者：预计完成时间最大的那段。
        let mut victim: Option<(u64, u64, u64, f64)> = None;
        for s in self.segs.values() {
            if s.done || s.last_cut.is_some_and(|t| now - t < CUT_COOLDOWN) {
                continue;
            }
            if now.saturating_duration_since(s.last_poll) > POLL_GAP || s.buffered >= SEG_BUFFER_MAX
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
            let r = s.recent_rate(now);
            if r <= 0.0 {
                continue;
            }
            let etc = remaining as f64 / r;
            // 比最快那家慢就算慢；只有抢过去反而更久才不动——算术，不是门槛。
            let steal = remaining as f64 / best_rate + setup;
            if etc <= steal {
                continue;
            }
            if victim.is_none_or(|(_, _, _, v)| etc > v) {
                victim = Some((s.start, pos, remaining, etc));
            }
        }
        let (start, pos, remaining, _) = victim?;
        let holder = self
            .segs
            .get(&start)
            .map_or(best_rate, |s| s.recent_rate(now));
        // 切口按两家速度比例分；刀口再按帮手实测速率封顶，防止新流起步慢被反复判慢、来回抖。
        let keep = split_keep(remaining, holder, best_rate, setup)
            .max(remaining.saturating_sub(handoff_cap(best_rate)));
        let out = self.cut(start, pos + keep, now);
        if out.is_some() {
            self.last_cut_any = Some(now);
        }
        out
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
            // 队首还没货：把其余段各推一轮（数据先进各自缓冲），有进展就回头再看队首；全体没动静才是真的 Pending。
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
