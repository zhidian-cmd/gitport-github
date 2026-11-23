//! 切片合并：按段位并发拉、按边界泵成单流；段是可缩边界而非固定连接——慢段让尾、断点续拉，不整段判死；交付线只认相对偏移。

use super::protocol::{self, BoxBody};
use bytes::Bytes;
use hyper::body::{Body as _, Frame};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// 单段缓冲上限：快段先到先存，超过就暂时不读它，等交付线推进再读。
pub(super) const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 多久没收到字节算死。5s 忍得住 CDN 抖动，又不让死连接白占位置。
pub(super) const STALL_MS: u64 = 5_000;
/// 重分配判据看近期速率：样本窗与 POLL_GAP 对齐（没在看的不算），历史停顿不拖累当下判断。
const RECENT_WIN: Duration = Duration::from_millis(1_500);
/// 连续多少次补发一个字节都没下到就认输（有进展立刻清零）。
pub(super) const MAX_DEAD_FILLS: u32 = 6;
/// 轮询断档超过这么久，回来后重新起算停滞——那是我们自己在忙队首，不是上游死了。
const POLL_GAP: Duration = Duration::from_millis(1_500);
/// 体检/重分配间隔：与测速窗同节奏（350ms），切片起 350ms 出成绩即首轮重分配。
const TICK_MS: u64 = 350;

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

/// 单字节探片（bytes=N-N）：下载器先探文件大小，不切分也不记分；大文件域直连第一棒（chain_fetch 起轮点），镜像兜底。
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

/// 206 起点校验（两处共用）：起点必须等于本段请求起点，否则字节错位拼进合并流，宁可当失败走补发。
pub(super) fn check_segment_start(v: Option<&str>, start: u64) -> Result<(), String> {
    match content_range_start(v) {
        Some(got) if got == start => Ok(()),
        Some(got) => Err(format!("206 起点不符: 要 {start}, 拿到 {got}")),
        None => Err("206 缺 Content-Range".to_string()),
    }
}

/// 一段：自己的响应体 + 自己的缓冲 + 自己的实测。边界可以被外面改小。
struct Seg {
    /// 段起点（相对区间）。
    start: u64,
    /// 段终点（相对区间），可被重分配改小。
    end: u64,
    body: BoxBody,
    /// 先到先存的数据，按到达顺序排。
    buf: VecDeque<Bytes>,
    buffered: usize,
    /// 已收到的字节数（含缓冲里还没交付的）。
    got: u64,
    /// 速率起点（首帧到达时刻），算速率用；首帧前为 None。
    first_at: Option<Instant>,
    /// 首帧前的占位起点，仅用于 last_poll 初始化。
    begin: Instant,
    /// 本段所属上游（切尾判据/日志用）。
    owner: String,
    /// 建段时快照的本家爬坡毫秒 EMA——切尾判据与它比。
    ramp: u64,
    /// 最近一次被轮询的时刻。
    last_poll: Instant,
    /// 开始"推了没数据"的时刻；None = 有数据或没在看。
    stalled_since: Option<Instant>,
    /// 被重分配缩过边界：下载越过刀口即掐流（正常段要 poll 到 EOF，不在此列）。
    cut: bool,
    /// 上游已结束（正常收尾、出错、或被停滞收割）。
    done: bool,
    /// 结束原因（仅 done 时有意义）。
    err: Option<std::io::Error>,
    /// 收尾时冻结的均速：断了之后时钟还在走，现算会一路衰减成假慢。
    frozen_rate: Option<f64>,
    /// 近期速率样本 (时刻, 已收字节)：重分配判据用滑窗。
    recent: VecDeque<(Instant, u64)>,
}

impl Seg {
    fn new(start: u64, end: u64, at: Instant, body: BoxBody, owner: String, ramp: u64) -> Self {
        Seg {
            start,
            end,
            body,
            buf: VecDeque::new(),
            buffered: 0,
            got: 0,
            first_at: None,
            begin: at,
            owner,
            ramp,
            last_poll: at,
            stalled_since: None,
            cut: false,
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

    /// 收尾时把均速定格：优先取近期速率（最后 1.5s 实测），样本不足退回全片均速。
    fn freeze(&mut self, now: Instant) {
        if self.frozen_rate.is_none() {
            let r = self.recent_rate(now);
            self.frozen_rate = Some(if r > 0.0 { r } else { self.rate(now) });
        }
    }

    /// 首帧到达：速率时钟从这一刻起算（爬坡不进分母——爬坡已单独计价），近期样本清空重开。
    fn on_first_frame(&mut self, at: Instant) {
        if self.first_at.is_none() {
            self.first_at = Some(at);
            self.begin = at;
            self.recent.clear();
        }
    }

    /// 首帧至今的均速。没首帧 = 没样本 → 0（不动刀）；收尾后返回冻结值。
    fn rate(&self, now: Instant) -> f64 {
        if let Some(r) = self.frozen_rate {
            return r;
        }
        let Some(first) = self.first_at else {
            return 0.0;
        };
        let el = now.saturating_duration_since(first);
        self.got as f64 / el.as_secs_f64().max(0.001)
    }

    /// 近期速率（最后 RECENT_WIN 的实测）：重分配判据用它，历史停顿不进分母；没样本退回全片均速。
    fn recent_rate(&self, now: Instant) -> f64 {
        if let Some(r) = self.frozen_rate {
            return r;
        }
        let Some((t0, b0)) = self.recent.front() else {
            return self.rate(now);
        };
        let el = now.saturating_duration_since(*t0);
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
    /// 待发请求的区间：缺口、被重分配切掉的尾巴。
    fill: VecDeque<(u64, u64)>,
    /// 已派出未回话的区间也要去重：只查 fill 队列会漏在途的，同一区间派两条流会错位重复吐字节。
    inflight: HashSet<(u64, u64)>,
    /// 连续"补发一个字节都没下到"的次数，有进展清零。
    dead_fills: u32,
    /// 上次体检时刻。
    last_tick: Instant,
    /// 重分配开关：直连腿骑单通道，段间重分配无意义（所有段同一根水管），关掉。
    pub(super) allow_yield: bool,
    /// 已经切过一次：校准期那轮重分配只做一次，之后所有派发交给 5ms ECT 市场。
    rebalanced: bool,
    /// 本轮切尾的段来自哪家（供上层日志显示）。
    pub(super) last_cut_owner: Option<String>,
    finished: bool,
    /// 生命周期钩子：随 body 一起丢弃（切片计划里登记的在途区间靠它注销）。
    _guard: Option<Box<dyn Send + Sync>>,
}

impl MergeBody {
    /// segs: (start, end, 起跑时刻, 响应体, 所属上游, 本家爬坡毫秒)，必须连续覆盖 [0, total)。
    pub(super) fn new(
        segs: Vec<(u64, u64, Instant, BoxBody, String, u64)>,
        total: u64,
    ) -> Self {
        MergeBody {
            segs: segs
                .into_iter()
                .map(|(s, e, at, b, owner, ramp)| (s, Seg::new(s, e, at, b, owner, ramp)))
                .collect(),
            sent: 0,
            total,
            fill: VecDeque::new(),
            inflight: HashSet::new(),
            dead_fills: 0,
            last_tick: Instant::now(),
            allow_yield: true,
            rebalanced: false,
            last_cut_owner: None,
            finished: false,
            _guard: None,
        }
    }

    /// 关掉重分配（直连腿用）：所有段骑同一根通道，段间摊派无意义，只走停滞补发。
    pub(super) fn without_yield(mut self) -> Self {
        self.allow_yield = false;
        self
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

    /// 取一个待发区间（缺口 / 重分配尾巴）。派出即登记在途，回来（feed/retry_fill）才清。
    pub(super) fn take_fill(&mut self) -> Option<(u64, u64)> {
        let iv = self.fill.pop_front()?;
        self.inflight.insert(iv);
        Some(iv)
    }

    /// 起流失败把这段塞回队尾重试，否则没人管这个洞；补发失败记一次空手，下次换家。
    pub(super) fn retry_fill(&mut self, from: u64, to: u64) {
        self.dead_fills += 1;
        self.inflight.remove(&(from, to));
        self.queue_fill(from, to);
    }

    /// 接管一条流：把 [start, end) 交给它。owner/ramp 来自派发时挑中的那家。
    pub(super) fn feed(
        &mut self,
        start: u64,
        end: u64,
        at: Instant,
        body: BoxBody,
        owner: String,
        ramp: u64,
    ) {
        self.inflight.remove(&(start, end));
        self.segs
            .insert(start, Seg::new(start, end, at, body, owner, ramp));
    }

    pub(super) fn queue_fill(&mut self, from: u64, to: u64) {
        if to <= from
            || self.fill.iter().any(|&(f, t)| f == from && t == to)
            || self.inflight.contains(&(from, to))
        {
            return;
        }
        self.fill.push_back((from, to));
    }

    /// 把还在跑的段各推一轮填进各自缓冲，返回是否有进展（拿到数据或某段结束）；缓冲满的段暂不推——waker 不再注册，等交付线推进后自然会再推它。
    fn fill_all(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        let now = Instant::now();
        let mut progressed = false;
        for seg in self.segs.values_mut() {
            // 重分配后的父段：掐掉上游流停止白下载（刀口外字节要丢），缓冲里已到的照常交付；这段必须排在缓冲守卫之前，否则父段灌满 2MB 时守卫 continue 会永远跳过掐流。
            if seg.cut && seg.pos() >= seg.end {
                seg.body = protocol::empty_body();
            }
            if seg.done || seg.buffered >= SEG_BUFFER_MAX {
                continue;
            }
            // 轮询断档（我们在忙队首）：这段没被看着的时间不算停滞。
            if now.saturating_duration_since(seg.last_poll) > POLL_GAP {
                seg.stalled_since = Some(now);
            }
            seg.last_poll = now;
            // 记近期速率样本点：判重分配用滑窗，全片均速的历史包袱不进判据。
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
                        // 首帧：速率时钟从这一刻起算（爬坡不进分母），近期样本清空重开。
                        if seg.first_at.is_none() {
                            seg.on_first_frame(now);
                        }
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
                }
                std::task::Poll::Pending => {
                    seg.stalled_since.get_or_insert(now);
                }
            }
        }
        progressed
    }

    /// 收尸真停滞的段：已收到的留下、没收到的那截排进补发——是"缩边界"不是"整段重下"，缓冲里的字节一个都不丢。
    pub(super) fn reap_stalled(&mut self, now: Instant) -> bool {
        let mut any = false;
        let mut tails: Vec<(u64, u64)> = Vec::new();
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
            tails.push((pos, old_end));
            any = true;
        }
        // 迭代借用结束后再排队——queue_fill 借整个 self，不能在 values_mut() 循环里调。
        for (pos, old_end) in tails {
            self.queue_fill(pos, old_end);
        }
        any
    }

    /// 校准期那一次重分配：全组跑得最快的那段保留不切（含并列）——它本就满速跑，切下来重派反而亏，
    /// 其余段按自己判据——剩余字节按本段速率传完的时间 > 本家爬坡成本 → 整段剩余让出，交给 5ms ECT 挑家重派。
    /// 一次切完即锁死；之后派发全交给 5ms 市场。停滞收尸是独立路径。
    pub(super) fn rebalance(&mut self, now: Instant) -> u64 {
        if !self.allow_yield || self.rebalanced || !self.fill.is_empty() {
            return 0;
        }
        // 第一遍：收集活段快照 (start, pos, end, owner, v, ramp)，并记全场最快的纯排水速率。
        // 只收有首帧的活段：没首帧 = 没速率样本，不动刀；没在看的（忙队首）与缓冲顶格的信号不可信。
        let mut cands: Vec<(u64, u64, u64, String, f64, u64)> = Vec::new();
        let mut fastest = 0.0f64;
        for s in self.segs.values() {
            if s.done || s.first_at.is_none() {
                continue;
            }
            if now.saturating_duration_since(s.last_poll) > POLL_GAP
                || s.buffered >= SEG_BUFFER_MAX
            {
                continue;
            }
            let pos = s.pos();
            let remaining = s.end.saturating_sub(pos);
            if remaining == 0 {
                continue;
            }
            let v = s.recent_rate(now);
            if v <= 0.0 {
                continue;
            }
            if v > fastest {
                fastest = v;
            }
            cands.push((s.start, pos, s.end, s.owner.clone(), v, s.ramp));
        }
        // 第二遍：最快的段（含并列）保留不切；其余段过原判据。
        // recent_rate 是 B/s，remaining/v 得秒，×1000 换毫秒再与 ramp 比。
        let mut tails: Vec<(u64, u64, u64, String)> = Vec::new();
        for (start, pos, end, owner, v, ramp) in cands {
            if v >= fastest {
                continue;
            }
            if (end - pos) as f64 / v * 1000.0 > ramp as f64 {
                tails.push((start, pos, end, owner));
            }
        }
        let mut moved = 0u64;
        for (start, pos, old_end, owner) in tails {
            if self.cut(start, pos).is_some() {
                moved += old_end - pos;
                self.last_cut_owner = Some(owner);
            }
        }
        if moved > 0 {
            self.rebalanced = true;
        }
        moved
    }

    /// 整段让出：把边界缩到 pos，[pos, old_end) 全部排补发（缓冲里已到的字节照常交付）。
    /// 允许 cut == pos（切走整段剩余）；掐流让上游停止白下载。
    fn cut(&mut self, start: u64, cut: u64) -> Option<(u64, u64)> {
        let seg = self.segs.get_mut(&start)?;
        let old_end = seg.end;
        if cut < seg.pos() || cut >= old_end {
            return None;
        }
        seg.end = cut;
        seg.cut = true;
        self.queue_fill(cut, old_end);
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
