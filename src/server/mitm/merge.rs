//! 切片合并：按段位并发拉、按边界泵成单流；段是可缩边界而非固定连接——慢段让尾、断点续拉，不整段判死；交付线只认相对偏移。

use super::protocol::{self, BoxBody};
use bytes::Bytes;
use hyper::body::{Body as _, Frame};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// 单段缓冲上限：快段先到先存，超过就暂时不读它，等交付线推进再读。
pub(super) const SEG_BUFFER_MAX: usize = 2 * 1024 * 1024;
/// 停滞判定 5s。
pub(super) const STALL_MS: u64 = 5_000;
/// 稳态速度：首帧后 500ms 基线、600ms 落定取 100ms 增量；增量为 0 时用整段均速兜底。
const STEADY_BASE_MS: u64 = 500;
const STEADY_RATE_MS: u64 = 600;
/// 连续多少次补发一个字节都没下到就认输（有进展立刻清零）。
pub(super) const MAX_DEAD_FILLS: u32 = 6;
/// 轮询断档超过此值重新起算停滞（忙队首，非上游死）。
const POLL_GAP: Duration = Duration::from_millis(1_500);
/// 体检/重分配兜底时钟 500ms（快段提前下完会提前触发体检）。
const TICK_MS: u64 = 500;

/// 均切 [base, base+len) 为 n 段：零重叠零缝，余数归末段，n 超字节数时收缩。
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

/// 客户端 Range 的 (起点, 终点含)；无/多区间/畸形 → None。
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

/// 单字节探片：探文件大小，不切分不记分；直连第一棒、镜像兜底。
pub(super) fn is_probe_range(range: Option<&str>) -> bool {
    matches!(parse_range(range), Some((a, Some(b))) if a == b)
}

/// 从 Content-Range 取文件总长；`*` 或缺失/畸形 → None。
pub(super) fn content_range_total(v: Option<&str>) -> Option<u64> {
    let t = v?.trim().rsplit('/').next()?.trim();
    if t == "*" {
        return None;
    }
    t.parse().ok()
}

/// 取 Content-Range 的区间部分（空格或 "bytes=" 写法）。
fn range_span(v: Option<&str>) -> Option<&str> {
    let s = v?.trim();
    s.strip_prefix("bytes ")
        .or_else(|| s.strip_prefix("bytes="))?
        .split('/')
        .next()
}

/// 本段起点；206 起点必须匹配，否则字节错位。
pub(super) fn content_range_start(v: Option<&str>) -> Option<u64> {
    range_span(v)?.split('-').next()?.trim().parse().ok()
}

/// 本段闭区间终点。用于确认 206 没有越过请求的段边界。
pub(super) fn content_range_end(v: Option<&str>) -> Option<u64> {
    range_span(v)?.split_once('-')?.1.trim().parse().ok()
}

/// 206 起点校验：不匹配当失败走补发。
pub(super) fn check_segment_start(v: Option<&str>, start: u64) -> Result<(), String> {
    match content_range_start(v) {
        Some(got) if got == start => Ok(()),
        Some(got) => Err(format!("206 起点不符: 要 {start}, 拿到 {got}")),
        None => Err("206 缺 Content-Range".to_string()),
    }
}

/// 一段：响应体 + 缓冲 + 实测；边界可被改小。
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
    /// 稳态窗基线：首帧后 500ms 的 (时刻, 字节)，600ms 算速度。
    w1_at: Option<Instant>,
    w1_got: u64,
    /// 段级稳态速度：500→600ms 窗实测；一趟到齐用整段均速。
    /// 一旦落定值不再变；没样本为 None，不动刀、不进 V_fast。
    steady_rate: Option<f64>,
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
    /// 边界被缩过：越过刀口即掐流。
    cut: bool,
    /// 上游已结束（正常收尾、出错、或被停滞收割）。
    done: bool,
    /// 结束原因（仅 done 时有意义）。
    err: Option<std::io::Error>,
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
            w1_at: None,
            w1_got: 0,
            steady_rate: None,
            begin: at,
            owner,
            ramp,
            last_poll: at,
            stalled_since: None,
            cut: false,
            done: false,
            err: None,
        }
    }

    /// 已收到的位置（= 已交付 + 缓冲）。
    fn pos(&self) -> u64 {
        self.start + self.got
    }

    /// 首帧到达：速率时钟从这一刻起算（爬坡不进分母——爬坡已单独计价）。
    fn on_first_frame(&mut self, at: Instant) {
        if self.first_at.is_none() {
            self.first_at = Some(at);
            self.begin = at;
        }
    }

    /// 记录稳态采样基线；返回 true = 本拍落下速度。
    fn sample_steady(&mut self, now: Instant) -> bool {
        if self.steady_rate.is_some() {
            return false;
        }
        let Some(first) = self.first_at else {
            return false;
        };
        if self.w1_at.is_none() {
            if now.saturating_duration_since(first) >= Duration::from_millis(STEADY_BASE_MS) {
                self.w1_at = Some(now);
                self.w1_got = self.got;
            }
            return false;
        }
        if now.saturating_duration_since(first) < Duration::from_millis(STEADY_RATE_MS) {
            return false;
        }
        let t0 = self.w1_at.unwrap_or(now);
        let el = now.saturating_duration_since(t0).as_secs_f64().max(0.001);
        let bytes = self.got.saturating_sub(self.w1_got);
        if bytes == 0 {
            // 100ms 无字节 = 一趟到齐，留给整段均速兜底。
            return false;
        }
        self.steady_rate = Some(bytes as f64 / el);
        true
    }

    /// 收尾定格速度；出错/停滞段不落样本；返回 true = 本拍落下样本。
    fn freeze(&mut self, now: Instant, ok: bool) -> bool {
        if self.steady_rate.is_some() || !ok {
            return false;
        }
        let Some(first) = self.first_at else {
            return false; // 连首帧都没到，没样本，不动刀、不进基准
        };
        let el = now.saturating_duration_since(first).as_secs_f64().max(0.001);
        // 中途 EOF 按实收计价，避免截断腿被高估。
        let bytes = self
            .got
            .min(self.end.saturating_sub(self.start));
        self.steady_rate = Some(bytes as f64 / el);
        true
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
    /// 区间去重含在途（不只查 fill 队列）。
    inflight: HashSet<(u64, u64)>,
    /// 连续"补发一个字节都没下到"的次数，有进展清零。
    dead_fills: u32,
    /// 上次体检时刻。
    last_tick: Instant,
    /// 重分配开关：直连单通道时关掉。
    pub(super) allow_yield: bool,
    /// 校准期重分配只做一次，之后交 5ms ECT。
    rebalanced: bool,
    /// 新段落定稳态速度后置位，触发提前 rebalance。
    /// 只作触发信号，要不要切由 rebalance 自己算；取走即清。
    done_probe: bool,
    /// 本拍新落定的段级速度 (owner, B/s)。
    steady_events: Vec<(String, f64)>,
    /// 本轮切尾的段来自哪家（供上层日志显示）。
    pub(super) last_cut_owner: Option<String>,
    /// 留切明细：(留字节, 留毫秒, 切字节, 切毫秒)。
    /// 两端应当同时完成——日志打出来，实测可直接核对拖尾来源。
    pub(super) last_cut: Option<(u64, u64, u64, u64)>,
    finished: bool,
    /// 生命周期钩子：随 body 丢弃注销在途区间。
    _guard: Option<Box<dyn Send + Sync>>,
}

impl MergeBody {
    /// segs: (start, end, 起跑时刻, 响应体, 上游, 爬坡毫秒)，连续覆盖 [0, total)。
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
            done_probe: false,
            steady_events: Vec::new(),
            last_cut_owner: None,
            last_cut: None,
            finished: false,
            _guard: None,
        }
    }

    /// 关掉重分配（直连腿）：只走停滞补发。
    pub(super) fn without_yield(mut self) -> Self {
        self.allow_yield = false;
        self
    }

    /// 挂生命周期钩子，body 丢弃时注销登记。
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

    /// 到体检点否（涓流也要体检）。
    pub(super) fn tick_due(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_tick) < Duration::from_millis(TICK_MS) {
            return false;
        }
        self.last_tick = now;
        true
    }

    /// 段收尾/稳态采样事件：有段刚落定速度就返回 true 并清标志。
    /// 据此提前体检，快段速率立即进基准。
    pub(super) fn take_done_probe(&mut self) -> bool {
        std::mem::take(&mut self.done_probe)
    }

    /// 取走本拍新落定的段级稳态速度，喂镜像级 EMA；取走即清。
    pub(super) fn take_steady_events(&mut self) -> Vec<(String, f64)> {
        std::mem::take(&mut self.steady_events)
    }

    /// 取待发区间；派出登记在途，回来才清。
    pub(super) fn take_fill(&mut self) -> Option<(u64, u64)> {
        let iv = self.fill.pop_front()?;
        self.inflight.insert(iv);
        Some(iv)
    }

    /// 起流失败塞回队尾；补发失败记空手，下次换家。
    pub(super) fn retry_fill(&mut self, from: u64, to: u64) {
        self.dead_fills += 1;
        self.inflight.remove(&(from, to));
        self.queue_fill(from, to);
    }

    /// 接管流：[start, end)，owner/ramp 来自派发。
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

    /// 推动各段填缓冲，返回是否有进展；缓冲满的段暂不推。
    fn fill_all(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        let now = Instant::now();
        let mut progressed = false;
        let mut just_done = false;
        let mut steady = Vec::new();
        for seg in self.segs.values_mut() {
            // 重分配父段掐流停白下载，须排在缓冲守卫之前。
            if seg.cut && seg.pos() >= seg.end {
                seg.body = protocol::empty_body();
            }
            // 稳态采样不依赖缓冲水位。
            if !seg.done && seg.sample_steady(now) {
                steady.push((seg.owner.clone(), seg.steady_rate.unwrap()));
            }
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
                        // 首帧：速率时钟从这一刻起算（爬坡不进分母）。
                        if seg.first_at.is_none() {
                            seg.on_first_frame(now);
                        }
                        seg.buffered += d.len();
                        seg.got += n;
                        seg.buf.push_back(d);
                        seg.stalled_since = None;
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    progressed = true;
                    seg.freeze(now, false); // 出错段不落速度样本
                    seg.done = true;
                    seg.err = Some(e);
                }
                std::task::Poll::Ready(None) => {
                    progressed = true;
                    if seg.freeze(now, true) {
                        // 提前下完：定格首帧剔除后的均速，供别人当"最快"基准并喂 EMA。
                        steady.push((seg.owner.clone(), seg.steady_rate.unwrap()));
                    }
                    seg.done = true;
                    just_done = true; // 借用结束后交给驱动循环提前体检，不在这里直接 rebalance
                }
                std::task::Poll::Pending => {
                    seg.stalled_since.get_or_insert(now);
                }
            }
        }
        if just_done || !steady.is_empty() {
            self.done_probe = true;
        }
        self.steady_events.extend(steady);
        progressed
    }

    /// 收尸停滞段：缩边界、缺口排补发，缓冲字节不丢。
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
            seg.freeze(now, false); // 停滞段不落速度样本（不进基准、不喂 EMA）
            seg.done = true;
            seg.err = Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "段停滞，尾巴转补发",
            ));
            tails.push((pos, old_end));
            any = true;
        }
        // 迭代结束后再排队（queue_fill 借整个 self）。
        for (pos, old_end) in tails {
            self.queue_fill(pos, old_end);
        }
        any
    }

    /// 校准期重分配：最快段不切；基准取活段/已收尾段的最快速率。
    /// 切量 C = (R − P·V) × V_fast / (V_fast + V)，让留下与切走同时传完；C ≤ 0 不切，只切尾部。
    /// 一次切完即锁死；之后派发全交给 5ms 市场。停滞收尸是独立路径。
    pub(super) fn rebalance(&mut self, now: Instant) -> u64 {
        if !self.allow_yield || self.rebalanced || !self.fill.is_empty() {
            return 0;
        }
        // 收集已落定速度的活段快照与最快速率；无样本不动刀；收尾段速度参与比较但不进 cands。
        // 出错/停滞收尾的段不算基准，避免把假快速度喂给判据。
        let mut cands: Vec<(u64, u64, u64, String, f64, u64)> = Vec::new();
        let mut fastest = 0.0f64;
        let mut fastest_ramp = 0u64;
        for s in self.segs.values() {
            if s.done {
                if s.err.is_none() {
                    if let Some(v) = s.steady_rate {
                        if v > fastest {
                            fastest = v;
                            fastest_ramp = s.ramp;
                        }
                    }
                }
                continue;
            }
            // 速度未落定不动刀。
            let Some(v) = s.steady_rate else {
                continue;
            };
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
            if v <= 0.0 {
                continue;
            }
            if v > fastest {
                fastest = v;
                fastest_ramp = s.ramp;
            }
            cands.push((s.start, pos, s.end, s.owner.clone(), v, s.ramp));
        }
        // 第二遍：最快段（含并列）保留；其余按公式算切量。
        // V/V_fast 为 B/s，P 由 ramp 毫秒换秒。
        let p_sec = fastest_ramp as f64 / 1000.0;
        let mut tails: Vec<(u64, u64, u64, u64, String, u64, u64, u64)> = Vec::new();
        // (start, cut_at, kept, cut_bytes, owner, kept_ms, cut_ms, _end)
        for (start, pos, end, owner, v, _ramp) in cands {
            if v >= fastest {
                continue;
            }
            let remaining = end - pos;
            let c_f = (remaining as f64 - p_sec * v) * fastest / (fastest + v);
            if c_f <= 0.0 {
                continue; // 本段预计传完不比爬坡久 → 切 0
            }
            let cut_bytes = (c_f as u64).min(remaining);
            if cut_bytes == 0 {
                continue;
            }
            let kept = remaining - cut_bytes;
            let kept_ms = (kept as f64 / v * 1000.0) as u64;
            let cut_ms = (fastest_ramp as f64 + cut_bytes as f64 / fastest * 1000.0) as u64;
            tails.push((start, end - cut_bytes, kept, cut_bytes, owner, kept_ms, cut_ms, end));
        }
        let mut moved = 0u64;
        for (start, cut_at, kept, cut_bytes, owner, kept_ms, cut_ms, _old_end) in tails {
            if self.cut(start, cut_at).is_some() {
                moved += cut_bytes;
                self.last_cut_owner = Some(owner);
                self.last_cut = Some((kept, kept_ms, cut_bytes, cut_ms));
            }
        }
        if moved > 0 {
            self.rebalanced = true;
        }
        moved
    }

    /// 边界缩到 cut，[cut, old_end) 排补发；cut == pos 整段让出，到新边界掐流。
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
            // 队首没货先推其余段；全体无进展才是真 Pending。
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
