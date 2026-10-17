//! 环形日志：带自增序号供 WebUI 增量拉取；崩溃取证（唯一落盘的日志）。

use crate::config::LOG_BUFFER_SIZE;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use time::macros::format_description;
use time::OffsetDateTime;

/// 本地时区偏移（进程内缓存一次）：now_local 每次调用都重新探测，多线程下
/// 偶发失败会回退 UTC —— 时间戳在 +08:00 和 UTC 之间跳跃。缓存后省掉每次
/// 系统调用，时间戳恒定本地时区(2026-10-17 复审)。
static LOCAL_OFFSET: std::sync::OnceLock<time::UtcOffset> = std::sync::OnceLock::new();

/// 本地时间戳：缓存偏移 + now_utc 换算（time 单一时间库）。
fn now_str(fd: &[time::format_description::FormatItem<'static>]) -> String {
    let offset = *LOCAL_OFFSET.get_or_init(|| {
        time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC)
    });
    OffsetDateTime::now_utc()
        .to_offset(offset)
        .format(fd)
        .unwrap_or_else(|_| "00:00:00".to_string())
}

#[derive(Clone)]
pub struct Logger {
    inner: std::sync::Arc<Mutex<LoggerInner>>,
}

struct LoggerInner {
    seq: u64,
    /// VecDeque：满员淘汰是 O(1) pop_front —— Vec::remove(0) 是整段搬移，
    /// 容量扩到 2000 后每行日志白挪 48KB，不可忍。
    buf: VecDeque<Entry>,
    echo_stdout: bool,
}

#[derive(Clone)]
struct Entry {
    seq: u64,
    line: String,
}

impl Logger {
    pub fn new(echo_stdout: bool) -> Self {
        Logger {
            inner: std::sync::Arc::new(Mutex::new(LoggerInner {
                seq: 0,
                buf: VecDeque::with_capacity(LOG_BUFFER_SIZE),
                echo_stdout,
            })),
        }
    }

    pub fn log(&self, msg: &str) {
        let line = format!(
            "[{}] {}",
            now_str(format_description!("[hour]:[minute]:[second]")),
            msg
        );
        let echo = {
            let mut g = self.inner.lock().unwrap();
            g.seq += 1;
            if g.buf.len() >= LOG_BUFFER_SIZE {
                g.buf.pop_front();
            }
            let seq = g.seq;
            g.buf.push_back(Entry {
                seq,
                line: line.clone(),
            });
            g.echo_stdout
        };
        // stdout 回显仅 headless 调试：GUI 构建的 stdout 一旦被重定向就落盘，
        // 日志含访问域名等浏览痕迹 —— 非调试场景不产生持久化副本。
        if echo {
            println!("{line}");
        }
    }

    /// 返回 seq > after 的日志与当前最新序号。
    pub fn since(&self, after: u64) -> (Vec<(u64, String)>, u64) {
        let g = self.inner.lock().unwrap();
        let out = g
            .buf
            .iter()
            .filter(|e| e.seq > after)
            .map(|e| (e.seq, e.line.clone()))
            .collect();
        (out, g.seq)
    }
}

// ---------- 崩溃取证（唯一落盘的日志） ----------
// windowsgui 构建的 stderr 不可见：任何线程的 panic = 静默退出，
// 无 WER 事件无任何痕迹 —— "挂托盘莫名退出"排障全靠它。crash.log 只含
// panic 堆栈与内部状态行（无域名/无浏览痕迹），与运行日志的隐私边界不同。

static CRASH: Mutex<CrashState> = Mutex::new(CrashState { path: None });

struct CrashState {
    path: Option<PathBuf>,
}

/// 设置崩溃日志路径（exe 目录）。
pub fn set_crash_path(dir: &std::path::Path) {
    let mut g = CRASH.lock().unwrap();
    g.path = Some(dir.join("crash.log"));
}

/// 严重事件/panic 取证：追加写 crash.log（带完整堆栈）。
/// 落盘失败静默放弃（内存里也别丢：调用方通常先 log 一份）。
pub fn crash(msg: &str) {
    let path = {
        let g = CRASH.lock().unwrap();
        g.path.clone()
    };
    let Some(path) = path else { return };
    let backtrace = std::backtrace::Backtrace::force_capture();
    let line = format!(
        "[{}] {msg}\n--- backtrace ---\n{backtrace}\n",
        now_str(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
    );
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }
}

/// 注册全局 panic hook：任何 panic 先取证落盘，再恢复默认行为（stderr 打印 + abort）。
/// 供 main 启动时调用一次。
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        crash(&format!("[panic] {info}"));
        default(info);
    }));
}

/// 长驻任务护栏：panic 只断该任务并取证，进程必须活着。
/// 与 server 的单连接 recover 同思路，覆盖托盘/webui/池刷新。
pub fn guard(name: &'static str, f: impl FnOnce()) {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        crash(&format!("[panic] {name} 护栏捕获(进程不受影响)"));
    });
}

/// 生成一个带护栏的后台任务：代理流量路径的所有后台任务必须经此派生。
pub fn spawn(name: &'static str, f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || guard(name, f))
        .ok();
}
