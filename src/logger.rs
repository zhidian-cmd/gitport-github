//! 环形日志：带自增序号供 WebUI 增量拉取；崩溃取证（唯一落盘的日志）。

use crate::config::LOG_BUFFER_SIZE;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use time::macros::format_description;
use time::OffsetDateTime;

/// 本地时区偏移（进程内缓存一次）：多线程探测偶发失败会致时间戳跳跃，缓存后恒定。
static LOCAL_OFFSET: std::sync::OnceLock<time::UtcOffset> = std::sync::OnceLock::new();

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
    /// VecDeque：满员淘汰 O(1)；Vec::remove(0) 整段搬移不可忍。
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
        // stdout 回显仅 headless 调试：GUI 构建 stdout 重定向会把浏览痕迹落盘。
        if echo {
            println!("{line}");
        }
    }

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


/// 崩溃取证落点：未装（headless 以外的早期阶段）时静默丢弃。
static CRASH: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn set_crash_path(dir: &std::path::Path) {
    *CRASH.lock().unwrap() = Some(dir.join("crash.log"));
}

pub fn crash(msg: &str) {
    let path = CRASH.lock().unwrap().clone();
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

pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        crash(&format!("[panic] {info}"));
        default(info);
    }));
}

/// 长驻任务护栏：panic 只断该任务并取证，进程必须活着。
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_evicts_oldest_keeps_window() {
        let lg = Logger::new(false);
        for i in 0..(LOG_BUFFER_SIZE + 5) {
            lg.log(&format!("line{i}"));
        }
        let (entries, latest) = lg.since(0);
        assert_eq!(entries.len(), LOG_BUFFER_SIZE);
        assert!(
            entries[0].1.ends_with("line5"),
            "最旧 5 条应被挤出: {}",
            entries[0].1
        );
        assert!(entries
            .last()
            .unwrap()
            .1
            .ends_with(&format!("line{}", LOG_BUFFER_SIZE + 4)));
        assert_eq!(latest, (LOG_BUFFER_SIZE + 5) as u64);
        let (tail, _) = lg.since(entries[0].0);
        assert_eq!(tail.len(), LOG_BUFFER_SIZE - 1);
    }
}
