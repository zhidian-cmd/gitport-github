//! 通用小工具：日志回调、毫秒时间、锁中毒自愈；最底层，不依赖业务模块。

use std::sync::{Arc, Mutex};

pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 锁中毒自愈：取内层值继续。
pub(crate) fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
