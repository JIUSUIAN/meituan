//! 节奏控制：限速器 + 可动态调整容量的在飞请求闸门。
//!
//! 对应 Python 版 `pacing.py`。
//! 与 Python 版一致的关键顺序：**先取在飞闸门，再在持闸期间卡最小间隔**——
//! 反过来（先限速、后等闸门）会让多个已错峰的线程在闸门放开的瞬间挤在一起发出，
//! 把配置的间隔打成 ~0。
//!
//! 用 `Condvar` + RAII guard 替代 Python 的 `Semaphore` 与 `set_max`，
//! 切换安全模式时不会有在途请求持旧容量的问题。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

struct LimiterState {
    min_gap: f64,
    last: Option<Instant>,
}

/// 领取请求限速器：任意两次 grant 之间至少间隔 `min_gap` 秒。
pub struct RateLimiter {
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    pub fn new(min_gap: f64) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                min_gap,
                last: None,
            }),
        }
    }

    pub fn set_min_gap(&self, min_gap: f64) {
        self.state.lock().unwrap().min_gap = min_gap;
    }

    pub fn min_gap(&self) -> f64 {
        self.state.lock().unwrap().min_gap
    }

    /// 等到距离上一次发送至少 `min_gap`。持锁休眠以保证顺序可预期。
    pub fn wait(&self) {
        let mut st = self.state.lock().unwrap();
        if let Some(last) = st.last {
            let since = last.elapsed().as_secs_f64();
            let wait_for = st.min_gap - since;
            if wait_for > 0.0 {
                std::thread::sleep(Duration::from_secs_f64(wait_for));
            }
        }
        st.last = Some(Instant::now());
    }
}

struct GateState {
    max: usize,
    inflight: usize,
}

/// 最多允许 `max` 个请求同时在飞；容量可运行时调整。
pub struct InflightGate {
    state: Mutex<GateState>,
    cond: Condvar,
}

/// 持有一个在飞位，drop 时归还并唤醒等待者。
pub struct GateGuard<'a> {
    gate: &'a InflightGate,
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        let mut st = self.gate.state.lock().unwrap();
        st.inflight -= 1;
        drop(st);
        self.gate.cond.notify_one();
    }
}

impl InflightGate {
    pub fn new(max: usize) -> Self {
        Self {
            state: Mutex::new(GateState { max, inflight: 0 }),
            cond: Condvar::new(),
        }
    }

    pub fn set_max(&self, max: usize) {
        self.state.lock().unwrap().max = max;
        self.cond.notify_all();
    }

    pub fn inflight(&self) -> usize {
        self.state.lock().unwrap().inflight
    }

    pub fn slot(&self) -> GateGuard<'_> {
        let mut st = self.state.lock().unwrap();
        while st.inflight >= st.max {
            st = self.cond.wait(st).unwrap();
        }
        st.inflight += 1;
        GateGuard { gate: self }
    }
}

/// 领取节奏 = 限速器（时间槽）+ 在飞闸门（并发上限）。
pub struct GrantPacing {
    limiter: RateLimiter,
    gate: InflightGate,
    sustained_gap: f64,
    sustained_inflight: usize,
    sustained: AtomicBool,
}

/// 同时持有在飞位与发送时间槽。
pub struct PacingGuard<'a> {
    _gate: GateGuard<'a>,
}

impl GrantPacing {
    pub fn new(
        first_gap: f64,
        first_inflight: usize,
        sustained_gap: f64,
        sustained_inflight: usize,
    ) -> Self {
        Self {
            limiter: RateLimiter::new(first_gap),
            gate: InflightGate::new(first_inflight),
            sustained_gap,
            sustained_inflight,
            sustained: AtomicBool::new(false),
        }
    }

    /// 先取并发容量，再在持闸期间卡最小间隔。
    pub fn slot(&self) -> PacingGuard<'_> {
        let gate = self.gate.slot();
        self.limiter.wait();
        PacingGuard { _gate: gate }
    }

    /// 第一波结束后切换到安全模式。
    pub fn enter_sustained_mode(&self) {
        self.limiter.set_min_gap(self.sustained_gap);
        self.gate.set_max(self.sustained_inflight);
        self.sustained.store(true, Ordering::SeqCst);
    }

    pub fn is_sustained(&self) -> bool {
        self.sustained.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn sustained_mode_updates_gap_and_capacity() {
        let p = GrantPacing::new(0.05, 4, 0.5, 2);
        assert!((p.limiter.min_gap() - 0.05).abs() < 1e-9);
        assert!(!p.is_sustained());
        p.enter_sustained_mode();
        assert!((p.limiter.min_gap() - 0.5).abs() < 1e-9);
        assert!(p.is_sustained());
        assert_eq!(p.gate.inflight(), 0);
    }

    #[test]
    fn gate_blocks_over_capacity() {
        // 用「进入 +1 / 离开 -1」测真实并发度，累计计数会因线程依次进入而超过容量
        let gate = Arc::new(InflightGate::new(2));
        let inflight_now = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..6 {
            let g = Arc::clone(&gate);
            let now = Arc::clone(&inflight_now);
            let mx = Arc::clone(&max_seen);
            let tt = Arc::clone(&total);
            handles.push(std::thread::spawn(move || {
                let _guard = g.slot();
                let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                mx.fetch_max(n, Ordering::SeqCst);
                tt.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(30));
                now.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(total.load(Ordering::SeqCst), 6, "6 个任务都跑完");
        assert_eq!(max_seen.load(Ordering::SeqCst), 2, "最大同时在飞应为容量 2");
        assert_eq!(gate.inflight(), 0, "guard drop 后全部归还");
    }

    #[test]
    fn limiter_enforces_min_gap_across_threads() {
        // 多个线程并发 wait：持锁休眠保证顺序可预期，相邻两次至少差 min_gap
        let limiter = Arc::new(RateLimiter::new(0.05));
        let stamps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..5 {
            let l = Arc::clone(&limiter);
            let s = Arc::clone(&stamps);
            handles.push(std::thread::spawn(move || {
                l.wait();
                s.lock().unwrap().push(Instant::now());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let v = stamps.lock().unwrap();
        let mut sorted: Vec<Instant> = v.clone();
        sorted.sort();
        for w in sorted.windows(2) {
            let gap = w[1].duration_since(w[0]).as_secs_f64();
            assert!(gap >= 0.045, "实际间隔 {:.4}s 小于 0.05s", gap);
        }
    }

    #[test]
    fn slot_holds_gate_then_limiter() {
        // GrantPacing.slot 的顺序：先 gate 后 limiter。用容量 1 验证
        // 第二个线程必须等第一个释放闸门才能进入，从而间隔被强制执行。
        let pacing = Arc::new(GrantPacing::new(0.2, 1, 0.2, 1));
        let stamps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let p = Arc::clone(&pacing);
            let s = Arc::clone(&stamps);
            handles.push(std::thread::spawn(move || {
                let _g = p.slot();
                s.lock().unwrap().push(Instant::now());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut v = stamps.lock().unwrap().clone();
        v.sort();
        for w in v.windows(2) {
            assert!(
                w[1].duration_since(w[0]).as_secs_f64() >= 0.15,
                "闸门容量 1 下实际间隔应 >= 0.15s"
            );
        }
    }
}
