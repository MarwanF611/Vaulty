//! Detecting that the user has gone away.
//!
//! `docs/SECURITY.md`, non-negotiables: "Lock on sleep and screen lock, not
//! only on an idle timer." Three signals, all pollable, none requiring an
//! Objective-C observer:
//!
//! * **Idle** — `CGEventSourceSecondsSinceLastEventType` reports seconds since
//!   the last input *anywhere on the system*, not just in our window. That is
//!   the signal that matters: a vault should lock because the user walked away
//!   from the machine, not because they switched to their browser.
//! * **Screen lock** — `CGSessionCopyCurrentDictionary` carries
//!   `CGSSessionScreenIsLocked`.
//! * **Sleep** — inferred from the two clocks disagreeing. `Instant` is
//!   monotonic and stops during sleep; `SystemTime` keeps counting. A gap
//!   between them is time the machine spent asleep.
//!
//! The sleep inference is worth being precise about: it detects sleep *after*
//! waking, not as it begins. In practice that is equivalent — the process is
//! suspended throughout, so there is no moment in between where anything could
//! read the key — and the watcher locks before the window is usable again.

#![allow(unsafe_code)]

use std::time::{Duration, Instant, SystemTime};

/// Seconds since the last input event anywhere on the system.
///
/// `None` where the platform does not expose it, in which case the caller
/// should fall back to in-app activity rather than never locking.
pub fn system_idle_seconds() -> Option<f64> {
    #[cfg(target_os = "macos")]
    {
        crate::macos_idle::system_idle_seconds()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Whether the screen is locked.
///
/// `None` when it cannot be determined — treated as "not locked" by callers, so
/// an unknown state never causes a spurious lock.
pub fn screen_is_locked() -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        crate::macos_idle::screen_is_locked()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Watches for the machine having slept.
///
/// Holds both clocks and reports the gap between them. Kept as a struct rather
/// than a free function because the detection is inherently stateful: it is the
/// *change* in the difference that indicates sleep.
#[derive(Debug)]
pub struct SleepDetector {
    monotonic: Instant,
    wall: SystemTime,
}

impl Default for SleepDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SleepDetector {
    pub fn new() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// How long the machine appears to have been asleep since the last call.
    ///
    /// Returns `Duration::ZERO` in the ordinary case. The clocks drift by
    /// milliseconds under normal scheduling, so callers apply a threshold
    /// rather than treating any gap as sleep.
    pub fn elapsed_asleep(&mut self) -> Duration {
        let now_mono = Instant::now();
        let now_wall = SystemTime::now();

        let mono_delta = now_mono.duration_since(self.monotonic);
        let wall_delta = now_wall.duration_since(self.wall).unwrap_or(Duration::ZERO);

        self.monotonic = now_mono;
        self.wall = now_wall;

        // Wall clock ahead of monotonic means time passed that the process did
        // not experience.
        wall_delta.saturating_sub(mono_delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_process_is_not_asleep() {
        let mut d = SleepDetector::new();
        // Both clocks advance together; the gap must stay negligible.
        let gap = d.elapsed_asleep();
        assert!(
            gap < Duration::from_secs(1),
            "an awake process reported {gap:?} of sleep"
        );
    }

    #[test]
    fn repeated_polls_do_not_accumulate_a_gap() {
        let mut d = SleepDetector::new();
        for _ in 0..5 {
            assert!(d.elapsed_asleep() < Duration::from_secs(1));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_system_idle_time() {
        let idle = system_idle_seconds().expect("macOS should report idle seconds");
        assert!(idle >= 0.0, "idle seconds was negative: {idle}");
        // A machine running tests has had input within the last day.
        assert!(idle < 86_400.0, "implausible idle time: {idle}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_a_screen_lock_state() {
        assert!(screen_is_locked().is_some());
    }
}
