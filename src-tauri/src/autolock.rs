//! Auto-lock: dropping the key when the user is no longer there.
//!
//! `docs/SECURITY.md`, non-negotiables: "Lock on sleep and screen lock, not
//! only on an idle timer." So the idle timeout is configurable and the other
//! two are not — a vault that stays open through a lid close is not a vault,
//! and making that switchable invites someone to switch it off.
//!
//! # Why a poller rather than notifications
//!
//! Sleep and screen-lock both have Objective-C notifications, and observing
//! them means defining a class with selectors and keeping it alive for the
//! process. A 2-second poll costs two syscalls, needs no Objective-C runtime
//! machinery, and — the part that matters — degrades safely: if a signal is
//! ever unreadable the idle timer still fires. A missed notification, by
//! contrast, is a vault that silently stays unlocked.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use vault_platform::SleepDetector;

use crate::popup;
use crate::state::AppState;

/// How often to check. Cheap enough to be frequent, frequent enough that the
/// worst-case overshoot on an idle timeout is small.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Clock disagreement below this is scheduling noise, not sleep.
const SLEEP_THRESHOLD: Duration = Duration::from_secs(5);

/// Emitted to every window when the vault locks itself.
pub const LOCK_EVENT: &str = "vaulty://locked";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    Idle,
    Sleep,
    ScreenLock,
}

impl LockReason {
    /// What to tell the user, in the unlock screen.
    pub fn message(self) -> &'static str {
        match self {
            LockReason::Idle => "Vaulty locked after a period of inactivity.",
            LockReason::Sleep => "Vaulty locked when your Mac went to sleep.",
            LockReason::ScreenLock => "Vaulty locked when your screen locked.",
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct LockedPayload {
    pub reason: LockReason,
    pub message: &'static str,
}

/// Decide whether to lock, given the current signals.
///
/// Split out from the polling loop so the policy is testable without a clock,
/// a window, or an OS.
pub fn should_lock(
    idle_seconds: Option<f64>,
    idle_limit_seconds: u64,
    screen_locked: Option<bool>,
    slept_for: Duration,
) -> Option<LockReason> {
    // Sleep first: it is the least ambiguous signal, and after a wake the idle
    // counter will also be over the limit, so reporting "idle" would be
    // misleading about what actually happened.
    if slept_for >= SLEEP_THRESHOLD {
        return Some(LockReason::Sleep);
    }

    // An unreadable screen-lock state is treated as unlocked: a signal we
    // cannot read must not cause a spurious lock. The idle timer still covers
    // the case.
    if screen_locked == Some(true) {
        return Some(LockReason::ScreenLock);
    }

    // Zero disables the idle timer. Sleep and screen lock still apply.
    if idle_limit_seconds > 0 {
        if let Some(idle) = idle_seconds {
            if idle >= idle_limit_seconds as f64 {
                return Some(LockReason::Idle);
            }
        }
    }

    None
}

/// Start the watcher. Returns a handle that stops it when dropped.
pub fn spawn(app: AppHandle) -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();

    std::thread::spawn(move || {
        let mut sleep_detector = SleepDetector::new();

        while flag.load(Ordering::Relaxed) {
            std::thread::sleep(POLL_INTERVAL);

            let slept_for = sleep_detector.elapsed_asleep();

            let Some(state) = app.try_state::<AppState>() else {
                continue;
            };
            // Nothing to protect while locked — but the sleep detector above
            // still runs every tick so its clocks stay current.
            if state.is_locked() {
                continue;
            }

            let idle_limit = state
                .settings()
                .map(|s| s.idle_lock_seconds)
                .unwrap_or(crate::settings::DEFAULT_IDLE_LOCK_SECONDS);

            let reason = should_lock(
                vault_platform::system_idle_seconds(),
                idle_limit,
                vault_platform::screen_is_locked(),
                slept_for,
            );

            if let Some(reason) = reason {
                lock_now(&app, reason);
            }
        }
    });

    running
}

/// Drop the key and tell the interface why.
pub fn lock_now(app: &AppHandle, reason: LockReason) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    // Zeroizes the vault key and discards any pending capture.
    let _ = state.lock();

    // A popup holding a half-typed capture should not outlive the session.
    popup::hide(app);

    let _ = app.emit(
        LOCK_EVENT,
        LockedPayload {
            reason,
            message: reason.message(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_SLEEP: Duration = Duration::ZERO;

    #[test]
    fn an_active_user_is_not_locked_out() {
        assert_eq!(should_lock(Some(3.0), 300, Some(false), NO_SLEEP), None);
    }

    #[test]
    fn idle_past_the_limit_locks() {
        assert_eq!(
            should_lock(Some(300.0), 300, Some(false), NO_SLEEP),
            Some(LockReason::Idle)
        );
        assert_eq!(
            should_lock(Some(301.0), 300, Some(false), NO_SLEEP),
            Some(LockReason::Idle)
        );
        assert_eq!(should_lock(Some(299.0), 300, Some(false), NO_SLEEP), None);
    }

    /// SECURITY.md: sleep and screen lock are not optional.
    #[test]
    fn sleep_and_screen_lock_ignore_the_idle_setting() {
        // Idle timer disabled entirely.
        assert_eq!(
            should_lock(Some(0.0), 0, Some(false), Duration::from_secs(60)),
            Some(LockReason::Sleep)
        );
        assert_eq!(
            should_lock(Some(0.0), 0, Some(true), NO_SLEEP),
            Some(LockReason::ScreenLock)
        );
    }

    #[test]
    fn a_zero_idle_limit_disables_only_the_idle_timer() {
        assert_eq!(should_lock(Some(99_999.0), 0, Some(false), NO_SLEEP), None);
    }

    /// After a wake the idle counter is also over the limit; the user should be
    /// told what actually happened.
    #[test]
    fn sleep_is_reported_in_preference_to_the_idle_it_causes() {
        assert_eq!(
            should_lock(Some(5000.0), 300, Some(false), Duration::from_secs(4000)),
            Some(LockReason::Sleep)
        );
    }

    #[test]
    fn clock_jitter_is_not_mistaken_for_sleep() {
        assert_eq!(
            should_lock(Some(1.0), 300, Some(false), Duration::from_millis(900)),
            None
        );
        assert_eq!(
            should_lock(
                Some(1.0),
                300,
                Some(false),
                SLEEP_THRESHOLD - Duration::from_millis(1)
            ),
            None
        );
    }

    /// A signal we cannot read must not cause a spurious lock.
    #[test]
    fn unreadable_signals_fail_towards_staying_unlocked() {
        assert_eq!(should_lock(None, 300, None, NO_SLEEP), None);
        // ... but the other signals still work.
        assert_eq!(
            should_lock(None, 300, Some(true), NO_SLEEP),
            Some(LockReason::ScreenLock)
        );
        assert_eq!(
            should_lock(None, 300, None, Duration::from_secs(30)),
            Some(LockReason::Sleep)
        );
    }

    #[test]
    fn every_reason_says_something_useful() {
        for r in [LockReason::Idle, LockReason::Sleep, LockReason::ScreenLock] {
            assert!(r.message().contains("locked"), "{r:?}: {}", r.message());
        }
    }
}
