//! The capture sequence from `docs/SPEC.md`.
//!
//! > 1. Save the current clipboard contents
//! > 2. Synthesise a copy keystroke into the focused app
//! > 3. Read the clipboard
//! > 4. Restore the previous clipboard
//! > 5. Show the popup with the captured text pre-filled
//!
//! Steps 1-4 live here. Step 5 is the caller's.
//!
//! # The exit criterion this file exists to satisfy
//!
//! `docs/PHASES.md`: "The previous clipboard is always restored, including when
//! the user cancels."
//!
//! *Including when the user cancels* is the load-bearing half. The restore
//! therefore happens here, before the popup is ever shown — not when the popup
//! closes. By the time the user can press Escape, their clipboard is already
//! back. There is no cancel path, no crash path and no timeout path that can
//! skip it, because cancelling happens strictly after this function returns.
//!
//! # Why the clipboard is never cleared first
//!
//! The obvious way to detect "did the copy produce anything" is to clear the
//! clipboard and look. That opens a window in which a crash loses the user's
//! clipboard for good. Instead we watch the OS's monotonic change counter (see
//! `vault_platform::clipboard_change_count`) and only ever read and write back.

use std::time::{Duration, Instant};

use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;
use vault_platform::{CapturedText, PlatformError};

/// How long to wait for the focused application to service the synthetic copy.
///
/// The focused app handles Cmd+C asynchronously, so some wait is unavoidable.
/// This is the dominant cost when *nothing* is selected, because then the
/// counter never moves and we wait the whole budget — which is why it is well
/// under the 300 ms keypress-to-cursor target rather than merely inside it.
pub const CAPTURE_DEADLINE: Duration = Duration::from_millis(150);

/// How often to check the change counter. Reading it is a cheap syscall.
const POLL_INTERVAL: Duration = Duration::from_millis(4);

#[derive(Debug)]
pub struct CaptureOutcome {
    /// The selection, if the copy produced one. `None` means nothing was
    /// selected, and the caller should open in search mode.
    pub captured: Option<CapturedText>,
    /// Whether the clipboard was written back to its previous contents.
    pub restored: bool,
    /// Wall-clock time for steps 1-4. Feeds the measured exit criterion.
    pub elapsed: Duration,
}

/// Run steps 1-4 of the capture sequence.
///
/// Returns `Ok(CaptureOutcome)` with `captured: None` when nothing was
/// selected — that is a normal outcome (search mode), not an error. `Err` is
/// reserved for the OS refusing to synthesise the keystroke at all, which on
/// macOS means Accessibility has not been granted.
pub fn capture_selection(app: &AppHandle) -> Result<CaptureOutcome, PlatformError> {
    let started = Instant::now();

    // 1. Save. A clipboard holding a non-text payload (an image, say) reads as
    //    None; see `restore` for what that costs.
    let previous = app.clipboard().read_text().ok();
    let before = vault_platform::clipboard_change_count();

    // 2. Synthesise.
    vault_platform::synthesize_copy()?;

    // 3. Read — once the counter says there is something new to read.
    let changed = wait_for_clipboard_change(before, CAPTURE_DEADLINE);
    let captured = if changed {
        app.clipboard()
            .read_text()
            .ok()
            .filter(|t| !t.is_empty())
            .map(CapturedText::new)
    } else {
        None
    };

    // 4. Restore. Only when the copy actually changed something, so we do not
    //    bump the change counter for no reason.
    let restored = if changed {
        restore(app, previous.as_deref())
    } else {
        true
    };

    Ok(CaptureOutcome {
        captured,
        restored,
        elapsed: started.elapsed(),
    })
}

/// Put the clipboard back the way we found it.
///
/// When there was no previous *text* the clipboard is cleared instead of left
/// alone. The synthetic copy has already overwritten whatever was there, so the
/// choice is between leaving the captured secret sitting in the clipboard or
/// clearing it — and for a vault, clearing is the only defensible option.
///
/// This is a real limitation worth naming: a non-text clipboard cannot be
/// restored, because by the time we know it was non-text the copy has already
/// replaced it. It is inherent to the capture design in SPEC.md.
fn restore(app: &AppHandle, previous: Option<&str>) -> bool {
    match previous {
        Some(text) => app.clipboard().write_text(text.to_string()).is_ok(),
        None => app.clipboard().write_text(String::new()).is_ok(),
    }
}

/// Block until the clipboard change counter moves, or the deadline passes.
///
/// Returns whether it moved. When the platform exposes no counter we cannot
/// tell, so we report no change and fall back to search mode — capturing a
/// stale clipboard would be worse than not capturing.
fn wait_for_clipboard_change(before: Option<i64>, deadline: Duration) -> bool {
    let Some(before) = before else {
        return false;
    };
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if vault_platform::clipboard_change_count() != Some(before) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// Schedule the clipboard to be cleared after `after`, unless it has changed.
///
/// SPEC.md: "Clipboard auto-clears 30 seconds after a copy."
///
/// The change counter recorded at write time is what makes this safe: if the
/// user has copied anything else in the meantime the counter has moved, and we
/// leave their clipboard alone rather than destroying it. Wiping whatever
/// happens to be in the clipboard 30 seconds after an unrelated action would be
/// its own kind of data loss.
pub fn schedule_clipboard_clear(app: &AppHandle, after: Duration) {
    let written_at = vault_platform::clipboard_change_count();
    let app = app.clone();

    std::thread::spawn(move || {
        std::thread::sleep(after);

        // Only clear what we put there.
        if vault_platform::clipboard_change_count() != written_at {
            return;
        }
        let _ = app.clipboard().write_text(String::new());
    });
}
