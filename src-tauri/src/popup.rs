//! The capture popup: one window that does both jobs.
//!
//! `docs/SPEC.md`:
//!
//! > **Shortcut pressed with text selected** -> capture mode: secret pre-filled,
//! > cursor in the label field, Enter saves, Escape cancels
//! > **Shortcut pressed with nothing selected** -> search mode: type, arrow
//! > keys, Enter copies
//!
//! The window is created hidden at startup and only ever shown and hidden
//! thereafter. Creating a window costs tens of milliseconds and the budget is
//! 300 ms from keypress to a usable cursor, so it is created once, up front.

use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use vault_platform::{CapturedText, PermissionStatus};

use crate::capture;
use crate::state::AppState;

pub const POPUP_LABEL: &str = "popup";
/// Event the popup listens for. Carries no secret — only how to present itself.
pub const CAPTURE_EVENT: &str = "vaulty://capture";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PopupMode {
    /// Something was selected; ask for a label.
    Capture,
    /// Nothing was selected; search the vault.
    Search,
    /// Capture is impossible until the OS grants permission.
    PermissionRequired,
}

/// Payload sent to the popup when it opens.
///
/// Note what is *not* here: the captured text. The popup is told how many
/// characters were captured so it can render a masked preview, and nothing
/// more. The text stays in `AppState` and is saved by reference
/// (CLAUDE.md rule 1).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturePayload {
    pub mode: PopupMode,
    pub char_count: Option<usize>,
    pub locked: bool,
    pub permission: &'static str,
    /// Milliseconds from shortcut to this payload being emitted. Surfaced in
    /// the UI so the 300 ms target in `docs/PHASES.md` is measurable in the
    /// real app rather than only in a benchmark.
    pub elapsed_ms: u64,
    /// How much of `elapsed_ms` was the capture sequence itself.
    pub capture_ms: Option<u64>,
    /// Whether the previous clipboard was put back.
    ///
    /// "The previous clipboard is always restored" is an exit criterion, so a
    /// failure is surfaced rather than swallowed: the user needs to know their
    /// clipboard is not what they left it as.
    pub clipboard_restored: bool,
}

/// Everything that happens when the global shortcut fires.
///
/// Ordering matters: the clipboard is captured *and restored* before the window
/// is shown, so by the time the user can press Escape their clipboard is
/// already back (see `capture.rs`).
pub fn on_shortcut(app: &AppHandle) {
    let started = Instant::now();
    let state = app.state::<AppState>();

    let permission = vault_platform::accessibility_status();

    let mut capture_ms = None;
    let mut clipboard_restored = true;

    let (mode, char_count) = if !vault_platform::capture_supported() {
        (PopupMode::Search, None)
    } else if !permission.is_usable() {
        // Do not synthesise a keystroke the OS will silently swallow; say so.
        (PopupMode::PermissionRequired, None)
    } else {
        match capture::capture_selection(app) {
            Ok(outcome) => {
                capture_ms = Some(millis(outcome.elapsed));
                clipboard_restored = outcome.restored;

                match outcome.captured {
                    Some(text) => {
                        let n = text.char_count();
                        if state.set_pending_capture(text).is_ok() {
                            (PopupMode::Capture, Some(n))
                        } else {
                            (PopupMode::Search, None)
                        }
                    }
                    None => {
                        // Nothing selected: this is search mode, not a failure.
                        let _ = state.discard_capture();
                        (PopupMode::Search, None)
                    }
                }
            }
            Err(_) => (PopupMode::PermissionRequired, None),
        }
    };

    present(
        app,
        started,
        mode,
        char_count,
        permission.as_str(),
        capture_ms,
        clipboard_restored,
    );
}

/// Text arriving from the right-click "Add to Vaulty" Services item.
///
/// Lands in the same popup as the shortcut, in capture mode, held in Rust the
/// same way (CLAUDE.md rule 1). It is the cleaner of the two paths: AppKit
/// delivers the selection on a private pasteboard, so there was no synthetic
/// keystroke, no Accessibility check, and the user's clipboard was never
/// touched — `clipboard_restored` is trivially true because nothing moved.
pub fn on_service_text(app: &AppHandle, text: CapturedText) {
    let started = Instant::now();
    let state = app.state::<AppState>();

    let n = text.char_count();
    let (mode, char_count) = if state.set_pending_capture(text).is_ok() {
        (PopupMode::Capture, Some(n))
    } else {
        (PopupMode::Search, None)
    };

    present(
        app,
        started,
        mode,
        char_count,
        PermissionStatus::NotRequired.as_str(),
        None,
        true,
    );
}

/// Show the popup and tell it how to present itself. Shared by both entry
/// points so they cannot drift in what the popup is told.
fn present(
    app: &AppHandle,
    started: Instant,
    mode: PopupMode,
    char_count: Option<usize>,
    permission: &'static str,
    capture_ms: Option<u64>,
    clipboard_restored: bool,
) {
    let state = app.state::<AppState>();
    show(app);

    let elapsed_ms = millis(started.elapsed());
    state.record_capture_ms(elapsed_ms);

    let payload = CapturePayload {
        mode,
        char_count,
        locked: state.is_locked(),
        permission,
        elapsed_ms,
        capture_ms,
        clipboard_restored,
    };
    let _ = app.emit_to(POPUP_LABEL, CAPTURE_EVENT, payload);
}

/// Saturating `Duration` -> milliseconds.
fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Show and focus the pre-created popup.
pub fn show(app: &AppHandle) {
    let Some(window) = app.get_webview_window(POPUP_LABEL) else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.center();
}

/// Hide the popup and zeroize anything it was holding.
pub fn hide(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(POPUP_LABEL) {
        let _ = window.hide();
    }
    // Escape means cancel, and SPEC.md says a cancelled capture is zeroized.
    let _ = app.state::<AppState>().discard_capture();
}

/// Ask the OS for Accessibility, then report where we ended up.
pub fn request_permission() -> PermissionStatus {
    vault_platform::prompt_for_accessibility()
}
