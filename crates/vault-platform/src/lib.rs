//! `vault-platform` — OS integration for Vaulty.
//!
//! Per `CLAUDE.md`'s layout this crate owns OS integration: keystore,
//! biometrics, global shortcut and clipboard. Today it holds the pieces Phase 2
//! needs — clipboard inspection, selection capture and the permission checks
//! that gate them. Phase 3 adds `BiometricProvider` alongside.
//!
//! It deliberately knows nothing about vaults, keys or ciphertext. The only
//! user data that passes through is the *captured selection* on its way into
//! the vault, and that is handled as [`CapturedText`], which zeroizes.
//!
//! # Why `changeCount` rather than clearing the clipboard
//!
//! The obvious way to tell whether a synthetic Cmd+C copied anything is to
//! clear the clipboard first and see if something appears. That risks the one
//! thing `docs/PHASES.md` makes an exit criterion — "the previous clipboard is
//! always restored" — because a crash between the clear and the restore loses
//! the user's clipboard permanently.
//!
//! Both platforms expose a monotonic counter that increments on every clipboard
//! write, so the question can be answered by observation instead:
//! read the counter, synthesise the copy, watch for it to move. The user's
//! clipboard is never cleared, only read and written back.

#![warn(missing_debug_implementations)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod biometrics;
mod error;
mod idle;
mod permissions;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_idle;
#[cfg(target_os = "macos")]
mod macos_keychain;
#[cfg(target_os = "windows")]
#[path = "windows_impl.rs"]
mod windows_impl;

pub use biometrics::{
    provider, BiometricAvailability, BiometricFailure, BiometricProvider, BiometryKind,
    UnsupportedProvider,
};
pub use error::{PlatformError, Result};
pub use idle::{screen_is_locked, system_idle_seconds, SleepDetector};
pub use permissions::{
    accessibility_status, open_accessibility_settings, prompt_for_accessibility, PermissionStatus,
};

use std::fmt;
use zeroize::Zeroizing;

/// Text lifted out of another application by the capture sequence.
///
/// This is the user's own selection, not a decrypted secret — but it is very
/// often *about to become* a secret, so it gets the same handling: zeroized on
/// drop, never `Debug`-printed.
pub struct CapturedText(Zeroizing<String>);

impl CapturedText {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for CapturedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Length is safe to show and useful in a log; the content is not.
        f.debug_struct("CapturedText")
            .field("chars", &self.char_count())
            .field("text", &"[redacted]")
            .finish()
    }
}

/// Whether selection capture is implemented for the current platform.
pub fn capture_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

/// Send a copy keystroke (Cmd+C / Ctrl+C) to the focused application.
///
/// Returns once the event has been posted. The focused app handles it
/// asynchronously, so the caller must wait for the clipboard to change rather
/// than assuming the copy has landed — see [`clipboard_change_count`].
pub fn synthesize_copy() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::synthesize_copy()
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::synthesize_copy()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(PlatformError::Unsupported)
    }
}

/// A counter that increments every time any process writes to the clipboard.
///
/// `None` when the platform does not expose one.
pub fn clipboard_change_count() -> Option<i64> {
    #[cfg(target_os = "macos")]
    {
        macos::clipboard_change_count()
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::clipboard_change_count()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_text_reports_length_but_never_content() {
        let c = CapturedText::new("SUPER-SECRET-SELECTION".into());
        assert_eq!(c.as_str(), "SUPER-SECRET-SELECTION");
        assert_eq!(c.char_count(), 22);
        assert!(!c.is_empty());

        let shown = format!("{c:?}");
        assert!(
            !shown.contains("SUPER-SECRET-SELECTION"),
            "Debug leaked the capture"
        );
        assert!(shown.contains("[redacted]"));
        assert!(
            shown.contains("22"),
            "length should still be visible: {shown}"
        );
    }

    #[test]
    fn captured_text_counts_characters_not_bytes() {
        // A four-character selection that is ten bytes of UTF-8.
        let c = CapturedText::new("héllo".into());
        assert_eq!(c.char_count(), 5);
    }

    #[test]
    fn empty_capture_is_reported_as_empty() {
        assert!(CapturedText::new(String::new()).is_empty());
    }

    #[test]
    fn permission_status_usability() {
        assert!(PermissionStatus::Granted.is_usable());
        assert!(PermissionStatus::NotRequired.is_usable());
        assert!(!PermissionStatus::Denied.is_usable());
        assert!(!PermissionStatus::Unsupported.is_usable());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_a_clipboard_change_counter() {
        // The value is whatever the machine's clipboard history says; what
        // matters is that the counter exists and is readable.
        assert!(clipboard_change_count().is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_supports_capture_and_reports_a_definite_permission_state() {
        assert!(capture_supported());
        let status = accessibility_status();
        assert!(
            matches!(status, PermissionStatus::Granted | PermissionStatus::Denied),
            "macOS must report a definite state, got {status:?}"
        );
    }
}
