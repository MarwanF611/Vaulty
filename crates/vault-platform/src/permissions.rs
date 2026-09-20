//! Permission checks for the capture path.
//!
//! Synthesising a keystroke into another application is a privileged act, and
//! both supported platforms gate it. This module reports the state so the UI can
//! explain what is needed rather than silently capturing nothing — which is
//! exactly what an un-granted Accessibility permission looks like on macOS:
//! `CGEventPost` succeeds and nothing happens.

/// Whether the app may drive the keyboard of other applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionStatus {
    /// Capture will work.
    Granted,
    /// The user has not granted it yet, or has revoked it.
    Denied,
    /// This platform does not gate the capability.
    NotRequired,
    /// Capture is not implemented here at all.
    Unsupported,
}

impl PermissionStatus {
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            PermissionStatus::Granted | PermissionStatus::NotRequired
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PermissionStatus::Granted => "granted",
            PermissionStatus::Denied => "denied",
            PermissionStatus::NotRequired => "not_required",
            PermissionStatus::Unsupported => "unsupported",
        }
    }
}

/// Current Accessibility status, without prompting.
///
/// Safe to call on every window focus: it does not show UI.
pub fn accessibility_status() -> PermissionStatus {
    #[cfg(target_os = "macos")]
    {
        crate::macos::accessibility_status()
    }
    #[cfg(target_os = "windows")]
    {
        // Windows does not gate SendInput for same-desktop input synthesis.
        // UIPI still blocks sending into a higher-integrity process, but that
        // is per-target and cannot be queried up front.
        PermissionStatus::NotRequired
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PermissionStatus::Unsupported
    }
}

/// Ask the OS to show its own permission prompt, once.
///
/// macOS only shows this prompt a single time per app bundle; afterwards the
/// user has to go to System Settings, which is why
/// [`open_accessibility_settings`] exists alongside it.
pub fn prompt_for_accessibility() -> PermissionStatus {
    #[cfg(target_os = "macos")]
    {
        crate::macos::prompt_for_accessibility()
    }
    #[cfg(not(target_os = "macos"))]
    {
        accessibility_status()
    }
}

/// Open the OS settings pane where the permission is granted.
pub fn open_accessibility_settings() -> crate::Result<()> {
    #[cfg(target_os = "macos")]
    {
        crate::macos::open_accessibility_settings()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(crate::PlatformError::Unsupported)
    }
}
