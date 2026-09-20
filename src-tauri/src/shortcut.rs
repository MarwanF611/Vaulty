//! Global shortcut registration and conflict detection.
//!
//! `docs/SPEC.md` is explicit that rebinding ships in the first build rather
//! than waiting for a settings phase, because the Windows default
//! (`Ctrl+Shift+Space`) collides with parameter hints in Visual Studio and the
//! JetBrains IDEs — which is exactly the audience.
//!
//! So a binding can fail in two distinguishable ways, and the UI needs to tell
//! them apart: text that is not a shortcut at all, and a shortcut the OS has
//! already given to somebody else.

use std::str::FromStr;

use tauri::AppHandle;
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutError {
    /// The string is not a valid accelerator, e.g. "Ctrl+" or "Banana".
    Unparseable,
    /// Valid, but the OS refused it — another application holds it.
    AlreadyTaken,
}

impl ShortcutError {
    pub fn code(self) -> &'static str {
        match self {
            ShortcutError::Unparseable => "shortcut_invalid",
            ShortcutError::AlreadyTaken => "shortcut_taken",
        }
    }

    pub fn message(self, accelerator: &str) -> String {
        match self {
            ShortcutError::Unparseable => {
                format!("\"{accelerator}\" is not a valid shortcut.")
            }
            ShortcutError::AlreadyTaken => format!(
                "{accelerator} is already used by another application. Pick a different one."
            ),
        }
    }
}

pub fn parse(accelerator: &str) -> Result<Shortcut, ShortcutError> {
    Shortcut::from_str(accelerator).map_err(|_| ShortcutError::Unparseable)
}

/// Register `accelerator`, replacing whatever was registered before.
///
/// The old binding is released first, so a failed rebind leaves the app with no
/// shortcut rather than two. Callers that care should re-register the previous
/// one on error — [`rebind`] does.
pub fn register(app: &AppHandle, accelerator: &str) -> Result<(), ShortcutError> {
    let shortcut = parse(accelerator)?;
    app.global_shortcut()
        .register(shortcut)
        .map_err(|_| ShortcutError::AlreadyTaken)
}

pub fn unregister_all(app: &AppHandle) {
    let _ = app.global_shortcut().unregister_all();
}

/// Swap the active binding, rolling back if the new one is refused.
///
/// Losing your shortcut because you typed a combination another app already
/// owns would be a poor trade, so a failure here leaves the previous binding
/// working.
pub fn rebind(app: &AppHandle, previous: &str, next: &str) -> Result<(), ShortcutError> {
    // Validate before tearing anything down.
    let _ = parse(next)?;

    unregister_all(app);

    match register(app, next) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Put the working binding back.
            let _ = register(app, previous);
            Err(e)
        }
    }
}
