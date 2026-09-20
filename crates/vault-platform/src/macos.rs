//! macOS implementation of the capture primitives.
//!
//! Three OS facilities are used here:
//!
//! * `AXIsProcessTrusted` — whether Accessibility has been granted. Without it
//!   `CGEventPost` still *succeeds* and simply does nothing, so this check is
//!   the only way to tell the user why capture is silently failing.
//! * `CGEvent` — synthesising the Cmd+C keystroke into the focused app.
//! * `NSPasteboard.changeCount` — a monotonic counter that tells us whether the
//!   synthetic copy actually produced anything, without ever clearing the
//!   user's clipboard to find out.

#![allow(unsafe_code)]

use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use core_graphics::event::{CGEvent, CGEventFlags, CGEventTapLocation};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use objc2_app_kit::NSPasteboard;

use crate::error::{PlatformError, Result};
use crate::permissions::PermissionStatus;

/// Virtual keycode for the "C" key on an ANSI layout (`kVK_ANSI_C`).
///
/// This is a *physical key* code, not a character, so it is correct on
/// non-QWERTY layouts too: Cmd+C lives on the same physical key regardless of
/// what that key types.
const KEYCODE_ANSI_C: u16 = 0x08;

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    // Returns `Boolean` (unsigned char), not C++ bool. Taking it as u8 and
    // comparing avoids relying on the value being exactly 0 or 1.
    fn AXIsProcessTrusted() -> u8;
    fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> u8;
    static kAXTrustedCheckOptionPrompt: CFStringRef;
}

pub(crate) fn accessibility_status() -> PermissionStatus {
    // Safety: no arguments, no pointers; returns a byte.
    let trusted = unsafe { AXIsProcessTrusted() } != 0;
    if trusted {
        PermissionStatus::Granted
    } else {
        PermissionStatus::Denied
    }
}

pub(crate) fn prompt_for_accessibility() -> PermissionStatus {
    // Safety: `kAXTrustedCheckOptionPrompt` is a framework-owned CFString
    // constant; we only read it to build the options dictionary, which we own
    // and which outlives the call.
    let trusted = unsafe {
        let key = CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt);
        let options = CFDictionary::from_CFType_pairs(&[(key, CFBoolean::true_value())]);
        AXIsProcessTrustedWithOptions(options.as_concrete_TypeRef()) != 0
    };

    if trusted {
        PermissionStatus::Granted
    } else {
        PermissionStatus::Denied
    }
}

pub(crate) fn open_accessibility_settings() -> Result<()> {
    // The documented URL scheme for the Accessibility pane. `open` returns as
    // soon as the request is handed off, so this does not block.
    let status = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        .status()
        .map_err(|_| PlatformError::Os("could not launch System Settings"))?;

    if status.success() {
        Ok(())
    } else {
        Err(PlatformError::Os("System Settings refused to open"))
    }
}

/// Post Cmd+C to whatever application currently has focus.
///
/// Refuses up front when Accessibility has not been granted, rather than
/// posting an event the OS will silently drop.
pub(crate) fn synthesize_copy() -> Result<()> {
    if !accessibility_status().is_usable() {
        return Err(PlatformError::PermissionDenied);
    }

    // `CombinedSessionState` makes the synthetic event behave as though it came
    // from the same session as real input, which is what lets the focused app
    // treat it as a genuine Cmd+C.
    let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
        .map_err(|_| PlatformError::Os("CGEventSource::new"))?;

    let key_down = CGEvent::new_keyboard_event(source.clone(), KEYCODE_ANSI_C, true)
        .map_err(|_| PlatformError::Os("CGEvent key down"))?;
    key_down.set_flags(CGEventFlags::CGEventFlagCommand);
    key_down.post(CGEventTapLocation::HID);

    let key_up = CGEvent::new_keyboard_event(source, KEYCODE_ANSI_C, false)
        .map_err(|_| PlatformError::Os("CGEvent key up"))?;
    key_up.set_flags(CGEventFlags::CGEventFlagCommand);
    key_up.post(CGEventTapLocation::HID);

    Ok(())
}

/// `NSPasteboard.changeCount` — increments on every write by any process.
///
/// This is what makes the capture sequence safe: we can tell whether the
/// synthetic copy produced anything by watching the counter, instead of
/// clearing the clipboard first and hoping to restore it.
pub(crate) fn clipboard_change_count() -> Option<i64> {
    // `generalPasteboard` returns a shared, process-wide object and
    // `changeCount` is documented as safe to read from any thread, so objc2
    // exposes both as safe.
    let pasteboard = NSPasteboard::generalPasteboard();
    // `changeCount` is an NSInteger, which is isize here.
    i64::try_from(pasteboard.changeCount()).ok()
}
