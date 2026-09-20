//! macOS implementations of the idle and screen-lock signals.

#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::CFString;

/// `kCGEventSourceStateCombinedSessionState` — input from every source in the
/// session, which is what "has the user touched this machine" means.
const COMBINED_SESSION_STATE: u32 = 0;
/// `kCGAnyInputEventType`.
const ANY_INPUT_EVENT: u32 = 0xFFFF_FFFF;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventSourceSecondsSinceLastEventType(state_id: u32, event_type: u32) -> f64;
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

pub(crate) fn system_idle_seconds() -> Option<f64> {
    // Safety: no pointers; returns a CFTimeInterval (f64).
    let seconds =
        unsafe { CGEventSourceSecondsSinceLastEventType(COMBINED_SESSION_STATE, ANY_INPUT_EVENT) };
    if seconds.is_finite() && seconds >= 0.0 {
        Some(seconds)
    } else {
        None
    }
}

pub(crate) fn screen_is_locked() -> Option<bool> {
    // Safety: returns a +1 CFDictionaryRef, or null when there is no session
    // (a daemon context, say).
    let dict_ref = unsafe { CGSessionCopyCurrentDictionary() };
    if dict_ref.is_null() {
        return None;
    }
    // Safety: taking ownership of the +1 reference.
    let dict: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(dict_ref) };

    let key = CFString::from_static_string("CGSSessionScreenIsLocked");
    match dict.find(&key) {
        // The key is absent entirely when the screen is not locked, which is
        // the common case — absence means unlocked, not unknown.
        None => Some(false),
        Some(value) => value
            .downcast::<CFBoolean>()
            .map(|b| b == CFBoolean::true_value())
            .or(Some(false)),
    }
}
