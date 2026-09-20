//! Windows implementation of the capture primitives.
//!
//! **Unverified.** `docs/PHASES.md` puts "Windows build of everything from
//! phases 1-2 verified" in Phase 4, on a real machine rather than a VM. This
//! compiles and follows the documented APIs, but it has not been run.

#![allow(unsafe_code)]

use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VIRTUAL_KEY, VK_C,
    VK_CONTROL,
};

use crate::error::{PlatformError, Result};

fn key_event(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: if up {
                    KEYEVENTF_KEYUP
                } else {
                    Default::default()
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Post Ctrl+C to the focused window.
///
/// UIPI blocks synthetic input into a process running at higher integrity than
/// ours. That cannot be detected in advance, so it surfaces here as a capture
/// that produced nothing, and the caller falls back to search mode.
pub(crate) fn synthesize_copy() -> Result<()> {
    let inputs = [
        key_event(VK_CONTROL, false),
        key_event(VK_C, false),
        key_event(VK_C, true),
        key_event(VK_CONTROL, true),
    ];

    // Safety: `inputs` is a live, correctly sized array of INPUT for the
    // duration of the call.
    let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };

    if sent as usize == inputs.len() {
        Ok(())
    } else {
        Err(PlatformError::KeystrokeRejected)
    }
}

/// `GetClipboardSequenceNumber` — the Windows equivalent of `changeCount`.
pub(crate) fn clipboard_change_count() -> Option<i64> {
    // Safety: no arguments, returns a DWORD.
    let n = unsafe { GetClipboardSequenceNumber() };
    Some(i64::from(n))
}
