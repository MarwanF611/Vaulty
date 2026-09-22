//! macOS Services: "Add to Vaulty" in the right-click menu of any app.
//!
//! `docs/SPEC.md`, "macOS Services entry": declare an `NSServices` entry in
//! `Info.plist` so "Add to Vault" appears in the right-click menu of every
//! Cocoa app.
//!
//! Two halves have to agree, and they live in different files:
//!
//! * `src-tauri/Info.plist` declares the service: its menu title, the message
//!   (`addToVaulty`) and the port name ([`SERVICES_PORT_NAME`]). macOS reads this from
//!   the *installed bundle* — which is why the entry never appears for a
//!   `cargo tauri dev` binary.
//! * This file registers the object that receives the message, under the same
//!   port name. `tests/window_config.rs` checks the two strings match, because a
//!   mismatch fails silently: the menu item appears and does nothing.
//!
//! # Why this path is the cleaner one
//!
//! AppKit hands the selection over on a *private* pasteboard. So unlike the
//! global shortcut there is no synthetic Cmd+C, no Accessibility permission,
//! and the user's clipboard is never read, cleared or restored — there is
//! nothing to put back.

#![allow(unsafe_code)]

use std::sync::OnceLock;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{define_class, msg_send, AllocAnyThread};
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::{MainThreadMarker, NSObjectProtocol, NSString};

use crate::{CapturedText, SERVICES_PORT_NAME};

type Handler = Box<dyn Fn(CapturedText) + Send + Sync + 'static>;

/// Set once, at registration. A second registration is refused rather than
/// silently replacing where captured text goes.
static HANDLER: OnceLock<Handler> = OnceLock::new();

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and this class has no
    // Drop impl and no ivars.
    #[unsafe(super(NSObject))]
    #[name = "VaultyServicesProvider"]
    struct ServicesProvider;

    impl ServicesProvider {
        /// `- (void)addToVaulty:(NSPasteboard *)pboard
        ///                userData:(NSString *)userData
        ///                   error:(NSString **)error`
        ///
        /// Called by AppKit on the main thread when the user picks
        /// "Add to Vaulty". Must return promptly: the requesting app waits.
        #[unsafe(method(addToVaulty:userData:error:))]
        fn add_to_vaulty(
            &self,
            pboard: &NSPasteboard,
            _user_data: Option<&NSString>,
            _error: *mut *mut AnyObject,
        ) {
            let Some(handler) = HANDLER.get() else {
                return;
            };
            // SAFETY: a framework-owned constant, read not written.
            let string_type = unsafe { NSPasteboardTypeString };
            let Some(text) = pboard.stringForType(string_type) else {
                return;
            };
            let text = text.to_string();
            if text.is_empty() {
                return;
            }
            // From here the selection is handled exactly like a capture:
            // zeroizing, never Debug-printed, held in Rust.
            handler(CapturedText::new(text));
        }
    }

    unsafe impl NSObjectProtocol for ServicesProvider {}
);

impl ServicesProvider {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        // SAFETY: NSObject's designated initialiser.
        unsafe { msg_send![super(this), init] }
    }
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {
    fn NSRegisterServicesProvider(provider: *mut AnyObject, name: *const AnyObject);
    fn NSUpdateDynamicServices();
}

/// Register the handler that receives "Add to Vaulty" text.
///
/// Returns `false` if not on the main thread (AppKit requires it) or if a
/// handler is already registered.
///
/// Registered explicitly under [`SERVICES_PORT_NAME`] with `NSRegisterServicesProvider`
/// rather than `-[NSApplication setServicesProvider:]`, because the latter uses
/// the process name — which is the executable's name, not the product name,
/// and would drift from `Info.plist` the first time the binary is renamed.
pub(crate) fn register(handler: Handler) -> bool {
    if MainThreadMarker::new().is_none() {
        return false;
    }
    if HANDLER.set(handler).is_err() {
        return false;
    }

    let provider = ServicesProvider::new();
    let name = NSString::from_str(SERVICES_PORT_NAME);

    // SAFETY: both pointers are live, retained objects; on the main thread.
    unsafe {
        NSRegisterServicesProvider(
            Retained::as_ptr(&provider) as *mut AnyObject,
            Retained::as_ptr(&name) as *const AnyObject,
        );
        NSUpdateDynamicServices();
    }

    // Both must outlive every future service request, which is the life of the
    // process. Whether AppKit retains them is not documented, so they are
    // leaked on purpose — one small object each, once.
    std::mem::forget(provider);
    std::mem::forget(name);
    true
}
