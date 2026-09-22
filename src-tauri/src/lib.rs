//! Vaulty's Tauri shell.
//!
//! Thin by design. Everything that touches key material lives in `vault-core`;
//! everything that touches the OS lives in `vault-platform`. This crate owns
//! the windows, the app state, and the IPC boundary.

mod autolock;
mod capture;

/// The capture sequence's wait budget, exposed for the timing test in
/// `tests/capture_boundary.rs` that guards the 300 ms target.
pub fn capture_deadline() -> std::time::Duration {
    capture::CAPTURE_DEADLINE
}

// Public so the IPC-boundary tests in `tests/` can exercise the real command
// functions rather than a reimplementation of them.
pub mod commands;
pub mod error;
pub mod popup;
pub mod settings;
pub mod shortcut;
pub mod state;

use std::path::PathBuf;

use tauri::{Manager, WindowEvent};
use tauri_plugin_global_shortcut::ShortcutState;

use state::AppState;

/// Where the vault lives.
///
/// `VAULTY_VAULT_PATH` overrides it, which is what the smoke tests and manual
/// runs use so they never touch a real vault. Falling back to `./vault.db` when
/// the per-OS app data directory cannot be determined keeps the app usable
/// instead of failing to start.
fn resolve_vault_path() -> PathBuf {
    if let Some(p) = std::env::var_os("VAULTY_VAULT_PATH") {
        return PathBuf::from(p);
    }
    vault_core::default_vault_path().unwrap_or_else(|| PathBuf::from("vault.db"))
}

/// Route the right-click "Add to Vaulty" item into the capture popup.
///
/// AppKit needs the provider registered on the main thread, and early: when a
/// Services request is what *launches* the app, the request is delivered once
/// launch finishes, so a provider registered late misses it. `setup` runs on
/// the main thread, so the direct call normally succeeds; the fallback covers
/// the case where it does not.
fn register_services(handle: &tauri::AppHandle) {
    let make_handler =
        |app: tauri::AppHandle| -> Box<dyn Fn(vault_platform::CapturedText) + Send + Sync> {
            Box::new(move |text| {
                // Leave the AppKit callback promptly — the requesting app is
                // waiting on it — and drive the window from a worker, exactly as
                // the shortcut path does.
                let app = app.clone();
                std::thread::spawn(move || popup::on_service_text(&app, text));
            })
        };

    if vault_platform::register_services_handler(make_handler(handle.clone())) {
        return;
    }
    let for_main = handle.clone();
    let _ = handle.run_on_main_thread(move || {
        let _ = vault_platform::register_services_handler(make_handler(for_main));
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::new(resolve_vault_path());

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state() != ShortcutState::Pressed {
                        return;
                    }
                    // The capture sequence waits on another application to
                    // service a synthetic Cmd+C, so it must not run on the
                    // shortcut dispatch thread.
                    let app = app.clone();
                    std::thread::spawn(move || popup::on_shortcut(&app));
                })
                .build(),
        )
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            // Phase 1 — vault lifecycle and entries
            commands::vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::change_master_password,
            commands::list_entries,
            commands::search_entries,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::reveal_secret,
            commands::copy_secret,
            commands::take_snapshot,
            commands::export_encrypted,
            // Phase 2 — capture, permissions, settings
            commands::capture_state,
            commands::reveal_capture,
            commands::save_capture,
            commands::discard_capture,
            commands::hide_popup,
            commands::permission_state,
            commands::request_accessibility,
            commands::open_accessibility_settings,
            commands::get_settings,
            commands::set_shortcut,
            commands::set_clipboard_clear_seconds,
            commands::set_idle_lock_seconds,
            commands::lock_reason_message,
            commands::list_snapshots,
            commands::restore_snapshot,
            commands::snapshot_now,
            // Phase 3 — biometrics
            commands::biometric_state,
            commands::enable_biometrics,
            commands::disable_biometrics,
            commands::unlock_with_biometrics,
        ])
        .setup(|app| {
            let handle = app.handle();

            // Bind the configured shortcut. A binding another application
            // already owns is not fatal: the app still works from its window,
            // and the settings screen reports the conflict so the user can
            // pick something else (SPEC.md).
            let configured = app
                .state::<AppState>()
                .settings()
                .map(|s| s.shortcut)
                .unwrap_or_else(|_| settings::DEFAULT_SHORTCUT.to_string());

            if let Err(e) = shortcut::register(handle, &configured) {
                eprintln!("vaulty: {}", e.message(&configured));
            }

            // Auto-lock runs for the life of the app (SECURITY.md: lock on
            // sleep and screen lock, not only on an idle timer).
            autolock::spawn(handle.clone());

            register_services(handle);
            Ok(())
        })
        .on_window_event(|window, event| {
            if !matches!(
                event,
                WindowEvent::Destroyed | WindowEvent::CloseRequested { .. }
            ) {
                return;
            }
            let Some(state) = window.app_handle().try_state::<AppState>() else {
                return;
            };

            if window.label() == popup::POPUP_LABEL {
                // Dismissing the popup cancels the capture (SPEC.md: zeroized
                // if the user cancels) but leaves the session alone.
                let _ = state.discard_capture();
            } else if matches!(event, WindowEvent::Destroyed) {
                // Closing the main window ends the session. The key is zeroized
                // here rather than left to process teardown (CLAUDE.md rule 4).
                //
                // Idle timeout, system sleep and screen lock are Phase 5.
                let _ = state.lock();
            }
        })
        .run(tauri::generate_context!());

    if let Err(e) = result {
        // No secret material reaches this path: startup failures are about
        // windows and webviews, not vaults.
        eprintln!("vaulty: could not start: {e}");
        std::process::exit(1);
    }
}
