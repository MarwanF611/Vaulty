//! Vaulty's Tauri shell.
//!
//! Thin by design. Everything that touches key material lives in `vault-core`;
//! this crate owns the window, the app state, and the IPC boundary.

// Public so the IPC-boundary tests in `tests/` can exercise the real command
// functions rather than a reimplementation of them.
pub mod commands;
pub mod error;
pub mod state;

use std::path::PathBuf;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::new(resolve_vault_path());

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
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
        ])
        .on_window_event(|window, event| {
            // Closing the window ends the session. The key is zeroized here
            // rather than left to process teardown (CLAUDE.md rule 4).
            //
            // Idle timeout, system sleep and screen lock are Phase 5.
            if matches!(event, tauri::WindowEvent::Destroyed) {
                use tauri::Manager;
                if let Some(state) = window.app_handle().try_state::<AppState>() {
                    let _ = state.lock();
                }
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
