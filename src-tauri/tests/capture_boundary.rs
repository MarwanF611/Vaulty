//! Tests for the Phase 2 capture path.
//!
//! The capture is the user's own selection on its way into the vault, and it is
//! treated as a secret: the popup is told how many characters were captured and
//! nothing else, and saving it sends a label — never the text. These tests pin
//! that down, along with the two exit criteria in `docs/PHASES.md` that can be
//! checked without a human pressing the shortcut.
//!
//! What is *not* tested here, and cannot be: the synthetic Cmd+C itself. It
//! needs macOS Accessibility, which is granted to a signed app bundle and not
//! to `cargo test`. See the notes at the bottom of `docs/PHASE2-NOTES.md`.

use std::time::Duration;

use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri::{App, Manager};
use tempfile::TempDir;
use vault_platform::CapturedText;
use vaulty_lib::commands::{self, SaveCaptureInput};
use vaulty_lib::settings::Settings;
use vaulty_lib::state::AppState;

const PW: &str = "correct horse battery staple";
const SELECTION: &str = "CAPTURED-SELECTION-NEEDLE";

fn mock_app(dir: &TempDir) -> App<tauri::test::MockRuntime> {
    mock_builder()
        .manage(AppState::new(dir.path().join("vault.db")))
        .build(mock_context(noop_assets()))
        .expect("mock app should build")
}

fn save_input(label: &str) -> SaveCaptureInput {
    SaveCaptureInput {
        label: label.into(),
        tags: vec!["captured".into()],
        kind: "password".into(),
        note: None,
    }
}

// ------------------------------------------------- what the popup may know

#[test]
fn capture_state_reports_a_length_and_never_the_text() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    let state = app.state::<AppState>();

    // Nothing captured yet.
    let s = commands::capture_state(app.state::<AppState>()).unwrap();
    assert!(!s.has_capture);
    assert!(s.char_count.is_none());

    state
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    let s = commands::capture_state(app.state::<AppState>()).unwrap();
    assert!(s.has_capture);
    assert_eq!(s.char_count, Some(SELECTION.chars().count()));

    // The serialised form is what the webview actually receives.
    let json = serde_json::to_string(&s).unwrap();
    assert!(
        !json.contains(SELECTION),
        "capture_state leaked the selection: {json}"
    );
}

#[test]
fn reveal_capture_is_the_explicit_path_to_the_text() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    assert_eq!(
        commands::reveal_capture(app.state::<AppState>())
            .unwrap_err()
            .code,
        "no_capture"
    );

    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    assert_eq!(
        commands::reveal_capture(app.state::<AppState>()).unwrap(),
        SELECTION
    );
}

/// The point of the design: the secret is not a parameter of `save_capture`.
#[test]
fn save_capture_stores_the_selection_without_it_crossing_ipc() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    let meta =
        commands::save_capture(app.state::<AppState>(), save_input("Recovery code")).unwrap();
    assert_eq!(meta.label, "Recovery code");

    // The input carried a label, tags and a kind — and no secret. The stored
    // entry nevertheless holds the captured text.
    // The returned metadata does not echo the secret back.
    let json = serde_json::to_string(&meta).unwrap();
    assert!(
        !json.contains(SELECTION),
        "save_capture echoed the secret: {json}"
    );

    let revealed = commands::reveal_secret(app.state::<AppState>(), meta.id).unwrap();
    assert_eq!(revealed.secret, SELECTION);
}

#[test]
fn a_saved_capture_is_consumed() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    commands::save_capture(app.state::<AppState>(), save_input("One")).unwrap();

    // Saving twice must not silently create a duplicate from a stale capture.
    assert!(
        !commands::capture_state(app.state::<AppState>())
            .unwrap()
            .has_capture
    );
    assert_eq!(
        commands::save_capture(app.state::<AppState>(), save_input("Two"))
            .unwrap_err()
            .code,
        "no_capture"
    );
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap()
            .len(),
        1
    );
}

/// SPEC.md: the captured text is "zeroized if the user cancels".
#[test]
fn discarding_a_capture_removes_it() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();
    commands::discard_capture(app.state::<AppState>()).unwrap();

    assert!(
        !commands::capture_state(app.state::<AppState>())
            .unwrap()
            .has_capture
    );
    assert_eq!(
        commands::reveal_capture(app.state::<AppState>())
            .unwrap_err()
            .code,
        "no_capture"
    );
}

/// Locking ends the session, and a captured secret is part of the session.
#[test]
fn locking_the_vault_discards_a_pending_capture() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    commands::lock_vault(app.state::<AppState>()).unwrap();

    assert!(
        !commands::capture_state(app.state::<AppState>())
            .unwrap()
            .has_capture
    );
}

/// SPEC.md holds the capture across an unlock prompt, so a *locked* vault must
/// not throw it away — only an explicit cancel or a lock does that.
#[test]
fn a_capture_survives_while_the_vault_is_merely_not_yet_unlocked() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    // Vault exists but this session has never unlocked it.
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    let s = commands::capture_state(app.state::<AppState>()).unwrap();
    assert!(s.has_capture);
    assert!(s.locked);

    // Unlocking then saving works, which is the flow SPEC.md describes.
    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    let meta = commands::save_capture(app.state::<AppState>(), save_input("Held")).unwrap();
    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), meta.id)
            .unwrap()
            .secret,
        SELECTION
    );
}

#[test]
fn saving_a_capture_into_a_locked_vault_is_refused() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();
    app.state::<AppState>()
        .set_pending_capture(CapturedText::new(SELECTION.into()))
        .unwrap();

    assert_eq!(
        commands::save_capture(app.state::<AppState>(), save_input("Nope"))
            .unwrap_err()
            .code,
        "locked"
    );
}

// ------------------------------------------------------------- settings

#[test]
fn settings_round_trip_through_commands() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    let s = commands::get_settings(app.state::<AppState>()).unwrap();
    assert_eq!(s.clipboard_clear_seconds, 30);
    assert_eq!(s.shortcut, s.default_shortcut);

    let s = commands::set_clipboard_clear_seconds(app.state::<AppState>(), 60).unwrap();
    assert_eq!(s.clipboard_clear_seconds, 60);

    // And it persists for the next app instance.
    drop(app);
    let restarted = mock_app(&dir);
    assert_eq!(
        commands::get_settings(restarted.state::<AppState>())
            .unwrap()
            .clipboard_clear_seconds,
        60
    );
}

#[test]
fn an_absurd_clipboard_timeout_is_clamped_rather_than_stored() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    let s = commands::set_clipboard_clear_seconds(app.state::<AppState>(), 0).unwrap();
    assert!(
        s.clipboard_clear_seconds >= 5,
        "got {}",
        s.clipboard_clear_seconds
    );

    let s = commands::set_clipboard_clear_seconds(app.state::<AppState>(), u64::MAX).unwrap();
    assert!(
        s.clipboard_clear_seconds <= 600,
        "got {}",
        s.clipboard_clear_seconds
    );
}

#[test]
fn permission_state_is_reported_without_prompting() {
    let p = commands::permission_state();
    assert!(matches!(
        p.accessibility,
        "granted" | "denied" | "not_required" | "unsupported"
    ));
    assert_eq!(
        p.capture_supported,
        cfg!(any(target_os = "macos", target_os = "windows"))
    );
}

// --------------------------------------------------- the 300 ms budget

/// `docs/PHASES.md`: "under 300 ms from keypress to a usable cursor, measured."
///
/// The dominant, controllable cost in that path is how long we are willing to
/// wait for the focused application to service the synthetic copy — and it is
/// paid in full whenever *nothing* is selected, because then the clipboard
/// counter never moves and we wait out the whole deadline.
///
/// This does not measure the real app; it guards the budget. If someone later
/// raises the deadline to "make capture more reliable", this fails and makes
/// the trade-off explicit instead of quietly blowing the target.
#[test]
fn the_capture_deadline_leaves_room_inside_the_300ms_budget() {
    const TARGET: Duration = Duration::from_millis(300);
    // Room for showing and focusing a pre-created window, plus the IPC emit.
    const RESERVED_FOR_WINDOW: Duration = Duration::from_millis(100);

    assert!(
        vaulty_lib::capture_deadline() + RESERVED_FOR_WINDOW <= TARGET,
        "capture deadline {:?} leaves no room inside the {TARGET:?} budget",
        vaulty_lib::capture_deadline()
    );
}

#[test]
fn settings_default_shortcut_matches_the_spec() {
    let s = Settings::default();
    if cfg!(target_os = "macos") {
        assert_eq!(s.shortcut, "CmdOrCtrl+Shift+Space");
    } else {
        assert_eq!(s.shortcut, "Ctrl+Shift+Space");
    }
}
