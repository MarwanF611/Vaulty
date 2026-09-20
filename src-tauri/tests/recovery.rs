//! Phase 5: crash recovery from a snapshot.
//!
//! `docs/PHASES.md`: "Crash recovery from snapshot, tested by corrupting a live
//! vault." So these tests do exactly that — write garbage over a real vault
//! file and check it comes back — rather than testing the restore in isolation
//! where the interesting failure cannot happen.

use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri::{App, Manager};
use tempfile::TempDir;
use vaulty_lib::commands::{self, NewEntryInput};
use vaulty_lib::state::AppState;

const PW: &str = "correct horse battery staple";
const SECRET: &str = "do-not-lose-this";

fn mock_app(dir: &TempDir) -> App<tauri::test::MockRuntime> {
    mock_builder()
        .manage(AppState::new(dir.path().join("vault.db")))
        .build(mock_context(noop_assets()))
        .expect("mock app should build")
}

fn entry(label: &str) -> NewEntryInput {
    NewEntryInput {
        label: label.into(),
        tags: vec![],
        kind: "password".into(),
        secret: SECRET.into(),
        note: None,
    }
}

#[test]
fn a_healthy_vault_reports_itself_readable() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    // No vault at all is "readable": there is nothing wrong, just nothing there.
    let s = commands::vault_status(app.state::<AppState>()).unwrap();
    assert!(!s.exists);
    assert!(s.readable);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    let s = commands::vault_status(app.state::<AppState>()).unwrap();
    assert!(s.exists);
    assert!(s.readable);
}

#[test]
fn a_corrupt_vault_is_reported_as_unreadable() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    std::fs::write(dir.path().join("vault.db"), b"\x00\x00 not a database \x00").unwrap();

    let s = commands::vault_status(app.state::<AppState>()).unwrap();
    assert!(s.exists, "the file is still there");
    assert!(!s.readable, "but it cannot be opened");
}

#[test]
fn snapshots_are_listed_newest_first() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();

    assert!(commands::list_snapshots(app.state::<AppState>())
        .unwrap()
        .is_empty());

    commands::add_entry(app.state::<AppState>(), entry("First")).unwrap();
    commands::snapshot_now(app.state::<AppState>()).unwrap();
    commands::add_entry(app.state::<AppState>(), entry("Second")).unwrap();
    let snaps = commands::snapshot_now(app.state::<AppState>()).unwrap();

    assert_eq!(snaps.len(), 2);
    assert_eq!(snaps[0].index, 1);
    assert!(snaps[0].size_bytes > 0);
    assert!(snaps[0].path.ends_with(".snap1"));
}

/// Only three are kept (SPEC.md, "File locations").
#[test]
fn snapshots_stop_at_three() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();

    for i in 0..5 {
        commands::add_entry(app.state::<AppState>(), entry(&format!("E{i}"))).unwrap();
        commands::snapshot_now(app.state::<AppState>()).unwrap();
    }
    assert_eq!(
        commands::list_snapshots(app.state::<AppState>())
            .unwrap()
            .len(),
        3
    );
}

/// The scenario the feature exists for.
#[test]
fn a_corrupted_live_vault_is_recovered_from_a_snapshot() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    let meta = commands::add_entry(app.state::<AppState>(), entry("Important")).unwrap();
    commands::snapshot_now(app.state::<AppState>()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    // The bad sector.
    std::fs::write(dir.path().join("vault.db"), b"\xde\xad\xbe\xef corrupted").unwrap();
    assert!(
        !commands::vault_status(app.state::<AppState>())
            .unwrap()
            .readable
    );
    assert!(commands::unlock_vault(app.state::<AppState>(), PW.into()).is_err());

    let status = commands::restore_snapshot(app.state::<AppState>(), 1).unwrap();
    assert!(status.readable);
    assert!(status.locked, "a restore must not leave the vault open");

    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), meta.id)
            .unwrap()
            .secret,
        SECRET
    );
}

/// Recovery has to work when the vault cannot be opened, so it must not require
/// an unlocked — or even readable — vault.
#[test]
fn recovery_does_not_require_an_unlocked_vault() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), entry("Important")).unwrap();
    commands::snapshot_now(app.state::<AppState>()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    std::fs::write(dir.path().join("vault.db"), b"garbage").unwrap();

    // Listing works on an unreadable vault ...
    assert_eq!(
        commands::list_snapshots(app.state::<AppState>())
            .unwrap()
            .len(),
        1
    );
    // ... and so does restoring.
    commands::restore_snapshot(app.state::<AppState>(), 1).unwrap();
    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
}

/// A restore should be undoable: the corrupt file is evidence, and a mistaken
/// restore should not be final.
#[test]
fn the_replaced_file_is_kept_alongside() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), entry("Important")).unwrap();
    commands::snapshot_now(app.state::<AppState>()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    std::fs::write(dir.path().join("vault.db"), b"the corrupt original").unwrap();
    commands::restore_snapshot(app.state::<AppState>(), 1).unwrap();

    let kept = dir.path().join("vault.db.prerestore");
    assert!(kept.exists(), "the replaced file should be kept");
    assert_eq!(std::fs::read(&kept).unwrap(), b"the corrupt original");
}

#[test]
fn restoring_a_snapshot_that_does_not_exist_is_refused() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();

    let err = commands::restore_snapshot(app.state::<AppState>(), 3).unwrap_err();
    assert_eq!(err.code, "not_found");
    // And the live vault is untouched.
    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
}

/// Restoring drops the key: continuing to hold one for a file that has been
/// replaced underneath is how you get a confusing failure two screens later.
#[test]
fn restoring_locks_the_vault_first() {
    let dir = TempDir::new().unwrap();
    let app = mock_app(&dir);
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), entry("Important")).unwrap();
    commands::snapshot_now(app.state::<AppState>()).unwrap();

    // Still unlocked here.
    assert!(
        !commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );

    let status = commands::restore_snapshot(app.state::<AppState>(), 1).unwrap();
    assert!(status.locked);
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap_err()
            .code,
        "locked"
    );
}
