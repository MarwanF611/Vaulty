//! Tests for the one rule this crate exists to enforce.
//!
//! CLAUDE.md rule 1: "No plaintext secret crosses into the webview unless the
//! user explicitly asked to reveal or copy it. The frontend gets labels, tags
//! and metadata. Nothing else."
//!
//! Phase 1's exit criterion is the observable version of that: "Nothing
//! sensitive appears in the webview devtools." What the webview can see is
//! exactly what these commands serialise, so that is what gets asserted —
//! against the real JSON, not against the Rust types.

use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri::{App, Manager};
use tempfile::TempDir;
use vaulty_lib::commands::{self, NewEntryInput, UpdateEntryInput};
use vaulty_lib::state::AppState;

const PW: &str = "correct horse battery staple";
const SECRET: &str = "PLAINTEXT-SECRET-NEEDLE";
const NOTE: &str = "PLAINTEXT-NOTE-NEEDLE";

fn app_with_vault_path(dir: &TempDir) -> App<tauri::test::MockRuntime> {
    mock_builder()
        .manage(AppState::new(dir.path().join("vault.db")))
        .build(mock_context(noop_assets()))
        .expect("mock app should build")
}

fn sample_entry() -> NewEntryInput {
    NewEntryInput {
        label: "GitHub".into(),
        tags: vec!["work".into()],
        kind: "password".into(),
        secret: SECRET.into(),
        note: Some(NOTE.into()),
    }
}

/// Serialise a value the way Tauri serialises a command's return value.
fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialisable")
}

fn assert_no_plaintext(json: &str, what: &str) {
    assert!(!json.contains(SECRET), "{what} leaked the secret: {json}");
    assert!(!json.contains(NOTE), "{what} leaked the note: {json}");
    assert!(
        !json.contains(PW),
        "{what} leaked the master password: {json}"
    );
}

#[test]
fn a_fresh_vault_reports_not_existing_and_locked() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);
    let status = commands::vault_status(app.state::<AppState>()).unwrap();
    assert!(!status.exists);
    assert!(status.locked);
    assert!(status.vault_id.is_none());
    assert!(status.entry_count.is_none());
}

#[test]
fn locked_commands_are_refused_before_unlock() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        commands::search_entries(app.state::<AppState>(), "x".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        commands::add_entry(app.state::<AppState>(), sample_entry())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), uuid::Uuid::now_v7().to_string())
            .unwrap_err()
            .code,
        "locked"
    );
}

#[test]
fn create_unlock_lock_cycle() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    let status = commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert!(status.exists);
    assert!(!status.locked);
    assert_eq!(status.entry_count, Some(0));
    assert_eq!(status.format_version, Some(vault_core::FORMAT_VERSION));

    commands::lock_vault(app.state::<AppState>()).unwrap();
    assert!(
        commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap_err()
            .code,
        "locked"
    );

    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert!(
        !commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );
}

#[test]
fn a_wrong_password_is_reported_as_the_single_auth_code() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    let err = commands::unlock_vault(app.state::<AppState>(), "wrong".into()).unwrap_err();
    assert_eq!(err.code, "auth");
    // The message must not hint at which half failed.
    assert!(!err.message.to_lowercase().contains("password"));
    assert!(
        commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );
}

#[test]
fn creating_a_second_vault_over_an_existing_one_is_refused() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert_eq!(
        commands::create_vault(app.state::<AppState>(), "another".into())
            .unwrap_err()
            .code,
        "invalid"
    );
}

// ------------------------------------------------------ the boundary itself

#[test]
fn list_entries_json_carries_metadata_and_no_plaintext() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();

    let list = commands::list_entries(app.state::<AppState>()).unwrap();
    let json = to_json(&list);

    // What the frontend is supposed to get.
    assert!(json.contains("GitHub"));
    assert!(json.contains("work"));
    assert!(json.contains("password"));
    // What it must never get.
    assert_no_plaintext(&json, "list_entries");
    // And there is no field that could carry one.
    assert!(!json.contains("\"secret\""));
    assert!(!json.contains("\"note\""));
}

#[test]
fn add_and_update_return_metadata_only() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    let added = commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();
    assert_no_plaintext(&to_json(&added), "add_entry");

    let updated = commands::update_entry(
        app.state::<AppState>(),
        added.id.clone(),
        UpdateEntryInput {
            label: Some("GitHub (work)".into()),
            tags: None,
            kind: None,
            secret: None,
            note: None,
        },
    )
    .unwrap();
    assert_eq!(updated.label, "GitHub (work)");
    assert_no_plaintext(&to_json(&updated), "update_entry");

    // The untouched secret survived the relabel.
    let revealed = commands::reveal_secret(app.state::<AppState>(), added.id).unwrap();
    assert_eq!(revealed.secret, SECRET);
}

#[test]
fn vault_status_json_carries_no_plaintext() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();

    let status = commands::vault_status(app.state::<AppState>()).unwrap();
    assert_no_plaintext(&to_json(&status), "vault_status");
}

#[test]
fn search_json_carries_no_plaintext() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();

    let hits = commands::search_entries(app.state::<AppState>(), "git".into()).unwrap();
    assert_eq!(hits.len(), 1);
    assert_no_plaintext(&to_json(&hits), "search_entries");

    // Searching for the secret itself must not find it: the index is labels
    // and tags, and the secret is in neither.
    assert!(
        commands::search_entries(app.state::<AppState>(), SECRET.into())
            .unwrap()
            .is_empty()
    );
}

/// The one command allowed to return plaintext, and only when asked.
#[test]
fn reveal_secret_is_the_only_path_to_plaintext() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    let meta = commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();

    let revealed = commands::reveal_secret(app.state::<AppState>(), meta.id).unwrap();
    assert_eq!(revealed.secret, SECRET);
    assert_eq!(revealed.note.as_deref(), Some(NOTE));

    // Even so, it must not be Debug-printable.
    let debugged = format!("{revealed:?}");
    assert!(!debugged.contains(SECRET), "Debug leaked the secret");
    assert!(!debugged.contains(NOTE), "Debug leaked the note");
    assert!(debugged.contains("[redacted]"));
}

#[test]
fn revealing_a_deleted_entry_reports_not_found() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    let meta = commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();
    commands::delete_entry(app.state::<AppState>(), meta.id.clone()).unwrap();

    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), meta.id)
            .unwrap_err()
            .code,
        "not_found"
    );
    assert!(commands::list_entries(app.state::<AppState>())
        .unwrap()
        .is_empty());
}

#[test]
fn a_malformed_id_is_rejected_without_touching_the_vault() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), "not-a-uuid".into())
            .unwrap_err()
            .code,
        "invalid"
    );
    assert_eq!(
        commands::delete_entry(app.state::<AppState>(), "../../etc/passwd".into())
            .unwrap_err()
            .code,
        "invalid"
    );
}

// ------------------------------------------------------------- persistence

/// Phase 1 exit criterion: "Entries survive restart."
#[test]
fn entries_survive_a_restart() {
    let dir = TempDir::new().unwrap();

    let id = {
        let app = app_with_vault_path(&dir);
        commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
        commands::add_entry(app.state::<AppState>(), sample_entry())
            .unwrap()
            .id
    }; // app dropped: state dropped, key zeroized

    // A completely separate app instance over the same file.
    let app = app_with_vault_path(&dir);
    assert!(
        commands::vault_status(app.state::<AppState>())
            .unwrap()
            .exists
    );
    assert!(
        commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );

    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), id)
            .unwrap()
            .secret,
        SECRET
    );
}

#[test]
fn changing_the_master_password_takes_effect_across_a_restart() {
    let dir = TempDir::new().unwrap();

    {
        let app = app_with_vault_path(&dir);
        commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
        commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();
        commands::change_master_password(
            app.state::<AppState>(),
            PW.into(),
            "a new master password".into(),
        )
        .unwrap();
    }

    let app = app_with_vault_path(&dir);
    assert_eq!(
        commands::unlock_vault(app.state::<AppState>(), PW.into())
            .unwrap_err()
            .code,
        "auth"
    );
    commands::unlock_vault(app.state::<AppState>(), "a new master password".into()).unwrap();
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn locking_drops_the_key_and_a_later_command_cannot_read() {
    let dir = TempDir::new().unwrap();
    let app = app_with_vault_path(&dir);

    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
    let meta = commands::add_entry(app.state::<AppState>(), sample_entry()).unwrap();

    commands::lock_vault(app.state::<AppState>()).unwrap();

    assert_eq!(
        commands::reveal_secret(app.state::<AppState>(), meta.id)
            .unwrap_err()
            .code,
        "locked"
    );
    // Locking twice is not an error.
    commands::lock_vault(app.state::<AppState>()).unwrap();
}
