//! Integration tests for the Phase 0 exit criteria (`docs/PHASES.md`).
//!
//! > the CLI creates a vault, adds and reads entries, survives restart. Tests
//! > prove the file is unreadable without the password, that a flipped byte
//! > fails cleanly, and that swapping a label between two entries fails
//! > authentication.
//!
//! These drive the public API only — no access to crate internals — so they
//! also serve as a check that the surface `src-tauri` will call in Phase 1 is
//! usable without reaching past it.

use std::path::Path;
use tempfile::tempdir;
use vault_core::{EntryKind, EntryUpdate, Error, KdfParams, NewEntry, PlaintextAck, Vault};
use zeroize::Zeroizing;

/// Argon2 at production cost would make this suite take minutes. The
/// construction under test is identical; only the work factor differs.
fn cheap() -> KdfParams {
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 2,
        p_cost: 1,
    }
}

const PW: &[u8] = b"correct horse battery staple";

fn new_vault(path: &Path) -> Vault {
    Vault::create_with_params(path, PW, cheap()).unwrap()
}

fn entry(label: &str, secret: &str) -> NewEntry {
    NewEntry {
        label: label.into(),
        tags: vec!["test".into()],
        kind: EntryKind::Password,
        secret: Zeroizing::new(secret.into()),
        note: None,
    }
}

// --------------------------------------------------------------- lifecycle

#[test]
fn create_add_read() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));

    let meta = v.add_entry(entry("GitHub", "ghp_supersecret")).unwrap();
    assert_eq!(meta.label, "GitHub");
    assert_eq!(meta.tags, vec!["test".to_string()]);

    let revealed = v.get_entry(&meta.id).unwrap();
    assert_eq!(revealed.secret.as_str(), "ghp_supersecret");
    assert!(revealed.note.is_none());
}

#[test]
fn a_new_vault_starts_unlocked_and_an_opened_one_starts_locked() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let v = new_vault(&p);
    assert!(!v.is_locked());
    drop(v);

    let v = Vault::open(&p).unwrap();
    assert!(v.is_locked());
}

#[test]
fn entries_survive_a_restart() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let id = {
        let mut v = new_vault(&p);
        let m = v.add_entry(entry("Router", "admin123")).unwrap();
        v.add_entry(entry("Wifi", "hunter2")).unwrap();
        m.id
    }; // vault dropped: key zeroized, file closed

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(v.list_entries().unwrap().len(), 2);
    assert_eq!(v.get_entry(&id).unwrap().secret.as_str(), "admin123");
}

#[test]
fn locked_vault_refuses_every_read() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let mut v = new_vault(&p);
    let meta = v.add_entry(entry("GitHub", "ghp_x")).unwrap();
    v.lock();

    assert!(v.is_locked());
    assert!(matches!(v.list_entries(), Err(Error::Locked)));
    assert!(matches!(v.get_entry(&meta.id), Err(Error::Locked)));
    assert!(matches!(v.get_meta(&meta.id), Err(Error::Locked)));
    assert!(matches!(v.search("git"), Err(Error::Locked)));
    assert!(matches!(v.add_entry(entry("x", "y")), Err(Error::Locked)));
    assert!(matches!(
        v.update_entry(&meta.id, EntryUpdate::default()),
        Err(Error::Locked)
    ));
    assert!(matches!(v.delete_entry(&meta.id), Err(Error::Locked)));

    // ... and unlocking brings it back.
    v.unlock(PW).unwrap();
    assert_eq!(v.get_entry(&meta.id).unwrap().secret.as_str(), "ghp_x");
}

#[test]
fn wrong_password_does_not_unlock_and_leaves_the_vault_locked() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    drop(new_vault(&p));

    let mut v = Vault::open(&p).unwrap();
    let err = v.unlock(b"not the password").unwrap_err();
    assert!(err.is_auth_failure());
    assert!(v.is_locked());

    v.unlock(PW).unwrap();
    assert!(!v.is_locked());
}

#[test]
fn creating_over_an_existing_vault_is_refused() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    drop(new_vault(&p));
    assert!(Vault::create_with_params(&p, b"other", cheap()).is_err());
}

#[test]
fn an_empty_master_password_is_refused() {
    let dir = tempdir().unwrap();
    assert!(Vault::create_with_params(&dir.path().join("v.db"), b"", cheap()).is_err());
}

// ------------------------------------------------------------------- CRUD

#[test]
fn update_changes_what_was_asked_and_nothing_else() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));

    let meta = v
        .add_entry(NewEntry {
            label: "Bank".into(),
            tags: vec!["money".into()],
            kind: EntryKind::Password,
            secret: Zeroizing::new("pin-1234".into()),
            note: Some(Zeroizing::new("second factor in the drawer".into())),
        })
        .unwrap();

    // Change only the label.
    let updated = v
        .update_entry(
            &meta.id,
            EntryUpdate {
                label: Some("Bank of Somewhere".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.label, "Bank of Somewhere");
    assert_eq!(updated.tags, vec!["money".to_string()]);
    assert_eq!(updated.created_at, meta.created_at);

    let r = v.get_entry(&meta.id).unwrap();
    assert_eq!(
        r.secret.as_str(),
        "pin-1234",
        "secret must survive a relabel"
    );
    assert_eq!(
        r.note.as_deref().map(|s| s.as_str()),
        Some("second factor in the drawer")
    );

    // Change only the secret.
    v.update_entry(
        &meta.id,
        EntryUpdate {
            secret: Some(Zeroizing::new("pin-5678".into())),
            ..Default::default()
        },
    )
    .unwrap();
    let r = v.get_entry(&meta.id).unwrap();
    assert_eq!(r.secret.as_str(), "pin-5678");
    assert_eq!(r.meta.label, "Bank of Somewhere");
}

#[test]
fn a_note_can_be_cleared_explicitly() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));
    let meta = v
        .add_entry(NewEntry {
            label: "X".into(),
            tags: vec![],
            kind: EntryKind::Note,
            secret: Zeroizing::new("s".into()),
            note: Some(Zeroizing::new("delete me".into())),
        })
        .unwrap();

    v.update_entry(
        &meta.id,
        EntryUpdate {
            note: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(v.get_entry(&meta.id).unwrap().note.is_none());
}

#[test]
fn delete_leaves_a_tombstone_and_the_entry_is_gone() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));
    let meta = v.add_entry(entry("Temp", "throwaway")).unwrap();

    v.delete_entry(&meta.id).unwrap();

    assert!(matches!(v.get_entry(&meta.id), Err(Error::NotFound)));
    assert!(matches!(v.get_meta(&meta.id), Err(Error::NotFound)));
    assert!(v.list_entries().unwrap().is_empty());
    assert!(matches!(v.delete_entry(&meta.id), Err(Error::NotFound)));
}

#[test]
fn change_seq_advances_on_every_mutation() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));

    let a = v.add_entry(entry("A", "1")).unwrap();
    let b = v.add_entry(entry("B", "2")).unwrap();
    assert!(b.change_seq > a.change_seq);

    let updated = v
        .update_entry(
            &a.id,
            EntryUpdate {
                label: Some("A2".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(updated.change_seq > b.change_seq);
}

#[test]
fn search_matches_labels_and_tags_case_insensitively() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));
    v.add_entry(NewEntry {
        label: "GitHub".into(),
        tags: vec!["Work".into()],
        kind: EntryKind::Password,
        secret: Zeroizing::new("a".into()),
        note: None,
    })
    .unwrap();
    v.add_entry(NewEntry {
        label: "Home Router".into(),
        tags: vec!["house".into()],
        kind: EntryKind::Wifi,
        secret: Zeroizing::new("b".into()),
        note: None,
    })
    .unwrap();

    assert_eq!(v.search("github").unwrap().len(), 1);
    assert_eq!(v.search("GITHUB").unwrap().len(), 1);
    assert_eq!(v.search("work").unwrap().len(), 1);
    assert_eq!(v.search("o").unwrap().len(), 2);
    assert_eq!(v.search("").unwrap().len(), 2);
    assert!(v.search("nothing here").unwrap().is_empty());
}

#[test]
fn reading_an_entry_marks_it_recently_used() {
    let dir = tempdir().unwrap();
    let mut v = new_vault(&dir.path().join("vault.db"));
    let meta = v.add_entry(entry("A", "1")).unwrap();
    assert!(meta.last_used_at.is_none());

    v.get_entry(&meta.id).unwrap();
    assert!(v.get_meta(&meta.id).unwrap().last_used_at.is_some());
}

// ----------------------------------------------------- exit criterion: secrecy

/// "Tests prove the file is unreadable without the password."
#[test]
fn no_plaintext_secret_appears_anywhere_in_the_file() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    {
        let mut v = new_vault(&p);
        v.add_entry(NewEntry {
            label: "Searchable Label".into(),
            tags: vec!["findme".into()],
            kind: EntryKind::Password,
            secret: Zeroizing::new("PLAINTEXT-SECRET-NEEDLE".into()),
            note: Some(Zeroizing::new("PLAINTEXT-NOTE-NEEDLE".into())),
        })
        .unwrap();
    }

    let bytes = std::fs::read(&p).unwrap();
    assert!(
        !contains(&bytes, b"PLAINTEXT-SECRET-NEEDLE"),
        "the secret is on disk in the clear"
    );
    assert!(
        !contains(&bytes, b"PLAINTEXT-NOTE-NEEDLE"),
        "the note is on disk in the clear"
    );
    assert!(
        !contains(&bytes, PW),
        "the master password is on disk in the clear"
    );

    // The label *is* clear text, and that is the documented trade
    // (SPEC.md, "Data model"). Asserting it keeps the decision visible: if this
    // ever changes, it should change deliberately.
    assert!(contains(&bytes, b"Searchable Label"));
}

#[test]
fn an_opened_vault_reveals_nothing_before_unlock() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    {
        let mut v = new_vault(&p);
        v.add_entry(entry("GitHub", "ghp_x")).unwrap();
    }
    let v = Vault::open(&p).unwrap();
    assert!(matches!(v.list_entries(), Err(Error::Locked)));
}

#[cfg(unix)]
#[test]
fn the_vault_file_is_not_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    drop(new_vault(&p));

    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "vault file mode was {mode:o}");
}

// ------------------------------------------ exit criterion: tamper detection

/// "a flipped byte fails cleanly"
#[test]
fn flipping_a_byte_of_the_ciphertext_fails_cleanly() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let id = {
        let mut v = new_vault(&p);
        v.add_entry(entry("GitHub", "ghp_supersecret_value"))
            .unwrap()
            .id
    };

    // Flip a bit inside the stored ciphertext, reaching past the API on purpose.
    let conn = rusqlite::Connection::open(&p).unwrap();
    let mut ct: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM entries WHERE id = ?1",
            rusqlite::params![id.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    ct[0] ^= 0x01;
    conn.execute(
        "UPDATE entries SET ciphertext = ?2 WHERE id = ?1",
        rusqlite::params![id.as_bytes().as_slice(), ct],
    )
    .unwrap();
    drop(conn);

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();

    let err = v.get_entry(&id).unwrap_err();
    assert!(
        err.is_auth_failure(),
        "a flipped byte must be an auth failure, got {err:?}"
    );
    // Metadata still reads: only the sealed payload is broken.
    assert!(v.get_meta(&id).is_ok());
}

/// "swapping a label between two entries fails authentication"
///
/// This is the test the associated-data design exists for.
#[test]
fn swapping_labels_between_two_entries_fails_authentication() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let (id_a, id_b) = {
        let mut v = new_vault(&p);
        let a = v.add_entry(entry("Personal Email", "personal-pw")).unwrap();
        let b = v.add_entry(entry("Work Email", "work-pw")).unwrap();
        (a.id, b.id)
    };

    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.execute_batch(
        "UPDATE entries SET label = 'TEMP' WHERE label = 'Personal Email';
         UPDATE entries SET label = 'Personal Email' WHERE label = 'Work Email';
         UPDATE entries SET label = 'Work Email' WHERE label = 'TEMP';",
    )
    .unwrap();
    drop(conn);

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();

    // The swap took effect in the clear-text column ...
    assert_eq!(v.get_meta(&id_a).unwrap().label, "Work Email");
    assert_eq!(v.get_meta(&id_b).unwrap().label, "Personal Email");

    // ... and both secrets are now unreadable, rather than silently attached to
    // the wrong label.
    assert!(v.get_entry(&id_a).unwrap_err().is_auth_failure());
    assert!(v.get_entry(&id_b).unwrap_err().is_auth_failure());
}

#[test]
fn retagging_or_rekinding_an_entry_behind_the_api_fails_authentication() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    let id = {
        let mut v = new_vault(&p);
        v.add_entry(entry("A", "s")).unwrap().id
    };

    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.execute(
        "UPDATE entries SET tags = 'injected' WHERE id = ?1",
        rusqlite::params![id.as_bytes().as_slice()],
    )
    .unwrap();
    drop(conn);

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
    assert!(v.get_entry(&id).unwrap_err().is_auth_failure());
}

#[test]
fn moving_a_ciphertext_onto_a_different_entry_fails_authentication() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    let (id_a, id_b) = {
        let mut v = new_vault(&p);
        let a = v.add_entry(entry("A", "secret-a")).unwrap();
        let b = v.add_entry(entry("B", "secret-b")).unwrap();
        (a.id, b.id)
    };

    // Copy A's sealed payload wholesale onto B. The entry id is in the
    // associated data, so this must not decrypt.
    let conn = rusqlite::Connection::open(&p).unwrap();
    let (nonce, ct): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT nonce, ciphertext FROM entries WHERE id = ?1",
            rusqlite::params![id_a.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    conn.execute(
        "UPDATE entries SET nonce = ?2, ciphertext = ?3 WHERE id = ?1",
        rusqlite::params![id_b.as_bytes().as_slice(), nonce, ct],
    )
    .unwrap();
    drop(conn);

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
    assert!(v.get_entry(&id_b).unwrap_err().is_auth_failure());
}

#[test]
fn a_truncated_vault_file_fails_to_open_rather_than_panicking() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    drop(new_vault(&p));

    let bytes = std::fs::read(&p).unwrap();
    std::fs::write(&p, &bytes[..bytes.len() / 2]).unwrap();

    // Either opening fails, or unlocking does. Neither may panic.
    match Vault::open(&p) {
        Err(_) => {}
        Ok(mut v) => {
            assert!(v.unlock(PW).is_err());
        }
    }
}

// ------------------------------------------------------- master password

#[test]
fn change_master_password_rewraps_without_touching_entries() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let mut v = new_vault(&p);
    let meta = v.add_entry(entry("GitHub", "ghp_stays_the_same")).unwrap();

    // The ciphertext before the password change ...
    let conn = rusqlite::Connection::open(&p).unwrap();
    let before: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM entries WHERE id = ?1",
            rusqlite::params![meta.id.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);

    v.change_master_password(PW, b"a brand new master password")
        .unwrap();

    // ... is byte-for-byte the same afterwards. Only the slot was rewrapped.
    let conn = rusqlite::Connection::open(&p).unwrap();
    let after: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM entries WHERE id = ?1",
            rusqlite::params![meta.id.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(before, after, "entries must not be re-encrypted");

    // The session stays usable, and the new password works after a restart.
    assert_eq!(
        v.get_entry(&meta.id).unwrap().secret.as_str(),
        "ghp_stays_the_same"
    );
    drop(v);

    let mut v = Vault::open(&p).unwrap();
    assert!(v.unlock(PW).is_err(), "the old password must stop working");
    v.unlock(b"a brand new master password").unwrap();
    assert_eq!(
        v.get_entry(&meta.id).unwrap().secret.as_str(),
        "ghp_stays_the_same"
    );
}

#[test]
fn change_master_password_requires_the_current_one() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    let mut v = new_vault(&p);

    assert!(v
        .change_master_password(b"wrong", b"new-pw")
        .unwrap_err()
        .is_auth_failure());
    assert!(v.change_master_password(PW, b"").is_err());

    // The original password still works: a failed change must not half-apply.
    drop(v);
    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
}

// -------------------------------------------------------------- snapshots

#[test]
fn snapshots_are_taken_rotated_and_restorable() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let mut v = new_vault(&p);
    let meta = v.add_entry(entry("Keeper", "value-to-recover")).unwrap();
    v.snapshot().unwrap();

    // Destroy the entry after the snapshot was taken.
    v.delete_entry(&meta.id).unwrap();
    assert!(v.list_entries().unwrap().is_empty());
    drop(v);

    vault_core::atomic::restore_snapshot(&p, 1).unwrap();

    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(v.list_entries().unwrap().len(), 1);
    assert_eq!(
        v.get_entry(&meta.id).unwrap().secret.as_str(),
        "value-to-recover"
    );
}

#[test]
fn only_three_snapshots_are_kept() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    let mut v = new_vault(&p);

    for i in 0..5 {
        v.add_entry(entry(&format!("E{i}"), "s")).unwrap();
        v.snapshot().unwrap();
    }
    assert_eq!(v.snapshots().len(), 3);
}

#[test]
fn restoring_from_a_corrupt_live_vault_recovers_it() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");

    let mut v = new_vault(&p);
    let meta = v.add_entry(entry("Important", "do-not-lose-this")).unwrap();
    v.snapshot().unwrap();
    drop(v);

    // Simulate the bad sector.
    std::fs::write(&p, b"\x00\x00\x00 corrupted beyond repair \x00\x00\x00").unwrap();
    assert!(Vault::open(&p).and_then(|mut v| v.unlock(PW)).is_err());

    vault_core::atomic::restore_snapshot(&p, 1).unwrap();
    let mut v = Vault::open(&p).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(
        v.get_entry(&meta.id).unwrap().secret.as_str(),
        "do-not-lose-this"
    );
}

// ------------------------------------------------------------ export/import

#[test]
fn encrypted_export_round_trips_under_its_own_password() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    let backup = dir.path().join("backup.vaultybak");

    let mut v = new_vault(&p);
    let meta = v.add_entry(entry("GitHub", "ghp_exported")).unwrap();
    v.export_encrypted(&backup, b"a different export password")
        .unwrap();
    drop(v);

    // The backup is not readable with the wrong password ...
    let mut b = Vault::open(&backup).unwrap();
    assert!(b.unlock(PW).is_err());
    b.unlock(b"a different export password").unwrap();
    assert_eq!(
        b.get_entry(&meta.id).unwrap().secret.as_str(),
        "ghp_exported"
    );
}

#[test]
fn encrypted_export_contains_no_plaintext() {
    let dir = tempdir().unwrap();
    let backup = dir.path().join("backup.vaultybak");
    let mut v = new_vault(&dir.path().join("vault.db"));
    v.add_entry(entry("X", "EXPORT-NEEDLE-VALUE")).unwrap();
    v.export_encrypted(&backup, b"export password").unwrap();

    let bytes = std::fs::read(&backup).unwrap();
    assert!(!contains(&bytes, b"EXPORT-NEEDLE-VALUE"));
}

#[test]
fn importing_an_encrypted_export_merges_and_is_idempotent() {
    let dir = tempdir().unwrap();
    let backup = dir.path().join("backup.vaultybak");

    let meta = {
        let mut src = new_vault(&dir.path().join("source.db"));
        let m = src.add_entry(entry("Shared", "shared-secret")).unwrap();
        src.export_encrypted(&backup, b"xp").unwrap();
        m
    };

    let mut dest = new_vault(&dir.path().join("dest.db"));
    dest.add_entry(entry("Local", "local-secret")).unwrap();

    let r = dest.import_encrypted(&backup, b"xp").unwrap();
    assert_eq!(r.added, 1);
    assert_eq!(dest.list_entries().unwrap().len(), 2);
    assert_eq!(
        dest.get_entry(&meta.id).unwrap().secret.as_str(),
        "shared-secret"
    );

    // Importing the same file again changes nothing.
    let r = dest.import_encrypted(&backup, b"xp").unwrap();
    assert_eq!(r.added, 0);
    assert_eq!(r.skipped, 1);
    assert_eq!(dest.list_entries().unwrap().len(), 2);
}

#[test]
fn importing_with_the_wrong_password_fails() {
    let dir = tempdir().unwrap();
    let backup = dir.path().join("backup.vaultybak");
    let mut src = new_vault(&dir.path().join("source.db"));
    src.add_entry(entry("A", "s")).unwrap();
    src.export_encrypted(&backup, b"right").unwrap();

    let mut dest = new_vault(&dir.path().join("dest.db"));
    assert!(dest
        .import_encrypted(&backup, b"wrong")
        .unwrap_err()
        .is_auth_failure());
    assert!(dest.list_entries().unwrap().is_empty());
}

#[test]
fn plaintext_export_carries_the_warning_and_round_trips() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("plain.json");

    let mut v = new_vault(&dir.path().join("vault.db"));
    v.add_entry(entry("GitHub", "ghp_in_the_clear")).unwrap();
    v.export_plaintext_json(&out, PlaintextAck::IUnderstandThisWritesSecretsInTheClear)
        .unwrap();

    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("WARNING"));
    assert!(text.contains("PLAIN TEXT"));
    // It is a plaintext export: the secret is, by design, right there.
    assert!(text.contains("ghp_in_the_clear"));

    let mut dest = new_vault(&dir.path().join("dest.db"));
    let r = dest.import_plaintext_json(&out).unwrap();
    assert_eq!(r.added, 1);
    let restored = &dest.list_entries().unwrap()[0];
    assert_eq!(restored.label, "GitHub");
    assert_eq!(
        dest.get_entry(&restored.id).unwrap().secret.as_str(),
        "ghp_in_the_clear"
    );
}

#[cfg(unix)]
#[test]
fn plaintext_export_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let out = dir.path().join("plain.json");
    let mut v = new_vault(&dir.path().join("vault.db"));
    v.add_entry(entry("A", "s")).unwrap();
    v.export_plaintext_json(&out, PlaintextAck::IUnderstandThisWritesSecretsInTheClear)
        .unwrap();

    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn export_refuses_to_overwrite_an_existing_file() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("taken");
    std::fs::write(&out, b"existing").unwrap();

    let v = new_vault(&dir.path().join("vault.db"));
    assert!(v.export_encrypted(&out, b"pw").is_err());
    assert!(v
        .export_plaintext_json(&out, PlaintextAck::IUnderstandThisWritesSecretsInTheClear)
        .is_err());
    assert_eq!(std::fs::read(&out).unwrap(), b"existing");
}

#[test]
fn export_requires_an_unlocked_vault() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    drop(new_vault(&p));

    let v = Vault::open(&p).unwrap();
    assert!(matches!(
        v.export_encrypted(&dir.path().join("b.vaultybak"), b"pw"),
        Err(Error::Locked)
    ));
}

// ------------------------------------------------------------------ misc

#[test]
fn format_version_is_stamped_from_the_first_commit() {
    let dir = tempdir().unwrap();
    let v = new_vault(&dir.path().join("vault.db"));
    assert_eq!(v.format_version(), vault_core::FORMAT_VERSION);
    assert_eq!(vault_core::FORMAT_VERSION, 1);
}

#[test]
fn two_vaults_get_different_ids() {
    let dir = tempdir().unwrap();
    let a = new_vault(&dir.path().join("a.db"));
    let b = new_vault(&dir.path().join("b.db"));
    assert_ne!(a.vault_id(), b.vault_id());
}

#[test]
fn a_fresh_vault_has_no_biometric_slot() {
    let dir = tempdir().unwrap();
    let v = new_vault(&dir.path().join("vault.db"));
    assert!(!v.has_biometric_slot());
}

#[test]
fn vault_debug_never_leaks() {
    let dir = tempdir().unwrap();
    let v = new_vault(&dir.path().join("vault.db"));
    let shown = format!("{v:?}");
    assert!(!shown.contains("correct horse"));
    assert!(shown.contains("locked"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
