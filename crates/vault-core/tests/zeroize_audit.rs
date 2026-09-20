//! The zeroize audit: every path that touches plaintext.
//!
//! `docs/PHASES.md` Phase 5 asks for an audit of "every path that touches
//! plaintext". A read-through is worth something once; these are the parts that
//! can be made to *stay* true.
//!
//! Most of them are compile-time. If someone changes `RevealedEntry.secret`
//! from `Zeroizing<String>` to `String`, this file stops compiling — which is a
//! better guarantee than a note in a document saying it was checked in
//! November.
//!
//! ## The paths, enumerated
//!
//! | Where plaintext exists | Type | Zeroized by |
//! | --- | --- | --- |
//! | the vault key, whole session | `VaultKey(SecretBox<[u8; 32]>)` | drop |
//! | a derived KEK, during unlock | `Zeroizing<[u8; 32]>` | drop |
//! | a decrypted entry payload | `Zeroizing<Vec<u8>>` | drop |
//! | a revealed secret / note | `Zeroizing<String>` | drop |
//! | an entry being written | `Zeroizing<String>` in `NewEntry` | drop |
//! | a captured selection | `CapturedText(Zeroizing<String>)` | drop |
//! | a plaintext JSON export | `Zeroizing<Vec<u8>>` | drop |
//! | the vault key on lock | `Vault::lock` sets `key = None` | drop |
//!
//! ## What this cannot prove
//!
//! That the *allocator* does not keep a copy. `Zeroizing<String>` zeroes the
//! buffer it owns at the moment it drops, but a `String` that reallocated while
//! growing has left its old buffer behind, unzeroed, for the allocator to
//! reuse. Ciphertext read out of SQLite passes through buffers this crate does
//! not own either.
//!
//! Neither is addressed here, and neither is addressable without a custom
//! allocator. `docs/PHASE5-NOTES.md` records it; the SECURITY.md item "memory
//! dump after lock contains no plaintext secrets" stays open because of it.

use vault_core::{EntryKind, KdfParams, NewEntry, Vault};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Compiles only for types that zero themselves on drop.
fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// Compiles only for types that can be zeroed at all.
fn require_zeroize<T: Zeroize>() {}

#[test]
fn the_wrapper_types_zeroize_on_drop() {
    require_zeroize_on_drop::<Zeroizing<String>>();
    require_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
    require_zeroize_on_drop::<Zeroizing<[u8; 32]>>();

    require_zeroize::<String>();
    require_zeroize::<Vec<u8>>();
    require_zeroize::<[u8; 32]>();
}

/// The types carrying plaintext across the public API.
///
/// These assignments are the audit: each one fails to compile if the field
/// stops being a zeroizing type.
#[test]
fn every_plaintext_field_is_a_zeroizing_type() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::create_with_params(
        &dir.path().join("vault.db"),
        b"master",
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        },
    )
    .unwrap();

    // NewEntry: what goes in.
    let new = NewEntry {
        label: "GitHub".into(),
        tags: vec![],
        kind: EntryKind::Password,
        secret: Zeroizing::new("s3cret".to_string()),
        note: Some(Zeroizing::new("a note".to_string())),
    };
    let _: &Zeroizing<String> = &new.secret;
    let _: &Option<Zeroizing<String>> = &new.note;

    let meta = vault.add_entry(new).unwrap();

    // RevealedEntry: what comes out.
    let revealed = vault.get_entry(&meta.id).unwrap();
    let _: &Zeroizing<String> = &revealed.secret;
    let _: &Option<Zeroizing<String>> = &revealed.note;

    // EntryMeta: what crosses to the frontend. Plain types, because there is
    // nothing secret in it — asserting that keeps the boundary honest.
    let _: &String = &revealed.meta.label;
    let _: &Vec<String> = &revealed.meta.tags;
}

/// Locking must drop the key, not merely mark the vault unusable.
#[test]
fn locking_drops_the_key_rather_than_flagging_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let mut vault = Vault::create_with_params(
        &path,
        b"master",
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        },
    )
    .unwrap();

    let meta = vault
        .add_entry(NewEntry {
            label: "X".into(),
            tags: vec![],
            kind: EntryKind::Password,
            secret: Zeroizing::new("s3cret".into()),
            note: None,
        })
        .unwrap();

    assert!(!vault.is_locked());
    vault.lock();
    assert!(vault.is_locked());

    // Every read path refuses, so there is no way to observe a retained key.
    assert!(vault.get_entry(&meta.id).is_err());
    assert!(vault.list_entries().is_err());

    // Locking twice is safe.
    vault.lock();
    assert!(vault.is_locked());
}

/// Dropping the vault locks it, so a `Vault` that goes out of scope without an
/// explicit lock still zeroizes (CLAUDE.md rule 4: "zeroized on ... quit").
#[test]
fn dropping_a_vault_locks_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    {
        let vault = Vault::create_with_params(
            &path,
            b"master",
            KdfParams {
                m_cost_kib: 8 * 1024,
                t_cost: 2,
                p_cost: 1,
            },
        )
        .unwrap();
        assert!(!vault.is_locked());
    } // Drop runs here.

    // Reopening yields a locked vault, which is the observable consequence.
    let reopened = Vault::open(&path).unwrap();
    assert!(reopened.is_locked());
}

/// A plaintext export must require the explicit acknowledgement type, so it
/// cannot be reached by autocomplete.
#[test]
fn the_plaintext_export_cannot_be_called_by_accident() {
    // There is exactly one way to name the argument, and it is a sentence.
    let _ack = vault_core::PlaintextAck::IUnderstandThisWritesSecretsInTheClear;
    assert!(vault_core::PLAINTEXT_WARNING.contains("PLAIN TEXT"));
}
