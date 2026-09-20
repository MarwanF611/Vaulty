//! The pre-release checklist at the end of `docs/SECURITY.md`, as tests.
//!
//! Phase 5's exit criterion is that every box in that list is ticked. Some of
//! those boxes are judgement calls that no test can close — "at least one
//! security-minded person outside the project has read the crypto code" is not
//! automatable — but most are checkable, and a checkable box should be a test
//! rather than a promise someone made once.

use std::path::Path;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use vault_core::{EntryKind, Error, KdfParams, NewEntry, Vault};
use zeroize::Zeroizing;

const PW: &[u8] = b"correct horse battery staple";
const SECRET: &str = "PLAINTEXT-SECRET-NEEDLE";

fn cheap() -> KdfParams {
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 2,
        p_cost: 1,
    }
}

fn seeded(path: &Path) -> Vault {
    let mut v = Vault::create_with_params(path, PW, cheap()).unwrap();
    v.add_entry(NewEntry {
        label: "GitHub".into(),
        tags: vec!["work".into()],
        kind: EntryKind::Password,
        secret: Zeroizing::new(SECRET.into()),
        note: None,
    })
    .unwrap();
    v
}

// ---------------------------------------------------------------------------
// "No secret appears in any log, error, panic message or crash dump"
// ---------------------------------------------------------------------------

/// Every error the unlock and read paths can produce, checked for leakage.
#[test]
fn no_error_message_carries_secret_material() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let id = {
        let mut v = seeded(&path);
        let m = v.list_entries().unwrap()[0].id;
        // Exercise the validation errors too.
        for bad in [
            v.add_entry(NewEntry {
                label: String::new(),
                tags: vec![],
                kind: EntryKind::Password,
                secret: Zeroizing::new(SECRET.into()),
                note: None,
            })
            .unwrap_err(),
            v.add_entry(NewEntry {
                label: "x".repeat(10_000),
                tags: vec![],
                kind: EntryKind::Password,
                secret: Zeroizing::new(SECRET.into()),
                note: None,
            })
            .unwrap_err(),
        ] {
            let text = format!("{bad}|{bad:?}");
            assert!(!text.contains(SECRET), "error leaked the secret: {text}");
        }
        m
    };

    let mut v = Vault::open(&path).unwrap();
    let wrong = v.unlock(b"not the password").unwrap_err();
    let text = format!("{wrong}|{wrong:?}");
    assert!(!text.contains(SECRET));
    assert!(
        !text.to_lowercase().contains("correct horse"),
        "error leaked the password: {text}"
    );

    v.unlock(PW).unwrap();
    let locked_err = {
        let mut other = Vault::open(&path).unwrap();
        other.delete_entry(&id).unwrap_err()
    };
    assert!(!format!("{locked_err}|{locked_err:?}").contains(SECRET));
}

/// `Debug` is the easiest accidental leak: a `{:?}` in a log line.
#[test]
fn no_debug_output_carries_secret_material() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let v = seeded(&path);

    let vault_debug = format!("{v:?}");
    assert!(!vault_debug.contains(SECRET));
    assert!(!vault_debug.contains("correct horse"));

    let meta = &v.list_entries().unwrap()[0];
    assert!(!format!("{meta:?}").contains(SECRET));

    let revealed = v.get_entry(&meta.id).unwrap();
    let revealed_debug = format!("{revealed:?}");
    assert!(
        !revealed_debug.contains(SECRET),
        "RevealedEntry Debug leaked: {revealed_debug}"
    );
    assert!(revealed_debug.contains("[redacted]"));
}

// ---------------------------------------------------------------------------
// "Wrong master password is indistinguishable in timing from a corrupt file"
// ---------------------------------------------------------------------------

fn time_unlock(path: &Path, password: &[u8]) -> Duration {
    let start = Instant::now();
    let _ = Vault::open_and_unlock(path, password);
    start.elapsed()
}

/// The gap Phase 0 left open: `open` rejects an unreadable header in
/// microseconds while a wrong password costs a full KDF run, so a stopwatch
/// tells an attacker which of the two they are looking at.
///
/// Production parameters are used deliberately — the point is the ratio at the
/// cost a real vault pays.
#[test]
fn a_corrupt_file_and_a_wrong_password_take_comparable_time() {
    let dir = tempdir().unwrap();

    let good = dir.path().join("good.db");
    drop(Vault::create(&good, PW).unwrap()); // production KDF params

    let corrupt = dir.path().join("corrupt.db");
    std::fs::write(&corrupt, b"this is not a vault file, not even close").unwrap();

    // Warm caches and let the allocator settle before measuring.
    let _ = time_unlock(&good, b"warmup");
    let _ = time_unlock(&corrupt, b"warmup");

    let mut wrong_password = Vec::new();
    let mut corrupt_file = Vec::new();
    for _ in 0..3 {
        wrong_password.push(time_unlock(&good, b"definitely not the password"));
        corrupt_file.push(time_unlock(&corrupt, b"definitely not the password"));
    }

    let median = |mut v: Vec<Duration>| {
        v.sort();
        v[v.len() / 2]
    };
    let pw = median(wrong_password);
    let bad = median(corrupt_file);

    // Both run one Argon2id at production cost, so they should land within the
    // same order of magnitude. A generous bound keeps this from flaking on a
    // loaded CI box while still catching the microseconds-versus-milliseconds
    // difference it exists to prevent.
    let ratio = pw.as_secs_f64() / bad.as_secs_f64().max(f64::EPSILON);
    assert!(
        (0.2..=5.0).contains(&ratio),
        "timing distinguishes the two: wrong password {pw:?}, corrupt file {bad:?} \
         (ratio {ratio:.1}x)"
    );
}

#[test]
fn a_corrupt_file_reports_the_same_error_as_a_wrong_password() {
    let dir = tempdir().unwrap();

    let good = dir.path().join("good.db");
    drop(Vault::create_with_params(&good, PW, cheap()).unwrap());
    let corrupt = dir.path().join("corrupt.db");
    std::fs::write(&corrupt, b"not a vault").unwrap();

    let a = Vault::open_and_unlock(&good, b"wrong").unwrap_err();
    let b = Vault::open_and_unlock(&corrupt, b"wrong").unwrap_err();

    assert!(a.is_auth_failure());
    assert!(b.is_auth_failure());
    // Identical text: the caller cannot tell them apart either.
    assert_eq!(a.to_string(), b.to_string());
}

/// A missing file is still reported as missing. That is not a leak — the user
/// knows whether they have a vault — and pretending otherwise would make a
/// first run look like a corruption.
#[test]
fn a_missing_file_is_still_reported_as_missing() {
    let dir = tempdir().unwrap();
    let err = Vault::open_and_unlock(&dir.path().join("nothing.db"), PW).unwrap_err();
    assert!(matches!(err, Error::VaultNotFound));
}

#[test]
fn open_and_unlock_still_works_on_a_good_vault() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let id = {
        let v = seeded(&path);
        v.list_entries().unwrap()[0].id
    };

    let v = Vault::open_and_unlock(&path, PW).unwrap();
    assert!(!v.is_locked());
    assert_eq!(v.get_entry(&id).unwrap().secret.as_str(), SECRET);
}

// ---------------------------------------------------------------------------
// "Corrupting any byte of the vault file causes a clean authentication
//  failure, never a silent wrong-plaintext read"
// ---------------------------------------------------------------------------

/// Byte-level corruption across the whole file, not just the header.
///
/// Sampled rather than exhaustive: a vault file is tens of kilobytes and this
/// would otherwise dominate the suite. Every 97th byte is a prime stride, so it
/// walks across page and record boundaries rather than landing in one region.
#[test]
fn corrupting_bytes_across_the_whole_file_never_yields_wrong_plaintext() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let id = {
        let v = seeded(&path);
        v.list_entries().unwrap()[0].id
    };
    let original = std::fs::read(&path).unwrap();

    let target = dir.path().join("corrupt.db");
    let mut checked = 0;

    for i in (0..original.len()).step_by(97) {
        let mut bytes = original.clone();
        bytes[i] ^= 0b0100_0000;
        std::fs::write(&target, &bytes).unwrap();

        match Vault::open_and_unlock(&target, PW) {
            // Rejected outright: fine.
            Err(_) => {}
            Ok(v) => match v.get_entry(&id) {
                // Authentication caught it: fine.
                Err(e) => assert!(
                    e.is_auth_failure() || matches!(e, Error::NotFound | Error::Db(_)),
                    "byte {i}: unexpected error {e:?}"
                ),
                // Decrypted: it must be the *right* plaintext, never a
                // different one.
                Ok(entry) => assert_eq!(
                    entry.secret.as_str(),
                    SECRET,
                    "byte {i} corrupted but produced different plaintext"
                ),
            },
        }
        checked += 1;
    }

    assert!(checked > 50, "only {checked} positions were exercised");
}
