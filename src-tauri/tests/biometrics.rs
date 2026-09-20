//! Phase 3: the biometric unlock flow.
//!
//! The real keychain needs a signed app with the `keychain-access-groups`
//! entitlement — verified: `SecItemAdd` is refused outright in an unsigned
//! build. So the provider is injected here and the OS is stood in for, which
//! covers everything except the Keychain FFI itself: enrolment, unlock,
//! disable, the password fallback on every failure mode, and the 14-day
//! re-prompt.
//!
//! What a fake cannot prove is that macOS discards the item when a fingerprint
//! is added. `docs/PHASE3-NOTES.md` records that as unverified.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri::{App, Manager};
use tempfile::TempDir;
use vault_platform::{
    BiometricAvailability, BiometricFailure, BiometricProvider, BiometryKind, PlatformError,
};
use vaulty_lib::commands;
use vaulty_lib::settings::Settings;
use vaulty_lib::state::AppState;
use zeroize::Zeroizing;

const PW: &str = "correct horse battery staple";

/// An in-memory keystore that behaves like the macOS keychain, including the
/// failure modes that matter.
///
/// Cloneable and `Arc`-backed so a test can keep a handle after the provider
/// has been boxed into `AppState` — that handle is how a test arms a specific
/// failure without reaching back through the trait object.
#[derive(Clone)]
struct FakeKeystore {
    items: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    availability: BiometricAvailability,
    /// What `load` should do instead of succeeding.
    fail_with: Arc<Mutex<Option<BiometricFailure>>>,
    /// Refuse writes, the way an unsigned build does.
    refuse_writes: bool,
}

impl FakeKeystore {
    fn new() -> Self {
        Self {
            items: Arc::new(Mutex::new(HashMap::new())),
            availability: BiometricAvailability::Available(BiometryKind::TouchId),
            fail_with: Arc::new(Mutex::new(None)),
            refuse_writes: false,
        }
    }

    fn with_availability(availability: BiometricAvailability) -> Self {
        Self {
            availability,
            ..Self::new()
        }
    }

    fn refusing_writes() -> Self {
        Self {
            refuse_writes: true,
            ..Self::new()
        }
    }

    /// Make the next `load` fail this way.
    fn arm_failure(&self, f: BiometricFailure) {
        *self.fail_with.lock().expect("fake keystore mutex") = Some(f);
    }

    fn get(&self, account: &str) -> Option<Vec<u8>> {
        self.items.lock().ok()?.get(account).cloned()
    }
}

impl BiometricProvider for FakeKeystore {
    fn availability(&self) -> BiometricAvailability {
        self.availability
    }

    fn store(&self, account: &str, secret: &[u8]) -> vault_platform::Result<()> {
        if self.refuse_writes {
            return Err(PlatformError::Os("refused"));
        }
        self.items
            .lock()
            .map_err(|_| PlatformError::Os("poisoned"))?
            .insert(account.to_string(), secret.to_vec());
        Ok(())
    }

    fn load(
        &self,
        account: &str,
        _reason: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, BiometricFailure> {
        if let Some(f) = *self
            .fail_with
            .lock()
            .map_err(|_| BiometricFailure::Unavailable)?
        {
            return Err(f);
        }
        self.items
            .lock()
            .map_err(|_| BiometricFailure::Unavailable)?
            .get(account)
            .cloned()
            .map(Zeroizing::new)
            .ok_or(BiometricFailure::NotFound)
    }

    fn delete(&self, account: &str) -> vault_platform::Result<()> {
        self.items
            .lock()
            .map_err(|_| PlatformError::Os("poisoned"))?
            .remove(account);
        Ok(())
    }

    fn exists(&self, account: &str) -> bool {
        self.items
            .lock()
            .map(|i| i.contains_key(account))
            .unwrap_or(false)
    }
}

fn app_with(dir: &TempDir, keystore: FakeKeystore) -> App<tauri::test::MockRuntime> {
    mock_builder()
        .manage(AppState::with_biometrics(
            dir.path().join("vault.db"),
            Box::new(keystore),
        ))
        .build(mock_context(noop_assets()))
        .expect("mock app should build")
}

fn app(dir: &TempDir) -> App<tauri::test::MockRuntime> {
    app_with(dir, FakeKeystore::new())
}

fn created(app: &App<tauri::test::MockRuntime>) {
    commands::create_vault(app.state::<AppState>(), PW.into()).unwrap();
}

// ------------------------------------------------------------- enrolment

#[test]
fn biometrics_starts_off() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);

    let s = commands::biometric_state(app.state::<AppState>()).unwrap();
    assert_eq!(s.availability, "available");
    assert_eq!(s.display_name, Some("Touch ID"));
    assert!(!s.enabled);
    assert!(!s.key_present);
    assert!(!s.can_unlock);
}

#[test]
fn enabling_stores_a_key_and_adds_a_slot() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);

    let s = commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
    assert!(s.enabled, "a biometric slot should exist");
    assert!(s.key_present, "a key should be in the keystore");
}

/// Adding a second way in should cost the credential it sits alongside.
#[test]
fn enabling_requires_the_master_password() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);

    let err = commands::enable_biometrics(app.state::<AppState>(), "not the password".into())
        .unwrap_err();
    assert_eq!(err.code, "auth");

    // And nothing was half-done.
    let s = commands::biometric_state(app.state::<AppState>()).unwrap();
    assert!(!s.enabled);
    assert!(!s.key_present);
}

#[test]
fn enabling_is_refused_when_no_biometric_is_enrolled() {
    let dir = TempDir::new().unwrap();
    let app = app_with(
        &dir,
        FakeKeystore::with_availability(BiometricAvailability::NotEnrolled(BiometryKind::TouchId)),
    );
    created(&app);

    let err = commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap_err();
    assert_eq!(err.code, "biometrics_unavailable");
    assert!(err.message.contains("no fingerprint is enrolled"));
}

/// An unsigned build cannot write to the keychain. The slot must not be added
/// pointing at a key that was never stored.
#[test]
fn a_refused_keychain_write_leaves_no_slot_behind() {
    let dir = TempDir::new().unwrap();
    let app = app_with(&dir, FakeKeystore::refusing_writes());
    created(&app);

    let err = commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap_err();
    assert_eq!(err.code, "keychain_write_failed");

    let s = commands::biometric_state(app.state::<AppState>()).unwrap();
    assert!(
        !s.enabled,
        "no slot should point at a key that was never stored"
    );
}

// ---------------------------------------------------------------- unlock

#[test]
fn biometric_unlock_opens_the_vault() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);
    commands::add_entry(
        app.state::<AppState>(),
        commands::NewEntryInput {
            label: "GitHub".into(),
            tags: vec![],
            kind: "password".into(),
            secret: "ghp_x".into(),
            note: None,
        },
    )
    .unwrap();
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    let outcome = commands::unlock_with_biometrics(app.state::<AppState>()).unwrap();
    assert!(!outcome.status.locked);
    assert_eq!(
        commands::list_entries(app.state::<AppState>())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn biometric_unlock_is_refused_when_it_was_never_enabled() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);
    commands::lock_vault(app.state::<AppState>()).unwrap();

    let err = commands::unlock_with_biometrics(app.state::<AppState>()).unwrap_err();
    assert_eq!(err.code, "biometrics_not_enabled");
}

/// SECURITY.md: "Never fall back silently: if biometrics fails, show the
/// password field — do not unlock."
#[test]
fn every_biometric_failure_leaves_the_vault_locked() {
    for (failure, expected_code) in [
        (BiometricFailure::Cancelled, "biometric_cancelled"),
        (BiometricFailure::NotRecognised, "biometric_failed"),
        (BiometricFailure::LockedOut, "biometric_failed"),
        (BiometricFailure::NotFound, "biometric_failed"),
        (BiometricFailure::Invalidated, "biometric_invalidated"),
        (BiometricFailure::Unavailable, "biometric_failed"),
    ] {
        let dir = TempDir::new().unwrap();
        let keystore = FakeKeystore::new();
        let app = app_with(&dir, keystore.clone());
        created(&app);
        commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
        commands::lock_vault(app.state::<AppState>()).unwrap();

        keystore.arm_failure(failure);

        let err = commands::unlock_with_biometrics(app.state::<AppState>()).unwrap_err();
        assert_eq!(err.code, expected_code, "for {failure:?}");
        assert!(
            commands::vault_status(app.state::<AppState>())
                .unwrap()
                .locked,
            "{failure:?} must leave the vault locked"
        );
        // The password still works, always.
        commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    }
}

/// The enrolment-changed case, which is the Phase 3 exit criterion's second
/// half: the stored key stops working and the password takes over.
#[test]
fn an_invalidated_key_forces_the_password() {
    let dir = TempDir::new().unwrap();
    let keystore = FakeKeystore::new();
    let app = app_with(&dir, keystore.clone());
    created(&app);
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
    commands::lock_vault(app.state::<AppState>()).unwrap();

    // Standing in for macOS discarding the item when a fingerprint is added.
    keystore.arm_failure(BiometricFailure::Invalidated);

    let err = commands::unlock_with_biometrics(app.state::<AppState>()).unwrap_err();
    assert_eq!(err.code, "biometric_invalidated");
    assert!(err.message.contains("master password"));
    assert!(
        commands::vault_status(app.state::<AppState>())
            .unwrap()
            .locked
    );

    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
}

// --------------------------------------------------------------- disable

#[test]
fn disabling_removes_both_the_slot_and_the_stored_key() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();

    let s = commands::disable_biometrics(app.state::<AppState>()).unwrap();
    assert!(!s.enabled, "the slot should be gone");
    assert!(!s.key_present, "the keychain item should be gone");

    commands::lock_vault(app.state::<AppState>()).unwrap();
    assert_eq!(
        commands::unlock_with_biometrics(app.state::<AppState>())
            .unwrap_err()
            .code,
        "biometrics_not_enabled"
    );
    // And the password is unaffected.
    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
}

#[test]
fn re_enabling_issues_a_fresh_key() {
    let dir = TempDir::new().unwrap();
    let keystore = FakeKeystore::new();
    let app = app_with(&dir, keystore.clone());
    created(&app);

    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
    let account = commands::vault_status(app.state::<AppState>())
        .unwrap()
        .vault_id
        .unwrap();
    let first = keystore.get(&account).expect("a key should be stored");

    commands::disable_biometrics(app.state::<AppState>()).unwrap();
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();
    let second = keystore
        .get(&account)
        .expect("a fresh key should be stored");

    assert_ne!(first, second, "re-enrolment must not reuse the old key");
}

// ------------------------------------------------- the 14-day re-prompt

#[test]
fn the_password_blocks_biometrics_once_it_is_due() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();

    // Backdate the last password unlock past the window.
    {
        let state = app.state::<AppState>();
        let current = state.settings().unwrap();
        state
            .set_settings(Settings {
                last_password_unlock_at: Some(vaulty_lib::settings::now() - 15 * 86_400),
                ..current
            })
            .unwrap();
    }
    commands::lock_vault(app.state::<AppState>()).unwrap();

    let s = commands::biometric_state(app.state::<AppState>()).unwrap();
    assert!(s.password_due);
    assert!(
        !s.can_unlock,
        "biometrics must not be offered when the password is due"
    );

    let err = commands::unlock_with_biometrics(app.state::<AppState>()).unwrap_err();
    assert_eq!(err.code, "password_due");

    // Using the password clears it for another fortnight.
    commands::unlock_vault(app.state::<AppState>(), PW.into()).unwrap();
    let s = commands::biometric_state(app.state::<AppState>()).unwrap();
    assert!(!s.password_due);
    assert_eq!(s.days_until_password_due, 14);
}

/// The window must measure time since a *password* unlock, so biometrics
/// cannot keep extending it indefinitely.
#[test]
fn a_biometric_unlock_does_not_reset_the_window() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    created(&app);
    commands::enable_biometrics(app.state::<AppState>(), PW.into()).unwrap();

    let backdated = vaulty_lib::settings::now() - 10 * 86_400;
    {
        let state = app.state::<AppState>();
        let current = state.settings().unwrap();
        state
            .set_settings(Settings {
                last_password_unlock_at: Some(backdated),
                ..current
            })
            .unwrap();
    }

    commands::lock_vault(app.state::<AppState>()).unwrap();
    commands::unlock_with_biometrics(app.state::<AppState>()).unwrap();

    let state = app.state::<AppState>();
    assert_eq!(
        state.settings().unwrap().last_password_unlock_at,
        Some(backdated),
        "a biometric unlock must not push the password window out"
    );
}
