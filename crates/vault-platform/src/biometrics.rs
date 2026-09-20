//! Biometric unlock: the `BiometricProvider` trait and its platform backends.
//!
//! # A fingerprint is not a key
//!
//! `docs/SECURITY.md` is emphatic about this, and the trait shape follows from
//! it. Touch ID does not produce key material — it returns a yes. What actually
//! protects the vault is the OS keystore: Vaulty generates 32 random bytes,
//! hands them to the keychain behind an access-control policy, and the
//! biometric is the gate on reading them back.
//!
//! So the trait is a *key store with a gate*, not an authenticator. There is no
//! `authenticate() -> bool` method, deliberately: a boolean return would invite
//! a caller to branch on it and unlock, and a local attacker who can patch the
//! binary can flip a boolean. They cannot conjure the 32 bytes.
//!
//! The bytes themselves never unlock anything on their own either — they unwrap
//! a header slot, which fails closed if the vault has moved on
//! (`vault_core::VaultHeader::unlock_with_keystore_key`).
//!
//! # What is stored
//!
//! Never the master password. Never the vault key. Only a key-encryption key
//! that unwraps one slot of one vault, and which is useless beside the vault
//! file it belongs to.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{PlatformError, Result};

/// Which biometric the machine offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometryKind {
    TouchId,
    FaceId,
    /// Windows Hello does not distinguish modality through the API we use.
    WindowsHello,
    Unknown,
}

impl BiometryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BiometryKind::TouchId => "touch_id",
            BiometryKind::FaceId => "face_id",
            BiometryKind::WindowsHello => "windows_hello",
            BiometryKind::Unknown => "unknown",
        }
    }

    /// What to call it in the interface.
    pub fn display_name(self) -> &'static str {
        match self {
            BiometryKind::TouchId => "Touch ID",
            BiometryKind::FaceId => "Face ID",
            BiometryKind::WindowsHello => "Windows Hello",
            BiometryKind::Unknown => "biometrics",
        }
    }
}

/// Whether biometric unlock can be offered, and if not, why.
///
/// The distinction between "no hardware" and "hardware but nothing enrolled"
/// matters to the interface: one is a dead end, the other is a sentence of
/// instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricAvailability {
    Available(BiometryKind),
    /// Hardware is present but the user has enrolled no fingerprint or face.
    NotEnrolled(BiometryKind),
    /// No biometric hardware on this machine.
    NoHardware,
    /// Locked out after too many failed attempts; a password unlock resets it.
    LockedOut(BiometryKind),
    /// This build does not implement biometrics for this platform.
    Unsupported,
}

impl BiometricAvailability {
    pub fn is_available(self) -> bool {
        matches!(self, BiometricAvailability::Available(_))
    }

    pub fn kind(self) -> Option<BiometryKind> {
        match self {
            BiometricAvailability::Available(k)
            | BiometricAvailability::NotEnrolled(k)
            | BiometricAvailability::LockedOut(k) => Some(k),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BiometricAvailability::Available(_) => "available",
            BiometricAvailability::NotEnrolled(_) => "not_enrolled",
            BiometricAvailability::NoHardware => "no_hardware",
            BiometricAvailability::LockedOut(_) => "locked_out",
            BiometricAvailability::Unsupported => "unsupported",
        }
    }
}

/// Why a biometric read did not produce a key.
///
/// Every variant leads to the same place — show the password field — but they
/// read differently to a user, and only one of them is worth a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricFailure {
    /// The user dismissed the prompt, or chose to use a password.
    Cancelled,
    /// The biometric was presented and rejected.
    NotRecognised,
    /// Too many failures; the OS has disabled biometrics until a password.
    LockedOut,
    /// No stored key for this vault.
    NotFound,
    /// The stored item was discarded by the OS.
    ///
    /// On macOS this is what enrolling a new fingerprint produces, because the
    /// item is created with `kSecAccessControlBiometryCurrentSet`. It is the
    /// expected outcome of the Phase 3 exit criterion, not an error worth
    /// alarming anyone about — but it does mean re-enrolling.
    Invalidated,
    /// Something else went wrong.
    Unavailable,
}

impl BiometricFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            BiometricFailure::Cancelled => "cancelled",
            BiometricFailure::NotRecognised => "not_recognised",
            BiometricFailure::LockedOut => "locked_out",
            BiometricFailure::NotFound => "not_found",
            BiometricFailure::Invalidated => "invalidated",
            BiometricFailure::Unavailable => "unavailable",
        }
    }
}

/// A key store whose reads are gated by a biometric.
///
/// Implementations must never return stored bytes without the OS having
/// actually verified the user. There is no "skip the prompt" path.
pub trait BiometricProvider: Send + Sync {
    /// Whether biometric unlock can be offered right now. Must not prompt.
    fn availability(&self) -> BiometricAvailability;

    /// Store `secret` for `account`, gated behind the biometric.
    ///
    /// Replaces any existing item for the same account. The item must be bound
    /// to the *current* biometric enrolment, so that adding a fingerprint
    /// invalidates it.
    fn store(&self, account: &str, secret: &[u8]) -> Result<()>;

    /// Read the stored secret back. **This is what shows the prompt.**
    ///
    /// `reason` is displayed to the user by the OS.
    fn load(
        &self,
        account: &str,
        reason: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, BiometricFailure>;

    /// Remove the stored item. Idempotent.
    fn delete(&self, account: &str) -> Result<()>;

    /// Whether an item exists, without prompting.
    fn exists(&self, account: &str) -> bool;
}

/// A provider for platforms where biometrics is not implemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedProvider;

impl BiometricProvider for UnsupportedProvider {
    fn availability(&self) -> BiometricAvailability {
        BiometricAvailability::Unsupported
    }
    fn store(&self, _account: &str, _secret: &[u8]) -> Result<()> {
        Err(PlatformError::Unsupported)
    }
    fn load(
        &self,
        _account: &str,
        _reason: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, BiometricFailure> {
        Err(BiometricFailure::Unavailable)
    }
    fn delete(&self, _account: &str) -> Result<()> {
        Ok(())
    }
    fn exists(&self, _account: &str) -> bool {
        false
    }
}

/// The provider for this platform.
pub fn provider() -> Box<dyn BiometricProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::macos_keychain::KeychainProvider::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Windows lands in Phase 4; PHASES.md wants a standalone prototype
        // before it is wired in here.
        Box::new(UnsupportedProvider)
    }
}

impl fmt::Debug for dyn BiometricProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BiometricProvider")
            .field("availability", &self.availability())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_reports_a_kind_only_where_hardware_exists() {
        assert_eq!(
            BiometricAvailability::Available(BiometryKind::TouchId).kind(),
            Some(BiometryKind::TouchId)
        );
        assert_eq!(
            BiometricAvailability::NotEnrolled(BiometryKind::TouchId).kind(),
            Some(BiometryKind::TouchId)
        );
        assert_eq!(BiometricAvailability::NoHardware.kind(), None);
        assert_eq!(BiometricAvailability::Unsupported.kind(), None);
    }

    #[test]
    fn only_available_counts_as_available() {
        assert!(BiometricAvailability::Available(BiometryKind::FaceId).is_available());
        for a in [
            BiometricAvailability::NotEnrolled(BiometryKind::TouchId),
            BiometricAvailability::NoHardware,
            BiometricAvailability::LockedOut(BiometryKind::TouchId),
            BiometricAvailability::Unsupported,
        ] {
            assert!(!a.is_available(), "{a:?} must not count as available");
        }
    }

    #[test]
    fn the_unsupported_provider_never_yields_a_key() {
        let p = UnsupportedProvider;
        assert_eq!(p.availability(), BiometricAvailability::Unsupported);
        assert!(p.store("acct", b"secret").is_err());
        assert!(p.load("acct", "reason").is_err());
        assert!(!p.exists("acct"));
        // Deleting what is not there is not an error.
        assert!(p.delete("acct").is_ok());
    }

    #[test]
    fn display_names_are_what_the_platform_calls_them() {
        assert_eq!(BiometryKind::TouchId.display_name(), "Touch ID");
        assert_eq!(BiometryKind::FaceId.display_name(), "Face ID");
        assert_eq!(BiometryKind::WindowsHello.display_name(), "Windows Hello");
    }

    /// The trait must stay object-safe: `AppState` holds a `Box<dyn ...>`.
    #[test]
    fn the_provider_trait_is_object_safe() {
        let p: Box<dyn BiometricProvider> = Box::new(UnsupportedProvider);
        assert_eq!(p.availability(), BiometricAvailability::Unsupported);
        assert!(format!("{p:?}").contains("BiometricProvider"));
    }
}
