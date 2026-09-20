//! Error type for `vault-core`.
//!
//! Rule 3 of CLAUDE.md: no error message ever embeds key material or plaintext.
//! Every variant here is deliberately coarse. In particular [`Error::Auth`] covers
//! *both* a wrong password and a corrupt/tampered file, because distinguishing them
//! for the caller would hand an attacker an oracle (SECURITY.md pre-release
//! checklist: "Wrong master password is indistinguishable in timing from a corrupt
//! file").

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Authentication failed: wrong password, wrong key, corrupt ciphertext, or
    /// tampered associated data. Deliberately not subdivided.
    #[error("authentication failed")]
    Auth,

    /// The file is not a Vaulty vault, or its header is structurally unreadable.
    #[error("not a vaulty vault file")]
    BadMagic,

    /// The file is a Vaulty vault but written by a newer format version.
    #[error("unsupported vault format version {found} (this build supports up to {supported})")]
    UnsupportedVersion { found: u16, supported: u16 },

    /// Header or slot bytes were truncated or internally inconsistent.
    #[error("malformed vault header")]
    MalformedHeader,

    /// An operation needing the vault key was attempted while locked.
    #[error("vault is locked")]
    Locked,

    /// No entry with that id, or the entry is a tombstone.
    #[error("entry not found")]
    NotFound,

    /// There is no vault file at the given path.
    #[error("no vault at that path")]
    VaultNotFound,

    /// Caller-supplied data failed validation (empty label, oversized secret, ...).
    #[error("invalid input: {0}")]
    Invalid(&'static str),

    /// KDF parameters in the header are outside the range this build accepts.
    #[error("unacceptable kdf parameters")]
    BadKdfParams,

    /// No unlock slot of the requested kind exists.
    #[error("no matching unlock slot")]
    NoSlot,

    #[error("database error")]
    Db(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// True when this error must be reported to the user as an indistinguishable
    /// "could not unlock" — used by callers that surface unlock failures.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Error::Auth)
    }
}

/// A newtype whose `Debug` never reveals its contents.
///
/// SECURITY.md: "Never `Debug`-print a type holding key material — implement
/// `Debug` manually as `[redacted]`."
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}
