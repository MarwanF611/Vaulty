//! The error shape that crosses into the webview.
//!
//! `vault-core` errors are already scrubbed of key material and plaintext
//! (CLAUDE.md rule 3), but they are a Rust enum. This turns them into a stable
//! `{ code, message }` the frontend can branch on without string-matching, and
//! without ever widening what is disclosed.
//!
//! In particular `Auth` stays a single code. The frontend must not be able to
//! tell "wrong password" from "tampered file" — doing so would hand that same
//! oracle to anyone who can read the IPC traffic.

use serde::Serialize;
use vault_core::Error as CoreError;

#[derive(Debug, Serialize)]
pub struct CmdError {
    /// Stable machine-readable discriminant.
    pub code: &'static str,
    /// Human-readable, safe to display. Never contains secret material.
    pub message: String,
}

impl CmdError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The vault is locked. The UI uses this to bounce back to the unlock screen.
    pub fn locked() -> Self {
        Self::new("locked", "The vault is locked.")
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }
}

impl From<CoreError> for CmdError {
    fn from(e: CoreError) -> Self {
        let code = match e {
            CoreError::Auth => "auth",
            CoreError::Locked => "locked",
            CoreError::NotFound => "not_found",
            CoreError::VaultNotFound => "vault_not_found",
            CoreError::BadMagic | CoreError::MalformedHeader => "corrupt",
            CoreError::UnsupportedVersion { .. } => "unsupported_version",
            CoreError::Invalid(_) => "invalid",
            CoreError::BadKdfParams => "corrupt",
            CoreError::NoSlot => "no_slot",
            CoreError::Db(_) => "storage",
            CoreError::Io(_) => "io",
            // `CoreError` is #[non_exhaustive]. A variant added later lands here
            // with a generic code rather than silently taking on the meaning of
            // whichever arm happened to be adjacent.
            _ => "internal",
        };
        // `Display` for CoreError is deliberately coarse; see vault-core/error.rs.
        CmdError::new(code, e.to_string())
    }
}

pub type CmdResult<T> = std::result::Result<T, CmdError>;
