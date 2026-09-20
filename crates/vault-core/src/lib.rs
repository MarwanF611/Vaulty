//! `vault-core` — Vaulty's crypto core.
//!
//! Everything that touches key material or the vault file lives here. There is
//! no UI and no Tauri dependency: this crate builds and tests on its own, which
//! is what keeps the crypto reviewable (CLAUDE.md, "Layout").
//!
//! # Design in one paragraph
//!
//! The master password never encrypts entries. Argon2id turns it into a
//! key-encryption key, which wraps a random 32-byte vault key held in a header
//! slot; entries are sealed with the vault key under XChaCha20-Poly1305 with a
//! fresh 24-byte nonce per write. Changing the password rewraps one key instead
//! of re-encrypting the vault, and a second unlock method (Touch ID, Windows
//! Hello) is a second slot rather than a migration. Each entry's clear-text
//! label, tags, kind and timestamps are authenticated as associated data, so a
//! label cannot be swapped onto a different secret.
//!
//! See `docs/SECURITY.md` for the threat model, and [`header`] for the byte
//! layout of the vault header.
//!
//! # What this crate will not do
//!
//! It will not hand you a plaintext secret except through [`Vault::get_entry`],
//! it will not `Debug`-print key material, and it will not tell you *why* an
//! unlock failed — a wrong password and a tampered file are the same
//! [`Error::Auth`].
//!
//! # Example
//!
//! ```no_run
//! use vault_core::{NewEntry, EntryKind, Vault};
//! use zeroize::Zeroizing;
//!
//! # fn main() -> vault_core::Result<()> {
//! let path = std::path::Path::new("/tmp/example-vault.db");
//! let mut vault = Vault::create(path, b"a strong master password")?;
//!
//! let meta = vault.add_entry(NewEntry {
//!     label: "Router admin".into(),
//!     tags: vec!["home".into()],
//!     kind: EntryKind::Password,
//!     secret: Zeroizing::new("hunter2".into()),
//!     note: None,
//! })?;
//!
//! // Listing returns metadata only — no secrets cross this boundary.
//! for m in vault.list_entries()? {
//!     println!("{} ({})", m.label, m.kind);
//! }
//!
//! // Plaintext appears only on an explicit reveal, and zeroizes on drop.
//! let revealed = vault.get_entry(&meta.id)?;
//! assert_eq!(revealed.secret.as_str(), "hunter2");
//!
//! vault.lock();
//! # Ok(())
//! # }
//! ```

// Deny the footguns this project cares about. `unwrap` and `expect` are allowed
// in tests (see the per-module `#[cfg(test)]` blocks) but not in shipped paths.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// These apply to shipped paths only. Test code indexes and unwraps freely:
// a panic in a test is a failing test, which is the point.
#![cfg_attr(
    not(test),
    warn(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod atomic;
pub mod crypto;
pub mod db;
pub mod entry;
pub mod error;
pub mod export;
pub mod header;
pub mod vault;

pub use crypto::{KdfParams, VaultKey};
pub use entry::{EntryId, EntryKind, EntryMeta, EntryUpdate, NewEntry, RevealedEntry};
pub use error::{Error, Result};
pub use export::{ImportReport, PlaintextAck, PLAINTEXT_WARNING};
pub use header::{SlotKind, VaultHeader, FORMAT_VERSION};
pub use vault::Vault;

/// Default on-disk location of the vault, per `docs/SPEC.md`.
///
/// * macOS — `~/Library/Application Support/Vault/vault.db`
/// * Windows — `%APPDATA%\Vault\vault.db`
pub fn default_vault_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            std::path::PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Vault")
                .join("vault.db"),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA")?;
        Some(
            std::path::PathBuf::from(appdata)
                .join("Vault")
                .join("vault.db"),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // Linux is not a supported target for v1, but tests and development
        // happen there; follow the XDG basedir convention.
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local").join("share"))
            })?;
        Some(base.join("vaulty").join("vault.db"))
    }
}
