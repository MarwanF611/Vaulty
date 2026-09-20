//! Application state: the one place an unlocked vault lives.
//!
//! The vault key never leaves this process (CLAUDE.md rule 1). The frontend
//! holds entry metadata and nothing else; every operation that needs the key
//! runs here, behind a mutex, and hands back only what the caller asked for.

use std::path::PathBuf;
use std::sync::Mutex;

use vault_core::Vault;

use crate::error::{CmdError, CmdResult};

pub struct AppState {
    /// `None` until a vault is opened. The inner `Vault` is `None`-keyed until
    /// unlocked; `Vault::lock` zeroizes the key.
    vault: Mutex<Option<Vault>>,
    path: PathBuf,
}

impl AppState {
    pub fn new(path: PathBuf) -> Self {
        Self {
            vault: Mutex::new(None),
            path,
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn vault_exists(&self) -> bool {
        self.path.exists()
    }

    /// Run `f` against the open vault.
    ///
    /// A poisoned mutex means a previous command panicked while holding the
    /// vault. Rather than recover the guard and carry on with state we cannot
    /// reason about, this reports an internal error; the user can lock and
    /// unlock to get a clean one.
    pub fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> CmdResult<T>) -> CmdResult<T> {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| CmdError::internal("vault state is unusable; restart the app"))?;
        let vault = guard.as_mut().ok_or_else(CmdError::locked)?;
        if vault.is_locked() {
            return Err(CmdError::locked());
        }
        f(vault)
    }

    /// Replace whatever vault is held. The previous one drops here, which
    /// zeroizes its key.
    pub fn set_vault(&self, vault: Option<Vault>) -> CmdResult<()> {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| CmdError::internal("vault state is unusable; restart the app"))?;
        *guard = vault;
        Ok(())
    }

    /// Drop the key. Safe to call when already locked.
    ///
    /// Called from the lock button, and on every lifecycle event that should
    /// end a session (CLAUDE.md rule 4).
    pub fn lock(&self) -> CmdResult<()> {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| CmdError::internal("vault state is unusable; restart the app"))?;
        if let Some(v) = guard.as_mut() {
            v.lock();
        }
        // Drop the Vault entirely: closes the SQLite connection and zeroizes.
        *guard = None;
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        match self.vault.lock() {
            Ok(g) => g.as_ref().map(|v| v.is_locked()).unwrap_or(true),
            // Fail closed: if we cannot tell, report locked.
            Err(_) => true,
        }
    }
}
