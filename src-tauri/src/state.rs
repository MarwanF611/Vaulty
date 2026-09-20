//! Application state: the one place an unlocked vault lives.
//!
//! The vault key never leaves this process (CLAUDE.md rule 1). The frontend
//! holds entry metadata and nothing else; every operation that needs the key
//! runs here, behind a mutex, and hands back only what the caller asked for.
//!
//! Since Phase 2 this also holds the *pending capture* — text lifted out of
//! another application by the global shortcut, on its way into the vault. It is
//! kept here rather than handed to the popup for the same reason the vault key
//! is: it is a secret, and the webview has no business holding it. The popup
//! shows a masked preview and saves by reference.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vault_core::Vault;
use vault_platform::CapturedText;

use crate::error::{CmdError, CmdResult};
use crate::settings::Settings;

/// How long a captured selection may sit unused before it is zeroized.
///
/// SPEC.md holds the capture in memory across an unlock prompt, so it cannot be
/// discarded the instant the popup loses focus. But text the user walked away
/// from should not live in memory indefinitely (CLAUDE.md rule 4).
pub const CAPTURE_TTL: Duration = Duration::from_secs(5 * 60);

/// A selection waiting to be labelled and saved.
#[derive(Debug)]
pub struct PendingCapture {
    pub text: CapturedText,
    pub captured_at: Instant,
}

impl PendingCapture {
    fn is_expired(&self) -> bool {
        self.captured_at.elapsed() > CAPTURE_TTL
    }
}

pub struct AppState {
    /// `None` until a vault is opened. `Vault::lock` zeroizes the key.
    vault: Mutex<Option<Vault>>,
    path: PathBuf,
    settings: Mutex<Settings>,
    /// Text captured by the global shortcut, awaiting a label.
    pending: Mutex<Option<PendingCapture>>,
    /// Milliseconds for the last capture sequence, for the measured exit
    /// criterion in `docs/PHASES.md`.
    last_capture_ms: Mutex<Option<u64>>,
}

impl AppState {
    pub fn new(path: PathBuf) -> Self {
        let settings = Settings::load(&path);
        Self {
            vault: Mutex::new(None),
            path,
            settings: Mutex::new(settings),
            pending: Mutex::new(None),
            last_capture_ms: Mutex::new(None),
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
        let mut guard = self.vault.lock().map_err(|_| Self::poisoned())?;
        let vault = guard.as_mut().ok_or_else(CmdError::locked)?;
        if vault.is_locked() {
            return Err(CmdError::locked());
        }
        f(vault)
    }

    /// Replace whatever vault is held. The previous one drops here, which
    /// zeroizes its key.
    pub fn set_vault(&self, vault: Option<Vault>) -> CmdResult<()> {
        let mut guard = self.vault.lock().map_err(|_| Self::poisoned())?;
        *guard = vault;
        Ok(())
    }

    /// Drop the key. Safe to call when already locked.
    ///
    /// Also discards any pending capture: locking the vault is the user saying
    /// the session is over, and a captured secret is part of that session.
    pub fn lock(&self) -> CmdResult<()> {
        {
            let mut guard = self.vault.lock().map_err(|_| Self::poisoned())?;
            if let Some(v) = guard.as_mut() {
                v.lock();
            }
            // Drop the Vault entirely: closes the SQLite connection and zeroizes.
            *guard = None;
        }
        self.discard_capture()
    }

    pub fn is_locked(&self) -> bool {
        match self.vault.lock() {
            Ok(g) => g.as_ref().map(|v| v.is_locked()).unwrap_or(true),
            // Fail closed: if we cannot tell, report locked.
            Err(_) => true,
        }
    }

    // ------------------------------------------------------------- settings

    pub fn settings(&self) -> CmdResult<Settings> {
        self.settings
            .lock()
            .map(|s| s.clone())
            .map_err(|_| Self::poisoned())
    }

    /// Update settings in memory and on disk.
    pub fn set_settings(&self, next: Settings) -> CmdResult<Settings> {
        let next = next.sanitised();
        next.save(&self.path)
            .map_err(|_| CmdError::internal("Could not save settings."))?;
        let mut guard = self.settings.lock().map_err(|_| Self::poisoned())?;
        *guard = next.clone();
        Ok(next)
    }

    // -------------------------------------------------------- capture

    /// Store a fresh capture, replacing and zeroizing any previous one.
    pub fn set_pending_capture(&self, text: CapturedText) -> CmdResult<()> {
        let mut guard = self.pending.lock().map_err(|_| Self::poisoned())?;
        *guard = Some(PendingCapture {
            text,
            captured_at: Instant::now(),
        });
        Ok(())
    }

    /// Number of characters in the pending capture, or `None` if there is none.
    ///
    /// This is what the popup is allowed to know without an explicit reveal:
    /// enough to render a masked preview, and nothing more.
    pub fn pending_capture_len(&self) -> CmdResult<Option<usize>> {
        let mut guard = self.pending.lock().map_err(|_| Self::poisoned())?;
        if guard.as_ref().is_some_and(PendingCapture::is_expired) {
            *guard = None;
        }
        Ok(guard.as_ref().map(|p| p.text.char_count()))
    }

    /// Read the pending capture. Used by the explicit reveal, and by save.
    pub fn with_pending_capture<T>(
        &self,
        f: impl FnOnce(&CapturedText) -> T,
    ) -> CmdResult<Option<T>> {
        let mut guard = self.pending.lock().map_err(|_| Self::poisoned())?;
        if guard.as_ref().is_some_and(PendingCapture::is_expired) {
            *guard = None;
        }
        Ok(guard.as_ref().map(|p| f(&p.text)))
    }

    /// Zeroize the pending capture.
    ///
    /// SPEC.md: the captured text is "zeroized if the user cancels".
    pub fn discard_capture(&self) -> CmdResult<()> {
        let mut guard = self.pending.lock().map_err(|_| Self::poisoned())?;
        *guard = None; // CapturedText zeroizes on drop
        Ok(())
    }

    pub fn record_capture_ms(&self, ms: u64) {
        if let Ok(mut g) = self.last_capture_ms.lock() {
            *g = Some(ms);
        }
    }

    pub fn last_capture_ms(&self) -> Option<u64> {
        self.last_capture_ms.lock().ok().and_then(|g| *g)
    }

    fn poisoned() -> CmdError {
        CmdError::internal("vault state is unusable; restart the app")
    }
}
