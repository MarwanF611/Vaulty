//! Persisted settings.
//!
//! Phase 2 needs two of them: the global shortcut binding and how long a copied
//! secret is allowed to sit in the clipboard. The full settings surface (idle
//! timeout, biometrics toggle) is Phase 5; this is the file it will grow into.
//!
//! Stored as JSON beside the vault. Nothing here is secret — it is a key
//! binding and a duration — so it is plain, readable, and hand-editable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// `Cmd+Shift+Space` on macOS, `Ctrl+Shift+Space` on Windows.
///
/// `docs/SPEC.md` flags the Windows default as a known collision: it is the
/// parameter-hints binding in Visual Studio and the JetBrains IDEs, which is
/// precisely the audience. That is why rebinding exists from the first build
/// rather than being deferred to a settings phase.
pub const DEFAULT_SHORTCUT: &str = if cfg!(target_os = "macos") {
    "CmdOrCtrl+Shift+Space"
} else {
    "Ctrl+Shift+Space"
};

/// SPEC.md: "Clipboard auto-clears 30 seconds after a copy".
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u64 = 30;

/// SECURITY.md: "Re-prompt for the master password roughly every 14 days so it
/// stays in muscle memory."
///
/// This is not a security control — biometrics is already gated by the OS. It
/// exists so that the one credential with no recovery path does not quietly
/// fade out of the user's memory over months of Touch ID.
pub const DEFAULT_PASSWORD_REPROMPT_DAYS: u64 = 14;

const MIN_PASSWORD_REPROMPT_DAYS: u64 = 1;
const MAX_PASSWORD_REPROMPT_DAYS: u64 = 90;

/// Idle seconds before the vault locks itself. Five minutes.
pub const DEFAULT_IDLE_LOCK_SECONDS: u64 = 300;

/// Zero disables the idle timer. Sleep and screen lock still lock the vault —
/// SECURITY.md makes those non-negotiable, so they are not settings.
const MIN_IDLE_LOCK_SECONDS: u64 = 30;
const MAX_IDLE_LOCK_SECONDS: u64 = 4 * 60 * 60;

/// Refuse absurd values from a hand-edited file, in both directions.
const MIN_CLIPBOARD_CLEAR_SECONDS: u64 = 5;
const MAX_CLIPBOARD_CLEAR_SECONDS: u64 = 600;

/// Unix seconds.
///
/// `vault_core` keeps its own clock helper crate-private, which is the right
/// boundary — this is the app layer's copy rather than a reason to widen that
/// API.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub shortcut: String,
    pub clipboard_clear_seconds: u64,
    /// How often the master password must be entered even when biometrics is on.
    #[serde(default = "default_reprompt_days")]
    pub password_reprompt_days: u64,
    /// Idle seconds before auto-lock. 0 disables the idle timer only.
    #[serde(default = "default_idle_lock_seconds")]
    pub idle_lock_seconds: u64,
    /// Unix seconds of the last unlock that used the master password.
    ///
    /// Not secret, and not security-relevant: the worst an attacker who edits
    /// it can do is make Vaulty ask for the password *less* often, and they
    /// still cannot read the keychain item or the vault without a biometric or
    /// the password itself.
    #[serde(default)]
    pub last_password_unlock_at: Option<i64>,
}

fn default_reprompt_days() -> u64 {
    DEFAULT_PASSWORD_REPROMPT_DAYS
}

fn default_idle_lock_seconds() -> u64 {
    DEFAULT_IDLE_LOCK_SECONDS
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            shortcut: DEFAULT_SHORTCUT.to_string(),
            clipboard_clear_seconds: DEFAULT_CLIPBOARD_CLEAR_SECONDS,
            password_reprompt_days: DEFAULT_PASSWORD_REPROMPT_DAYS,
            idle_lock_seconds: DEFAULT_IDLE_LOCK_SECONDS,
            last_password_unlock_at: None,
        }
    }
}

impl Settings {
    /// Clamp anything out of range rather than refusing to start.
    ///
    /// A settings file is not a security boundary; a bad value should degrade
    /// to a sane one, not lock the user out of their own app.
    pub fn sanitised(mut self) -> Self {
        if self.shortcut.trim().is_empty() {
            self.shortcut = DEFAULT_SHORTCUT.to_string();
        }
        self.clipboard_clear_seconds = self
            .clipboard_clear_seconds
            .clamp(MIN_CLIPBOARD_CLEAR_SECONDS, MAX_CLIPBOARD_CLEAR_SECONDS);
        self.password_reprompt_days = self
            .password_reprompt_days
            .clamp(MIN_PASSWORD_REPROMPT_DAYS, MAX_PASSWORD_REPROMPT_DAYS);
        // Zero is meaningful — it turns the idle timer off — so it is preserved
        // rather than clamped up to the minimum.
        if self.idle_lock_seconds != 0 {
            self.idle_lock_seconds = self
                .idle_lock_seconds
                .clamp(MIN_IDLE_LOCK_SECONDS, MAX_IDLE_LOCK_SECONDS);
        }
        self
    }

    /// Whether the master password is due, regardless of biometrics.
    ///
    /// A vault that has never been unlocked with a password in this record is
    /// treated as due: failing towards asking for the password is the safe
    /// direction, and it costs one extra unlock.
    pub fn password_reprompt_due(&self, now: i64) -> bool {
        let Some(last) = self.last_password_unlock_at else {
            return true;
        };
        // A clock that has gone backwards should not lock anyone out of
        // biometrics forever, but it also should not extend the window.
        if now < last {
            return true;
        }
        let elapsed_days = (now - last) / 86_400;
        elapsed_days >= self.password_reprompt_days as i64
    }

    /// Days remaining before the master password is asked for again.
    pub fn days_until_reprompt(&self, now: i64) -> i64 {
        let Some(last) = self.last_password_unlock_at else {
            return 0;
        };
        let elapsed_days = (now.saturating_sub(last)) / 86_400;
        (self.password_reprompt_days as i64 - elapsed_days).max(0)
    }

    /// Settings live beside the vault file.
    pub fn path_for_vault(vault_path: &Path) -> PathBuf {
        vault_path.with_file_name("settings.json")
    }

    /// Read settings, falling back to defaults for a missing or unreadable file.
    pub fn load(vault_path: &Path) -> Self {
        let path = Self::path_for_vault(vault_path);
        let Ok(bytes) = std::fs::read(&path) else {
            return Settings::default();
        };
        serde_json::from_slice::<Settings>(&bytes)
            .map(Settings::sanitised)
            .unwrap_or_default()
    }

    pub fn save(&self, vault_path: &Path) -> std::io::Result<()> {
        let path = Self::path_for_vault(vault_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_are_the_documented_ones() {
        let s = Settings::default();
        assert_eq!(s.clipboard_clear_seconds, 30);
        assert_eq!(s.password_reprompt_days, 14);
        assert!(s.shortcut.contains("Shift+Space"));
    }

    const DAY: i64 = 86_400;

    #[test]
    fn the_idle_lock_default_is_five_minutes() {
        assert_eq!(Settings::default().idle_lock_seconds, 300);
    }

    #[test]
    fn zero_idle_seconds_survives_sanitising() {
        // It means "no idle timer", not "an invalid value to be clamped".
        let s = Settings {
            idle_lock_seconds: 0,
            ..Settings::default()
        }
        .sanitised();
        assert_eq!(s.idle_lock_seconds, 0);
    }

    #[test]
    fn an_absurd_idle_window_is_clamped() {
        let s = Settings {
            idle_lock_seconds: 1,
            ..Settings::default()
        }
        .sanitised();
        assert_eq!(s.idle_lock_seconds, MIN_IDLE_LOCK_SECONDS);

        let s = Settings {
            idle_lock_seconds: u64::MAX,
            ..Settings::default()
        }
        .sanitised();
        assert_eq!(s.idle_lock_seconds, MAX_IDLE_LOCK_SECONDS);
    }

    #[test]
    fn a_vault_never_unlocked_by_password_is_due_immediately() {
        let s = Settings::default();
        assert!(s.last_password_unlock_at.is_none());
        assert!(s.password_reprompt_due(1_700_000_000));
        assert_eq!(s.days_until_reprompt(1_700_000_000), 0);
    }

    #[test]
    fn the_password_comes_due_after_the_configured_window() {
        let now = 1_700_000_000;
        let s = Settings {
            last_password_unlock_at: Some(now),
            ..Settings::default()
        };

        assert!(!s.password_reprompt_due(now));
        assert!(!s.password_reprompt_due(now + 13 * DAY));
        assert!(s.password_reprompt_due(now + 14 * DAY));
        assert!(s.password_reprompt_due(now + 400 * DAY));

        assert_eq!(s.days_until_reprompt(now), 14);
        assert_eq!(s.days_until_reprompt(now + 10 * DAY), 4);
        assert_eq!(s.days_until_reprompt(now + 99 * DAY), 0);
    }

    /// A clock that jumps backwards must not hand out an indefinite biometric
    /// window.
    #[test]
    fn a_backwards_clock_makes_the_password_due() {
        let now = 1_700_000_000;
        let s = Settings {
            last_password_unlock_at: Some(now),
            ..Settings::default()
        };
        assert!(s.password_reprompt_due(now - DAY));
    }

    #[test]
    fn the_reprompt_window_is_clamped() {
        let s = Settings {
            password_reprompt_days: 0,
            ..Settings::default()
        }
        .sanitised();
        assert!(s.password_reprompt_days >= 1);

        let s = Settings {
            password_reprompt_days: 100_000,
            ..Settings::default()
        }
        .sanitised();
        assert!(s.password_reprompt_days <= 90);
    }

    /// Settings files written before Phase 3 have neither new field.
    #[test]
    fn a_pre_phase_3_settings_file_still_loads() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault.db");
        std::fs::write(
            Settings::path_for_vault(&vault),
            br#"{"shortcut":"CmdOrCtrl+Shift+Space","clipboardClearSeconds":45}"#,
        )
        .unwrap();

        let s = Settings::load(&vault);
        assert_eq!(s.clipboard_clear_seconds, 45);
        assert_eq!(s.password_reprompt_days, DEFAULT_PASSWORD_REPROMPT_DAYS);
        assert!(s.last_password_unlock_at.is_none());
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault.db");

        let s = Settings {
            shortcut: "CmdOrCtrl+Alt+V".into(),
            clipboard_clear_seconds: 45,
            ..Settings::default()
        };
        s.save(&vault).unwrap();

        let back = Settings::load(&vault);
        assert_eq!(back.shortcut, "CmdOrCtrl+Alt+V");
        assert_eq!(back.clipboard_clear_seconds, 45);
    }

    #[test]
    fn a_missing_file_yields_defaults() {
        let dir = TempDir::new().unwrap();
        let s = Settings::load(&dir.path().join("nothing.db"));
        assert_eq!(s.shortcut, DEFAULT_SHORTCUT);
    }

    #[test]
    fn a_corrupt_file_yields_defaults_rather_than_failing_to_start() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault.db");
        std::fs::write(Settings::path_for_vault(&vault), b"{ not json at all").unwrap();

        let s = Settings::load(&vault);
        assert_eq!(s.shortcut, DEFAULT_SHORTCUT);
        assert_eq!(s.clipboard_clear_seconds, DEFAULT_CLIPBOARD_CLEAR_SECONDS);
    }

    #[test]
    fn out_of_range_values_are_clamped_not_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault.db");
        std::fs::write(
            Settings::path_for_vault(&vault),
            br#"{"shortcut":"","clipboardClearSeconds":999999}"#,
        )
        .unwrap();

        let s = Settings::load(&vault);
        assert_eq!(s.shortcut, DEFAULT_SHORTCUT);
        assert_eq!(s.clipboard_clear_seconds, MAX_CLIPBOARD_CLEAR_SECONDS);
    }

    #[test]
    fn settings_sit_beside_the_vault() {
        let p = Settings::path_for_vault(Path::new("/tmp/somewhere/vault.db"));
        assert_eq!(p, Path::new("/tmp/somewhere/settings.json"));
    }
}
