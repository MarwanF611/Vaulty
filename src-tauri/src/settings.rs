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

/// Refuse absurd values from a hand-edited file, in both directions.
const MIN_CLIPBOARD_CLEAR_SECONDS: u64 = 5;
const MAX_CLIPBOARD_CLEAR_SECONDS: u64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub shortcut: String,
    pub clipboard_clear_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            shortcut: DEFAULT_SHORTCUT.to_string(),
            clipboard_clear_seconds: DEFAULT_CLIPBOARD_CLEAR_SECONDS,
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
        self
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
        assert!(s.shortcut.contains("Shift+Space"));
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault.db");

        let s = Settings {
            shortcut: "CmdOrCtrl+Alt+V".into(),
            clipboard_clear_seconds: 45,
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
