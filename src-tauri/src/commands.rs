//! The Tauri command surface.
//!
//! This file *is* the boundary named in CLAUDE.md rule 1: "No plaintext secret
//! crosses into the webview unless the user explicitly asked to reveal or copy
//! it. The frontend gets labels, tags and metadata. Nothing else."
//!
//! So the DTOs below are a deliberate allowlist rather than a re-export of
//! `vault_core` types. If a field is not written out here, it cannot reach the
//! frontend by accident when a core type later grows a member.
//!
//! Exactly one struct in this file carries plaintext — [`RevealedSecret`] — and
//! exactly one command returns it. `copy_secret` does not: it writes to the
//! clipboard from Rust, so a copy never puts the secret in the webview at all.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use vault_core::{EntryKind, EntryMeta, EntryUpdate, NewEntry, Vault};
use zeroize::Zeroizing;

use crate::error::{CmdError, CmdResult};
use crate::settings::Settings;
use crate::state::AppState;
use crate::{capture, popup, shortcut};

// ------------------------------------------------------------------- DTOs

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// Whether a vault file exists at the configured path.
    pub exists: bool,
    pub locked: bool,
    pub path: String,
    /// Only populated while unlocked.
    pub vault_id: Option<String>,
    pub format_version: Option<u16>,
    pub entry_count: Option<usize>,
}

/// Entry metadata. No secret, no note — by construction.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryMetaDto {
    pub id: String,
    pub label: String,
    pub tags: Vec<String>,
    pub kind: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

impl From<EntryMeta> for EntryMetaDto {
    fn from(m: EntryMeta) -> Self {
        Self {
            id: m.id.to_string(),
            label: m.label,
            tags: m.tags,
            kind: m.kind.to_string(),
            created_at: m.created_at,
            updated_at: m.updated_at,
            last_used_at: m.last_used_at,
        }
    }
}

/// The only plaintext-bearing type that crosses the IPC boundary.
///
/// Returned solely by [`reveal_secret`], which the user reaches by pressing a
/// "reveal" button. The frontend must render it and drop it — never store it in
/// a component that outlives the reveal.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedSecret {
    pub secret: String,
    pub note: Option<String>,
}

// Never Debug-print plaintext, even here (CLAUDE.md rule 3).
impl std::fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedSecret")
            .field("secret", &"[redacted]")
            .field("note", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewEntryInput {
    pub label: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub kind: String,
    pub secret: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEntryInput {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    /// `None` leaves the note alone; `Some(None)` clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub note: Option<Option<String>>,
}

/// Distinguish "field absent" from "field present and null" in the JSON.
fn double_option<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(de).map(Some)
}

// -------------------------------------------------------------- helpers

fn parse_id(id: &str) -> CmdResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| CmdError::invalid("that is not a valid entry id"))
}

fn parse_kind(kind: &str) -> CmdResult<EntryKind> {
    kind.parse::<EntryKind>()
        .map_err(|_| CmdError::invalid("unknown entry kind"))
}

// ------------------------------------------------------------- lifecycle

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    let exists = state.vault_exists();
    let locked = state.is_locked();
    let path = state.path().display().to_string();

    if locked {
        return Ok(VaultStatus {
            exists,
            locked,
            path,
            vault_id: None,
            format_version: None,
            entry_count: None,
        });
    }

    state.with_vault(|v| {
        Ok(VaultStatus {
            exists: true,
            locked: false,
            path: v.path().display().to_string(),
            vault_id: Some(v.vault_id().to_string()),
            format_version: Some(v.format_version()),
            entry_count: Some(v.list_entries()?.len()),
        })
    })
}

/// Create a new vault and leave it unlocked.
///
/// `password` arrives from the webview as a plain `String` — there is no way
/// around that, the user typed it into a text field. It is moved into a
/// `Zeroizing` immediately so the Rust-side copy has a bounded lifetime.
#[tauri::command]
pub fn create_vault(state: State<'_, AppState>, password: String) -> CmdResult<VaultStatus> {
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err(CmdError::invalid("The master password must not be empty."));
    }
    if state.vault_exists() {
        return Err(CmdError::invalid("A vault already exists at that path."));
    }

    let vault = Vault::create(state.path(), password.as_bytes())?;
    state.set_vault(Some(vault))?;
    vault_status(state)
}

#[tauri::command]
pub fn unlock_vault(state: State<'_, AppState>, password: String) -> CmdResult<VaultStatus> {
    let password = Zeroizing::new(password);

    let mut vault = Vault::open(state.path())?;
    // On failure the vault is dropped here, so nothing half-opened is retained.
    vault.unlock(password.as_bytes())?;
    state.set_vault(Some(vault))?;
    vault_status(state)
}

/// Drop the key. The manual lock button, and every future auto-lock trigger.
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> CmdResult<()> {
    state.lock()
}

#[tauri::command]
pub fn change_master_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> CmdResult<()> {
    let old = Zeroizing::new(old_password);
    let new = Zeroizing::new(new_password);
    if new.is_empty() {
        return Err(CmdError::invalid("The new password must not be empty."));
    }
    state.with_vault(|v| {
        v.change_master_password(old.as_bytes(), new.as_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------- entries

#[tauri::command]
pub fn list_entries(state: State<'_, AppState>) -> CmdResult<Vec<EntryMetaDto>> {
    state.with_vault(|v| Ok(v.list_entries()?.into_iter().map(Into::into).collect()))
}

#[tauri::command]
pub fn search_entries(state: State<'_, AppState>, query: String) -> CmdResult<Vec<EntryMetaDto>> {
    state.with_vault(|v| Ok(v.search(&query)?.into_iter().map(Into::into).collect()))
}

#[tauri::command]
pub fn add_entry(state: State<'_, AppState>, input: NewEntryInput) -> CmdResult<EntryMetaDto> {
    let kind = parse_kind(&input.kind)?;
    let secret = Zeroizing::new(input.secret);
    let note = input.note.map(Zeroizing::new);

    state.with_vault(|v| {
        let meta = v.add_entry(NewEntry {
            label: input.label.clone(),
            tags: input.tags.clone(),
            kind,
            secret: secret.clone(),
            note: note.clone(),
        })?;
        Ok(meta.into())
    })
}

#[tauri::command]
pub fn update_entry(
    state: State<'_, AppState>,
    id: String,
    input: UpdateEntryInput,
) -> CmdResult<EntryMetaDto> {
    let id = parse_id(&id)?;
    let kind = match &input.kind {
        Some(k) => Some(parse_kind(k)?),
        None => None,
    };
    let secret = input.secret.map(Zeroizing::new);
    let note = input.note.map(|inner| inner.map(Zeroizing::new));

    state.with_vault(|v| {
        let meta = v.update_entry(
            &id,
            EntryUpdate {
                label: input.label.clone(),
                tags: input.tags.clone(),
                kind,
                secret: secret.clone(),
                note: note.clone(),
            },
        )?;
        Ok(meta.into())
    })
}

#[tauri::command]
pub fn delete_entry(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    state.with_vault(|v| {
        v.delete_entry(&id)?;
        Ok(())
    })
}

// ------------------------------------------------- the two explicit escapes

/// Decrypt one entry and hand the plaintext to the webview.
///
/// This is the *only* command that returns a secret. It exists because the user
/// pressed "reveal". The decrypted value lives in a `Zeroizing` up to the point
/// serde takes it; from there it is the frontend's job not to retain it.
#[tauri::command]
pub fn reveal_secret(state: State<'_, AppState>, id: String) -> CmdResult<RevealedSecret> {
    let id = parse_id(&id)?;
    state.with_vault(|v| {
        let revealed = v.get_entry(&id)?;
        Ok(RevealedSecret {
            secret: revealed.secret.to_string(),
            note: revealed.note.as_ref().map(|n| n.to_string()),
        })
    })
}

/// Copy one secret to the system clipboard, from Rust.
///
/// Deliberately returns `()`. A copy is a far more common action than a reveal,
/// and routing it through the webview would put plaintext in the renderer for
/// no reason — the user wants it in the clipboard, not on screen.
///
/// The 30-second auto-clear is Phase 2.
#[tauri::command]
pub fn copy_secret(app: tauri::AppHandle, state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let clear_after = Duration::from_secs(state.settings()?.clipboard_clear_seconds);

    state.with_vault(|v| {
        let revealed = v.get_entry(&id)?;
        app.clipboard()
            .write_text(revealed.secret.as_str())
            .map_err(|_| CmdError::internal("Could not write to the clipboard."))?;
        Ok(())
    })?;

    // SPEC.md: the clipboard auto-clears 30 seconds after a copy. Scheduled
    // after the write so it can record what the clipboard looked like when we
    // left it, and leave it alone if the user has copied something since.
    capture::schedule_clipboard_clear(&app, clear_after);
    Ok(())
}

// ------------------------------------------------------------ maintenance

#[tauri::command]
pub fn take_snapshot(state: State<'_, AppState>) -> CmdResult<String> {
    state.with_vault(|v| Ok(v.snapshot()?.display().to_string()))
}

#[tauri::command]
pub fn export_encrypted(
    state: State<'_, AppState>,
    target_path: String,
    export_password: String,
) -> CmdResult<()> {
    let password = Zeroizing::new(export_password);
    if password.is_empty() {
        return Err(CmdError::invalid("The export password must not be empty."));
    }
    state.with_vault(|v| {
        v.export_encrypted(std::path::Path::new(&target_path), password.as_bytes())?;
        Ok(())
    })
}

// ============================================================ Phase 2: capture

/// What the popup is allowed to know about a pending capture.
///
/// A character count, not the text. Enough to render a masked preview.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureState {
    pub has_capture: bool,
    pub char_count: Option<usize>,
    pub locked: bool,
    /// Milliseconds taken by the most recent capture sequence.
    pub last_capture_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveCaptureInput {
    pub label: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub kind: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionState {
    /// "granted" | "denied" | "not_required" | "unsupported"
    pub accessibility: &'static str,
    pub capture_supported: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    pub shortcut: String,
    pub clipboard_clear_seconds: u64,
    pub default_shortcut: &'static str,
}

impl From<Settings> for SettingsDto {
    fn from(s: Settings) -> Self {
        Self {
            shortcut: s.shortcut,
            clipboard_clear_seconds: s.clipboard_clear_seconds,
            default_shortcut: crate::settings::DEFAULT_SHORTCUT,
        }
    }
}

#[tauri::command]
pub fn capture_state(state: State<'_, AppState>) -> CmdResult<CaptureState> {
    let char_count = state.pending_capture_len()?;
    Ok(CaptureState {
        has_capture: char_count.is_some(),
        char_count,
        locked: state.is_locked(),
        last_capture_ms: state.last_capture_ms(),
    })
}

/// Show the captured text.
///
/// The sibling of `reveal_secret`: the capture is the user's own selection, but
/// it is still plaintext, so it crosses the boundary only when asked for.
#[tauri::command]
pub fn reveal_capture(state: State<'_, AppState>) -> CmdResult<String> {
    state
        .with_pending_capture(|c| c.as_str().to_string())?
        .ok_or_else(|| CmdError::new("no_capture", "There is nothing captured."))
}

/// Save the pending capture as a new entry.
///
/// The secret is never sent from the webview: the popup supplies a label, tags
/// and kind, and the captured text is taken from Rust-side state. That keeps
/// the round trip one-way — plaintext goes in via the OS clipboard and out via
/// the vault, without passing through the renderer.
#[tauri::command]
pub fn save_capture(
    state: State<'_, AppState>,
    input: SaveCaptureInput,
) -> CmdResult<EntryMetaDto> {
    let kind = parse_kind(&input.kind)?;
    let note = input.note.map(Zeroizing::new);

    let secret = state
        .with_pending_capture(|c| Zeroizing::new(c.as_str().to_string()))?
        .ok_or_else(|| CmdError::new("no_capture", "There is nothing captured to save."))?;

    let meta = state.with_vault(|v| {
        let meta = v.add_entry(NewEntry {
            label: input.label.clone(),
            tags: input.tags.clone(),
            kind,
            secret: secret.clone(),
            note: note.clone(),
        })?;
        Ok(meta)
    })?;

    state.discard_capture()?;
    Ok(meta.into())
}

/// Throw the capture away and zeroize it. Escape, in other words.
#[tauri::command]
pub fn discard_capture(state: State<'_, AppState>) -> CmdResult<()> {
    state.discard_capture()
}

#[tauri::command]
pub fn hide_popup(app: tauri::AppHandle) -> CmdResult<()> {
    popup::hide(&app);
    Ok(())
}

// ------------------------------------------------------------- permissions

#[tauri::command]
pub fn permission_state() -> PermissionState {
    PermissionState {
        accessibility: vault_platform::accessibility_status().as_str(),
        capture_supported: vault_platform::capture_supported(),
    }
}

/// Trigger the OS permission prompt.
///
/// macOS shows this once per app bundle; after that the user has to go to
/// System Settings, which is why `open_accessibility_settings` exists too.
#[tauri::command]
pub fn request_accessibility() -> PermissionState {
    let status = popup::request_permission();
    PermissionState {
        accessibility: status.as_str(),
        capture_supported: vault_platform::capture_supported(),
    }
}

#[tauri::command]
pub fn open_accessibility_settings() -> CmdResult<()> {
    vault_platform::open_accessibility_settings()
        .map_err(|_| CmdError::internal("Could not open System Settings."))
}

// --------------------------------------------------------------- settings

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> CmdResult<SettingsDto> {
    Ok(state.settings()?.into())
}

/// Rebind the global shortcut, rolling back if the OS refuses.
#[tauri::command]
pub fn set_shortcut(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    accelerator: String,
) -> CmdResult<SettingsDto> {
    let current = state.settings()?;

    shortcut::rebind(&app, &current.shortcut, &accelerator)
        .map_err(|e| CmdError::new(e.code(), e.message(&accelerator)))?;

    let next = Settings {
        shortcut: accelerator,
        ..current
    };
    Ok(state.set_settings(next)?.into())
}

#[tauri::command]
pub fn set_clipboard_clear_seconds(
    state: State<'_, AppState>,
    seconds: u64,
) -> CmdResult<SettingsDto> {
    let current = state.settings()?;
    let next = Settings {
        clipboard_clear_seconds: seconds,
        ..current
    };
    Ok(state.set_settings(next)?.into())
}
