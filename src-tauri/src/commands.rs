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

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use vault_core::{EntryKind, EntryMeta, EntryUpdate, NewEntry, Vault};
use zeroize::Zeroizing;

use crate::error::{CmdError, CmdResult};
use crate::state::AppState;

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
    state.with_vault(|v| {
        let revealed = v.get_entry(&id)?;
        app.clipboard()
            .write_text(revealed.secret.as_str())
            .map_err(|_| CmdError::internal("Could not write to the clipboard."))?;
        Ok(())
    })
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
