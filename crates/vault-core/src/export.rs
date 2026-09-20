//! Export and import.
//!
//! SPEC.md, "Business model": export is never paywalled and is a first-class
//! feature. Charging users to get their own passwords out of the app reads as
//! hostage-taking.
//!
//! Two formats:
//!
//! * **Encrypted** — a complete, self-contained vault file wrapped under an
//!   export password of the user's choosing. This is the backup format.
//! * **Plaintext JSON** — every secret in the clear. Exists because a user must
//!   be able to leave, and refuses to run without an explicit acknowledgement
//!   argument so it cannot happen by accident.

use std::path::Path;
use zeroize::Zeroizing;

use crate::atomic;
use crate::crypto::{self, KdfParams};
use crate::db::{self, EntryRow};
use crate::entry::{self, EntryAad, EntryKind, EntryUpdate, NewEntry};
use crate::error::{Error, Result};
use crate::vault::Vault;

/// What an import did. Returned so a caller can show "12 added, 3 already there".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}

/// The banner written into every plaintext export.
pub const PLAINTEXT_WARNING: &str = "THIS FILE CONTAINS EVERY SECRET IN YOUR VAULT IN PLAIN TEXT. \
     Anyone who reads this file has all of them. Delete it as soon as you have \
     finished with it, and do not put it in cloud storage, a backup, or a git repository.";

/// Passed to [`export_plaintext_json`] so the call cannot be made by accident.
///
/// There is no `Default` and no way to build it other than naming the variant.
#[derive(Debug, Clone, Copy)]
pub enum PlaintextAck {
    /// "Yes, I understand this writes every secret to disk unencrypted."
    IUnderstandThisWritesSecretsInTheClear,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PlaintextExport {
    #[serde(rename = "WARNING")]
    warning: String,
    format: String,
    vault_id: String,
    exported_at: i64,
    entries: Vec<PlaintextEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PlaintextEntry {
    id: String,
    label: String,
    tags: Vec<String>,
    kind: EntryKind,
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl Vault {
    /// Write a complete encrypted backup, unlockable with `export_password`.
    ///
    /// The vault key is unchanged and the vault id is preserved, so entry
    /// ciphertexts are copied rather than re-encrypted. Only the wrapping slot
    /// is new.
    pub fn export_encrypted(&self, target: &Path, export_password: &[u8]) -> Result<()> {
        if export_password.is_empty() {
            return Err(Error::Invalid("export password must not be empty"));
        }
        let key = self.vault_key()?;
        if target.exists() {
            return Err(Error::Invalid("a file already exists at that path"));
        }

        let params = KdfParams::default();
        let mut header = self.header().clone();
        header.rewrap_password(key, export_password, params, crate::vault::now())?;

        // Build the export in memory, then land it with one atomic write.
        let mem = db::open_in_memory()?;
        db::init_schema(&mem)?;
        db::set_meta(&mem, db::META_HEADER, &header.encode()?)?;
        db::set_meta_i64(&mem, db::META_SCHEMA_VERSION, db::SCHEMA_VERSION)?;
        db::set_meta_i64(
            &mem,
            db::META_CHANGE_SEQ,
            db::get_meta_i64(self.conn(), db::META_CHANGE_SEQ)?.unwrap_or(0),
        )?;

        // Tombstones come along: a backup that silently resurrects deleted
        // entries on restore would be worse than useless.
        for row in db::list_rows_including_tombstones(self.conn())? {
            db::insert_entry(&mem, &row)?;
        }

        let tmp = target.with_extension("vaultybak.building");
        let _ = std::fs::remove_file(&tmp);
        let tmp_str = tmp.to_string_lossy().to_string();
        mem.execute("VACUUM INTO ?1", rusqlite::params![tmp_str])
            .map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                Error::Db(e)
            })?;

        let bytes = std::fs::read(&tmp)?;
        let _ = std::fs::remove_file(&tmp);
        atomic::write_atomic(target, &bytes)?;
        Ok(())
    }

    /// Merge an encrypted export into this vault.
    ///
    /// Entries are decrypted with the source key and re-encrypted with this
    /// vault's key, because the vault id is part of every entry's associated
    /// data. Matching ids are resolved by `updated_at`, newest wins.
    pub fn import_encrypted(
        &mut self,
        source_path: &Path,
        source_password: &[u8],
    ) -> Result<ImportReport> {
        self.vault_key()?;

        let mut source = Vault::open(source_path)?;
        source.unlock(source_password)?;

        let mut report = ImportReport::default();
        for meta in source.list_entries()? {
            let revealed = source.get_entry(&meta.id)?;

            match self.get_meta(&meta.id) {
                Ok(existing) => {
                    if existing.updated_at >= meta.updated_at {
                        report.skipped += 1;
                        continue;
                    }
                    self.update_entry(
                        &meta.id,
                        EntryUpdate {
                            label: Some(meta.label.clone()),
                            tags: Some(meta.tags.clone()),
                            kind: Some(meta.kind),
                            secret: Some(revealed.secret.clone()),
                            note: Some(revealed.note.clone()),
                        },
                    )?;
                    report.updated += 1;
                }
                Err(Error::NotFound) => {
                    // Re-encrypting means a new id would be issued by
                    // `add_entry`; insert directly so the id survives and a
                    // second import of the same file is idempotent.
                    self.insert_reencrypted(
                        meta.id,
                        &meta.label,
                        &meta.tags,
                        meta.kind,
                        &revealed.secret,
                        revealed.note.as_deref().map(|s| s.as_str()),
                        meta.created_at,
                        meta.updated_at,
                    )?;
                    report.added += 1;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Insert an entry under a caller-chosen id and timestamps, sealed with this
    /// vault's key. Used by import; not part of the public CRUD surface.
    #[allow(clippy::too_many_arguments)]
    fn insert_reencrypted(
        &mut self,
        id: uuid::Uuid,
        label: &str,
        tags: &[String],
        kind: EntryKind,
        secret: &str,
        note: Option<&str>,
        created_at: i64,
        updated_at: i64,
    ) -> Result<()> {
        let key = self.vault_key()?;
        entry::validate_label(label)?;
        let tags = entry::canonical_tags(tags)?;
        let tags_encoded = entry::encode_tags(&tags);
        let change_seq = db::next_change_seq(self.conn())?;

        let payload = entry::encode_payload(secret, note)?;
        let nonce = crypto::random_nonce();
        let aad = EntryAad {
            vault_id: &self.vault_id(),
            entry_id: &id,
            kind,
            label,
            tags_encoded: &tags_encoded,
            created_at,
            updated_at,
            change_seq,
        }
        .to_bytes();
        let ciphertext = crypto::seal(key.expose(), &nonce, &payload, &aad)?;

        db::insert_entry(
            self.conn(),
            &EntryRow {
                id,
                label: label.to_string(),
                tags: tags_encoded,
                kind: kind as u8,
                nonce: nonce.to_vec(),
                ciphertext,
                created_at,
                updated_at,
                last_used_at: None,
                deleted: false,
                change_seq,
            },
        )
    }

    /// Write every secret to `target` as plain-text JSON.
    ///
    /// Requires [`PlaintextAck`] so no caller reaches this by tab-completion.
    /// The file is created 0600 on Unix, but that is a speed bump, not
    /// protection: the contents are unencrypted.
    pub fn export_plaintext_json(&self, target: &Path, _ack: PlaintextAck) -> Result<()> {
        self.vault_key()?;
        if target.exists() {
            return Err(Error::Invalid("a file already exists at that path"));
        }

        let mut entries = Vec::new();
        for meta in self.list_entries()? {
            let revealed = self.get_entry(&meta.id)?;
            entries.push(PlaintextEntry {
                id: meta.id.to_string(),
                label: meta.label,
                tags: meta.tags,
                kind: meta.kind,
                secret: revealed.secret.to_string(),
                note: revealed.note.as_ref().map(|n| n.to_string()),
                created_at: meta.created_at,
                updated_at: meta.updated_at,
            });
        }

        let doc = PlaintextExport {
            warning: PLAINTEXT_WARNING.to_string(),
            format: "vaulty-plaintext-v1".to_string(),
            vault_id: self.vault_id().to_string(),
            exported_at: crate::vault::now(),
            entries,
        };

        // Zeroized once written: this buffer is every secret in the vault.
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&doc)
                .map_err(|_| Error::Invalid("could not serialise export"))?,
        );
        atomic::write_atomic(target, &json)?;
        Ok(())
    }

    /// Read a plaintext JSON export back in. Every entry gets a fresh id.
    pub fn import_plaintext_json(&mut self, source: &Path) -> Result<ImportReport> {
        self.vault_key()?;
        let bytes = Zeroizing::new(std::fs::read(source)?);
        let doc: PlaintextExport = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Invalid("not a vaulty plaintext export"))?;
        if doc.format != "vaulty-plaintext-v1" {
            return Err(Error::Invalid("unsupported plaintext export format"));
        }

        let mut report = ImportReport::default();
        for e in doc.entries {
            self.add_entry(NewEntry {
                label: e.label,
                tags: e.tags,
                kind: e.kind,
                secret: Zeroizing::new(e.secret),
                note: e.note.map(Zeroizing::new),
            })?;
            report.added += 1;
        }
        Ok(report)
    }
}
