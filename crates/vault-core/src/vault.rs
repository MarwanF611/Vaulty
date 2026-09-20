//! The vault: open, unlock, lock, and entry CRUD.
//!
//! Lifecycle is deliberately explicit. [`Vault::open`] gives you a *locked*
//! vault; nothing can be read until [`Vault::unlock`] succeeds, and
//! [`Vault::lock`] drops the key immediately.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::atomic;
use crate::crypto::{self, KdfParams, VaultKey};
use crate::db::{self, EntryRow};
use crate::entry::{
    self, EntryAad, EntryId, EntryKind, EntryMeta, EntryUpdate, NewEntry, RevealedEntry,
};
use crate::error::{Error, Result};
use crate::header::{SlotKind, VaultHeader};

/// Unix seconds. Never fails: a clock before the epoch yields 0 rather than a
/// panic, and nothing security-relevant depends on the value.
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An open vault, locked or unlocked.
pub struct Vault {
    conn: Connection,
    path: PathBuf,
    header: VaultHeader,
    /// `None` means locked. Dropping it zeroizes the key.
    key: Option<VaultKey>,
}

// Never Debug-print anything that could carry key material.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &self.header.vault_id)
            .field("locked", &self.is_locked())
            .finish()
    }
}

impl Vault {
    /// Create a new vault at `path` and return it **unlocked**.
    ///
    /// Fails if a vault already exists there: silently overwriting somebody's
    /// vault is not a recoverable mistake.
    pub fn create(path: &Path, password: &[u8]) -> Result<Self> {
        Self::create_with_params(path, password, KdfParams::default())
    }

    /// As [`Vault::create`], with explicit KDF cost. Tests use cheap parameters;
    /// the app uses [`KdfParams::default`].
    pub fn create_with_params(path: &Path, password: &[u8], params: KdfParams) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::Invalid("master password must not be empty"));
        }
        if path.exists() {
            return Err(Error::Invalid("a vault already exists at that path"));
        }
        params.validate()?;

        let conn = db::open(path)?;
        db::init_schema(&conn)?;
        db::migrate(&conn)?;

        let vault_key = VaultKey::generate();
        let header = VaultHeader::create(&vault_key, password, params, now())?;
        db::set_meta(&conn, db::META_HEADER, &header.encode()?)?;
        db::set_meta_i64(&conn, db::META_CHANGE_SEQ, 0)?;

        Ok(Vault {
            conn,
            path: path.to_path_buf(),
            header,
            key: Some(vault_key),
        })
    }

    /// Open an existing vault. The returned vault is **locked**.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::VaultNotFound);
        }
        let conn = db::open(path)?;
        db::migrate(&conn)?;

        let raw = db::get_meta(&conn, db::META_HEADER)?.ok_or(Error::BadMagic)?;
        let header = VaultHeader::decode(&raw)?;

        Ok(Vault {
            conn,
            path: path.to_path_buf(),
            header,
            key: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    pub fn format_version(&self) -> u16 {
        self.header.format_version
    }

    pub fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    pub fn has_biometric_slot(&self) -> bool {
        self.header.has_slot(SlotKind::Biometric)
    }

    /// Unlock with the master password.
    ///
    /// On failure the vault stays locked and the error is the undifferentiated
    /// [`Error::Auth`] — a wrong password and a tampered file look the same.
    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        let key = self.header.unlock_with_password(password)?;
        self.key = Some(key);
        Ok(())
    }

    /// Prove knowledge of the master password without altering the session.
    ///
    /// Used before granting a second unlock path: enabling biometrics should
    /// require the credential it is being added alongside, not merely an
    /// already-unlocked window someone walked up to.
    pub fn verify_password(&self, password: &[u8]) -> Result<()> {
        // The derived key is dropped immediately; this is a check, not an unlock.
        self.header.unlock_with_password(password).map(|_| ())
    }

    /// Drop the vault key. Called on explicit lock, idle timeout, sleep and quit.
    ///
    /// `VaultKey` holds a `SecretBox`, so the bytes are zeroized as it drops.
    pub fn lock(&mut self) {
        self.key = None;
    }

    fn key(&self) -> Result<&VaultKey> {
        self.key.as_ref().ok_or(Error::Locked)
    }

    // ---------------------------------------------------------------- entries

    /// Add an entry. Returns its metadata — never the secret.
    pub fn add_entry(&mut self, new: NewEntry) -> Result<EntryMeta> {
        let key = self.key()?;
        entry::validate_label(&new.label)?;
        let tags = entry::canonical_tags(&new.tags)?;
        let tags_encoded = entry::encode_tags(&tags);

        let id = Uuid::now_v7();
        let ts = now();
        let change_seq = db::next_change_seq(&self.conn)?;

        let payload = entry::encode_payload(&new.secret, new.note.as_deref().map(|s| s.as_str()))?;
        let nonce = crypto::random_nonce();
        let aad = EntryAad {
            vault_id: &self.header.vault_id,
            entry_id: &id,
            kind: new.kind,
            label: &new.label,
            tags_encoded: &tags_encoded,
            created_at: ts,
            updated_at: ts,
            change_seq,
        }
        .to_bytes();
        let ciphertext = crypto::seal(key.expose(), &nonce, &payload, &aad)?;

        let row = EntryRow {
            id,
            label: new.label.clone(),
            tags: tags_encoded,
            kind: new.kind as u8,
            nonce: nonce.to_vec(),
            ciphertext,
            created_at: ts,
            updated_at: ts,
            last_used_at: None,
            deleted: false,
            change_seq,
        };
        db::insert_entry(&self.conn, &row)?;

        Ok(EntryMeta {
            id,
            label: new.label,
            tags,
            kind: new.kind,
            created_at: ts,
            updated_at: ts,
            last_used_at: None,
            change_seq,
        })
    }

    /// Metadata for every live entry, most recently updated first.
    ///
    /// This is the shape the frontend gets. No secrets cross this boundary
    /// (CLAUDE.md rule 1).
    pub fn list_entries(&self) -> Result<Vec<EntryMeta>> {
        // Listing is metadata only, but it still requires an unlocked vault:
        // clear-text labels are not something a locked app should hand out.
        self.key()?;
        let rows = db::list_rows(&self.conn)?;
        rows.iter().map(meta_from_row).collect()
    }

    /// Case-insensitive substring match over labels and tags.
    ///
    /// Done in Rust rather than SQL so that case folding is Unicode-correct;
    /// vaults are small enough that this is not the bottleneck at v1 scale.
    pub fn search(&self, query: &str) -> Result<Vec<EntryMeta>> {
        let all = self.list_entries()?;
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(all);
        }
        Ok(all
            .into_iter()
            .filter(|m| {
                m.label.to_lowercase().contains(&q)
                    || m.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect())
    }

    /// Metadata for one entry, without decrypting anything.
    pub fn get_meta(&self, id: &EntryId) -> Result<EntryMeta> {
        self.key()?;
        let row = db::get_row(&self.conn, id)?.ok_or(Error::NotFound)?;
        if row.deleted {
            return Err(Error::NotFound);
        }
        meta_from_row(&row)
    }

    /// Decrypt one entry.
    ///
    /// This is the only path that produces plaintext, and it is reached only from
    /// an explicit reveal or copy. The result zeroizes on drop. Marks the entry
    /// as recently used.
    pub fn get_entry(&self, id: &EntryId) -> Result<RevealedEntry> {
        let key = self.key()?;
        let row = db::get_row(&self.conn, id)?.ok_or(Error::NotFound)?;
        if row.deleted {
            return Err(Error::NotFound);
        }

        let meta = meta_from_row(&row)?;
        let nonce = nonce_from(&row.nonce)?;
        let aad = EntryAad {
            vault_id: &self.header.vault_id,
            entry_id: &row.id,
            kind: meta.kind,
            label: &row.label,
            tags_encoded: &row.tags,
            created_at: row.created_at,
            updated_at: row.updated_at,
            change_seq: row.change_seq,
        }
        .to_bytes();

        let plaintext = crypto::open(key.expose(), &nonce, &row.ciphertext, &aad)?;
        let (secret, note) = entry::decode_payload(&plaintext)?;

        db::touch_last_used(&self.conn, id, now())?;

        Ok(RevealedEntry { meta, secret, note })
    }

    /// Update an entry. Any change re-encrypts under a fresh nonce, because the
    /// clear-text fields are authenticated.
    pub fn update_entry(&mut self, id: &EntryId, update: EntryUpdate) -> Result<EntryMeta> {
        let key = self.key()?;
        let row = db::get_row(&self.conn, id)?.ok_or(Error::NotFound)?;
        if row.deleted {
            return Err(Error::NotFound);
        }

        // Read the current plaintext so unchanged fields survive the re-seal.
        let old_kind = EntryKind::from_u8(row.kind)?;
        let old_nonce = nonce_from(&row.nonce)?;
        let old_aad = EntryAad {
            vault_id: &self.header.vault_id,
            entry_id: &row.id,
            kind: old_kind,
            label: &row.label,
            tags_encoded: &row.tags,
            created_at: row.created_at,
            updated_at: row.updated_at,
            change_seq: row.change_seq,
        }
        .to_bytes();
        let old_plain = crypto::open(key.expose(), &old_nonce, &row.ciphertext, &old_aad)?;
        let (old_secret, old_note) = entry::decode_payload(&old_plain)?;

        let label = match update.label {
            Some(l) => {
                entry::validate_label(&l)?;
                l
            }
            None => row.label.clone(),
        };
        let tags = match update.tags {
            Some(t) => entry::canonical_tags(&t)?,
            None => entry::decode_tags(&row.tags),
        };
        let tags_encoded = entry::encode_tags(&tags);
        let kind = update.kind.unwrap_or(old_kind);
        let secret: Zeroizing<String> = update.secret.unwrap_or(old_secret);
        let note: Option<Zeroizing<String>> = match update.note {
            Some(n) => n,
            None => old_note,
        };

        let ts = now();
        let change_seq = db::next_change_seq(&self.conn)?;
        let payload = entry::encode_payload(&secret, note.as_deref().map(|s| s.as_str()))?;
        let nonce = crypto::random_nonce();
        let aad = EntryAad {
            vault_id: &self.header.vault_id,
            entry_id: &row.id,
            kind,
            label: &label,
            tags_encoded: &tags_encoded,
            created_at: row.created_at,
            updated_at: ts,
            change_seq,
        }
        .to_bytes();
        let ciphertext = crypto::seal(key.expose(), &nonce, &payload, &aad)?;

        let updated = EntryRow {
            id: row.id,
            label: label.clone(),
            tags: tags_encoded,
            kind: kind as u8,
            nonce: nonce.to_vec(),
            ciphertext,
            created_at: row.created_at,
            updated_at: ts,
            last_used_at: row.last_used_at,
            deleted: false,
            change_seq,
        };
        db::replace_entry(&self.conn, &updated)?;

        Ok(EntryMeta {
            id: row.id,
            label,
            tags,
            kind,
            created_at: row.created_at,
            updated_at: ts,
            last_used_at: row.last_used_at,
            change_seq,
        })
    }

    /// Delete an entry, leaving a tombstone so a future sync can propagate it.
    pub fn delete_entry(&mut self, id: &EntryId) -> Result<()> {
        self.key()?;
        let change_seq = db::next_change_seq(&self.conn)?;
        db::tombstone(&self.conn, id, now(), change_seq)
    }

    // ----------------------------------------------------------------- keying

    /// Rewrap the vault key under a new master password.
    ///
    /// Entries are *not* re-encrypted: the vault key does not change, only the
    /// slot that wraps it (SECURITY.md, "Two-key design").
    pub fn change_master_password(&mut self, old: &[u8], new: &[u8]) -> Result<()> {
        if new.is_empty() {
            return Err(Error::Invalid("master password must not be empty"));
        }
        // Always verify against the file, never against an already-unlocked key:
        // "change password" must prove knowledge of the current one.
        let vault_key = self.header.unlock_with_password(old)?;

        let params = self
            .header
            .slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .and_then(|s| s.kdf)
            .unwrap_or_default();

        let mut next = self.header.clone();
        next.rewrap_password(&vault_key, new, params, now())?;
        db::set_meta(&self.conn, db::META_HEADER, &next.encode()?)?;
        self.header = next;

        // Keep the session usable: the key itself is unchanged.
        self.key = Some(vault_key);
        Ok(())
    }

    /// Add a keystore-backed unlock slot wrapping the current vault key.
    ///
    /// Requires an unlocked vault: we can only wrap a key we hold. `kek` is
    /// the 32 bytes the OS keystore will guard behind Touch ID or Hello — the
    /// caller generates it, stores it, and passes it here.
    pub fn enable_keystore_unlock(
        &mut self,
        kind: SlotKind,
        kek: &[u8; crypto::KEY_LEN],
    ) -> Result<()> {
        let vault_key = self.key()?;
        let slot = self
            .header
            .build_keystore_slot(vault_key, kek, kind, now())?;

        let mut next = self.header.clone();
        next.set_slot(slot);
        db::set_meta(&self.conn, db::META_HEADER, &next.encode()?)?;
        self.header = next;
        Ok(())
    }

    /// Unlock using a key read back from the OS keystore.
    ///
    /// The biometric prompt happened before this call — it is what let the
    /// caller read `kek`. A failure leaves the vault locked so the UI falls
    /// back to the master password; there is no silent unlock path
    /// (SECURITY.md, "Rules for both platforms").
    pub fn unlock_with_keystore_key(
        &mut self,
        kek: &[u8; crypto::KEY_LEN],
        kind: SlotKind,
    ) -> Result<()> {
        let key = self.header.unlock_with_keystore_key(kek, kind)?;
        self.key = Some(key);
        Ok(())
    }

    /// Remove a keystore-backed slot. The master password is unaffected.
    ///
    /// Works whether or not the vault is unlocked: turning biometrics off
    /// should not require proving you can turn it on.
    pub fn disable_keystore_unlock(&mut self, kind: SlotKind) -> Result<()> {
        let mut next = self.header.clone();
        next.remove_slots(kind)?;
        db::set_meta(&self.conn, db::META_HEADER, &next.encode()?)?;
        self.header = next;
        Ok(())
    }

    pub fn has_slot(&self, kind: SlotKind) -> bool {
        self.header.has_slot(kind)
    }

    // -------------------------------------------------------------- snapshots

    /// Take a snapshot and rotate the older ones.
    pub fn snapshot(&self) -> Result<PathBuf> {
        atomic::snapshot(&self.conn, &self.path)
    }

    pub fn snapshots(&self) -> Vec<PathBuf> {
        atomic::list_snapshots(&self.path)
    }

    // ----------------------------------------------------- internals for export

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub(crate) fn vault_key(&self) -> Result<&VaultKey> {
        self.key()
    }
}

/// Zeroize the key when the vault goes out of scope (CLAUDE.md rule 4).
impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}

fn meta_from_row(row: &EntryRow) -> Result<EntryMeta> {
    Ok(EntryMeta {
        id: row.id,
        label: row.label.clone(),
        tags: entry::decode_tags(&row.tags),
        kind: EntryKind::from_u8(row.kind)?,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_used_at: row.last_used_at,
        change_seq: row.change_seq,
    })
}

fn nonce_from(bytes: &[u8]) -> Result<[u8; crypto::NONCE_LEN]> {
    bytes.try_into().map_err(|_| Error::Auth)
}
