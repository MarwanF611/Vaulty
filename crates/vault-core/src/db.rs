//! SQLite storage. Schema per `docs/SPEC.md`, "Data model".
//!
//! Per-entry encrypted blobs, not one big encrypted document: decrypting
//! everything to read one item, and rewriting everything to change one item, is
//! how a single bad write loses the lot.
//!
//! The sync-ready fields (`change_seq`, tombstones, `updated_at`, UUIDv7 ids) are
//! here from day one even though v1 has no sync. Retrofitting them later would
//! mean asking every existing user to export and re-import.

use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

use crate::error::{Error, Result};

/// Bumped whenever the SQL schema changes; each bump ships a migration in
/// [`migrate`].
pub const SCHEMA_VERSION: i64 = 1;

pub const META_HEADER: &str = "header";
pub const META_SCHEMA_VERSION: &str = "schema_version";
pub const META_CHANGE_SEQ: &str = "change_seq";

/// One row of `entries`, straight from SQLite. Ciphertext is still sealed here.
///
/// `Debug` omits the sealed bytes: they are not plaintext, but there is no
/// reason for a log line to carry them either (CLAUDE.md rule 3).
pub struct EntryRow {
    pub id: Uuid,
    pub label: String,
    pub tags: String,
    pub kind: u8,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub deleted: bool,
    pub change_seq: i64,
}

/// Open (or create) the database file and apply connection pragmas.
///
/// `journal_mode = DELETE` is deliberate: WAL would leave `-wal` and `-shm`
/// sidecar files next to the vault, which makes "copy the vault" and the
/// snapshot rotation in [`crate::atomic`] a three-file problem instead of a
/// one-file one. A single-process desktop app does not need WAL's concurrency.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    restrict_db_permissions(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// The vault file is owner-only. SQLite creates it with the process umask,
/// which on a default macOS account is 0644 — readable by every other account
/// on the machine.
fn restrict_db_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// An in-memory database, used by tests and by the encrypted-export writer.
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> Result<()> {
    // `synchronous = FULL`: this is a vault. Losing the last write to a power
    // cut is worse than the write being slow.
    conn.pragma_update(None, "journal_mode", "DELETE")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Create the schema if it is not already there.
pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS vault_meta (
            key   TEXT PRIMARY KEY NOT NULL,
            value BLOB NOT NULL
        ) STRICT;

        CREATE TABLE IF NOT EXISTS entries (
            id           BLOB    PRIMARY KEY NOT NULL,
            label        TEXT    NOT NULL,
            tags         TEXT    NOT NULL,
            kind         INTEGER NOT NULL,
            nonce        BLOB    NOT NULL,
            ciphertext   BLOB    NOT NULL,
            created_at   INTEGER NOT NULL,
            updated_at   INTEGER NOT NULL,
            last_used_at INTEGER,
            deleted      INTEGER NOT NULL DEFAULT 0,
            change_seq   INTEGER NOT NULL
        ) STRICT;

        -- Search-as-you-type over labels is the hot path (SPEC.md, UX).
        CREATE INDEX IF NOT EXISTS idx_entries_label      ON entries(label);
        CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON entries(updated_at);
        CREATE INDEX IF NOT EXISTS idx_entries_change_seq ON entries(change_seq);
        -- Recently-used ranking, live entries only.
        CREATE INDEX IF NOT EXISTS idx_entries_live
            ON entries(deleted, last_used_at);
        "#,
    )?;
    Ok(())
}

/// Apply any migrations needed to bring an existing file up to [`SCHEMA_VERSION`].
pub fn migrate(conn: &Connection) -> Result<()> {
    let current = get_meta_i64(conn, META_SCHEMA_VERSION)?.unwrap_or(SCHEMA_VERSION);
    if current > SCHEMA_VERSION {
        return Err(Error::UnsupportedVersion {
            found: u16::try_from(current).unwrap_or(u16::MAX),
            supported: u16::try_from(SCHEMA_VERSION).unwrap_or(u16::MAX),
        });
    }
    // Version 1 is the first schema; there is nothing to migrate from yet.
    // Future versions add `if current < N { ... }` blocks here.
    set_meta_i64(conn, META_SCHEMA_VERSION, SCHEMA_VERSION)?;
    Ok(())
}

pub fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    let v = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(v)
}

pub fn set_meta_i64(conn: &Connection, key: &str, value: i64) -> Result<()> {
    set_meta(conn, key, &value.to_le_bytes())
}

pub fn get_meta_i64(conn: &Connection, key: &str) -> Result<Option<i64>> {
    match get_meta(conn, key)? {
        None => Ok(None),
        Some(b) => {
            let arr: [u8; 8] = b
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedHeader)?;
            Ok(Some(i64::from_le_bytes(arr)))
        }
    }
}

/// Reserve the next change sequence number.
pub fn next_change_seq(conn: &Connection) -> Result<i64> {
    let current = get_meta_i64(conn, META_CHANGE_SEQ)?.unwrap_or(0);
    let next = current.saturating_add(1);
    set_meta_i64(conn, META_CHANGE_SEQ, next)?;
    Ok(next)
}

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    let id_bytes: Vec<u8> = row.get("id")?;
    let id = Uuid::from_slice(&id_bytes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "entry id is not a uuid".into(),
        )
    })?;
    Ok(EntryRow {
        id,
        label: row.get("label")?,
        tags: row.get("tags")?,
        kind: row.get::<_, i64>("kind")? as u8,
        nonce: row.get("nonce")?,
        ciphertext: row.get("ciphertext")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        last_used_at: row.get("last_used_at")?,
        deleted: row.get::<_, i64>("deleted")? != 0,
        change_seq: row.get("change_seq")?,
    })
}

impl std::fmt::Debug for EntryRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryRow")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("tags", &self.tags)
            .field("kind", &self.kind)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .field("deleted", &self.deleted)
            .field("change_seq", &self.change_seq)
            .finish()
    }
}

const SELECT_COLS: &str = "id, label, tags, kind, nonce, ciphertext, \
                           created_at, updated_at, last_used_at, deleted, change_seq";

pub fn insert_entry(conn: &Connection, r: &EntryRow) -> Result<()> {
    conn.execute(
        "INSERT INTO entries
            (id, label, tags, kind, nonce, ciphertext,
             created_at, updated_at, last_used_at, deleted, change_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            r.id.as_bytes().as_slice(),
            r.label,
            r.tags,
            r.kind as i64,
            r.nonce,
            r.ciphertext,
            r.created_at,
            r.updated_at,
            r.last_used_at,
            i64::from(r.deleted),
            r.change_seq,
        ],
    )?;
    Ok(())
}

pub fn replace_entry(conn: &Connection, r: &EntryRow) -> Result<()> {
    let n = conn.execute(
        "UPDATE entries SET
            label = ?2, tags = ?3, kind = ?4, nonce = ?5, ciphertext = ?6,
            created_at = ?7, updated_at = ?8, last_used_at = ?9,
            deleted = ?10, change_seq = ?11
         WHERE id = ?1",
        rusqlite::params![
            r.id.as_bytes().as_slice(),
            r.label,
            r.tags,
            r.kind as i64,
            r.nonce,
            r.ciphertext,
            r.created_at,
            r.updated_at,
            r.last_used_at,
            i64::from(r.deleted),
            r.change_seq,
        ],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Fetch one row, tombstones included. Callers decide what to do with a tombstone.
pub fn get_row(conn: &Connection, id: &Uuid) -> Result<Option<EntryRow>> {
    let sql = format!("SELECT {SELECT_COLS} FROM entries WHERE id = ?1");
    let r = conn
        .query_row(&sql, rusqlite::params![id.as_bytes().as_slice()], row_from)
        .optional()?;
    Ok(r)
}

/// All live rows, most recently updated first.
pub fn list_rows(conn: &Connection) -> Result<Vec<EntryRow>> {
    let sql =
        format!("SELECT {SELECT_COLS} FROM entries WHERE deleted = 0 ORDER BY updated_at DESC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_from)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Every row including tombstones, ordered by `change_seq`. This is the shape a
/// future sync pass needs; v1 uses it for export.
pub fn list_rows_including_tombstones(conn: &Connection) -> Result<Vec<EntryRow>> {
    let sql = format!("SELECT {SELECT_COLS} FROM entries ORDER BY change_seq ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_from)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Turn a row into a tombstone: keep the id and the sync bookkeeping, drop
/// everything else. A deleted entry should not leave its label behind.
pub fn tombstone(conn: &Connection, id: &Uuid, now: i64, change_seq: i64) -> Result<()> {
    let n = conn.execute(
        "UPDATE entries SET
            label = '', tags = '', nonce = x'', ciphertext = x'',
            last_used_at = NULL, deleted = 1, updated_at = ?2, change_seq = ?3
         WHERE id = ?1 AND deleted = 0",
        rusqlite::params![id.as_bytes().as_slice(), now, change_seq],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Record that a secret was copied or revealed.
///
/// `last_used_at` is not part of the authenticated data, so this is a plain
/// column write with no re-encryption. See [`crate::entry::EntryAad`].
pub fn touch_last_used(conn: &Connection, id: &Uuid, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE entries SET last_used_at = ?2 WHERE id = ?1 AND deleted = 0",
        rusqlite::params![id.as_bytes().as_slice(), now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = open_in_memory().unwrap();
        init_schema(&c).unwrap();
        migrate(&c).unwrap();
        c
    }

    fn row(label: &str, seq: i64) -> EntryRow {
        EntryRow {
            id: Uuid::now_v7(),
            label: label.into(),
            tags: String::new(),
            kind: 1,
            nonce: vec![0u8; 24],
            ciphertext: vec![1, 2, 3],
            created_at: 1000,
            updated_at: 1000 + seq,
            last_used_at: None,
            deleted: false,
            change_seq: seq,
        }
    }

    #[test]
    fn schema_is_idempotent() {
        let c = conn();
        init_schema(&c).unwrap();
        init_schema(&c).unwrap();
        assert_eq!(get_meta_i64(&c, META_SCHEMA_VERSION).unwrap(), Some(1));
    }

    #[test]
    fn meta_round_trips() {
        let c = conn();
        set_meta(&c, "k", b"value").unwrap();
        assert_eq!(get_meta(&c, "k").unwrap().as_deref(), Some(&b"value"[..]));
        set_meta(&c, "k", b"replaced").unwrap();
        assert_eq!(
            get_meta(&c, "k").unwrap().as_deref(),
            Some(&b"replaced"[..])
        );
        assert!(get_meta(&c, "absent").unwrap().is_none());
    }

    #[test]
    fn change_seq_is_monotonic() {
        let c = conn();
        assert_eq!(next_change_seq(&c).unwrap(), 1);
        assert_eq!(next_change_seq(&c).unwrap(), 2);
        assert_eq!(next_change_seq(&c).unwrap(), 3);
    }

    #[test]
    fn insert_get_and_list() {
        let c = conn();
        let a = row("alpha", 1);
        let b = row("beta", 2);
        insert_entry(&c, &a).unwrap();
        insert_entry(&c, &b).unwrap();

        let got = get_row(&c, &a.id).unwrap().unwrap();
        assert_eq!(got.label, "alpha");
        assert_eq!(got.ciphertext, vec![1, 2, 3]);

        let all = list_rows(&c).unwrap();
        assert_eq!(all.len(), 2);
        // Most recently updated first.
        assert_eq!(all[0].label, "beta");
    }

    #[test]
    fn delete_leaves_a_tombstone_with_no_residue() {
        let c = conn();
        let a = row("alpha", 1);
        insert_entry(&c, &a).unwrap();
        tombstone(&c, &a.id, 5000, 2).unwrap();

        assert!(list_rows(&c).unwrap().is_empty());

        let t = get_row(&c, &a.id).unwrap().unwrap();
        assert!(t.deleted);
        assert_eq!(t.label, "");
        assert_eq!(t.tags, "");
        assert!(t.ciphertext.is_empty());
        assert!(t.nonce.is_empty());
        assert!(t.last_used_at.is_none());
        // The sync bookkeeping survives.
        assert_eq!(t.id, a.id);
        assert_eq!(t.change_seq, 2);
        assert_eq!(t.updated_at, 5000);
    }

    #[test]
    fn deleting_twice_reports_not_found() {
        let c = conn();
        let a = row("alpha", 1);
        insert_entry(&c, &a).unwrap();
        tombstone(&c, &a.id, 5000, 2).unwrap();
        assert!(matches!(
            tombstone(&c, &a.id, 5001, 3).unwrap_err(),
            Error::NotFound
        ));
    }

    #[test]
    fn replacing_a_missing_row_reports_not_found() {
        let c = conn();
        let ghost = row("ghost", 1);
        assert!(matches!(
            replace_entry(&c, &ghost).unwrap_err(),
            Error::NotFound
        ));
    }

    #[test]
    fn tombstones_are_visible_to_the_sync_view() {
        let c = conn();
        let a = row("alpha", 1);
        insert_entry(&c, &a).unwrap();
        tombstone(&c, &a.id, 5000, 2).unwrap();
        let all = list_rows_including_tombstones(&c).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].deleted);
    }

    #[test]
    fn touch_last_used_does_not_alter_the_ciphertext() {
        let c = conn();
        let a = row("alpha", 1);
        insert_entry(&c, &a).unwrap();
        touch_last_used(&c, &a.id, 9999).unwrap();
        let got = get_row(&c, &a.id).unwrap().unwrap();
        assert_eq!(got.last_used_at, Some(9999));
        assert_eq!(got.ciphertext, a.ciphertext);
        assert_eq!(got.updated_at, a.updated_at);
    }

    #[test]
    fn a_newer_schema_version_is_refused() {
        let c = conn();
        set_meta_i64(&c, META_SCHEMA_VERSION, SCHEMA_VERSION + 1).unwrap();
        assert!(migrate(&c).is_err());
    }
}
