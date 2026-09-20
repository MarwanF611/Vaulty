//! Atomic file writes and rolling snapshots.
//!
//! CLAUDE.md rule 7: writes are atomic — temp file, fsync, rename. Never write
//! in place. A half-written vault is a lost vault.
//!
//! Two different durability mechanisms are at work and it is worth being precise
//! about which covers what:
//!
//! * **Entry writes** go through SQLite transactions with `synchronous = FULL`
//!   and a rollback journal. SQLite's own crash-safety covers those; hand-rolling
//!   a temp-and-rename around a live database would be strictly worse.
//! * **Snapshots and exports** are whole-file products. Those use
//!   [`write_atomic`] / [`snapshot`]: build the new file under a temporary name,
//!   fsync it, rename it into place, then fsync the directory so the rename
//!   itself is durable.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::error::{Error, Result};

/// How many snapshots to keep (SPEC.md, "File locations": keep the last three).
pub const SNAPSHOT_COUNT: usize = 3;

/// Path of snapshot `n`, where 1 is the most recent.
pub fn snapshot_path(db_path: &Path, n: usize) -> PathBuf {
    let mut name = db_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("vault.db"))
        .to_os_string();
    name.push(format!(".snap{n}"));
    db_path.with_file_name(name)
}

fn temp_path(target: &Path, tag: &str) -> PathBuf {
    let mut name = target
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("vault.db"))
        .to_os_string();
    // The pid keeps two processes from colliding on the same temp name.
    name.push(format!(".{tag}.{}.tmp", std::process::id()));
    target.with_file_name(name)
}

/// Make a freshly created file owner-read/write only.
///
/// Applied before anything is written to it, so there is no window where the
/// file is world-readable. On Windows the default ACL already inherits the
/// user's profile permissions, and there is no portable mode to set.
fn restrict_permissions(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

/// fsync the directory holding `path`, so a rename into it survives a power cut.
fn sync_parent_dir(path: &Path) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    // Opening a directory read-only and syncing it is the portable-enough idiom
    // on Unix. On Windows this is not available and not needed: ReplaceFile /
    // MoveFileEx give the ordering guarantee.
    #[cfg(unix)]
    {
        let f = fs::File::open(dir)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Write `bytes` to `target` atomically: temp file, fsync, rename, fsync dir.
///
/// A reader either sees the old file or the new one, never a partial write.
pub fn write_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = temp_path(target, "write");

    // Scoped so the file is closed before the rename.
    {
        let mut f = fs::File::create(&tmp)?;
        restrict_permissions(&f)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }

    // rename(2) is atomic within a filesystem, and replaces the destination.
    if let Err(e) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::Io(e));
    }
    sync_parent_dir(target)?;
    Ok(())
}

/// Take a snapshot of the live database and rotate the older ones.
///
/// `VACUUM INTO` asks SQLite to write a clean, self-consistent copy — that is
/// safer than copying the file underneath a live connection.
pub fn snapshot(conn: &Connection, db_path: &Path) -> Result<PathBuf> {
    let tmp = temp_path(db_path, "snap");
    let _ = fs::remove_file(&tmp); // VACUUM INTO refuses an existing target.

    let tmp_str = tmp.to_string_lossy().to_string();
    conn.execute("VACUUM INTO ?1", rusqlite::params![tmp_str])
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::Db(e)
        })?;

    // `VACUUM INTO` creates the file itself, under the process umask — which on
    // a default macOS account means 0644. A snapshot holds everything the vault
    // holds, so it gets the same 0600 the vault file does.
    {
        let f = fs::File::open(&tmp)?;
        restrict_permissions(&f)?;
        f.sync_all()?;
    }

    rotate(db_path)?;

    let newest = snapshot_path(db_path, 1);
    if let Err(e) = fs::rename(&tmp, &newest) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::Io(e));
    }
    sync_parent_dir(&newest)?;
    Ok(newest)
}

/// Shift snapshot 1 -> 2 -> 3 and drop what falls off the end.
fn rotate(db_path: &Path) -> Result<()> {
    let oldest = snapshot_path(db_path, SNAPSHOT_COUNT);
    if oldest.exists() {
        fs::remove_file(&oldest)?;
    }
    for n in (1..SNAPSHOT_COUNT).rev() {
        let from = snapshot_path(db_path, n);
        let to = snapshot_path(db_path, n + 1);
        if from.exists() {
            fs::rename(&from, &to)?;
        }
    }
    Ok(())
}

/// Snapshots that currently exist, newest first.
pub fn list_snapshots(db_path: &Path) -> Vec<PathBuf> {
    (1..=SNAPSHOT_COUNT)
        .map(|n| snapshot_path(db_path, n))
        .filter(|p| p.exists())
        .collect()
}

/// Replace the live database with snapshot `n`.
///
/// The caller must have no open connection to `db_path`. The current file is
/// kept as `<name>.prerestore` rather than deleted: recovering from a corrupt
/// vault should not be the step that destroys the evidence.
pub fn restore_snapshot(db_path: &Path, n: usize) -> Result<()> {
    let snap = snapshot_path(db_path, n);
    if !snap.exists() {
        return Err(Error::NotFound);
    }
    let bytes = fs::read(&snap)?;

    if db_path.exists() {
        let mut backup_name = db_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("vault.db"))
            .to_os_string();
        backup_name.push(".prerestore");
        let backup = db_path.with_file_name(backup_name);
        let _ = fs::remove_file(&backup);
        fs::rename(db_path, &backup)?;
    }

    write_atomic(db_path, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_atomic_creates_and_replaces() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("f.bin");

        write_atomic(&p, b"first").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"first");

        write_atomic(&p, b"second").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"second");
    }

    #[test]
    fn write_atomic_leaves_no_temp_files_behind() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("f.bin");
        write_atomic(&p, b"data").unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn write_atomic_creates_missing_directories() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nested").join("deeper").join("f.bin");
        write_atomic(&p, b"data").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"data");
    }

    fn seeded_db(path: &Path, label: &str) -> Connection {
        let c = crate::db::open(path).unwrap();
        crate::db::init_schema(&c).unwrap();
        crate::db::set_meta(&c, "marker", label.as_bytes()).unwrap();
        c
    }

    #[test]
    fn snapshots_rotate_and_cap_at_three() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let c = seeded_db(&db, "v1");

        for i in 0..5 {
            crate::db::set_meta(&c, "marker", format!("v{i}").as_bytes()).unwrap();
            snapshot(&c, &db).unwrap();
        }

        assert_eq!(list_snapshots(&db).len(), SNAPSHOT_COUNT);
        assert!(!snapshot_path(&db, SNAPSHOT_COUNT + 1).exists());
    }

    #[test]
    fn snapshot_one_is_the_newest() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let c = seeded_db(&db, "old");
        snapshot(&c, &db).unwrap();

        crate::db::set_meta(&c, "marker", b"new").unwrap();
        snapshot(&c, &db).unwrap();

        let newest = crate::db::open(&snapshot_path(&db, 1)).unwrap();
        assert_eq!(
            crate::db::get_meta(&newest, "marker").unwrap().as_deref(),
            Some(&b"new"[..])
        );
        let older = crate::db::open(&snapshot_path(&db, 2)).unwrap();
        assert_eq!(
            crate::db::get_meta(&older, "marker").unwrap().as_deref(),
            Some(&b"old"[..])
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshots_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let c = seeded_db(&db, "secret-ish");
        let snap = snapshot(&c, &db).unwrap();

        let mode = fs::metadata(&snap).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snapshot mode was {mode:o}");
    }

    #[test]
    fn snapshot_is_a_readable_database() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let c = seeded_db(&db, "hello");
        let snap = snapshot(&c, &db).unwrap();

        let reopened = crate::db::open(&snap).unwrap();
        assert_eq!(
            crate::db::get_meta(&reopened, "marker").unwrap().as_deref(),
            Some(&b"hello"[..])
        );
    }

    #[test]
    fn restore_brings_back_the_snapshot_and_keeps_the_old_file() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let c = seeded_db(&db, "good");
        snapshot(&c, &db).unwrap();
        drop(c);

        // Corrupt the live vault the way a bad sector would.
        fs::write(&db, b"this is not a database at all").unwrap();

        restore_snapshot(&db, 1).unwrap();

        let recovered = crate::db::open(&db).unwrap();
        assert_eq!(
            crate::db::get_meta(&recovered, "marker")
                .unwrap()
                .as_deref(),
            Some(&b"good"[..])
        );
        assert!(
            db.with_file_name("vault.db.prerestore").exists(),
            "the corrupt file should be kept, not destroyed"
        );
    }

    #[test]
    fn restoring_a_missing_snapshot_is_an_error() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        assert!(matches!(
            restore_snapshot(&db, 2).unwrap_err(),
            Error::NotFound
        ));
    }
}
