//! Entry types, and the exact bytes that get authenticated alongside a secret.
//!
//! Which fields are encrypted is fixed by `docs/SPEC.md`, "Data model":
//! `secret` and `note` are encrypted; `label`, `tags`, `kind` and the timestamps
//! are clear text so search stays fast. That is a deliberate trade — an attacker
//! holding the file learns that an account exists, not what it is.
//!
//! The clear-text fields are passed as **associated data** so a label cannot be
//! swapped onto a different secret without breaking authentication
//! (SECURITY.md, "Two-key design", point 5).

use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const ENTRY_AAD_DOMAIN: &[u8] = b"vaulty.entry.v1";

/// Caps that keep a hostile or accidental input from ballooning memory.
pub const MAX_LABEL_LEN: usize = 512;
pub const MAX_SECRET_LEN: usize = 64 * 1024;
pub const MAX_NOTE_LEN: usize = 256 * 1024;
pub const MAX_TAGS: usize = 32;
pub const MAX_TAG_LEN: usize = 64;

/// Separator for the canonical tag encoding. ASCII unit separator: not typeable,
/// so it cannot appear inside a tag.
const TAG_SEP: char = '\u{1f}';

pub type EntryId = Uuid;

/// What sort of thing the secret is. Drives the icon and nothing security-relevant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum EntryKind {
    Password = 1,
    Code = 2,
    Note = 3,
    Card = 4,
    Wifi = 5,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(EntryKind::Password),
            2 => Ok(EntryKind::Code),
            3 => Ok(EntryKind::Note),
            4 => Ok(EntryKind::Card),
            5 => Ok(EntryKind::Wifi),
            _ => Err(Error::Invalid("unknown entry kind")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Password => "password",
            EntryKind::Code => "code",
            EntryKind::Note => "note",
            EntryKind::Card => "card",
            EntryKind::Wifi => "wifi",
        }
    }
}

impl std::str::FromStr for EntryKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "password" => Ok(EntryKind::Password),
            "code" => Ok(EntryKind::Code),
            "note" => Ok(EntryKind::Note),
            "card" => Ok(EntryKind::Card),
            "wifi" => Ok(EntryKind::Wifi),
            _ => Err(Error::Invalid("unknown entry kind")),
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything about an entry except the secret and the note.
///
/// This is the type that is safe to hand to the frontend (CLAUDE.md rule 1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EntryMeta {
    pub id: EntryId,
    pub label: String,
    pub tags: Vec<String>,
    pub kind: EntryKind,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    /// Monotonic per-vault counter. Sync-ready plumbing (SPEC.md); unused in v1.
    pub change_seq: i64,
}

/// An entry plus its decrypted secret. Zeroized on drop.
///
/// Only produced by an explicit reveal or copy. Never serialised, never logged.
pub struct RevealedEntry {
    pub meta: EntryMeta,
    pub secret: Zeroizing<String>,
    pub note: Option<Zeroizing<String>>,
}

impl fmt::Debug for RevealedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never Debug-print plaintext (CLAUDE.md rule 3).
        f.debug_struct("RevealedEntry")
            .field("meta", &self.meta)
            .field("secret", &"[redacted]")
            .field("note", &"[redacted]")
            .finish()
    }
}

/// Input for `add_entry`.
pub struct NewEntry {
    pub label: String,
    pub tags: Vec<String>,
    pub kind: EntryKind,
    pub secret: Zeroizing<String>,
    pub note: Option<Zeroizing<String>>,
}

impl fmt::Debug for NewEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewEntry")
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("secret", &"[redacted]")
            .field("note", &"[redacted]")
            .finish()
    }
}

/// Input for `update_entry`. `None` means "leave unchanged".
///
/// `note` is doubly wrapped: `None` leaves it alone, `Some(None)` clears it.
#[derive(Default)]
pub struct EntryUpdate {
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub kind: Option<EntryKind>,
    pub secret: Option<Zeroizing<String>>,
    pub note: Option<Option<Zeroizing<String>>>,
}

impl fmt::Debug for EntryUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryUpdate")
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .field("note", &self.note.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Normalise tags: trim, drop empties, deduplicate, sort.
///
/// Sorting makes the stored form canonical, which matters because the tag string
/// is authenticated: two logically identical tag sets must produce identical bytes.
pub fn canonical_tags(tags: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(tags.len());
    for t in tags {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if t.len() > MAX_TAG_LEN {
            return Err(Error::Invalid("tag too long"));
        }
        if t.contains(TAG_SEP) {
            return Err(Error::Invalid("tag contains a reserved character"));
        }
        if !out.iter().any(|e| e == t) {
            out.push(t.to_string());
        }
    }
    if out.len() > MAX_TAGS {
        return Err(Error::Invalid("too many tags"));
    }
    out.sort();
    Ok(out)
}

/// Join canonical tags into the single TEXT column stored in SQLite.
pub fn encode_tags(tags: &[String]) -> String {
    tags.join(&TAG_SEP.to_string())
}

/// Split the stored TEXT column back into tags.
pub fn decode_tags(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(TAG_SEP).map(|t| t.to_string()).collect()
}

pub fn validate_label(label: &str) -> Result<()> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(Error::Invalid("label must not be empty"));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::Invalid("label too long"));
    }
    Ok(())
}

/// Fields bound into the AEAD as associated data.
///
/// `last_used_at` is deliberately **excluded**: it changes every time a secret is
/// copied, and binding it would force a re-encrypt (and a new nonce) on every
/// read. Everything else that describes the entry is bound, so relabelling,
/// retagging, changing the kind, or rewinding `updated_at`/`change_seq` all break
/// authentication.
#[derive(Debug)]
pub struct EntryAad<'a> {
    pub vault_id: &'a Uuid,
    pub entry_id: &'a Uuid,
    pub kind: EntryKind,
    pub label: &'a str,
    pub tags_encoded: &'a str,
    pub created_at: i64,
    pub updated_at: i64,
    pub change_seq: i64,
}

impl EntryAad<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            ENTRY_AAD_DOMAIN.len() + 64 + self.label.len() + self.tags_encoded.len(),
        );
        aad.extend_from_slice(ENTRY_AAD_DOMAIN);
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad.extend_from_slice(self.entry_id.as_bytes());
        aad.push(self.kind as u8);
        // Length-prefix every variable-length field so that ("ab","c") and
        // ("a","bc") cannot produce the same authenticated bytes.
        push_lp(&mut aad, self.label.as_bytes());
        push_lp(&mut aad, self.tags_encoded.as_bytes());
        aad.extend_from_slice(&self.created_at.to_le_bytes());
        aad.extend_from_slice(&self.updated_at.to_le_bytes());
        aad.extend_from_slice(&self.change_seq.to_le_bytes());
        aad
    }
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Encode `(secret, note)` into the single plaintext that gets sealed.
///
/// One ciphertext per entry rather than two means one nonce per entry per write,
/// which is one fewer chance to reuse a nonce.
pub fn encode_payload(secret: &str, note: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() > MAX_SECRET_LEN {
        return Err(Error::Invalid("secret too large"));
    }
    let note_bytes = note.map(|n| n.as_bytes()).unwrap_or(&[]);
    if note_bytes.len() > MAX_NOTE_LEN {
        return Err(Error::Invalid("note too large"));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(8 + secret.len() + note_bytes.len()));
    // A note that is absent and a note that is empty are different states.
    let has_note = u8::from(note.is_some());
    buf.push(has_note);
    push_lp(&mut buf, secret.as_bytes());
    push_lp(&mut buf, note_bytes);
    Ok(buf)
}

/// Inverse of [`encode_payload`], applied to freshly decrypted bytes.
pub fn decode_payload(buf: &[u8]) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>)> {
    let mut pos = 0usize;

    let has_note = *buf.get(pos).ok_or(Error::Auth)?;
    pos += 1;

    let secret = read_lp(buf, &mut pos)?;
    let note = read_lp(buf, &mut pos)?;

    if pos != buf.len() {
        return Err(Error::Auth);
    }

    let secret = Zeroizing::new(String::from_utf8(secret.to_vec()).map_err(|_| Error::Auth)?);
    let note = match has_note {
        0 => None,
        1 => Some(Zeroizing::new(
            String::from_utf8(note.to_vec()).map_err(|_| Error::Auth)?,
        )),
        _ => return Err(Error::Auth),
    };
    Ok((secret, note))
}

fn read_lp<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(4).ok_or(Error::Auth)?;
    let len_bytes: [u8; 4] = buf
        .get(*pos..end)
        .ok_or(Error::Auth)?
        .try_into()
        .map_err(|_| Error::Auth)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    *pos = end;
    let data_end = pos.checked_add(len).ok_or(Error::Auth)?;
    let data = buf.get(*pos..data_end).ok_or(Error::Auth)?;
    *pos = data_end;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_canonicalised() {
        let t = canonical_tags(&[
            "  work ".into(),
            "aws".into(),
            "work".into(),
            "".into(),
            "  ".into(),
        ])
        .unwrap();
        assert_eq!(t, vec!["aws".to_string(), "work".to_string()]);
    }

    #[test]
    fn tag_order_does_not_change_the_encoding() {
        let a = canonical_tags(&["b".into(), "a".into()]).unwrap();
        let b = canonical_tags(&["a".into(), "b".into()]).unwrap();
        assert_eq!(encode_tags(&a), encode_tags(&b));
    }

    #[test]
    fn tags_round_trip_through_the_text_column() {
        let t = canonical_tags(&["aws".into(), "work".into(), "prod".into()]).unwrap();
        assert_eq!(decode_tags(&encode_tags(&t)), t);
        assert_eq!(decode_tags(""), Vec::<String>::new());
    }

    #[test]
    fn tags_reject_the_separator_and_overlong_input() {
        assert!(canonical_tags(&["a\u{1f}b".into()]).is_err());
        assert!(canonical_tags(&["x".repeat(MAX_TAG_LEN + 1)]).is_err());
        let many: Vec<String> = (0..MAX_TAGS + 1).map(|i| i.to_string()).collect();
        assert!(canonical_tags(&many).is_err());
    }

    #[test]
    fn labels_must_not_be_blank() {
        assert!(validate_label("gmail").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("   ").is_err());
        assert!(validate_label(&"x".repeat(MAX_LABEL_LEN + 1)).is_err());
    }

    #[test]
    fn payload_round_trips_with_and_without_a_note() {
        let p = encode_payload("hunter2", Some("recovery codes")).unwrap();
        let (s, n) = decode_payload(&p).unwrap();
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(n.as_deref().map(|s| s.as_str()), Some("recovery codes"));

        let p = encode_payload("hunter2", None).unwrap();
        let (s, n) = decode_payload(&p).unwrap();
        assert_eq!(s.as_str(), "hunter2");
        assert!(n.is_none());
    }

    #[test]
    fn an_empty_note_is_distinct_from_no_note() {
        let with = encode_payload("s", Some("")).unwrap();
        let without = encode_payload("s", None).unwrap();
        assert_ne!(with.as_slice(), without.as_slice());
        assert_eq!(
            decode_payload(&with)
                .unwrap()
                .1
                .as_deref()
                .map(|s| s.as_str()),
            Some("")
        );
        assert!(decode_payload(&without).unwrap().1.is_none());
    }

    #[test]
    fn payload_rejects_oversized_input() {
        assert!(encode_payload(&"x".repeat(MAX_SECRET_LEN + 1), None).is_err());
        assert!(encode_payload("s", Some(&"x".repeat(MAX_NOTE_LEN + 1))).is_err());
    }

    #[test]
    fn truncated_payload_never_panics() {
        let p = encode_payload("hunter2", Some("note")).unwrap();
        for cut in 0..p.len() {
            assert!(decode_payload(&p[..cut]).is_err(), "len {cut} parsed");
        }
    }

    #[test]
    fn payload_with_trailing_bytes_is_rejected() {
        let mut p = encode_payload("s", None).unwrap().to_vec();
        p.push(0xff);
        assert!(decode_payload(&p).is_err());
    }

    #[test]
    fn aad_changes_when_any_bound_field_changes() {
        let vault = Uuid::now_v7();
        let entry = Uuid::now_v7();
        let base = EntryAad {
            vault_id: &vault,
            entry_id: &entry,
            kind: EntryKind::Password,
            label: "gmail",
            tags_encoded: "work",
            created_at: 100,
            updated_at: 200,
            change_seq: 1,
        };
        let baseline = base.to_bytes();

        let other_vault = Uuid::now_v7();
        let other_entry = Uuid::now_v7();
        let variants = [
            EntryAad {
                vault_id: &other_vault,
                ..base_copy(&base)
            },
            EntryAad {
                entry_id: &other_entry,
                ..base_copy(&base)
            },
            EntryAad {
                kind: EntryKind::Note,
                ..base_copy(&base)
            },
            EntryAad {
                label: "gmai1",
                ..base_copy(&base)
            },
            EntryAad {
                tags_encoded: "home",
                ..base_copy(&base)
            },
            EntryAad {
                created_at: 101,
                ..base_copy(&base)
            },
            EntryAad {
                updated_at: 201,
                ..base_copy(&base)
            },
            EntryAad {
                change_seq: 2,
                ..base_copy(&base)
            },
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v.to_bytes(), baseline, "variant {i} did not change the aad");
        }
    }

    // Length prefixes must stop a label/tag boundary shift from colliding.
    #[test]
    fn aad_is_not_ambiguous_across_field_boundaries() {
        let vault = Uuid::now_v7();
        let entry = Uuid::now_v7();
        let a = EntryAad {
            vault_id: &vault,
            entry_id: &entry,
            kind: EntryKind::Password,
            label: "ab",
            tags_encoded: "c",
            created_at: 0,
            updated_at: 0,
            change_seq: 0,
        };
        let b = EntryAad {
            label: "a",
            tags_encoded: "bc",
            ..base_copy(&a)
        };
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    fn base_copy<'a>(a: &EntryAad<'a>) -> EntryAad<'a> {
        EntryAad {
            vault_id: a.vault_id,
            entry_id: a.entry_id,
            kind: a.kind,
            label: a.label,
            tags_encoded: a.tags_encoded,
            created_at: a.created_at,
            updated_at: a.updated_at,
            change_seq: a.change_seq,
        }
    }

    #[test]
    fn entry_kind_round_trips() {
        for k in [
            EntryKind::Password,
            EntryKind::Code,
            EntryKind::Note,
            EntryKind::Card,
            EntryKind::Wifi,
        ] {
            assert_eq!(EntryKind::from_u8(k as u8).unwrap(), k);
            assert_eq!(k.as_str().parse::<EntryKind>().unwrap(), k);
        }
        assert!(EntryKind::from_u8(0).is_err());
        assert!(EntryKind::from_u8(99).is_err());
        assert!("nonsense".parse::<EntryKind>().is_err());
    }

    #[test]
    fn debug_impls_never_print_plaintext() {
        let n = NewEntry {
            label: "gmail".into(),
            tags: vec![],
            kind: EntryKind::Password,
            secret: Zeroizing::new("super-secret-value".into()),
            note: Some(Zeroizing::new("private-note-value".into())),
        };
        let shown = format!("{n:?}");
        assert!(!shown.contains("super-secret-value"));
        assert!(!shown.contains("private-note-value"));
        assert!(shown.contains("[redacted]"));

        let u = EntryUpdate {
            secret: Some(Zeroizing::new("another-secret".into())),
            ..Default::default()
        };
        assert!(!format!("{u:?}").contains("another-secret"));
    }
}
