//! The vault header: format version, slot list, wrapped key.
//!
//! Versioned from the first commit (CLAUDE.md rule 6, SECURITY.md non-negotiables).
//! Every future format change bumps [`FORMAT_VERSION`] and ships a migration.
//!
//! # Binary layout, format version 1
//!
//! All integers little-endian. Offsets in bytes.
//!
//! ```text
//! off  size  field
//!   0     8  magic          b"VAULTYDB"
//!   8     2  format_version u16   = 1
//!  10     1  aead_id        u8    1 = XChaCha20-Poly1305
//!  11     1  reserved       u8    = 0
//!  12    16  vault_id       UUIDv7 bytes
//!  28     8  created_at     i64 unix seconds
//!  36     2  slot_count     u16
//!  38   ...  slots, slot_count of them, each:
//!
//!        1  kind        u8   1 = password, 2 = biometric, 3 = recovery
//!        1  flags       u8   reserved, = 0
//!       16  slot_id     UUIDv7 bytes
//!        8  created_at  i64 unix seconds
//!        1  kdf_id      u8   1 = Argon2id, 0 = none (key comes from OS keystore)
//!        4  m_cost_kib  u32
//!        4  t_cost      u32
//!        4  p_cost      u32
//!        2  salt_len    u16
//!        N  salt
//!       24  nonce
//!        2  wrapped_len u16
//!        M  wrapped_key  ciphertext || poly1305 tag  (48 bytes for a 32-byte key)
//! ```
//!
//! A second unlock method is a new slot, not a migration (SPEC.md, "Vault header").
//! Phase 3 adds a biometric slot by appending one; nothing else changes.
//!
//! ## What binds a slot
//!
//! The wrapped key's associated data is
//! `b"vaulty.slot.v1" || vault_id || slot_id || kind || kdf_id || m || t || p || salt_len || salt`.
//!
//! That means the KDF parameters and salt are authenticated: a file edited to claim
//! cheaper Argon2 parameters fails to unwrap rather than silently producing a
//! weaker vault, and a slot cannot be spliced from one vault into another.

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};

pub const MAGIC: &[u8; 8] = b"VAULTYDB";
/// Bumped on every wire-format change, with a migration.
pub const FORMAT_VERSION: u16 = 1;

const AEAD_XCHACHA20POLY1305: u8 = 1;
const KDF_NONE: u8 = 0;
const KDF_ARGON2ID: u8 = 1;

const SLOT_AAD_DOMAIN: &[u8] = b"vaulty.slot.v1";

/// Guard against a hostile header claiming an implausible slot count.
const MAX_SLOTS: u16 = 64;

/// How a given slot is unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotKind {
    /// Argon2id over the master password. Always present; always works.
    Password = 1,
    /// Key held in the OS keystore behind Touch ID / Hello. Phase 3.
    Biometric = 2,
    /// Printed recovery key. Not used in v1.
    Recovery = 3,
}

impl SlotKind {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(SlotKind::Password),
            2 => Ok(SlotKind::Biometric),
            3 => Ok(SlotKind::Recovery),
            _ => Err(Error::MalformedHeader),
        }
    }
}

/// One way into the vault. Each slot wraps the *same* vault key.
#[derive(Debug, Clone)]
pub struct Slot {
    pub kind: SlotKind,
    pub flags: u8,
    pub slot_id: Uuid,
    pub created_at: i64,
    /// `None` for a slot whose key material comes from the OS keystore rather
    /// than from a password.
    pub kdf: Option<KdfParams>,
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub wrapped_key: Vec<u8>,
}

impl Slot {
    /// Associated data binding this slot's parameters to its wrapped key.
    fn aad(&self, vault_id: &Uuid) -> Vec<u8> {
        let (kdf_id, m, t, p) = match self.kdf {
            Some(k) => (KDF_ARGON2ID, k.m_cost_kib, k.t_cost, k.p_cost),
            None => (KDF_NONE, 0, 0, 0),
        };
        let mut aad = Vec::with_capacity(SLOT_AAD_DOMAIN.len() + 64 + self.salt.len());
        aad.extend_from_slice(SLOT_AAD_DOMAIN);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(self.slot_id.as_bytes());
        aad.push(self.kind as u8);
        aad.push(kdf_id);
        aad.extend_from_slice(&m.to_le_bytes());
        aad.extend_from_slice(&t.to_le_bytes());
        aad.extend_from_slice(&p.to_le_bytes());
        aad.extend_from_slice(&(self.salt.len() as u16).to_le_bytes());
        aad.extend_from_slice(&self.salt);
        aad
    }
}

/// The parsed vault header.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub format_version: u16,
    pub vault_id: Uuid,
    pub created_at: i64,
    pub slots: Vec<Slot>,
}

impl VaultHeader {
    /// Build a brand-new header with a single password slot wrapping `vault_key`.
    pub fn create(
        vault_key: &crypto::VaultKey,
        password: &[u8],
        params: KdfParams,
        now: i64,
    ) -> Result<Self> {
        let vault_id = Uuid::now_v7();
        let mut header = VaultHeader {
            format_version: FORMAT_VERSION,
            vault_id,
            created_at: now,
            slots: Vec::new(),
        };
        let slot = header.build_password_slot(vault_key, password, params, now)?;
        header.slots.push(slot);
        Ok(header)
    }

    /// Wrap `vault_key` under a KEK derived from `password`, producing a new slot.
    pub fn build_password_slot(
        &self,
        vault_key: &crypto::VaultKey,
        password: &[u8],
        params: KdfParams,
        now: i64,
    ) -> Result<Slot> {
        params.validate()?;
        let salt = crypto::random_salt();
        let mut slot = Slot {
            kind: SlotKind::Password,
            flags: 0,
            slot_id: Uuid::now_v7(),
            created_at: now,
            kdf: Some(params),
            salt: salt.to_vec(),
            nonce: crypto::random_nonce(),
            wrapped_key: Vec::new(),
        };

        let kek = crypto::derive_kek(password, &slot.salt, params)?;
        let aad = slot.aad(&self.vault_id);
        slot.wrapped_key = crypto::seal(&kek, &slot.nonce, vault_key.expose(), &aad)?;
        Ok(slot)
    }

    /// Wrap `vault_key` under a key held by the OS keystore.
    ///
    /// No KDF: the key material is 32 random bytes generated by us and handed
    /// to the keystore, which gates reading it back behind Touch ID or Windows
    /// Hello. There is nothing to stretch — the secret is already full entropy,
    /// and running Argon2 over it would only make unlock slower.
    ///
    /// SECURITY.md: "Never store the master password itself in the keystore.
    /// Store the wrapped key." This is that: the keystore holds a key that
    /// unwraps the vault key, never the password and never the vault key.
    pub fn build_keystore_slot(
        &self,
        vault_key: &crypto::VaultKey,
        kek: &[u8; KEY_LEN],
        kind: SlotKind,
        now: i64,
    ) -> Result<Slot> {
        if kind == SlotKind::Password {
            return Err(Error::Invalid("a password slot needs a kdf"));
        }
        let mut slot = Slot {
            kind,
            flags: 0,
            slot_id: Uuid::now_v7(),
            created_at: now,
            // `None` marks this as keystore-backed; it encodes as KDF_NONE.
            kdf: None,
            salt: Vec::new(),
            nonce: crypto::random_nonce(),
            wrapped_key: Vec::new(),
        };

        let aad = slot.aad(&self.vault_id);
        slot.wrapped_key = crypto::seal(kek, &slot.nonce, vault_key.expose(), &aad)?;
        Ok(slot)
    }

    /// Unwrap the vault key using a key read back from the OS keystore.
    ///
    /// The biometric prompt has already happened by the time this is called —
    /// the caller got `kek` out of the keystore, which is what Touch ID gated.
    /// A failure here means the stored key no longer matches the vault, which
    /// is what enrolling a new fingerprint produces once the keychain item is
    /// invalidated. The caller falls back to the password; it never unlocks
    /// silently (SECURITY.md, "Rules for both platforms").
    pub fn unlock_with_keystore_key(
        &self,
        kek: &[u8; KEY_LEN],
        kind: SlotKind,
    ) -> Result<crypto::VaultKey> {
        for slot in self.slots.iter().filter(|s| s.kind == kind) {
            if slot.kdf.is_some() {
                // A keystore slot must not carry KDF parameters.
                continue;
            }
            let aad = slot.aad(&self.vault_id);
            if let Ok(pt) = crypto::open(kek, &slot.nonce, &slot.wrapped_key, &aad) {
                if pt.len() == KEY_LEN {
                    let mut raw = Zeroizing::new([0u8; KEY_LEN]);
                    raw.copy_from_slice(&pt);
                    return Ok(crypto::VaultKey::from_bytes(*raw));
                }
            }
        }
        Err(Error::Auth)
    }

    /// Add a slot, replacing any existing slot of the same kind.
    ///
    /// One biometric enrolment per vault: re-enabling Touch ID should replace
    /// the old slot, not accumulate stale ones that still unwrap the key.
    pub fn set_slot(&mut self, slot: Slot) {
        self.slots.retain(|s| s.kind != slot.kind);
        self.slots.push(slot);
    }

    /// Drop every slot of `kind`. Refuses to remove the last password slot —
    /// the master password always works (SECURITY.md).
    pub fn remove_slots(&mut self, kind: SlotKind) -> Result<()> {
        if kind == SlotKind::Password {
            return Err(Error::Invalid("the master password slot cannot be removed"));
        }
        self.slots.retain(|s| s.kind != kind);
        Ok(())
    }

    /// Try every password slot against `password`.
    ///
    /// The KDF runs for each candidate slot regardless of outcome, so a wrong
    /// password and a corrupt wrapped key take the same path and the same time
    /// (SECURITY.md pre-release checklist).
    pub fn unlock_with_password(&self, password: &[u8]) -> Result<crypto::VaultKey> {
        let mut found: Option<crypto::VaultKey> = None;

        for slot in self.slots.iter().filter(|s| s.kind == SlotKind::Password) {
            let Some(params) = slot.kdf else {
                continue;
            };
            // A slot with bad params is skipped, not fatal: another slot may work.
            let Ok(kek) = crypto::derive_kek(password, &slot.salt, params) else {
                continue;
            };
            let aad = slot.aad(&self.vault_id);
            if let Ok(pt) = crypto::open(&kek, &slot.nonce, &slot.wrapped_key, &aad) {
                if pt.len() == KEY_LEN && found.is_none() {
                    let mut raw = Zeroizing::new([0u8; KEY_LEN]);
                    raw.copy_from_slice(&pt);
                    found = Some(crypto::VaultKey::from_bytes(*raw));
                }
            }
        }

        found.ok_or(Error::Auth)
    }

    /// Replace every password slot with one freshly wrapped under `new_password`.
    ///
    /// This rewraps the key; entries are untouched (SECURITY.md, "Two-key design").
    pub fn rewrap_password(
        &mut self,
        vault_key: &crypto::VaultKey,
        new_password: &[u8],
        params: KdfParams,
        now: i64,
    ) -> Result<()> {
        let slot = self.build_password_slot(vault_key, new_password, params, now)?;
        self.slots.retain(|s| s.kind != SlotKind::Password);
        self.slots.push(slot);
        Ok(())
    }

    pub fn has_slot(&self, kind: SlotKind) -> bool {
        self.slots.iter().any(|s| s.kind == kind)
    }

    /// Serialise to the on-disk byte layout documented at the top of this module.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.slots.len() > MAX_SLOTS as usize {
            return Err(Error::MalformedHeader);
        }

        let mut out = Vec::with_capacity(64 + self.slots.len() * 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.push(AEAD_XCHACHA20POLY1305);
        out.push(0); // reserved
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&(self.slots.len() as u16).to_le_bytes());

        for slot in &self.slots {
            let (kdf_id, m, t, p) = match slot.kdf {
                Some(k) => (KDF_ARGON2ID, k.m_cost_kib, k.t_cost, k.p_cost),
                None => (KDF_NONE, 0, 0, 0),
            };
            let salt_len = u16::try_from(slot.salt.len()).map_err(|_| Error::MalformedHeader)?;
            let wrapped_len =
                u16::try_from(slot.wrapped_key.len()).map_err(|_| Error::MalformedHeader)?;

            out.push(slot.kind as u8);
            out.push(slot.flags);
            out.extend_from_slice(slot.slot_id.as_bytes());
            out.extend_from_slice(&slot.created_at.to_le_bytes());
            out.push(kdf_id);
            out.extend_from_slice(&m.to_le_bytes());
            out.extend_from_slice(&t.to_le_bytes());
            out.extend_from_slice(&p.to_le_bytes());
            out.extend_from_slice(&salt_len.to_le_bytes());
            out.extend_from_slice(&slot.salt);
            out.extend_from_slice(&slot.nonce);
            out.extend_from_slice(&wrapped_len.to_le_bytes());
            out.extend_from_slice(&slot.wrapped_key);
        }

        Ok(out)
    }

    /// Parse the on-disk byte layout. Never panics on hostile input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);

        if r.take(8)? != MAGIC {
            return Err(Error::BadMagic);
        }
        let format_version = r.u16()?;
        if format_version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: format_version,
                supported: FORMAT_VERSION,
            });
        }
        let aead_id = r.u8()?;
        if aead_id != AEAD_XCHACHA20POLY1305 {
            return Err(Error::MalformedHeader);
        }
        let _reserved = r.u8()?;
        let vault_id = Uuid::from_slice(r.take(16)?).map_err(|_| Error::MalformedHeader)?;
        let created_at = r.i64()?;
        let slot_count = r.u16()?;
        if slot_count > MAX_SLOTS {
            return Err(Error::MalformedHeader);
        }

        let mut slots = Vec::with_capacity(slot_count as usize);
        for _ in 0..slot_count {
            let kind = SlotKind::from_u8(r.u8()?)?;
            let flags = r.u8()?;
            let slot_id = Uuid::from_slice(r.take(16)?).map_err(|_| Error::MalformedHeader)?;
            let slot_created = r.i64()?;
            let kdf_id = r.u8()?;
            let m = r.u32()?;
            let t = r.u32()?;
            let p = r.u32()?;
            let salt_len = r.u16()? as usize;
            let salt = r.take(salt_len)?.to_vec();
            let nonce: [u8; NONCE_LEN] = r.array::<NONCE_LEN>()?;
            let wrapped_len = r.u16()? as usize;
            let wrapped_key = r.take(wrapped_len)?.to_vec();

            let kdf = match kdf_id {
                KDF_NONE => None,
                KDF_ARGON2ID => Some(KdfParams {
                    m_cost_kib: m,
                    t_cost: t,
                    p_cost: p,
                }),
                _ => return Err(Error::MalformedHeader),
            };

            // A password slot without a KDF, or a wrapped key of the wrong size,
            // is structurally impossible: reject rather than carry it forward.
            if kind == SlotKind::Password && kdf.is_none() {
                return Err(Error::MalformedHeader);
            }
            if wrapped_key.len() != KEY_LEN + TAG_LEN {
                return Err(Error::MalformedHeader);
            }

            slots.push(Slot {
                kind,
                flags,
                slot_id,
                created_at: slot_created,
                kdf,
                salt,
                nonce,
                wrapped_key,
            });
        }

        if !r.is_empty() {
            return Err(Error::MalformedHeader);
        }

        Ok(VaultHeader {
            format_version,
            vault_id,
            created_at,
            slots,
        })
    }
}

/// Bounds-checked byte reader. Returns `MalformedHeader` instead of panicking.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedHeader)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::MalformedHeader)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read exactly `N` bytes as a fixed-size array.
    ///
    /// Going through `try_into` rather than indexing keeps every one of these
    /// readers free of a panicking path, which is what
    /// `clippy::indexing_slicing` is switched on to enforce.
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::MalformedHeader)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array::<8>()?))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::VaultKey;

    fn cheap() -> KdfParams {
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }

    fn make() -> (VaultHeader, VaultKey) {
        let key = VaultKey::generate();
        let h = VaultHeader::create(&key, b"master-pw", cheap(), 1_700_000_000).unwrap();
        (h, key)
    }

    #[test]
    fn create_then_unlock_returns_the_same_key() {
        let (h, key) = make();
        let got = h.unlock_with_password(b"master-pw").unwrap();
        assert_eq!(got.expose(), key.expose());
    }

    #[test]
    fn wrong_password_is_an_auth_error() {
        let (h, _) = make();
        let err = h.unlock_with_password(b"wrong-pw").unwrap_err();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn header_round_trips_through_bytes() {
        let (h, key) = make();
        let bytes = h.encode().unwrap();
        let back = VaultHeader::decode(&bytes).unwrap();

        assert_eq!(back.format_version, FORMAT_VERSION);
        assert_eq!(back.vault_id, h.vault_id);
        assert_eq!(back.created_at, h.created_at);
        assert_eq!(back.slots.len(), 1);
        assert_eq!(
            back.unlock_with_password(b"master-pw").unwrap().expose(),
            key.expose()
        );
    }

    #[test]
    fn encoded_header_starts_with_magic_and_version() {
        let (h, _) = make();
        let bytes = h.encode().unwrap();
        assert_eq!(&bytes[0..8], MAGIC);
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), FORMAT_VERSION);
    }

    #[test]
    fn foreign_file_is_rejected_by_magic() {
        let err = VaultHeader::decode(b"SQLite format 3\0and then some").unwrap_err();
        assert!(matches!(err, Error::BadMagic));
    }

    #[test]
    fn future_format_version_is_refused_not_guessed() {
        let (h, _) = make();
        let mut bytes = h.encode().unwrap();
        bytes[8..10].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        match VaultHeader::decode(&bytes).unwrap_err() {
            Error::UnsupportedVersion { found, supported } => {
                assert_eq!(found, FORMAT_VERSION + 1);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn truncation_at_every_length_fails_cleanly() {
        let (h, _) = make();
        let bytes = h.encode().unwrap();
        for cut in 0..bytes.len() {
            // Must return an error, and must not panic.
            assert!(
                VaultHeader::decode(&bytes[..cut]).is_err(),
                "len {cut} parsed"
            );
        }
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let (h, _) = make();
        let mut bytes = h.encode().unwrap();
        bytes.push(0);
        assert!(VaultHeader::decode(&bytes).is_err());
    }

    // Corrupting any byte must fail cleanly: either the parse rejects it, or the
    // slot no longer unwraps. It must never yield a different working key.
    #[test]
    fn corrupting_any_header_byte_fails_cleanly() {
        let (h, key) = make();
        let bytes = h.encode().unwrap();

        for i in 0..bytes.len() {
            let mut c = bytes.clone();
            c[i] ^= 0b1000_0000;
            match VaultHeader::decode(&c) {
                Err(_) => {}
                Ok(parsed) => match parsed.unlock_with_password(b"master-pw") {
                    Err(e) => assert!(e.is_auth_failure(), "byte {i}: {e:?}"),
                    Ok(k) => assert_eq!(
                        k.expose(),
                        key.expose(),
                        "byte {i} corrupted but produced a different key"
                    ),
                },
            }
        }
    }

    // The KDF parameters are associated data, so editing them down breaks the tag.
    #[test]
    fn downgrading_kdf_parameters_breaks_unwrap() {
        let (mut h, _) = make();
        h.slots[0].kdf = Some(KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 2, // was 1
        });
        assert!(h.unlock_with_password(b"master-pw").is_err());
    }

    // A slot cannot be lifted out of one vault and dropped into another,
    // because vault_id is in the associated data.
    #[test]
    fn slot_cannot_be_spliced_into_another_vault() {
        let (h_a, _) = make();
        let (mut h_b, _) = make();
        assert_ne!(h_a.vault_id, h_b.vault_id);
        h_b.slots = h_a.slots.clone();
        assert!(h_b.unlock_with_password(b"master-pw").is_err());
    }

    #[test]
    fn rewrap_changes_the_password_but_keeps_the_key() {
        let (mut h, key) = make();
        h.rewrap_password(&key, b"new-pw", cheap(), 1_700_000_100)
            .unwrap();

        assert!(h.unlock_with_password(b"master-pw").is_err());
        let got = h.unlock_with_password(b"new-pw").unwrap();
        assert_eq!(got.expose(), key.expose());
        assert_eq!(
            h.slots.len(),
            1,
            "rewrap must not leave the old slot behind"
        );
    }

    #[test]
    fn each_slot_gets_its_own_salt_and_nonce() {
        let (mut h, key) = make();
        let first = h.slots[0].clone();
        h.rewrap_password(&key, b"master-pw", cheap(), 1_700_000_100)
            .unwrap();
        let second = &h.slots[0];
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.wrapped_key, second.wrapped_key);
    }

    // ------------------------------------------------ keystore / biometric slots

    #[test]
    fn a_keystore_slot_unwraps_the_same_vault_key() {
        let (mut h, key) = make();
        let kek = [0x5Au8; KEY_LEN];

        let slot = h
            .build_keystore_slot(&key, &kek, SlotKind::Biometric, 1_700_000_200)
            .unwrap();
        h.set_slot(slot);

        let got = h
            .unlock_with_keystore_key(&kek, SlotKind::Biometric)
            .unwrap();
        assert_eq!(got.expose(), key.expose());
        // The password still works. It always does.
        assert_eq!(
            h.unlock_with_password(b"master-pw").unwrap().expose(),
            key.expose()
        );
    }

    #[test]
    fn a_wrong_keystore_key_is_an_auth_failure_not_a_silent_unlock() {
        let (mut h, key) = make();
        let slot = h
            .build_keystore_slot(&key, &[0x5Au8; KEY_LEN], SlotKind::Biometric, 0)
            .unwrap();
        h.set_slot(slot);

        let err = h
            .unlock_with_keystore_key(&[0x5Bu8; KEY_LEN], SlotKind::Biometric)
            .unwrap_err();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn a_keystore_slot_survives_the_byte_format() {
        let (mut h, key) = make();
        let kek = [0x11u8; KEY_LEN];
        let slot = h
            .build_keystore_slot(&key, &kek, SlotKind::Biometric, 1_700_000_300)
            .unwrap();
        h.set_slot(slot);

        let back = VaultHeader::decode(&h.encode().unwrap()).unwrap();
        assert_eq!(back.slots.len(), 2);
        assert!(back.has_slot(SlotKind::Biometric));
        assert_eq!(
            back.unlock_with_keystore_key(&kek, SlotKind::Biometric)
                .unwrap()
                .expose(),
            key.expose()
        );
    }

    #[test]
    fn a_keystore_slot_carries_no_kdf_parameters() {
        let (h, key) = make();
        let slot = h
            .build_keystore_slot(&key, &[0u8; KEY_LEN], SlotKind::Biometric, 0)
            .unwrap();
        assert!(slot.kdf.is_none(), "keystore slots must not run a kdf");
        assert!(slot.salt.is_empty());
    }

    #[test]
    fn re_enabling_replaces_the_slot_rather_than_accumulating() {
        let (mut h, key) = make();
        let first = [1u8; KEY_LEN];
        let second = [2u8; KEY_LEN];

        h.set_slot(
            h.build_keystore_slot(&key, &first, SlotKind::Biometric, 0)
                .unwrap(),
        );
        h.set_slot(
            h.build_keystore_slot(&key, &second, SlotKind::Biometric, 1)
                .unwrap(),
        );

        assert_eq!(
            h.slots
                .iter()
                .filter(|s| s.kind == SlotKind::Biometric)
                .count(),
            1
        );
        // The superseded key must no longer open the vault.
        assert!(h
            .unlock_with_keystore_key(&first, SlotKind::Biometric)
            .is_err());
        assert!(h
            .unlock_with_keystore_key(&second, SlotKind::Biometric)
            .is_ok());
    }

    #[test]
    fn disabling_biometrics_removes_the_slot() {
        let (mut h, key) = make();
        let kek = [7u8; KEY_LEN];
        h.set_slot(
            h.build_keystore_slot(&key, &kek, SlotKind::Biometric, 0)
                .unwrap(),
        );
        assert!(h.has_slot(SlotKind::Biometric));

        h.remove_slots(SlotKind::Biometric).unwrap();

        assert!(!h.has_slot(SlotKind::Biometric));
        assert!(h
            .unlock_with_keystore_key(&kek, SlotKind::Biometric)
            .is_err());
        // And the vault is still openable the way it always was.
        assert!(h.unlock_with_password(b"master-pw").is_ok());
    }

    /// SECURITY.md: "The master password always works."
    #[test]
    fn the_password_slot_cannot_be_removed() {
        let (mut h, _) = make();
        assert!(h.remove_slots(SlotKind::Password).is_err());
        assert!(h.has_slot(SlotKind::Password));
    }

    #[test]
    fn a_keystore_slot_cannot_be_built_as_a_password_slot() {
        let (h, key) = make();
        assert!(h
            .build_keystore_slot(&key, &[0u8; KEY_LEN], SlotKind::Password, 0)
            .is_err());
    }

    /// A biometric slot lifted from another vault must not open this one.
    #[test]
    fn a_keystore_slot_is_bound_to_its_vault() {
        let (h_a, key_a) = make();
        let (mut h_b, _) = make();
        let kek = [9u8; KEY_LEN];

        let foreign = h_a
            .build_keystore_slot(&key_a, &kek, SlotKind::Biometric, 0)
            .unwrap();
        h_b.set_slot(foreign);

        assert!(h_b
            .unlock_with_keystore_key(&kek, SlotKind::Biometric)
            .is_err());
    }

    /// Changing the master password must not orphan the biometric slot: both
    /// wrap the same vault key, and rewrapping one leaves the other alone.
    #[test]
    fn changing_the_password_leaves_the_biometric_slot_working() {
        let (mut h, key) = make();
        let kek = [3u8; KEY_LEN];
        h.set_slot(
            h.build_keystore_slot(&key, &kek, SlotKind::Biometric, 0)
                .unwrap(),
        );

        h.rewrap_password(&key, b"new-pw", cheap(), 1_700_000_400)
            .unwrap();

        assert!(h.unlock_with_password(b"new-pw").is_ok());
        assert_eq!(
            h.unlock_with_keystore_key(&kek, SlotKind::Biometric)
                .unwrap()
                .expose(),
            key.expose()
        );
    }

    #[test]
    fn slot_kinds_are_distinguishable() {
        let (h, _) = make();
        assert!(h.has_slot(SlotKind::Password));
        assert!(!h.has_slot(SlotKind::Biometric));
    }

    #[test]
    fn absurd_slot_count_is_refused_without_allocating() {
        let (h, _) = make();
        let mut bytes = h.encode().unwrap();
        bytes[36..38].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(VaultHeader::decode(&bytes).is_err());
    }
}
