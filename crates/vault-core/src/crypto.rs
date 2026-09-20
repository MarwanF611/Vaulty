//! Crypto primitives. Thin, boring wrappers over audited crates.
//!
//! Constructions are fixed by `docs/SECURITY.md`:
//!   * KDF  — Argon2id, parameters stored per slot in the header
//!   * AEAD — XChaCha20-Poly1305, 24-byte nonce, fresh per write
//!
//! There is no novel crypto here and there must never be (CLAUDE.md rule 2).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Length of the vault key and of every derived key-encryption key.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length, appended to ciphertext by the `aead` crate.
pub const TAG_LEN: usize = 16;
/// Salt length for Argon2id. 16 bytes is the recommended minimum.
pub const SALT_LEN: usize = 16;

/// Default Argon2id cost, per SECURITY.md: 64 MiB, 3 iterations, parallelism 4.
/// Stored in the header so a future tuning pass does not lock out existing vaults.
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

/// Lower bounds this build refuses to go below, so a tampered header cannot
/// downgrade a vault into cheap-to-crack territory. An attacker editing these
/// would break the slot's associated data anyway, but failing loudly is cheaper
/// than relying on that.
const MIN_M_COST_KIB: u32 = 8 * 1024;
const MIN_T_COST: u32 = 2;
/// Upper bounds so a hostile file cannot turn `unlock` into a denial of service.
///
/// Every one of these matters. Without the `t_cost` ceiling, flipping a single
/// bit in the header's iteration count turns 3 iterations into 32 770 and the
/// unlock never visibly returns — the user's own vault becomes unopenable, and
/// the file looks merely "slow" rather than corrupt. The memory ceiling is the
/// same argument for allocation.
///
/// The ceilings sit well above anything the tuning pass in SECURITY.md would
/// pick (64 MiB / 3 / 4), so they cost nothing in practice.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

/// Argon2id cost parameters as stored in a header slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Reject parameters outside the range this build is willing to run.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost_kib < MIN_M_COST_KIB
            || self.m_cost_kib > MAX_M_COST_KIB
            || self.t_cost < MIN_T_COST
            || self.t_cost > MAX_T_COST
            || self.p_cost == 0
            || self.p_cost > MAX_P_COST
        {
            return Err(Error::BadKdfParams);
        }
        Ok(())
    }
}

/// The 32-byte symmetric key that encrypts every entry.
///
/// Lives only in Rust, never in a Tauri payload, never in the webview
/// (CLAUDE.md rule 1, SECURITY.md "Key material in memory").
pub struct VaultKey(SecretBox<[u8; KEY_LEN]>);

impl VaultKey {
    /// Generate a fresh vault key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut raw = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut raw);
        Self(SecretBox::new(Box::new(raw)))
    }

    pub fn from_bytes(raw: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(raw)))
    }

    /// Borrow the raw key. Call sites should be few and obvious.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

// SECURITY.md: never Debug-print a type holding key material.
impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey([redacted])")
    }
}

/// Fill a buffer from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// A fresh 24-byte nonce. One per write, never reused under the same key.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

/// `KEK = Argon2id(password, salt)`.
///
/// The returned key is zeroized on drop. This is the only place a password is
/// turned into key material.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    if salt.len() < 8 {
        return Err(Error::BadKdfParams);
    }

    let a2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::BadKdfParams)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::BadKdfParams)?;
    Ok(out)
}

/// AEAD-encrypt `plaintext` with `key` under `nonce`, binding `aad`.
///
/// Returns `ciphertext || tag`.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // An encryption failure here means the message exceeded the AEAD limit.
        // It carries no secret-dependent information.
        .map_err(|_| Error::Invalid("plaintext too large to encrypt"))
}

/// AEAD-decrypt, verifying `aad`. Any failure — wrong key, flipped byte,
/// swapped label — is the single [`Error::Auth`].
///
/// The plaintext is zeroized on drop.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap params so the test suite stays fast. Production uses the defaults.
    fn test_params() -> KdfParams {
        KdfParams {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: MIN_T_COST,
            p_cost: 1,
        }
    }

    #[test]
    fn kdf_is_deterministic_for_same_inputs() {
        let salt = [7u8; SALT_LEN];
        let a = derive_kek(b"correct horse", &salt, test_params()).unwrap();
        let b = derive_kek(b"correct horse", &salt, test_params()).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn kdf_differs_on_password_and_on_salt() {
        let salt_a = [7u8; SALT_LEN];
        let salt_b = [9u8; SALT_LEN];
        let base = derive_kek(b"pw-one", &salt_a, test_params()).unwrap();
        let other_pw = derive_kek(b"pw-two", &salt_a, test_params()).unwrap();
        let other_salt = derive_kek(b"pw-one", &salt_b, test_params()).unwrap();
        assert_ne!(base.as_ref(), other_pw.as_ref());
        assert_ne!(base.as_ref(), other_salt.as_ref());
    }

    #[test]
    fn kdf_rejects_weak_and_absurd_params() {
        let salt = [7u8; SALT_LEN];
        let weak = KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(derive_kek(b"pw", &salt, weak).is_err());

        let huge = KdfParams {
            m_cost_kib: MAX_M_COST_KIB + 1,
            t_cost: 3,
            p_cost: 1,
        };
        assert!(derive_kek(b"pw", &salt, huge).is_err());
    }

    // A tampered header must not be able to make unlock run for minutes.
    // Found by `header::tests::corrupting_any_header_byte_fails_cleanly`, which
    // flips a bit in the iteration count and produced a 32 770-iteration KDF.
    #[test]
    fn kdf_refuses_a_denial_of_service_iteration_count() {
        let salt = [7u8; SALT_LEN];
        let slow = KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 32_770,
            p_cost: 1,
        };
        assert!(slow.validate().is_err());
        assert!(derive_kek(b"pw", &salt, slow).is_err());

        let wide = KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 3,
            p_cost: MAX_P_COST + 1,
        };
        assert!(wide.validate().is_err());
    }

    #[test]
    fn kdf_rejects_short_salt() {
        assert!(derive_kek(b"pw", &[0u8; 4], test_params()).is_err());
    }

    #[test]
    fn seal_open_round_trip() {
        let key = [3u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"attack at dawn", b"header").unwrap();
        assert_ne!(ct.as_slice(), b"attack at dawn");
        let pt = open(&key, &nonce, &ct, b"header").unwrap();
        assert_eq!(pt.as_slice(), b"attack at dawn");
    }

    #[test]
    fn ciphertext_carries_a_tag() {
        let key = [3u8; KEY_LEN];
        let ct = seal(&key, &random_nonce(), b"abc", b"").unwrap();
        assert_eq!(ct.len(), 3 + TAG_LEN);
    }

    #[test]
    fn open_fails_on_wrong_key() {
        let nonce = random_nonce();
        let ct = seal(&[3u8; KEY_LEN], &nonce, b"secret", b"ad").unwrap();
        let err = open(&[4u8; KEY_LEN], &nonce, &ct, b"ad").unwrap_err();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn open_fails_on_wrong_nonce() {
        let key = [3u8; KEY_LEN];
        let ct = seal(&key, &random_nonce(), b"secret", b"ad").unwrap();
        assert!(open(&key, &random_nonce(), &ct, b"ad").is_err());
    }

    #[test]
    fn open_fails_on_modified_aad() {
        let key = [3u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"secret", b"label-a").unwrap();
        let err = open(&key, &nonce, &ct, b"label-b").unwrap_err();
        assert!(err.is_auth_failure());
    }

    // SECURITY.md pre-release checklist: "Corrupting any byte of the vault file
    // causes a clean authentication failure, never a silent wrong-plaintext read."
    #[test]
    fn flipping_any_single_bit_of_ciphertext_fails_cleanly() {
        let key = [3u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"a moderately long secret value", b"ad").unwrap();

        for byte_idx in 0..ct.len() {
            for bit in 0..8 {
                let mut corrupt = ct.clone();
                corrupt[byte_idx] ^= 1 << bit;
                match open(&key, &nonce, &corrupt, b"ad") {
                    Err(e) => assert!(e.is_auth_failure()),
                    Ok(_) => {
                        panic!("bit {bit} of byte {byte_idx} flipped but decryption succeeded")
                    }
                }
            }
        }
    }

    #[test]
    fn generated_keys_and_nonces_are_not_constant() {
        let a = VaultKey::generate();
        let b = VaultKey::generate();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(random_nonce(), random_nonce());
        assert_ne!(random_salt(), random_salt());
    }

    #[test]
    fn vault_key_debug_is_redacted() {
        let k = VaultKey::from_bytes([0xAB; KEY_LEN]);
        let shown = format!("{k:?}");
        assert_eq!(shown, "VaultKey([redacted])");
        assert!(
            !shown.contains("ab"),
            "debug output must not leak key bytes"
        );
    }
}
