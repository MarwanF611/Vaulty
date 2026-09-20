# Vaulty — security design and threat model

Read this before touching `crates/vault-core/` or `crates/vault-platform/`.

## Two-key design

The master password never encrypts entries directly. It derives a key-encryption key (KEK)
that wraps a random vault key; entries are encrypted with the vault key. Changing the master
password rewraps one key instead of re-encrypting the whole vault, and biometric unlock
becomes a second path to the same wrapped key.

1. `KEK = Argon2id(password, salt)` — start at 64 MiB memory, 3 iterations, parallelism 4,
   then tune on the slowest supported machine. Store the parameters in the header.
   The parameters read back from a header are **bounded on both sides** before they are
   used: 8 MiB–1 GiB memory, 2–16 iterations, 1–16 lanes. Without an upper bound, flipping
   one bit of the stored iteration count turns 3 iterations into 32 770 and unlock never
   returns — a tampered file that presents as a hung app rather than a corrupt vault.
   The ceilings sit far above any value the tuning pass would pick.
2. `vault_key` = 32 bytes from the OS CSPRNG, generated once at vault creation.
3. `wrapped_key = XChaCha20-Poly1305(KEK, vault_key)` — lives in the vault header.
4. Each entry's secret is encrypted with `vault_key` under its own random 24-byte nonce.
5. The entry's `label`, `tags`, `kind` and timestamps are passed as **associated data**, so a
   label cannot be swapped onto a different secret without breaking authentication.

## Key material in memory

- `vault_key` lives in Rust as `Secret<[u8; 32]>`, never in the webview, never in a Tauri
  event payload.
- Zeroize on: lock, idle timeout, system sleep, screen lock, quit.
- Decrypt an individual secret only at the moment it is copied or revealed, then zeroize.
- Never `Debug`-print a type holding key material — implement `Debug` manually as `[redacted]`.

## Biometric unlock

A fingerprint is not a key. Touch ID and Hello return a yes. The design is always: the OS
keystore holds the wrapped key, biometrics is the gate on reading it back.

### macOS

Keychain item with access control `kSecAccessControlBiometryCurrentSet`, Secure Enclave
protected — or `LAContext.evaluatePolicy` in front of a keychain read. Prefer
`BiometryCurrentSet`: enrolling a new fingerprint invalidates the item.

Reached from Rust via `security-framework` + `objc2`, or a thin Swift/ObjC shim over FFI.
**Requires a signed app with a keychain-access-groups entitlement — verify this in phase 3,
not the week before launch.**

### Windows

Two layers, both needed:

- `UserConsentVerifier.RequestVerificationAsync` (WinRT) shows the Hello prompt and returns
  yes/no.
- A yes alone is spoofable by a local attacker who patches the binary, so the secret itself is
  protected by DPAPI (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`, user-scoped) or,
  better, a TPM-backed `KeyCredentialManager` key used to sign a challenge.

Reached from Rust via the `windows` crate. This is the finicky one — prototype it as a
standalone 50-line binary before wiring it into the app.

### Rules for both platforms

- Biometrics is convenience over the master password, never a replacement.
- The master password always works. **There is no recovery.** Say this at setup, twice.
- Re-prompt for the master password roughly every 14 days so it stays in muscle memory.
- Biometric enrolment changes invalidate the stored key.
- Never store the master password itself in the keystore. Store the wrapped key.
- Never fall back silently: if biometrics fails, show the password field — do not unlock.

## Threat model

**Protects against:** a stolen laptop, a stolen backup drive, someone copying the vault file,
the vault file ending up in a cloud backup.

**Does not protect against:** malware already running as the user, a keylogger, a
kernel-level attacker, someone reading the screen, clipboard sniffers during the copy window.

State this plainly in the README and on the website. Overclaiming here is how vault products
get taken apart publicly.

## Non-negotiables

- No custom crypto, no novel constructions.
- Versioned file format from the first commit.
- Lock on sleep and screen lock, not only on an idle timer.
- The core is open source. A closed-source vault from an unknown developer does not get
  installed; an open core is what buys trust.
- Reproducible builds where feasible.

## Implementation notes

`docs/PHASE0-NOTES.md` records the header byte layout, exactly which fields are
authenticated as associated data, and the storage decisions behind them.

## Pre-release checklist

- [ ] No secret appears in any log, error, panic message or crash dump
- [ ] `strings` on the binary reveals no embedded key material
- [ ] Memory dump after lock contains no plaintext secrets
- [x] Corrupting any byte of the vault file causes a clean authentication failure, never a
      silent wrong-plaintext read
      *(covered for the header and for entry ciphertext by `corrupting_any_header_byte_fails_cleanly`
      and `flipping_any_single_bit_of_ciphertext_fails_cleanly`; re-verify once the UI can
      surface the failure)*
- [ ] Wrong master password is indistinguishable in timing from a corrupt file
      *(holds for a corrupt wrapped key — both run the KDF then fail. A structurally
      malformed header still fails before the KDF runs: see PHASE0-NOTES.md)*
- [ ] Restore from snapshot tested on both platforms
- [ ] At least one security-minded person outside the project has read the crypto code
