# Phase 0 — what was built, and the decisions inside it

`KICKOFF.md` asks for three things to be approved before implementation: the crate layout,
the vault header byte format, and the exact crypto crates and versions. They are recorded
here. The header layout is the one that is expensive to change later — everything else is
a refactor, that is a migration.

## Crate layout

```
crates/
  vault-core/          no UI, no Tauri, no network. Builds and tests standalone.
    src/crypto.rs      Argon2id + XChaCha20-Poly1305 wrappers, VaultKey
    src/header.rs      vault header and slot list, byte layout below
    src/entry.rs       entry types, associated-data construction, payload encoding
    src/db.rs          SQLite schema and row access
    src/vault.rs       open / unlock / lock / CRUD — the public surface
    src/atomic.rs      atomic writes, rolling snapshots, restore
    src/export.rs      encrypted backup, plaintext JSON export
    src/error.rs       one coarse error type, no secrets in messages
    tests/vault_lifecycle.rs   the Phase 0 exit criteria, driven through the public API
  vault-cli/           thin manual-testing CLI. Not a shipped surface (SPEC.md).
```

`vault-platform` is not here yet: it is Phase 3, and there is nothing for it to do until
biometrics.

## Crypto crates, as resolved

| Crate | Version | Role |
| --- | --- | --- |
| `argon2` | 0.5.3 | Argon2id KDF |
| `chacha20poly1305` | 0.10.1 | XChaCha20-Poly1305 AEAD |
| `zeroize` | 1.9.0 | `Zeroizing<T>` for transient plaintext |
| `secrecy` | 0.10.3 | `SecretBox` for the vault key |
| `subtle` | 2.6.1 | constant-time comparison |
| `rand_core` | 0.6.4 | OS CSPRNG (`OsRng`) |
| `rusqlite` | 0.32.1 | SQLite, `bundled` so there is no system-library dependency |
| `uuid` | 1.26.1 | UUIDv7 ids |

All RustCrypto, all widely used, no novel constructions (CLAUDE.md rule 2). Nothing in the
tree wants the network.

## Vault header — format version 1

Stored as a blob under the `header` key of the `vault_meta` table. All integers
little-endian.

```text
off  size  field
  0     8  magic          b"VAULTYDB"
  8     2  format_version u16 = 1
 10     1  aead_id        u8  1 = XChaCha20-Poly1305
 11     1  reserved       u8  = 0
 12    16  vault_id       UUIDv7
 28     8  created_at     i64 unix seconds
 36     2  slot_count     u16  (max 64)
 38   ...  slots, slot_count of them:

       1  kind        u8   1 = password, 2 = biometric, 3 = recovery
       1  flags       u8   reserved, = 0
      16  slot_id     UUIDv7
       8  created_at  i64
       1  kdf_id      u8   1 = Argon2id, 0 = none (key from the OS keystore)
       4  m_cost_kib  u32
       4  t_cost      u32
       4  p_cost      u32
       2  salt_len    u16
       N  salt
      24  nonce
       2  wrapped_len u16
       M  wrapped_key ciphertext || tag (48 bytes for a 32-byte key)
```

Each slot wraps the *same* vault key. Adding Touch ID in Phase 3 appends a slot with
`kind = 2`, `kdf_id = 0`; it is not a format change and not a migration.

### What is authenticated

Slot wrapping binds:

```
b"vaulty.slot.v1" || vault_id || slot_id || kind || kdf_id || m || t || p || salt_len || salt
```

So the KDF parameters and the salt are authenticated — a file edited to claim cheaper
Argon2 parameters fails to unwrap rather than quietly becoming a weaker vault, and a slot
cannot be lifted out of one vault and dropped into another.

Entry sealing binds:

```
b"vaulty.entry.v1" || vault_id || entry_id || kind
                   || len(label) || label || len(tags) || tags
                   || created_at || updated_at || change_seq
```

Every variable-length field is length-prefixed, so a boundary shift between label and tags
cannot produce colliding authenticated bytes.

`last_used_at` is deliberately **not** bound. It changes every time a secret is copied, and
binding it would force a re-encrypt and a fresh nonce on every read. Everything else that
describes an entry is bound, which is what makes the label-swap test fail cleanly.

### Entry payload

`secret` and `note` are sealed together as one ciphertext:

```
has_note u8 || len(secret) u32 || secret || len(note) u32 || note
```

One ciphertext per entry means one nonce per entry per write — one fewer opportunity to
reuse a nonce than encrypting the two fields separately.

## Storage decisions worth knowing

* **`journal_mode = DELETE`, not WAL.** WAL leaves `-wal` and `-shm` sidecars next to the
  vault, which turns "copy the vault" and the snapshot rotation into a three-file problem.
  A single-process desktop app does not need WAL's concurrency. `synchronous = FULL`.
* **Atomicity has two mechanisms.** Entry writes rely on SQLite transactions; hand-rolling
  temp-and-rename around a live database would be strictly worse. Snapshots and exports are
  whole-file products and use temp → fsync → rename → fsync-dir.
* **Snapshots use `VACUUM INTO`**, which asks SQLite for a self-consistent copy rather than
  copying bytes out from under a live connection.
* **Restore keeps the old file** as `<name>.prerestore`. Recovering from a corrupt vault
  should not be the step that destroys the evidence.
* **Tombstones keep the id, `updated_at` and `change_seq` and drop everything else** — a
  deleted entry does not leave its label behind.

## Two bugs the exit-criteria tests caught

Both were found by tests that exist because `docs/PHASES.md` asked for them, which is the
argument for writing this phase headless and first.

**1. Unbounded Argon2 iteration count — a denial of service on your own vault.**
`KdfParams::validate` bounded `m_cost` from above but not `t_cost`. The
"corrupt every byte of the header" test flipped one bit in the iteration count, turning 3
iterations into 32 770, and `unlock` stopped returning. A user hitting this would see a
vault that hangs rather than one that reports tampering. Fixed by adding ceilings
(`t_cost ≤ 16`, `p_cost ≤ 16`), well above anything the tuning pass in `SECURITY.md` would
choose. Regression test: `crypto::tests::kdf_refuses_a_denial_of_service_iteration_count`.

**2. World-readable snapshots.** The vault file and exports were chmod 0600, but snapshots
are created by SQLite's `VACUUM INTO`, which uses the process umask — 0644 on a default
macOS account. A snapshot holds everything the vault holds. Fixed by restricting the
snapshot before it is renamed into place. Regression test:
`atomic::tests::snapshots_are_not_world_readable`.

## Deliberately deferred

* **Timing equivalence is partial.** A wrong password and a corrupt *wrapped key* take the
  same path: the KDF runs, then the AEAD fails. A structurally malformed header fails before
  the KDF runs and is therefore distinguishable by timing. Closing that fully means running
  a dummy KDF on a parse failure. It is on the Phase 5 list rather than here because the
  pre-release checklist item is about the password-versus-corrupt-file case, which is
  covered.
* **No `zeroize` audit of `rusqlite`'s internal buffers.** Ciphertext read out of SQLite
  passes through buffers this crate does not own. Plaintext is `Zeroizing` from the moment
  it exists, but the sealed bytes are not. That is Phase 5's "zeroize audit — every path
  that touches plaintext".
* **Search is a linear scan in Rust**, not SQL. Correct Unicode case folding matters more
  than speed at v1 vault sizes; revisit if anyone has 10 000 entries.
