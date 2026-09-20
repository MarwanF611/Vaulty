# Vaulty — project rules for Claude Code

A local-first secrets vault for macOS and Windows. Select text anywhere, press a global
shortcut, give it a label, and it is encrypted on disk. Unlock with Touch ID or Windows Hello.

Read `docs/SPEC.md` before writing code. Read `docs/SECURITY.md` before touching anything
in `crates/vault-core/`. Work through `docs/PHASES.md` in order — do not skip ahead.

## Stack

- **Shell:** Tauri 2
- **Core:** Rust (all crypto, all key handling, all OS integration)
- **Frontend:** SvelteKit + TypeScript
- **Storage:** SQLite via `rusqlite`, per-entry encrypted blobs
- **Crypto:** `argon2` (Argon2id) + `chacha20poly1305` (XChaCha20-Poly1305) + `zeroize` + `secrecy`

## Hard rules — do not violate these without asking

1. **No plaintext secret crosses into the webview** unless the user explicitly asked to
   reveal or copy it. The frontend gets labels, tags and metadata. Nothing else.
2. **No custom crypto.** Audited crates, standard constructions. If a task seems to need a
   novel scheme, stop and say so instead of inventing one.
3. **Never log a secret.** No `println!`, no `dbg!`, no `console.log`, no error message that
   embeds key material or plaintext. Check this before every commit.
4. **Secrets in memory are `Secret<T>` / `Zeroizing<T>`** and are zeroized on lock, idle
   timeout, sleep and quit. Plaintext lives for the shortest possible time.
5. **Biometrics is a gate, not a key.** Touch ID and Hello return a yes/no; the OS keystore
   holds the wrapped key. The master password always works as fallback.
6. **The vault file format is versioned** from the first commit. Every format change bumps the
   version and ships a migration.
7. **Writes are atomic**: temp file, fsync, rename. Never write in place.
8. **No network calls in v1.** The app is offline. If a dependency wants the network, that is
   a red flag worth raising.

## Layout

```
crates/
  vault-core/      crypto, vault file, entry CRUD — no UI, no Tauri, fully testable
  vault-platform/  OS integration: keystore, biometrics, global shortcut, clipboard
src-tauri/         Tauri commands, app state, lock lifecycle
src/               SvelteKit frontend
docs/              SPEC, SECURITY, PHASES
```

`vault-core` must compile and pass its tests with no Tauri dependency. That boundary is what
keeps the crypto reviewable.

## Conventions

- Rust 2021, `cargo fmt`, `cargo clippy -- -D warnings` clean before every commit.
- Errors: `thiserror` in the crates, `anyhow` in the app layer. Error messages never contain
  secret material.
- Every crypto function gets a unit test. Every vault-file change gets a round-trip test plus
  a "corrupt a byte, expect failure" test.
- Commits are small and scoped to one phase item.
- No `unwrap()` in non-test code outside of provably-infallible cases, and comment those.

## Working style

- Before starting a phase item, restate what "done" means from `docs/PHASES.md`.
- After each item: run `cargo test`, `cargo clippy`, and say what you verified.
- If something in the spec is wrong or impossible, say so — do not quietly work around it.
- Prefer asking over guessing on anything security-relevant.
