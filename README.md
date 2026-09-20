# Vaulty

A local-first secrets vault for macOS and Windows. Select text anywhere, press the shortcut,
give it a label — encrypted on disk. Unlock with Touch ID or Windows Hello.

**Status:** Phase 3 — crypto core, CLI, desktop app, global shortcut with selection
capture, and Touch ID unlock. Touch ID needs a signed build to work; see
[`docs/PHASE3-NOTES.md`](docs/PHASE3-NOTES.md).

## Build

```sh
npm install
cargo test --workspace                              # 180 tests
cargo clippy --workspace --all-targets -- -D warnings
npm run check                                       # frontend types
```

Run the desktop app:

```sh
npm run tauri dev
```

The vault lands at the per-OS app data path. Set `VAULTY_VAULT_PATH` to point it
somewhere else — useful for trying it without touching a real vault.

Or drive the core from the CLI:

```sh
cargo run -p vault-cli -- --vault /tmp/demo.db init
cargo run -p vault-cli -- --vault /tmp/demo.db add "GitHub" --tags work
cargo run -p vault-cli -- --vault /tmp/demo.db list
cargo run -p vault-cli -- --vault /tmp/demo.db get GitHub
```

The CLI is developer tooling for exercising `vault-core` by hand, not a shipped surface.

## Documents

- [`CLAUDE.md`](CLAUDE.md) — rules for Claude Code working in this repo
- [`KICKOFF.md`](KICKOFF.md) — how to start the first session
- [`docs/SPEC.md`](docs/SPEC.md) — what the product is and is not
- [`docs/SECURITY.md`](docs/SECURITY.md) — crypto design and threat model
- [`docs/PHASES.md`](docs/PHASES.md) — build phases and exit criteria
- [`docs/PHASE0-NOTES.md`](docs/PHASE0-NOTES.md) — header byte format, crate choices, what Phase 0 found
- [`docs/PHASE2-NOTES.md`](docs/PHASE2-NOTES.md) — the capture sequence, and what it cannot do yet
- [`docs/PHASE3-NOTES.md`](docs/PHASE3-NOTES.md) — biometrics, and what needs a signed build

## Security, honestly

Vaulty protects against a stolen laptop, a stolen backup drive, and someone copying the vault
file. It does not protect against malware already running as your user, a keylogger, or a
kernel-level attacker. No password manager does.

There is no password recovery. If you lose the master password, the vault is gone.
