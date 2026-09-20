# Vaulty — build phases

Work these in order. Do not start a phase until the previous one meets its exit criteria.
Times assume evenings and weekends, and assume Rust is new; halve if it is not.

---

## Phase 0 — Crypto core, no UI (1–2 weeks)

The most important phase. Getting this right as a headless library, with tests, before any UI
exists is what stops a design flaw surfacing in month four with real user data in the old
format. Resist starting with the window.

- [x] Cargo workspace with `crates/vault-core`
- [x] Vault header: format version, KDF params, salt, wrapped key, slot list
- [x] `create_vault(password) -> Vault` — Argon2id KEK, random vault key, wrapped and stored
- [x] `unlock(password) -> VaultKey` — constant-time failure, no distinguishable timing
- [x] `add_entry`, `get_entry`, `list_entries`, `update_entry`, `delete_entry` (tombstone)
- [x] SQLite schema per `docs/SPEC.md`, including the sync-ready fields
- [x] Atomic write: temp, fsync, rename; rolling three snapshots
- [x] `change_master_password` — rewraps the key, does not re-encrypt entries
- [x] Export and import (encrypted format, plus a plaintext JSON export with a loud warning)
- [x] A thin CLI binary for manual testing (`vault-cli add`, `list`, `get`)

**Status: complete.** 100 tests, `cargo clippy -- -D warnings` clean, `cargo fmt` clean.
Verified end-to-end through `vault-cli`: create, add, list, search, reveal, delete,
snapshot, restore, password change, encrypted export/import. See `docs/PHASE0-NOTES.md`
for the header byte layout and the two bugs the exit-criteria tests caught.

**Exit criteria:** the CLI creates a vault, adds and reads entries, survives restart. Tests
prove the file is unreadable without the password, that a flipped byte fails cleanly, and
that swapping a label between two entries fails authentication. `cargo clippy -- -D warnings`
is clean.

---

## Phase 1 — Tauri shell (1–2 weeks)

- [x] Tauri 2 app wrapping `vault-core`
- [x] SvelteKit frontend: unlock screen, entry list, search box, add/edit form
- [x] Tauri commands for each core operation — returning metadata only, never plaintext
      secrets, except an explicit `reveal_secret` and `copy_secret`
- [x] App state holds the unlocked key in Rust; frontend holds nothing sensitive
- [x] Master password unlock only (biometrics comes later)
- [x] Manual lock button

**Status: built and verified at the command layer.** 15 IPC-boundary tests assert that
every command's serialised JSON carries metadata and no plaintext, that a locked vault
refuses every read, and that entries and a changed master password both survive a
restart. `npm run check` is clean, clippy is clean, the app boots. The click-through of
the actual UI has not been done — run `npm run tauri dev` and confirm it feels right.

**Exit criteria:** you can use it as a real (ugly) password manager. Entries survive restart.
Nothing sensitive appears in the webview devtools.

---

## Phase 2 — Global shortcut and capture (1 week)

- [x] `tauri-plugin-global-shortcut`, default binding, user-configurable, conflict detection
- [x] Capture sequence per `docs/SPEC.md` (save clipboard, synthesise copy, read, restore)
- [x] Pre-created hidden popup window, always-on-top, appears over any app
- [x] Capture mode (text selected) and search mode (nothing selected) in one window
- [x] Copy to clipboard with a 30-second auto-clear
- [x] macOS Accessibility and Input Monitoring permission flow with an explanation screen

**Status: built.** The clipboard is captured and restored before the popup is shown, so no
cancel, timeout or crash path can skip the restore. Detection uses the OS clipboard change
counter rather than clearing the clipboard, so the user's clipboard is never at risk. The
captured text stays in Rust and the popup sees only a character count.
140 tests, clippy clean, `npm run check` clean.

**Not yet observed:** the 300 ms figure is instrumented and displayed in the popup, but
reading it needs a signed build with Accessibility granted and a human pressing the key.
See `docs/PHASE2-NOTES.md` for that and the other limitations.

**Exit criteria:** under 300 ms from keypress to a usable cursor, measured. The previous
clipboard is always restored, including when the user cancels.

---

## Phase 3 — macOS biometrics (1–2 weeks)

- [ ] `crates/vault-platform` with a `BiometricProvider` trait
- [ ] macOS implementation: keychain item, `kSecAccessControlBiometryCurrentSet`
- [ ] Apple Developer signing + keychain-access-groups entitlement working locally
- [ ] Enable/disable biometrics in settings; disabling removes the keychain item
- [ ] Password fallback on any biometric failure — never a silent unlock
- [ ] Periodic master-password re-prompt (≈14 days)

**Exit criteria:** Touch ID unlocks a signed build. Adding a fingerprint in System Settings
invalidates the stored key and forces the password.

---

## Phase 4 — Windows biometrics (2–3 weeks)

- [ ] Standalone prototype binary first: Hello prompt + TPM-backed key, nothing else
- [ ] `UserConsentVerifier` for the prompt
- [ ] DPAPI or `KeyCredentialManager` for the key itself
- [ ] Same `BiometricProvider` trait, same fallback rules
- [ ] Windows build of everything from phases 1–2 verified

**Exit criteria:** Hello unlocks on a real Windows machine (not only a VM), with the same
fallback behaviour as macOS.

---

## Phase 5 — Hardening (1–2 weeks)

- [ ] Auto-lock: idle timeout (configurable), system sleep, screen lock
- [ ] Zeroize audit — every path that touches plaintext
- [ ] Secret-in-logs audit across the whole repo
- [ ] Crash recovery from snapshot, tested by corrupting a live vault
- [ ] Settings: shortcut, idle timeout, clipboard clear delay, biometrics toggle
- [ ] First-run onboarding that states plainly there is no password recovery
- [ ] The full checklist at the end of `docs/SECURITY.md`

**Exit criteria:** every box in the SECURITY.md pre-release checklist is ticked.

---

## Phase 6 — Shipping (2–3 weeks)

- [ ] Apple Developer signing and notarization, stapled
- [ ] Windows OV code signing certificate, SmartScreen-clean installer
- [ ] Installers for both platforms
- [ ] Auto-update (Tauri updater), signed
- [ ] Landing page: what it does, the threat model, the price, a link to the source
- [ ] Public repo with README, threat model and build instructions

**Exit criteria:** a stranger can download, install and use it without a security warning.

---

## Phase 7 — v1.0 public

**Exit criteria:** 20 people outside your circle using it daily, zero data-loss reports.

---

## After 1.0, in order

1. TOTP codes
2. macOS Services menu entry
3. End-to-end encrypted sync — the first paid feature
4. Browser extension

---

## Open questions to resolve before phase 3

- Apple Developer account: existing, or a cost to plan for (€99/year)?
- Windows OV code signing certificate (~€200–400/year) — when to buy?
- Mac-first with Windows in 1.1, or both at 1.0? Mac-first ships months earlier.
