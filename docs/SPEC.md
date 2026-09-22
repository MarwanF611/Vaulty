# Vaulty — specification

## The product in one line

Select text anywhere, press the shortcut, label it, and it is encrypted on disk. Unlock with
Touch ID or Windows Hello.

## Why it exists

1Password and Bitwarden are built around browser autofill. Saving a stray recovery code, a
wifi key or a door PIN in them takes six clicks. Vault optimises for one thing: getting a
secret out of your head or your screen and into encrypted storage in under three seconds.

The product is that moment. Everything else is support for it.

## In scope for v1.0

- Entries with: label, secret, optional note, tags, kind
- Kinds: `password`, `code`, `note`, `card`, `wifi`
- Global shortcut capture from selected text or clipboard
- Search-as-you-type over labels and tags; Enter copies the match
- Clipboard auto-clears 30 seconds after a copy
- Biometric unlock with master password fallback
- Auto-lock on idle timeout, on system sleep, on screen lock
- Password and passphrase generator
- Encrypted export and plaintext-warning import (both free, see below)
- macOS and Windows

## Explicitly out of scope for v1.0

- Browser autofill — a separate product, do not start it
- Sync of any kind — but the data model must not block it (see Data model)
- TOTP codes — first thing after 1.0
- Sharing, teams, mobile, CLI

## UX

One window does both jobs:

- **Shortcut pressed with text selected** → capture mode: secret pre-filled, cursor in the
  label field, Enter saves, Escape cancels
- **Shortcut pressed with nothing selected** → search mode: type, arrow keys, Enter copies

Target: under 300 ms from keypress to a usable cursor. Keep the process warm and the window
pre-created and hidden. This number is a feature, not an aspiration.

### Capture sequence

1. Save the current clipboard contents
2. Synthesise a copy keystroke into the focused app
3. Read the clipboard
4. Restore the previous clipboard
5. Show the popup with the captured text pre-filled

If the vault is locked, the biometric prompt comes first and the captured text is held in
memory (zeroized if the user cancels).

### Shortcut

Default `Cmd+Shift+Space` on macOS, `Ctrl+Shift+Space` on Windows. **Configurable from the
first build**, with conflict detection — `Ctrl+Shift+Space` collides with parameter hints in
Visual Studio and JetBrains IDEs, which is exactly the target audience.

### macOS Services entry

Declare an `NSServices` entry in `Info.plist` with `NSSendTypes` of `NSStringPboardType`, so
"Add to Vaulty" appears in the right-click Services submenu of every Cocoa app. This is a
bonus path, not the taught one — it lives under **Services**, which many users never open.

**Built** (pulled forward from after 1.0 at the user's request). Declared in
`src-tauri/Info.plist`, served by `crates/vault-platform/src/macos_services.rs`, and lands in
the same capture popup as the shortcut. It is the cleaner of the two paths: AppKit hands
the selection over on a private pasteboard, so there is no synthetic keystroke, no
Accessibility permission, and the user's clipboard is never touched.

It only appears for an installed `.app` bundle — macOS reads the declaration from the
bundle on disk, never from a `tauri dev` binary.

**There is no Windows equivalent.** The shell context menu covers files and folders, not
arbitrary selected text. Do not promise it, do not build a workaround for it in v1.

## Data model

SQLite, per-entry encrypted blobs. Not one big encrypted JSON file: a single blob means
decrypting everything to read one item, rewriting everything to change one item, and one bad
write losing the lot.

| Field | Encrypted | Notes |
| --- | --- | --- |
| `id` | no | UUIDv7, sortable by creation |
| `label` | no | must be searchable with the vault open, fast |
| `tags` | no | filtering |
| `kind` | no | password / code / note / card / wifi |
| `secret` | **yes** | the field that matters |
| `note` | **yes** | people paste recovery codes here |
| `created_at`, `updated_at`, `last_used_at` | no | sorting, recently-used ranking |
| `nonce` | no | 24 bytes, fresh per write |

Clear-text labels are a deliberate trade: fast search, and an attacker with the file learns
only that an account exists somewhere. Encrypted labels mean an encrypted search index — a
much larger v2, not a v1 detail.

### Vault header

Format version, KDF parameters, salt, wrapped key, and a **slot list**. A second unlock
method (biometric key, recovery key, later a sync key) is a new slot, not a migration.

### Sync-ready without building sync

UUIDv7 ids, `updated_at` on every row, tombstone rows instead of hard deletes, and a
monotonic `change_seq`. Roughly a day of extra work now; it is what makes v2 sync possible
without asking every user to export and re-import.

### File locations

- macOS: `~/Library/Application Support/Vault/vault.db`
- Windows: `%APPDATA%\Vault\vault.db`
- Atomic writes. Keep the last three snapshots.

## Business model — relevant to what you build

Free tier is the **whole local app**, including export and local backup. Export is never
paywalled: charging users to get their own passwords out of the app reads as hostage-taking
and destroys the trust the product is built on.

Paid (post-1.0) is end-to-end encrypted sync, versioned cloud backup with restore, TOTP and a
browser extension. Those cost money to run, so charging for them is honest.

Practical consequence for v1: **build export and backup as first-class free features**, and
keep the sync-ready fields in the schema from day one.
