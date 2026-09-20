# Phase 5 — hardening

## What is where

```
crates/vault-platform/src/
  idle.rs, macos_idle.rs      system idle seconds, screen-lock state, sleep detection
crates/vault-core/src/
  vault.rs                    open_and_unlock — the constant-time unlock path
src-tauri/src/
  autolock.rs                 the watcher and the lock policy
src/lib/components/
  Onboarding.svelte           first run, including the no-recovery acknowledgement
  Recovery.svelte             snapshot restore for an unopenable vault
scripts/security-audit.sh     the checklist items that need a built binary
```

Tests: `security_checklist.rs`, `zeroize_audit.rs`, `no_secret_logging.rs`,
`recovery.rs`, plus `autolock.rs`'s policy tests.

## Auto-lock

Three signals, all polled every two seconds:

- **Idle** — `CGEventSourceSecondsSinceLastEventType`, which counts input
  anywhere on the system rather than in our window. That is the right question:
  the vault should lock because the user walked away, not because they switched
  to a browser.
- **Screen lock** — `CGSessionCopyCurrentDictionary`.
- **Sleep** — inferred from `Instant` (which stops during sleep) disagreeing
  with `SystemTime` (which does not). Detected on wake rather than as sleep
  begins, which is equivalent in practice: the process is suspended throughout,
  so there is no moment in between when anything could read the key.

Polling rather than Objective-C notifications, for one reason that matters:
it degrades safely. If a signal becomes unreadable the idle timer still fires,
whereas a missed notification is a vault that silently stays unlocked.
`should_lock` is a pure function so the policy is tested without a clock, a
window or an OS.

**The idle timeout is configurable; sleep and screen lock are not.**
SECURITY.md lists them under non-negotiables, and a vault that stays open
through a lid close is not a vault. Making that switchable invites switching it
off.

## Timing: the gap Phase 0 left open

SECURITY.md's checklist asks that a wrong master password be indistinguishable
in timing from a corrupt file. Phase 0 recorded this as only half-met, and it
was worse than it sounded: `Vault::open` rejects an unreadable header in
microseconds while a wrong password costs a full Argon2id run. Measured, the
gap was **524×** — 73 ms against 140 µs. A stopwatch told an attacker whether
their tampering had broken the header or merely the password.

`Vault::open_and_unlock` closes it. Both paths now run exactly one KDF at
production cost: the real one when the header parses, a discarded one when it
does not, and both return the same `Error::Auth` with the same text. The test
asserts the ratio stays inside 0.2–5×, and fails at 524× if the dummy run is
removed — verified by removing it.

A *missing* file is still reported as missing. That is not a leak: the user
knows whether they have a vault, and pretending otherwise would make a first run
look like a corruption.

## The audits

Both are tests rather than read-throughs, because "check this before every
commit" is a habit and habits lapse.

**Secret-in-logs** (`no_secret_logging.rs`) walks the tree with different
strictness per layer: `vault-core` and `vault-platform` may not print at all;
`src-tauri` may report startup failures but never `dbg!` and never on a
secret-bearing line; the frontend gets no `console.*` at all. `vault-cli` is
exempt — printing a secret is what `vault-cli get` is for. The audit also
asserts it can see the files it claims to check, so it cannot pass vacuously.

**Zeroize** (`zeroize_audit.rs`) is mostly compile-time. Changing
`RevealedEntry.secret` from `Zeroizing<String>` to `String` stops the file
compiling, which outlasts any note saying it was checked once. The file carries
the enumerated table of every path where plaintext exists.

## What is still open

Phase 5's exit criterion is "every box in the SECURITY.md pre-release checklist
is ticked". **Four of seven are ticked.** The three that are not:

1. **Memory dump after lock contains no plaintext.** Not attempted, and it may
   not pass as written. `Zeroizing<String>` zeroes the buffer it owns when it
   drops, but a `String` that reallocated while growing left its old buffer
   behind unzeroed, and ciphertext read out of SQLite passes through buffers
   this crate does not own. Closing this properly means a custom allocator, not
   more `Zeroizing`. It needs a signed build and lldb to even measure.

2. **Restore from snapshot tested on both platforms.** macOS only — Phase 4
   (Windows) has not been done.

3. **A security-minded person outside the project has read the crypto code.**
   Not something a build can do.

Also still outstanding from earlier phases, unchanged: Touch ID has never run
against a real keychain, and the 300 ms capture figure has never been read.
Both need the Apple Developer account.
