# Phase 3 — macOS biometrics

## What is where

```
crates/vault-platform/src/
  biometrics.rs          BiometricProvider trait, availability, failure modes
  macos_keychain.rs      Security.framework FFI: the keychain item + LAContext
crates/vault-core/src/
  header.rs              keystore slots — build/unlock/remove, no KDF
  vault.rs               enable_keystore_unlock, unlock_with_keystore_key, verify_password
src-tauri/src/
  commands.rs            biometric_state, enable, disable, unlock
  settings.rs            the 14-day master-password window
src/lib/components/
  BiometricsSetting.svelte
entitlements.plist       keychain-access-groups, hardened runtime
```

## A fingerprint is not a key

`docs/SECURITY.md` says it and the trait shape follows from it. There is no
`authenticate() -> bool` method, deliberately — a boolean invites a caller to
branch on it and unlock, and a local attacker who patches the binary flips
booleans for a living. They cannot conjure 32 bytes out of the Secure Enclave.

So `BiometricProvider` is a *key store with a gate*:

1. Vaulty generates a random 32-byte key-encryption key.
2. The keychain holds it behind `kSecAccessControlBiometryCurrentSet`.
3. A header slot (`SlotKind::Biometric`, `kdf_id = 0`) wraps the vault key with it.

Touch ID gates step 2. Even a successful read only yields something that
unwraps one slot of one vault — useless beside any other file, and it fails
closed if the vault has moved on.

Never the master password, never the vault key. SECURITY.md: "Never store the
master password itself in the keystore. Store the wrapped key."

## Why `BiometryCurrentSet` rather than `evaluatePolicy`

`LAContext.evaluatePolicy` splits into two steps — "was that a valid finger?"
then "read an unprotected item" — and a patched binary skips the first.
`kSecAccessControlBiometryCurrentSet` has no decision to patch: the item is
encrypted by the Secure Enclave against the enrolment set in force when it was
written. Without a matching biometric the bytes do not come back.

It also gives the second half of the exit criterion for free: changing the
enrolment set discards the item, so adding a fingerprint forces the password.

## The slot design needed no format change

`docs/PHASE0-NOTES.md` promised this: "A second unlock method is a new slot, not
a migration." It held. `SlotKind::Biometric` and `kdf_id = 0` were already in
the format from the first commit; Phase 3 added the code that writes one. An
existing vault gains biometric unlock without a version bump or a migration.

Both slots wrap the *same* vault key, so changing the master password leaves
biometrics working and vice versa — tested.

## The 14-day re-prompt

SECURITY.md wants the master password re-entered roughly fortnightly so it stays
in muscle memory. It is not a security control — the OS already gates the
keychain — it is protection against the one credential with no recovery path
quietly fading from memory.

The window measures from the last *password* unlock, so biometrics cannot keep
extending it. `last_password_unlock_at` lives in `settings.json`; an attacker who
edits it can only make Vaulty ask for the password *less* often, and still needs
a biometric or the password itself.

Creating a vault and enabling biometrics both count as password events — found
by a test, which had the first biometric unlock refused as overdue because
nothing had ever recorded one.

## The interface

Apple's Human Interface Guidelines for macOS, not an invented look: system
colours as tokens with light and dark from one switch, the SF type scale
(`-apple-system` resolves to SF Pro), 8pt spacing, standard control shapes and
radii, a translucent sidebar with the traffic lights floating over it, and the
capture popup as a Spotlight-style panel. A security tool that looks foreign to
its OS looks untrustworthy.

Kind icons are drawn rather than taken from SF Symbols: those live in a
private-use Unicode range and render as tofu wherever SF Pro is not resolved.

## What is verified, and what is not

Covered by tests — the provider is injected, so the whole flow runs on any
machine:

- enrolment, unlock, disable, re-enrolment issuing a fresh key
- enabling requires the master password; a refused keychain write leaves no slot
  pointing at a key that was never stored
- **every** failure mode leaves the vault locked and the password working
- an invalidated key forces the password, with a message that says why
- the 14-day window, and that a biometric unlock does not reset it

**Not verified, and it needs an Apple Developer account:**

1. **Nothing has ever been stored in a real keychain.** Verified empirically
   that an unsigned build cannot: `SecItemAdd` is refused. This is exactly what
   `KICKOFF.md` warns about — "biometrics does not work in an unsigned app, and
   discovering that late costs a week."
2. **No Touch ID prompt has ever been raised.** `LAContext` reports
   `Available(TouchId)` on this machine, so the hardware and enrolment are
   detected correctly, but `SecItemCopyMatching` has never run against a real
   item.
3. **The invalidation behaviour is assumed, not observed.** That adding a
   fingerprint discards a `BiometryCurrentSet` item is documented Apple
   behaviour; the test stands in for it with a fake.

### To finish this phase

1. Apple Developer Program account (€99/year).
2. Put the Team ID in `entitlements.plist` — replace `$(AppIdentifierPrefix)` if
   your signing setup does not expand it.
3. Set `bundle.macOS.signingIdentity` in `tauri.conf.json`, then
   `npm run tauri build`.
4. Run the signed `.app` and confirm: enabling biometrics succeeds, Touch ID
   unlocks, and adding a fingerprint in System Settings forces the password.

Until then the feature is present, reachable in Settings, and will report
`keychain_write_failed` when switched on.
