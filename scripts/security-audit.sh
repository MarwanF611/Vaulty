#!/usr/bin/env bash
#
# The parts of the docs/SECURITY.md pre-release checklist that need a built
# binary rather than a unit test.
#
# Run before a release:  ./scripts/security-audit.sh
#
# Everything else in that checklist is covered by tests:
#   crates/vault-core/tests/security_checklist.rs   error/timing/corruption
#   src-tauri/tests/no_secret_logging.rs            the secret-in-logs audit
#   src-tauri/tests/recovery.rs                     snapshot restore

set -uo pipefail
cd "$(dirname "$0")/.."

FAILED=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAILED=1; }
note() { printf '  \033[33m•\033[0m %s\n' "$1"; }

BIN=target/release/vaulty-app
echo "==> Building release binary"
cargo build --release -p vaulty-app >/dev/null 2>&1 || { fail "release build failed"; exit 1; }
pass "built $BIN"

echo
echo "==> strings: no embedded key material"

# A 32-byte key or a 24-byte nonce baked into the binary would show up as a long
# run of hex or base64. Real code has neither: every key is generated at runtime
# from the OS CSPRNG.
HEX_HITS=$(strings -n 40 "$BIN" | grep -cE '^[0-9a-fA-F]{40,}$' || true)
if [ "$HEX_HITS" -eq 0 ]; then
  pass "no long hex literals"
else
  fail "$HEX_HITS long hex literal(s) — inspect: strings -n 40 $BIN | grep -E '^[0-9a-fA-F]{40,}\$'"
fi

# Test fixtures must not reach a release binary.
for needle in "correct horse battery staple" "hunter2" "PLAINTEXT-SECRET-NEEDLE" \
              "CAPTURED-SELECTION-NEEDLE" "ghp_deadbeef"; do
  if strings "$BIN" | grep -qF "$needle"; then
    fail "test fixture in the binary: $needle"
  fi
done
[ "$FAILED" -eq 0 ] && pass "no test fixtures embedded"

# The vault's own magic is expected; flag anything that looks like a key name.
for needle in "BEGIN PRIVATE KEY" "BEGIN RSA" "-----BEGIN"; do
  # `--` so a leading-dash needle is not read as options.
  strings "$BIN" | grep -qF -- "$needle" && fail "key material marker in binary: $needle"
done
pass "no PEM markers"

echo
echo "==> Entitlements and signing"
if [ -f src-tauri/entitlements.plist ]; then
  if grep -q "keychain-access-groups" src-tauri/entitlements.plist; then
    pass "keychain-access-groups declared"
  else
    fail "entitlements.plist lacks keychain-access-groups"
  fi
  # Strip comments before matching: the file explains why the network
  # entitlement is absent, and matching prose flagged that explanation.
  if sed '/<!--/,/-->/d' src-tauri/entitlements.plist \
      | grep -qE "<key>com\.apple\.security\.network"; then
    fail "network entitlement declared — v1 is offline (CLAUDE.md rule 8)"
  else
    pass "no network entitlement"
  fi
else
  fail "src-tauri/entitlements.plist missing"
fi

SIGNING=$(codesign -dvv "$BIN" 2>&1 | grep -E "^Authority=" | head -1 || true)
if [ -z "$SIGNING" ]; then
  # Apple Silicon ad-hoc signs every binary, so "has a signature" means
  # nothing on its own. Only a real authority grants the keychain entitlement.
  note "ad-hoc signature only — Touch ID cannot work (docs/PHASE3-NOTES.md)"
else
  pass "signed by ${SIGNING#Authority=}"
  codesign -d --entitlements :- "$BIN" 2>/dev/null | head -20
fi

echo
echo "==> Manual checks still outstanding"
note "Memory dump after lock contains no plaintext — needs a signed build and lldb"
note "A security-minded person outside the project has read the crypto code"

echo
if [ "$FAILED" -eq 0 ]; then
  printf '\033[32mAutomated checks passed.\033[0m\n'
else
  printf '\033[31mAutomated checks FAILED.\033[0m\n'
fi
exit "$FAILED"
