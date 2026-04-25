#!/bin/sh
# Code-sign bwx + bwx-agent on macOS. Picks the strongest signing
# identity available in the login keychain:
#
#   1. `$IDENTITY`                           (explicit override)
#   2. "Developer ID Application: …"         (paid cert, distributable)
#   3. "Apple Development: …"                (free, Xcode auto-provisioned)
#   4. ad-hoc (`-`)                          (no cert; cargo-install users)
#
# Tier 2 also signs an entitlements plist declaring a
# `keychain-access-groups` entry scoped to the signing identity's team
# ID. That unlocks the biometric-ACL Keychain path at runtime. Tiers 3
# and 4 fall through to the plain-Keychain path; Touch ID enforcement
# lives in the agent's `require_presence` call rather than in the item
# ACL.
#
# Usage:
#   ./scripts/sign-macos.sh                  # sign ~/.cargo/bin/bwx{,-agent}
#   ./scripts/sign-macos.sh /path/to/dir     # sign binaries in a different dir
#   IDENTITY="Developer ID Application: …" ./scripts/sign-macos.sh
set -eu

BIN_DIR="${1:-$HOME/.cargo/bin}"

pick_identity() {
  if [ -n "${IDENTITY:-}" ]; then
    printf "%s" "$IDENTITY"
    return
  fi
  ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"
  # Developer ID Application is the only CLI-tool-friendly identity
  # that can carry a `keychain-access-groups` entitlement without a
  # provisioning profile. Apple Development certs *can* sign, but the
  # entitlement would only work inside a `.app` bundle with an
  # embedded profile, so they get signed plain (no entitlement) —
  # identical in effect to ad-hoc for bwx's purposes.
  pick="$(printf "%s" "$ids" | grep 'Developer ID Application' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  pick="$(printf "%s" "$ids" | grep 'Apple Development' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  printf "%s" "-"
}

extract_team_id() {
  # "Apple Development: Name (ABCD123456)" -> ABCD123456
  printf "%s" "$1" | sed -nE 's/.*\(([A-Z0-9]{10})\).*/\1/p'
}

IDENTITY_STR="$(pick_identity)"
case "$IDENTITY_STR" in
  "Developer ID Application"*) USE_ENTITLEMENTS=1 ;;
  *)                           USE_ENTITLEMENTS=0 ;;
esac

if [ "$USE_ENTITLEMENTS" -eq 0 ]; then
  if [ "$IDENTITY_STR" = "-" ]; then
    echo "signing mode: ad-hoc (plain Keychain path)"
  else
    echo "signing mode: $IDENTITY_STR (plain Keychain path)"
    echo "  (Developer ID Application is required for biometric-ACL"
    echo "   Keychain items on command-line tools; Apple Development"
    echo "   works for code-signing but not for"
    echo "   keychain-access-groups without a provisioning profile.)"
  fi
  for name in bwx bwx-agent; do
    bin="$BIN_DIR/$name"
    [ -x "$bin" ] || continue
    codesign --force --sign "$IDENTITY_STR" "$bin"
    echo "  signed: $bin"
  done
  exit 0
fi

TEAM_ID="$(extract_team_id "$IDENTITY_STR")"
if [ -z "$TEAM_ID" ]; then
  echo "error: couldn't extract team id from identity: $IDENTITY_STR" >&2
  exit 1
fi

echo "signing mode: $IDENTITY_STR (biometric-ACL Keychain path)"

# `HARDENED_RUNTIME=1` opts the binary into Apple's hardened runtime
# (`codesign --options runtime`), required for notarization. The
# `allow-unsigned-executable-memory` entitlement is also added so AMFI
# doesn't kill the Rust binary on first run — Rust's allocator + a few
# crates touch executable pages in ways the strict default rejects.
# Local dev (no env var) skips both.
ENTITLEMENTS="$(mktemp -t bwx-entitlements).plist"
trap "rm -f '$ENTITLEMENTS'" EXIT
if [ "${HARDENED_RUNTIME:-0}" = "1" ]; then
  cat > "$ENTITLEMENTS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM_ID}.bwx</string>
  </array>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <true/>
</dict>
</plist>
EOF
  HR_FLAG="--options=runtime"
else
  cat > "$ENTITLEMENTS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM_ID}.bwx</string>
  </array>
</dict>
</plist>
EOF
  HR_FLAG=""
fi

for name in bwx bwx-agent; do
  bin="$BIN_DIR/$name"
  [ -x "$bin" ] || continue
  # shellcheck disable=SC2086
  codesign --force $HR_FLAG --timestamp \
           --entitlements "$ENTITLEMENTS" \
           --sign "$IDENTITY_STR" "$bin"
  echo "  signed: $bin"
done

echo ""
echo "access group: ${TEAM_ID}.bwx"
if [ "${HARDENED_RUNTIME:-0}" = "1" ]; then
  echo "hardened runtime: on (notarization-ready)"
fi
echo "bwx touchid enroll will use a biometric-ACL Keychain item."
