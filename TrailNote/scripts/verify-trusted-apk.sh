#!/usr/bin/env bash
set -euo pipefail

APK="${1:-}"
EXPECTED_CERT="${2:-}"
REPO="${3:-sc8z35a-collab/-APK-}"

if [ -z "$APK" ] || [ ! -f "$APK" ]; then
  echo "Usage: $0 <apk> <expected-cert-sha256> [owner/repo]" >&2
  exit 2
fi

APKSIGNER="${APKSIGNER:-}"
if [ -z "$APKSIGNER" ]; then
  APKSIGNER="$(command -v apksigner || true)"
fi
if [ -z "$APKSIGNER" ] && [ -n "${ANDROID_HOME:-}" ]; then
  APKSIGNER="$(find "$ANDROID_HOME/build-tools" -type f -name apksigner 2>/dev/null | sort -V | tail -n 1)"
fi
if [ -z "$APKSIGNER" ] || [ ! -x "$APKSIGNER" ]; then
  echo "apksigner is required (Android SDK Build Tools)." >&2
  exit 3
fi

VERIFY_OUT="$($APKSIGNER verify --verbose --print-certs "$APK")"
printf '%s\n' "$VERIFY_OUT"
printf '%s\n' "$VERIFY_OUT" | grep -Eq 'Verified using v2 scheme.*true'

ACTUAL="$(printf '%s\n' "$VERIFY_OUT" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f')"
EXPECTED="$(printf '%s' "$EXPECTED_CERT" | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f')"
if [ "${#EXPECTED}" -ne 64 ]; then
  echo "Expected certificate SHA-256 must be 64 hex characters." >&2
  exit 4
fi
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "SIGNING CERTIFICATE MISMATCH" >&2
  echo "expected=$EXPECTED" >&2
  echo "actual=$ACTUAL" >&2
  exit 5
fi

HASH="$(sha256sum "$APK" | awk '{print $1}')"
echo "APK_SHA256=$HASH"
echo "SIGNER_SHA256=$ACTUAL"

if command -v gh >/dev/null 2>&1; then
  gh attestation verify "$APK" --repo "$REPO"
else
  echo "gh CLI not installed: provenance verification was not performed." >&2
  exit 6
fi

echo "TRIPLE TRUST VERIFICATION: PASS"
