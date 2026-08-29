#!/usr/bin/env bash
set -euo pipefail

# TrailNote production signing boundary.
# The private key MUST remain inside an HSM exposed through a runner-configured
# PKCS#11 JCA provider. This script intentionally has no file-keystore fallback.

INPUT_APK="${1:?input unsigned APK required}"
OUTPUT_APK="${2:?output signed APK required}"
: "${HSM_PIN:?HSM_PIN is required}"
: "${HSM_KEY_ALIAS:?HSM_KEY_ALIAS is required}"
: "${TRAILNOTE_TRUSTED_CERT_SHA256:?TRAILNOTE_TRUSTED_CERT_SHA256 is required}"

if [[ -n "${TRAILNOTE_SIGNING_STORE_FILE:-}" ]]; then
  echo "ERROR: exportable file-keystore signing is forbidden." >&2
  exit 40
fi
if [[ ! -f "$INPUT_APK" ]]; then
  echo "ERROR: unsigned APK not found: $INPUT_APK" >&2
  exit 41
fi

NORMALIZED_CERT="$(printf '%s' "$TRAILNOTE_TRUSTED_CERT_SHA256" | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f')"
if [[ ${#NORMALIZED_CERT} -ne 64 ]]; then
  echo "ERROR: trusted production certificate fingerprint is invalid." >&2
  exit 42
fi

APKSIGNER="${APKSIGNER:-}"
if [[ -z "$APKSIGNER" ]]; then
  APKSIGNER="$(find "${ANDROID_HOME:?ANDROID_HOME is required}/build-tools" -type f -name apksigner | sort -V | tail -n 1)"
fi
if [[ ! -x "$APKSIGNER" ]]; then
  echo "ERROR: apksigner unavailable." >&2
  exit 43
fi

# The self-hosted runner must register the hardware token's PKCS#11 provider in
# its Java security configuration. --ks NONE/PKCS11 means the signing key is
# addressed in the token; no private-key file is materialized on disk.
rm -f "$OUTPUT_APK"
"$APKSIGNER" sign \
  --ks NONE \
  --ks-type PKCS11 \
  --ks-key-alias "$HSM_KEY_ALIAS" \
  --ks-pass env:HSM_PIN \
  --v1-signing-enabled false \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$OUTPUT_APK" \
  "$INPUT_APK"

VERIFY_OUT="$($APKSIGNER verify --verbose --print-certs "$OUTPUT_APK")"
printf '%s\n' "$VERIFY_OUT"
printf '%s\n' "$VERIFY_OUT" | grep -Eq 'Verified using v2 scheme.*true'
ACTUAL_CERT="$(printf '%s\n' "$VERIFY_OUT" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f')"
if [[ -z "$ACTUAL_CERT" || "$ACTUAL_CERT" != "$NORMALIZED_CERT" ]]; then
  rm -f "$OUTPUT_APK"
  echo "ERROR: HSM signer certificate did not match the pinned production identity." >&2
  exit 44
fi

printf 'HSM_SIGN_OK signer=%s apk=%s\n' "$ACTUAL_CERT" "$(sha256sum "$OUTPUT_APK" | awk '{print $1}')"
