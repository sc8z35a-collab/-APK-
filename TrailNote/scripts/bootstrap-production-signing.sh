#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-trailnote-production.p12}"
ALIAS="${2:-trailnote-production}"

if ! command -v keytool >/dev/null 2>&1; then
  echo "keytool (JDK 17+) is required" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

if [ -e "$OUT" ]; then
  echo "Refusing to overwrite existing keystore: $OUT" >&2
  exit 1
fi

read -r -s -p "New production keystore password: " STORE_PASS
echo
read -r -s -p "Repeat password: " STORE_PASS_2
echo
if [ "$STORE_PASS" != "$STORE_PASS_2" ] || [ "${#STORE_PASS}" -lt 16 ]; then
  echo "Passwords must match and be at least 16 characters." >&2
  exit 1
fi

umask 077
keytool -genkeypair \
  -keystore "$OUT" \
  -storetype PKCS12 \
  -storepass "$STORE_PASS" \
  -keypass "$STORE_PASS" \
  -alias "$ALIAS" \
  -keyalg RSA \
  -keysize 4096 \
  -sigalg SHA256withRSA \
  -validity 36500 \
  -dname "CN=TrailNote Production,O=RST Lab,C=JP"

CERT_DER="$(mktemp)"
trap 'rm -f "$CERT_DER"' EXIT
keytool -exportcert -keystore "$OUT" -storetype PKCS12 -storepass "$STORE_PASS" -alias "$ALIAS" -file "$CERT_DER" >/dev/null
FINGERPRINT="$(sha256sum "$CERT_DER" | awk '{print $1}')"

cat <<EOF

Production signing identity created.

KEEP OFFLINE / BACKED UP:
  Keystore: $OUT
  Alias:    $ALIAS

PUBLIC TRUST PIN (safe to record):
  SHA-256:  $FINGERPRINT

Configure the protected GitHub Environment named:
  trailnote-production-signing

Environment secrets required:
  TRAILNOTE_SIGNING_KEYSTORE_B64      = base64 of $OUT
  TRAILNOTE_SIGNING_STORE_PASSWORD    = the password entered above
  TRAILNOTE_SIGNING_KEY_ALIAS         = $ALIAS
  TRAILNOTE_SIGNING_KEY_PASSWORD      = the same password for this PKCS12 file
  TRAILNOTE_TRUSTED_CERT_SHA256       = $FINGERPRINT

Recommended: require manual reviewers on that Environment and never use these
secrets in ordinary push jobs. The repository workflow is designed accordingly.
EOF

unset STORE_PASS STORE_PASS_2
