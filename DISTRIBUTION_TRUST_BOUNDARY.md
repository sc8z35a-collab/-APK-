# TrailNote Triple Distribution Trust Boundary

TrailNote 2.1 separates distribution trust into three independent boundaries. A production APK is accepted only when all three boundaries agree.

## Boundary 1 — Production signing identity

Production uses the canonical package `com.rstlab.trailnote`. CI diagnostic builds are moved to `com.rstlab.trailnote.diagnostic` (and debug to `.debug`) so a test/debug signing identity cannot be confused with the production update lineage.

The Gradle `release` build is fail-closed. It refuses to build unless all of the following are present:

- `TRAILNOTE_SIGNING_STORE_FILE`
- `TRAILNOTE_SIGNING_STORE_PASSWORD`
- `TRAILNOTE_SIGNING_KEY_ALIAS`
- `TRAILNOTE_SIGNING_KEY_PASSWORD`
- `TRAILNOTE_TRUSTED_CERT_SHA256` (exact 64-hex SHA-256 certificate fingerprint)

The private keystore is never committed. The production workflow expects it only from the protected GitHub Environment `trailnote-production-signing`. Configure required reviewers for that Environment so ordinary pushes cannot automatically access the signing identity.

The production APK embeds only the public signing-certificate SHA-256 pin. Runtime verification accepts a cryptographically valid Android signing-history lineage containing a configured pin, allowing future APK Signature Scheme v3 key rotation without accepting unrelated signers.

Use `TrailNote/scripts/bootstrap-production-signing.sh` offline to create a long-lived RSA-4096 PKCS12 identity and print its public SHA-256 trust pin.

## Boundary 2 — Build provenance and immutable inputs

The GitHub Actions path is split into a caller workflow and a reusable trusted builder. Third-party Actions are referenced by full 40-character commit SHA instead of mutable `@v4`/`@v5` tags. Checkout uses `persist-credentials: false`.

Every diagnostic artifact receives:

- SHA-256 manifest
- machine-readable trust JSON
- GitHub Artifact Attestation created through OIDC/Sigstore
- immediate `gh attestation verify` verification before upload

A gated production build additionally receives an attested production trust manifest containing:

- exact APK SHA-256
- exact Android signing-certificate SHA-256
- repository
- source commit
- workflow run ID
- production trust mode

The build verifies that Gradle did not mutate tracked source files. The production job rebuilds in a separate job after the diagnostic/lint job succeeds and is attached to the protected `trailnote-production-signing` Environment.

## Boundary 3 — On-device DistributionTrustPlant

Independent runtime code lives at:

`TrailNote/app/src/main/java/com/rstlab/trailnote/securityplant/distribution/DistributionTrustPlant.java`

Production mode performs fail-closed checks before Security Container Plant allows protected data operations:

1. Canonical package identity must match.
2. `FLAG_DEBUGGABLE` must not be present.
3. Current Android signer / verified signing-history lineage must contain the compiled production certificate pin.
4. The installed APK bytes are SHA-256 hashed.
5. Highest observed versionCode, APK hash and signer are stored as a state tuple protected by a separate Android Keystore HMAC-SHA256 key.
6. A lower versionCode is treated as rollback.
7. A different APK hash with the same versionCode is treated as binary substitution.
8. A previous signer disappearing from the Android-verified signing lineage is treated as a rotation-lineage break.
9. Tampering with the sealed distribution-state preferences is detected by the Keystore HMAC.
10. Critical distribution failures zeroize the Security Container Plant session key and block protected reads/writes/authentication operations.

The existing ThreatScanner and TamperLedger remain independent, so DistributionTrustPlant does not replace RASP, anti-debugging, hook detection, root/environment signals, APK baseline checks or the HMAC audit chain. It is an additional trust plane.

## Production release procedure

1. Generate and back up the production signing key offline.
2. Put the five signing values in the protected GitHub Environment `trailnote-production-signing`; require reviewers.
3. Run `TrailNote Android Trust Pipeline` with `production=true` from the intended source commit.
4. Download `TrailNote-v2.1-production-triple-trust`.
5. Verify the APK with `TrailNote/scripts/verify-trusted-apk.sh <apk> <cert-sha256>`.
6. Publish the APK together with `SHA256SUMS-production.txt` and `production-trust.json`.
7. Consumers should verify both the Android signer and GitHub attestation before installing.

## Security boundary limitations

This design greatly raises the cost of repository compromise, artifact substitution, accidental debug-key distribution, local rollback, same-version binary replacement and ordinary repackaging. It is still not mathematically unbreakable: a fully controlled kernel/OS, theft of the production private signing key, compromise of an approved production-signing environment, or sufficiently powerful runtime instrumentation can defeat client-side controls. Production signing secrets should therefore be kept outside source control, protected by environment approval, and ideally migrated to hardware/KMS-backed signing if distribution scale grows.
