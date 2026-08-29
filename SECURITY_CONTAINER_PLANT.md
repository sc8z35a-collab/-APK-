# Security Container Plant

TrailNote 2.0 introduces an independent security layer under:

`TrailNote/app/src/main/java/com/rstlab/trailnote/securityplant/`

The legacy `SecurityVault` class is now only a compatibility adapter. Sensitive data operations are routed through the plant gateway.

## Architecture

1. **SecurityContainerPlant** — orchestration/gateway. Applies runtime policy checkpoints before authentication, reads, writes, backup import/export and PIN changes. Hardens the Activity window with `FLAG_SECURE`, obscured-touch filtering and Android 12+ overlay hiding.
2. **CryptoPlant** — AES-256-GCM data container, Android Keystore key wrapping, PIN-derived wrapping, PBKDF2-HMAC-SHA256 verification, authenticated backup format, in-memory master-key zeroization and v1.3→v3 cryptographic migration.
3. **ThreatScanner** — RASP-style runtime signals: debugger attachment, `TracerPid`, unexpected debuggable state, root artifacts, test-key builds, SELinux enforcing state, emulator heuristics, `/proc/self/maps` hook/instrumentation indicators, Xposed/Substrate class probes, signing-certificate baseline and same-version APK-byte integrity baseline.
4. **PlantPolicy** — proportional risk scoring. Root/custom-ROM indicators alone do not automatically destroy usability; high-confidence debugger/hook/tamper combinations progressively restrict key mutation, backup and write operations. Critical integrity failures use fail-closed behavior.
5. **TamperLedger** — local HMAC-SHA256 chained audit events using a separate Android Keystore HMAC key. Event history includes previous-MAC chaining and bounded retention with an anchor MAC.

## Runtime response model

- `NORMAL`: regular operation.
- `GUARDED`: low-confidence environmental signals; all sensitive checkpoints remain active.
- `ELEVATED`: key/backup operations restricted.
- `HIGH`: protected data becomes read-only; writes and key/backup mutations are blocked.
- `CRITICAL`: protected operations are denied; session master key is zeroized; sanitized diagnostics remain available.

## Hardened build

The `hardened` Android build type is non-debuggable and enables R8 minification/obfuscation and resource shrinking. CI still creates a separate debug diagnostics artifact, but the hardened artifact is the preferred installable security build.

The CI hardened artifact currently uses Android's debug signing configuration solely so GitHub Actions can produce an installable APK without storing a private production signing key in the repository. A production deployment should use a private release signing key held outside source control.

## Compatibility

- Existing v1.3 Android Keystore alias is deliberately preserved so old ciphertext remains decryptable.
- Legacy v1.3 PIN metadata (PBKDF2 160k verifier / 220k wrapping) is accepted once and automatically re-wrapped with the stronger v3 KDF parameters after a successful unlock.
- Legacy `M2.` protected payloads are re-encrypted into the `M3.` container after successful unlock.
- Legacy encrypted backup envelopes remain importable; new exports use the Security Plant v3 envelope.

## Security limits

This is defense-in-depth, not a claim of being unhackable. A fully compromised/root-controlled OS, kernel-level attacker, patched application with control of the signing environment, or sufficiently capable dynamic instrumentation may bypass client-side protections. The goal is to reduce attack surface, detect common analysis/tampering conditions, protect keys and data at rest, and increase the effort required to bypass multiple independent controls.
