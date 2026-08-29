# TrailNote v4 Security Architecture

TrailNote 4.0.0 introduces five major trust-boundary upgrades while keeping the application offline and preserving migration from existing encrypted workspace formats.

## 1. StrongBox-first hardware root

`CryptoPlant` now creates a new Android Keystore AES-256 root alias dedicated to v4. On Android 9+ it first requests StrongBox with `setIsStrongBoxBacked(true)`. If the device cannot provide the requested StrongBox key, the implementation falls back to the normal Android Keystore, which is commonly TEE-backed when hardware support exists.

The previous `trailnote.vault.aes.v1` alias is retained only so older encrypted material can still be decrypted during migration. New v4 material uses `trailnote.vault.aes.v2.hardware`.

Diagnostics expose the requested root mode and whether Android reports the key as inside secure hardware. A software-backed Keystore fallback is treated as a Guard Mesh warning rather than silently claiming hardware protection.

## 2. Non-exportable production APK signing

The old CI design accepted a base64-encoded production keystore. v4 removes that production path.

Gradle now emits an unsigned release APK and refuses release preparation unless `TRAILNOTE_HSM_SIGNING=1` and a pinned production signing-certificate SHA-256 are present. Supplying a file-keystore path is explicitly rejected.

The production workflow runs only on a self-hosted runner carrying the `trailnote-hsm` label and uses `security/sign-with-pkcs11-hsm.sh`. The script addresses the private key through a runner-configured PKCS#11 JCA provider using `--ks NONE --ks-type PKCS11`. No private-key file is created by the workflow. After signing, `apksigner` verifies the APK and compares the actual signer certificate against the pinned SHA-256 identity before provenance can be generated.

The HSM device/provider and its runner must be provisioned outside the repository. Until that exists, production signing intentionally remains unavailable/fail-closed; diagnostic builds continue to work.

## 3. Component Integrity Plant

`ComponentIntegrityPlant` forms an additional runtime integrity boundary independent from the whole-file APK hash. It separately fingerprints security-relevant APK ZIP entries:

- `classes.dex`, `classes2.dex`, etc.
- `AndroidManifest.xml`
- `resources.arsc`
- native `lib/*/*.so` entries

The canonical component map is sealed with a separate Android Keystore HMAC-SHA256 key. Same-version component substitution, rollback of the sealed version state, or modification of the sealed component baseline is surfaced independently.

For a production build, first-use trust is anchored by `DistributionTrustPlant`'s pinned signer identity. Component integrity is defense in depth; Android APK signatures and the existing whole-APK checks remain in place.

## 4. Five-guard Security Plant mesh

`GuardMesh` separates security evaluation into five independently evaluated surfaces:

1. **Crypto Guard** — hardware/Keystore root availability.
2. **Runtime Guard** — debugger, tracer, root, hook/instrumentation and related RASP evidence.
3. **Distribution Guard** — package/signing identity, anti-rollback and whole-APK distribution state.
4. **Storage Guard** — TamperLedger plus Component Integrity Plant and H4 migration state.
5. **UI Guard** — `FLAG_SECURE` and obscured-touch filtering.

The mesh performs cross-consistency checks in addition to the original `PlantPolicy`. Critical distribution/storage failures, multiple independent guard failures, or an extreme aggregate mesh score cause the root/session key to be zeroized and the protected operation to fail closed.

This does not make client-side code impossible to patch. It raises the cost of bypassing the security decision by requiring multiple independent checks to be neutralized consistently.

## 5. Three-tier key hierarchy and H4 storage

v4 replaces the single-workspace encryption boundary with a three-tier hierarchy:

```text
Hardware/PIN Root
    |
    +-- random 256-bit Workspace KEK
            |
            +-- Logs DEK
            +-- Spots DEK
            +-- Plans DEK
            +-- Missions DEK
            +-- Assets DEK
            +-- Gear DEK
```

Each domain DEK is random 256-bit key material and is wrapped independently by the Workspace KEK. The Workspace KEK is wrapped by the device-bound hardware root when no PIN is configured, or by the PIN-unwrapped session root when PIN protection is active.

The six domain arrays are encrypted separately with AES-256-GCM and domain-specific AAD inside the `H4.` hierarchy envelope. Root-level workspace metadata is separately authenticated/encrypted by the root boundary.

This provides cryptographic compartmentalization: disclosure of one domain DEK does not directly decrypt the other five domains. Root compromise still represents the highest-level compromise and can ultimately expose subordinate keys; the hierarchy is intended to reduce blast radius below that level and support future independent rotation.

## Migration

Existing data formats are not intentionally discarded:

- old direct Android-Keystore ciphertext
- `M2.` master-key payloads
- `M3.` Security Plant payloads
- v2/v3 PIN metadata
- v3 Security Plant encrypted backups

are accepted through the compatibility path. After successful authenticated decryption, workspace data is rewritten into H4. Older PIN root metadata is rewrapped into the v4 StrongBox/modern-Keystore boundary after the correct PIN unlocks it.

v4 encrypted backup exports use the v4 backup AAD and stronger PBKDF2 settings while retaining imports for previous supported backup formats.

## Deliberate limitations

- StrongBox is device dependent. A device may fall back to its normal Android Keystore; diagnostics report this instead of pretending StrongBox exists.
- HSM production signing cannot be proven by normal GitHub-hosted diagnostic CI because the non-exportable private key is intentionally absent there. The repository can verify the fail-closed boundary and the PKCS#11 signing path; an actual production signature requires the dedicated HSM runner.
- Component integrity uses a sealed per-version runtime baseline. Production first-use authenticity therefore depends on the pinned APK signing identity and Android's package signature verification.
- RASP and client-side integrity defenses are defense in depth and remain bypassable under sufficiently powerful OS/kernel or code-patching control.

## Version

TrailNote v4.0.0 uses `versionCode 10`. Diagnostic builds remain isolated under the diagnostic package/signing domain. Production remains unavailable unless the HSM signing boundary is explicitly requested and available.
