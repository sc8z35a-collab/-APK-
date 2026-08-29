# TrailNote v3

TrailNote is an offline Android exploration and filming operations workspace protected by the Security Container Plant.

## v3.0 — Operations expansion

TrailNote is no longer only an exploration log. Version 3 adds a six-surface operational workspace:

- **Command Center** — global stats, top filming target, quick actions, unified search and production pulse.
- **Field Intelligence** — exploration spots + legacy/new field logs.
- **Production Planner** — shooting plans, missions and gear/loadout readiness.
- **Media Pipeline** — video/audio/photo/narration metadata through RAW → SELECT → EDIT → READY → PUBLISHED.
- **Operations Analytics** — readiness score, completion KPIs, category mix and Top 5 filming targets.
- **Security Vault** — PIN/session controls, encrypted backup and security diagnostics.

### Exploration spots

Each spot can store:

- name / area / category / tags
- optional latitude/longitude memo
- priority 1–5
- visual strength 1–5
- novelty 1–5
- access 1–5
- risk 1–5
- favorite / filmed status
- field notes

The offline `PriorityEngine` combines these values with active plans and registered media to calculate a 0–100 filming candidate score.

### Production planning

Shooting plans include spot, date, priority, shot list, narration ideas and BGM mood. Their state advances through `PLANNED → READY → DONE`.

Missions include deadline, priority, completion conditions and 0–100% progress. Gear entries track quantity and packed state.

### Media operations

TrailNote stores media management metadata, not the media file itself. Assets can represent VIDEO, AUDIO, PHOTO, NARRATION or another user-defined type, with reference memo, spot, duration, notes and pipeline stage.

## Encrypted v3 workspace

All product data is stored as one authenticated workspace document with schema 3:

- logs
- spots
- plans
- missions
- assets
- gear

Old TrailNote log-array payloads are automatically migrated into `logs` and re-saved through the encrypted vault. No new plaintext app database is introduced.

## Security

The existing security stack remains active around the larger application:

- AES-256-GCM authenticated workspace storage
- Android Keystore key wrapping
- PIN-derived second key boundary
- PBKDF2-HMAC-SHA256 PIN/backup derivation
- in-memory master-key zeroization
- PIN failure lockout and background auto-lock
- screenshot/recording protection and Android 12+ overlay hiding
- obscured-touch rejection
- ThreatScanner RASP signals for debugger, TracerPid, hook/instrumentation/root/integrity anomalies
- Keystore-backed HMAC tamper ledger
- DistributionTrustPlant signing lineage, APK integrity and rollback/substitution checks
- fail-closed production signing gate
- SHA-256 manifests and GitHub/Sigstore artifact attestations

See `SECURITY_CONTAINER_PLANT.md`, `DISTRIBUTION_TRUST_BOUNDARY.md`, and `TRAILNOTE_V3_ARCHITECTURE.md`.

## Privacy / permissions

- no INTERNET permission
- no location permission
- no background service
- no server account
- `allowBackup=false`
- `usesCleartextTraffic=false`

Coordinates are optional manual memos in v3; the app does not request device GPS permission.

## Android

- canonical production applicationId: `com.rstlab.trailnote`
- diagnostic applicationId: `com.rstlab.trailnote.diagnostic`
- debug applicationId: `com.rstlab.trailnote.debug`
- minSdk 26
- targetSdk 35
- compileSdk 35
- Java 17
- Android Gradle Plugin 8.7.3
- versionCode 7
- versionName 3.0.0

## Trusted builds

Ordinary branch CI verifies that the production signing gate fails closed, then builds the isolated diagnostic package, runs lint/R8, creates SHA-256 trust metadata, produces a GitHub/Sigstore Artifact Attestation and immediately verifies that attestation before artifact upload.

The production job is opt-in and protected by the `trailnote-production-signing` GitHub Environment. It cannot produce the canonical production package unless dedicated signing secrets and the pinned certificate SHA-256 identity are present.
