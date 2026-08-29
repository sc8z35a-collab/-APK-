# TrailNote v3 Operations Architecture

TrailNote 3.0 expands the application from an encrypted exploration log into an offline exploration and filming operations workspace.

## Product areas

The main application is organized into six operational surfaces:

1. **HOME / Command Center** — global counts, quick-create actions, unified workspace search, top filming target and production readiness.
2. **EXPLORE / Field Intelligence** — exploration spots and field logs. Spots store area, category, tags, coordinates memo, priority, visual strength, novelty, access and risk.
3. **PLAN / Production Planner** — shooting plans, missions and field gear readiness.
4. **MEDIA / Media Pipeline** — metadata registry for video/audio/photo/narration assets and a RAW → SELECT → EDIT → READY → PUBLISHED workflow.
5. **ANALYZE / Operations Analytics** — completion KPIs, category composition, ranked filming candidates and encrypted workspace scale.
6. **VAULT / Security Vault** — Security Container Plant state, PIN/session management, encrypted .tnvault backup and sanitized diagnostics.

## Encrypted workspace schema

`WorkspaceRepository` stores one authenticated JSON workspace inside the existing SecurityVault:

```text
schema: 3
logs: []
spots: []
plans: []
missions: []
assets: []
gear: []
```

Legacy TrailNote payloads that contain only the old JSON log array are migrated automatically into `logs` without discarding the existing records. The migrated v3 document is then written back through the same authenticated encrypted vault.

## Spot intelligence

`PriorityEngine` computes a 0–100 candidate score using independent signals:

- manual priority
- visual strength
- novelty
- access
- risk penalty
- already-filmed penalty
- favorite bonus
- active shooting-plan bonus
- whether media already exists for the spot

The Command Center and Analyze surfaces rank spots using this score so TrailNote can answer not only “what did I save?” but also “what should I film next?”.

## Production model

Shooting plans have a lightweight state machine:

`PLANNED → READY → DONE → PLANNED`

Media assets have a production pipeline:

`RAW → SELECT → EDIT → READY → PUBLISHED → RAW`

Missions carry explicit completion percentage and deadline/priority metadata. Gear items carry quantity and packed state. This allows the dashboard to derive plan completion, average mission progress, media publication ratio and loadout readiness.

## Security integration

No separate plaintext database was introduced. All new v3 objects pass through `SecurityVault` and therefore through:

- Security Container Plant policy checkpoints
- AES-256-GCM authenticated storage
- Android Keystore key wrapping
- optional PIN-derived second key boundary
- RASP / debugger / hook / tamper checks
- HMAC audit chain
- DistributionTrustPlant runtime distribution checks
- encrypted `.tnvault` export/import

The application also rejects obscured touch events at the Activity dispatch boundary and retains screenshot/overlay protection from Security Container Plant.

## Distribution

Version 3.0.0 uses versionCode 7. Diagnostic and production package/signing domains remain isolated. The trusted builder now emits an attested `TrailNote-3.0.0-diagnostic.apk` and the gated production path emits `TrailNote-3.0.0-production.apk` only when the protected production signing boundary is configured.
