# TrailNote Adaptive Operations Core

TrailNote 3.5 adds a deterministic offline input-response layer under:

`TrailNote/app/src/main/java/com/rstlab/trailnote/workspace/adaptive/`

The goal is to make the workspace react to what the user writes instead of behaving like a passive database.

## Architecture

1. **AdaptiveRulebook** — Japanese/English keyword semantics for location categories, weather/time, filming intent, transport, hazards, access restrictions, production mood and field gear.
2. **AdaptiveOperationsCore** — applies the rulebook to Spots, Logs, Plans, Missions, Assets and Gear. It enriches the input, resolves links and creates high-confidence follow-up operations.
3. **WorkspaceRepository integration** — every create/update path re-runs the adaptive layer before the encrypted workspace is committed through SecurityVault.
4. **PriorityEngine integration** — semantic opportunity bonuses and safety/restriction penalties directly influence filming candidate ranking.

No network inference is used and no INTERNET permission is introduced. The behavior remains available offline and the entire result is stored inside the encrypted Security Container Plant workspace.

## Example

Input:

`夜の山間の旧道を自転車で撮影したい。崖あり、圏外。夕方も良さそう。`

Possible automatic response:

- category → `廃道・道路`
- tags → `夜間, 自転車, 夕景, 撮影候補`
- risk raised due to cliff / no-signal evidence
- access adjusted when difficult access evidence exists
- recommended time inferred
- adaptive opportunity / risk penalty attached
- tailored shooting plan generated when filming intent confidence is high
- safety/scouting mission generated for high-risk conditions
- headlight, spare light, mobile battery, first-aid/water and cycling-related field gear inserted if not already present
- candidate ranking recalculated using the adaptive fields

## Cross-object behavior

### Spots

The engine can infer or update:

- category
- semantic tags
- risk
- access
- visual value
- novelty
- priority command overrides
- recommended shooting time
- adaptive opportunity bonus
- adaptive risk penalty
- restricted-access state

High-confidence input can create shooting plans, scouting/safety missions and required gear.

### Exploration logs

The engine can:

- extract condition tags
- detect explicit “filmed” wording
- synchronize a linked spot to filmed state
- create a revisit/follow-up mission when the note says footage/information is missing or another visit is needed

### Shooting plans

The engine resolves a typed spot name to a Spot ID when possible. Generic/default text can be replaced with context-specific:

- shot list
- narration structure
- BGM direction
- recommended field gear

When a linked plan becomes `DONE`, the linked Spot can synchronize to filmed state.

### Media assets

The engine can infer media type from explicit filename extensions/text and infer production stage from phrases such as selected, editing, ready or published. A published linked asset can synchronize the Spot to filmed state.

### Missions

Input commands can raise urgency or mark a mission complete.

### Gear

Gear is automatically grouped into CAMERA / AUDIO / POWER / LIGHT / SAFETY / OTHER categories.

## Input commands

The command words are optional. Natural-language inference still works.

- `#manual` or `自動化しない` — do not run automatic changes for that input.
- `#auto` / `#autopilot` — force the full high-confidence automation path.
- `#plan` — force creation of a shooting plan when safe to do so.
- `#scout` — force a scouting mission.
- `#urgent` — raise relevant priority to the highest level.
- `#done` / `[done]` — explicit mission completion command.

## Safety response

The engine does not treat every discovered place as a recommendation.

Signals such as cliffs, collapse, dangerous wildlife, flooding, difficult footing, no signal and dark/cave conditions raise risk and can create safety missions/gear.

`立入禁止`, `進入禁止`, `私有地`, `封鎖` or equivalent restriction signals set a restricted-access state unless the same text contains a clear permission signal such as `許可済み`. Restricted spots are capped to a very low PriorityEngine score and an automatic permission/legality verification mission can be created instead of a filming plan.

## Duplication control

Generated plans and missions carry:

- `adaptiveGenerated`
- `adaptiveSourceId`
- `adaptiveSourceType`
- `adaptiveKey`

The core checks those keys before generating a duplicate. Gear names are globally de-duplicated. Deleting a source item also removes auto-generated child plans/missions tied only to that source; manually created data is not cascaded.

## Existing data

On first load with a newer Adaptive Operations Core version, existing workspace records are re-analyzed in enrichment-only mode. This avoids suddenly creating large numbers of plans/missions during an upgrade while still adding derived metadata to existing records. New user mutations run the normal automatic-response path.

## Security

Adaptive output never bypasses the security layer. The resulting workspace JSON is persisted only through SecurityVault, which routes to Security Container Plant, encryption, runtime threat policy, tamper ledger and DistributionTrustPlant.

Version 3.5.0 uses application versionCode 8 and Adaptive Operations Core 1.0.0.
