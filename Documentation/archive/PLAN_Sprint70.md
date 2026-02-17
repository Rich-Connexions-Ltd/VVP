# Sprint 70: Automatic Witness Re-Publishing on Startup

## Problem Statement

After Sprint 69 made KERI Agent LMDB ephemeral, and the subsequent witness ephemeral storage fix, the system has a gap: after a full redeploy, witnesses start with fresh LMDB and don't know about previously-created identities. OOBI resolution for existing identities fails until someone manually re-bootstraps.

This breaks the promise of ephemeral storage: the system should be fully self-healing after any redeploy without manual intervention.

## Spec References

- Sprint 69 Technical Notes (line 5367): *"Witness publishing — On rebuild, the KERI Agent re-publishes KEL events to witnesses."* — described but never implemented.

## Current State

```
KERI Agent startup sequence:
  1. init_database()             # Create seed tables if missing
  2. get_identity_manager()      # Initialize Habery with PG salt
  3. get_registry_manager()      # Initialize Regery
  4. get_credential_issuer()     # Initialize issuer
  5. StateBuilder.rebuild()      # Reconstruct identities/registries/credentials
  6. MockVLEI.initialize()       # Initialize mock vLEI chain
  7. Ready to serve              # ← BUT witnesses don't have identity events
```

After step 5, the KERI Agent has full local state in LMDB. But witnesses have fresh ephemeral LMDB with only their own inception events. External OOBI resolution for the KERI Agent's identities fails.

## Proposed Solution

### Approach

Add a final phase to `StateBuilder.rebuild()` that publishes all rebuilt identity KELs to witnesses. This uses existing infrastructure:
- `IssuerIdentityManager.get_kel_bytes(aid)` — serialize KEL for an identity
- `WitnessPublisher.publish_oobi(aid, kel_bytes)` — two-phase publish to witnesses

This is the minimal, focused change. No new services, no new endpoints, no new dependencies.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Explicit API endpoint called by CI/CD | Separation of concerns | Requires CI/CD change, manual step | Defeats self-healing goal |
| Witness-side pull from KERI Agent | Witnesses self-heal | Major witness code change, keripy modification | Over-engineered for our use case |
| StateBuilder publish (chosen) | Minimal code, uses existing infra | Adds startup time | Acceptable trade-off (~1-2s per identity) |

### Detailed Design

#### Component 1: `_publish_to_witnesses()` in StateBuilder

- **Purpose**: After rebuilding all identities, publish their KELs to witnesses
- **Location**: `services/keri-agent/app/keri/state_builder.py`
- **Interface**: `async def _publish_to_witnesses(self, report: RebuildReport) -> int`
- **Behavior**:
  1. Iterate over in-memory `identity_mgr.hby.habs` collection (already populated by earlier rebuild phases)
  2. Filter to habs that have witnesses configured (`hab.kever.wits` is non-empty), skipping internal identities like the Habery's signator
  3. For each identity with witnesses, prepare a publish coroutine:
     a. Serialize KEL: `identity_mgr.get_kel_bytes(hab.pre)`
     b. Publish: `publisher.publish_oobi(hab.pre, kel_bytes)`
  4. Execute all publish coroutines concurrently via `asyncio.gather(*tasks, return_exceptions=True)` to avoid N * timeout_seconds worst-case
  5. Collect results, log successes/failures per identity
  6. Return count of successfully published identities

- **Error handling**: Log failures but continue — witnesses may still be starting up. Do not fail the rebuild or prevent the KERI Agent from starting.

#### Component 2: RebuildReport extension

- **Purpose**: Track witness publishing statistics in the rebuild report
- **Location**: Same file, `RebuildReport` dataclass
- **Changes**:
  - Add `witnesses_published: int = 0` field
  - Add `witness_publish_seconds: float = 0.0` field
  - Update `__str__` to include witness publishing stats

#### Component 3: Startup integration

- **Purpose**: Wire the new phase into the existing startup sequence
- **Location**: `services/keri-agent/app/keri/state_builder.py` — `rebuild()` method
- **Changes**: Add `self._publish_to_witnesses(report)` call after `_verify_state()`

### Data Flow

```
StateBuilder.rebuild()
  ├── _rebuild_identities()      # Replay makeHab() from PG seeds
  ├── _replay_rotations()        # Replay rotate() calls
  ├── _rebuild_registries()      # Replay makeRegistry() calls
  ├── _rebuild_credentials()     # Replay issue_credential() calls
  ├── _verify_state()            # Verify AIDs/SAIDs match expected
  └── _publish_to_witnesses()    # NEW: Publish KELs to witnesses
       ├── Iterate hby.habs (in-memory, no DB lookup)
       ├── Filter: hab.kever.wits is non-empty
       ├── Prepare tasks: [get_kel_bytes + publish_oobi for each]
       ├── asyncio.gather(*tasks)  # Concurrent, not sequential
       └── Log results (X/Y published, Z.Zs)
```

### Error Handling

- **Witness unreachable**: Log warning, continue to next identity. The KERI Agent must start even if witnesses are offline.
- **Timeout**: Use the configured `WITNESS_TIMEOUT_SECONDS` (default 10s). Log timeout and continue.
- **Partial publish**: Log which witnesses succeeded/failed. The threshold check is informational during startup, not enforced.
- **No witnesses configured**: Skip the phase entirely (e.g., local development without witnesses).

### Test Strategy

1. **Unit test**: Mock `WitnessPublisher` and verify `_publish_to_witnesses()` calls `publish_oobi()` for each identity with witnesses
2. **Unit test**: Verify identities without `witness_aids` are skipped
3. **Unit test**: Verify witness failures don't prevent startup
4. **Unit test**: Verify `RebuildReport` includes witness stats
5. **Integration test**: Full rebuild round-trip with mocked HTTP witnesses

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/keri-agent/app/keri/state_builder.py` | Modify | Add `_publish_to_witnesses()` phase, extend `RebuildReport` |
| `services/keri-agent/tests/test_state_builder.py` | Modify | Add tests for witness publishing phase |
| `knowledge/architecture.md` | Modify | Document self-healing startup flow |
| `knowledge/deployment.md` | Modify | Document witness re-publishing |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Startup time increases | Medium | Low | ~1-2s per identity for witness publish. Publish in parallel. |
| Witnesses not ready during KERI Agent startup | Medium | Low | Log and continue — witnesses will be populated on first use |
| Witness publish timeout slows startup | Low | Medium | Use configured timeout (10s default), publish concurrently |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-02-17 | Initial draft |
| R2 | 2026-02-17 | Per Gemini R2: (1) Use concurrent asyncio.gather for publishing instead of sequential loop, (2) iterate in-memory hby.habs instead of seed_store DB lookups |

---

## Implementation Notes

### Deviations from Plan

1. **Seed-based identity filtering instead of pure hby.habs iteration**: The plan specified iterating `hby.habs` and skipping the signator. In practice, the Habery's signator identity also has default witnesses configured, making it hard to distinguish by properties alone. Instead, we filter `hby.habs` by checking if the AID exists in the seed store's identity seeds. This is a lightweight DB query and ensures only VVP-created identities are published.

2. **Inception-only publishing (not full KEL)**: The plan assumed sending the full KEL bytes to witnesses. In practice, the witness's `parseOne` with `framed=True` gets confused by subsequent interaction/rotation events after the inception event's controller signature. Fixed by adding `get_inception_msg()` to only send the inception event (fn=0), which is the minimum needed for witness receipting and OOBI resolution.

3. **Receipt distribution via POST CESR+JSON (not PUT raw CESR)**: The plan's Phase 2 (distributing receipts between witnesses) used PUT to the witness root URL. Azure Container Apps proxy returns 502 on PUT requests. Fixed by POSTing each receipt individually in CESR+JSON format (JSON body + CESR-ATTACHMENT header), which the witness's `HttpEnd.on_post` handler accepts.

### Bug Fixes During Deploy Verification

Two bugs were discovered and fixed during deployment verification:

1. **Witness escrow (HTTP 202 instead of 200)**: When sending the full KEL (inception + interactions), the witness parser's `framed=True` mode couldn't parse the extra event bytes after the first event's CESR attachments. The parser raised a `ValidationError` (caught and swallowed by `onceParsator`), preventing kever creation. Root cause: `cloneEvtMsg` returns individual events but `get_kel_bytes` concatenates them all. Fix: Added `get_inception_msg()` to `identity.py` that returns only the inception event message.

2. **Receipt distribution 502 (OOBI still 404 after receipting)**: Each witness only had its own receipt (1 out of TOAD=2). The OOBI endpoint's `fullyWitnessed()` check requires TOAD witness receipts. Receipt distribution via PUT to `/` failed with 502 from Azure proxy. Fix: Changed to POST each receipt individually in CESR+JSON format to the witness's `/` endpoint.

### Test Results

131 tests pass (125 existing + 6 new witness publishing tests):
- `test_report_includes_witness_fields` — RebuildReport formatting
- `test_report_zero_witnesses` — RebuildReport defaults
- `test_publish_skips_identities_without_witnesses` — No-witness identity filter
- `test_publish_called_for_identities_with_witnesses` — Successful publish flow
- `test_publish_failure_does_not_block_startup` — Error resilience
- `test_publish_concurrent_multiple_identities` — Concurrent publish via asyncio.gather

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/keri-agent/app/keri/state_builder.py` | +75 | Added `_publish_to_witnesses()` phase, extended `RebuildReport` |
| `services/keri-agent/app/keri/identity.py` | +27 | Added `get_inception_msg()` for inception-only KEL extraction |
| `services/keri-agent/app/keri/witness.py` | +33/-19 | Fixed receipt distribution: POST CESR+JSON instead of PUT raw CESR |
| `services/keri-agent/tests/test_state_builder.py` | +150 | 6 new tests for witness publishing |
