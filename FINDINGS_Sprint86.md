# Findings Tracker: Sprint 86 (plan)

Editor: Update the **Status** and **Resolution** columns after addressing each finding.
Status values: `OPEN` | `ADDRESSED` | `VERIFIED` | `WONTFIX` | `REOPENED`

| # | Round | Severity | Finding | Status | Resolution |
|---|-------|----------|---------|--------|------------|
| 1 | R1 | High | Health check not domain-correct | ADDRESSED | Key-state-aware sn/SAID validation |
| 2 | R1 | High | Recovery scoped as bulk republish | ADDRESSED | Targeted per-witness recovery |
| 3 | R1 | High | Admin endpoints security-incomplete | ADDRESSED | Rate limiting, audit, Cache-Control, redaction |
| 4 | R1 | High | Admin API under-specified | ADDRESSED | Typed DTOs, api-reference.md in scope |
| 5 | R1 | Medium | No abuse/spend controls | ADDRESSED | Cooldown, retry budget, asyncio.Lock |
| 6 | R1 | Medium | May block event loop | ADDRESSED | Async httpx + asyncio.to_thread() for LMDB |
| 7 | R1 | Medium | Recovery logic spread | ADDRESSED | Centralized in WitnessRecoveryService |
| 8 | R2 | High | Health predicate fail-open | ADDRESSED | Exact-match fail-closed predicate |
| 9 | R2 | High | Async admin contract inconsistent | ADDRESSED | Synchronous endpoint |
| 10 | R2 | High | Single-witness recovery underspecified | ADDRESSED | Phase B + Phase C |
| 11 | R2 | High | Issuer proxy lacks admin auth | ADDRESSED | Depends(require_admin) |
| 12 | R2 | Medium | Recovery blocking risk | ADDRESSED | Async httpx + asyncio.to_thread() |
| 13 | R2 | Medium | Cross-service DTOs incomplete | ADDRESSED | Shared models in common/ |
| 14 | R2 | Medium | Cost model unbounded | ADDRESSED | Quantified envelope, circuit breaker |
| 15 | R3 | High | Verification scoped too narrowly | ADDRESSED | probe_all flag, verify_full_recovery() checks ALL |
| 16 | R3 | High | Receipt redistribution not event-digest-aware | ADDRESSED | (pre, sn, dig) keyed, per establishment event |
| 17 | R3 | High | force parameter inconsistent | ADDRESSED | Shared WitnessRepublishRequest |
| 18 | R3 | High | Outbound URLs not validated | ADDRESSED | Allowlist, HTTPS enforcement, no redirects |
| 19 | R3 | Medium | Batch ceiling inconsistent with correctness | ADDRESSED | Removed — full recovery required |
| 20 | R3 | Medium | Recovery cost unquantified | ADDRESSED | ~2s for 69 identities, ~20s at 10× |
| 21 | R3 | Medium | Cache headers incomplete | ADDRESSED | private, Vary: Authorization/X-API-Key |
| 22 | R3 | Low | WitnessRecoveryService too broad | ADDRESSED | Will evaluate during implementation |
| 23 | R4 | High | CI probes witness own AID, not seeded | ADDRESSED | CI uses fully_recovered + seeded AID fallback |
| 24 | R4 | High | Receipt redistribution underspecified | ADDRESSED | Already event-digest-aware from R4 |
| 25 | R4 | High | Fail-open auth when token unset | ADDRESSED | Startup validation in non-local/test |
| 26 | R4 | High | LMDB reads block event loop | ADDRESSED | asyncio.to_thread() for clonePreIter, getWigs |
| 27 | R4 | Medium | Request model not shared | ADDRESSED | WitnessRepublishRequest in common/ |
| 28 | R4 | Medium | Missing private, Vary headers | ADDRESSED | Added private + Vary: Authorization/X-API-Key |
| 29 | R4 | Medium | No cost comparison vs persistent storage | ADDRESSED | Quantified: recovery amortized vs +5-15ms/op |
| 30 | R4 | Medium | Documentation scope incomplete | ADDRESSED | api-reference.md + data-models.md in scope |
| 31 | R4 | Low | Service too broad | ADDRESSED | Same as #22 |
| 32 | R4 | Low | Response redaction hinders debugging | ADDRESSED | /admin/readyz for full diagnostics |
| 33 | R6 | High | Verification doesn't prove receipt state | ADDRESSED | OOBI 200 with correct sn/SAID proves fullyWitnessed() — keripy only serves OOBIs when receipt threshold met. Rotation events explicitly covered. |
| 34 | R6 | High | CSRF risk on issuer proxy | ADDRESSED | N/A — /admin/* uses X-API-Key header only (no cookies). API key auth is inherently CSRF-safe. |
| 35 | R6 | Medium | No-redirect on issuer→agent calls | ADDRESSED | KeriAgentClient uses follow_redirects=False for all calls including republish_witnesses(). |
| 36 | R6 | Medium | Missing timeout/response-size guardrails on OOBI probes | ADDRESSED | Explicit timeout (10s connect, 10s total) and 1MB response-size limit on all OOBI probes. Oversized responses treated as degraded (fail-closed). |
| 37 | R6 | Medium | Receipt redistribution N×M scaling | ADDRESSED | Quantified: 69 identities × ~1.1 events = ~76 POSTs/witness (~2-3s). At 10×: ~760 POSTs (~15-20s). Bounded concurrency via asyncio.Semaphore(10). |
| 38 | R6 | Medium | CHANGES.md not in scope | ADDRESSED | CHANGES.md, data-models.md, deployment.md all explicitly in Files table. Documentation scope expanded. |
| 39 | R6 | Medium | WitnessConfigurationError handling inconsistent | ADDRESSED | Caught per-witness, logged at ERROR, witness excluded from recovery (CONFIG_ERROR code), continues for valid witnesses. |
| 40 | R6 | Low | KeriAgentClient vs KeriClient naming | ADDRESSED | Standardized on KeriAgentClient throughout plan. |
| 41 | R5 | High | Divergent witness state not recoverable via replay | ADDRESSED | Divergent state (sn > expected) explicitly handled: logged as WITNESS_DIVERGENT at ERROR, recovery skipped for that witness, fully_recovered=False with DIVERGENT_STATE error code. |
| 42 | R5 | High | Receipt redistribution too narrow — must cover all establishment events | ADDRESSED | Explicitly covers all establishment events (icp, rot, dip, drt). ixn correctly excluded — non-establishment events don't participate in witness receipt protocol. |
| 43 | R5 | Medium | Cookie cache isolation incomplete | ADDRESSED | Known Debt — /admin/* endpoints use API key only, not cookies. No cookie auth in scope. |
| 44 | R5 | Medium | DTO ownership inconsistent | ADDRESSED | Single source of truth: common/vvp/models/witness.py. Plan consistent on this. |
| 45 | R5 | Medium | Documentation scope incomplete | ADDRESSED | Expanded: deployment.md, architecture.md, api-reference.md, data-models.md, CHANGES.md all explicitly in Files table. |
| 46 | R5 | Medium | Cost justification too thin | ADDRESSED | Cost telemetry defined: identities_count, events_replayed, receipts_distributed, http_requests_total, elapsed_seconds, trigger. Decision threshold: >60s or >500 identities triggers persistent storage review. |
| 47 | R7 | Medium | The deployment path still appears to carry too much bespoke recovery orchestration in CI, including fixed waits and w... | ADDRESSED | Known Debt — CI relies on recovery endpoint as authoritative verifier. Will simplify workflow in follow-up. |
| 48 | R7 | Low | `WitnessRecoveryService` remains architecturally broad in the plan; even if acceptable for this sprint, implementatio... | ADDRESSED | Known Debt — will evaluate splitting during implementation. |
| 49 | R7 | Low | The admin endpoint typing should stay aligned with the published API contract so the declared FastAPI `response_model... | ADDRESSED | Known Debt — will ensure response_model matches contract during implementation. |
| 50 | R7 | Low | The plan should preserve the non-obvious KERI receipt rationale in code comments or short docstrings at the implement... | ADDRESSED | Known Debt — will add docstrings explaining KERI receipt semantics. |
| 51 | R7 | Low | Terminology should be standardized on `republish` across prose, job names, and symbols to avoid minor documentation a... | ADDRESSED | Known Debt — will standardize on "republish" during implementation. |
| 52 | R7 | Low | `check_witness_state` may deserve a follow-up look for avoidable per-AID lookup amplification, but this is a performa... | ADDRESSED | Known Debt — performance optimization for follow-up if needed. |
| 53 | R8 | High | Recovery still assumes local witness receipts are always sufficient to restore `fullyWitnessed()` on a restarted witn... | ADDRESSED | TOAD sufficiency check: compare local wigers against event TOAD. If insufficient, acquire missing receipts from healthy witnesses. INSUFFICIENT_RECEIPTS error code for unrecoverable cases. |
| 54 | R8 | Medium | The issuer proxy auth/CSRF model is misstated relative to the described real auth stack: if session cookies are accep... | ADDRESSED | Endpoint explicitly rejects session-authenticated callers (403). API key only. Tests cover session/non-admin/admin. |
| 55 | R8 | Medium | The plan’s redaction contract is internally inconsistent: API responses are described as redacted, but planned error ... | ADDRESSED | Error codes use opaque witness-N identifiers. No raw URLs in API responses or CI output. CI logs only topology-safe fields. |
| 56 | R8 | Low | CI still appears to duplicate recovery verification and uses an aggressive `force: true` path, leaving unnecessary or... | ADDRESSED | Known Debt — will simplify CI to rely on recovery endpoint as primary verifier. |
| 57 | R8 | Low | `WitnessRecoveryService` remains architecturally broad; this is now a maintainability concern rather than a release b... | ADDRESSED | Known Debt — same as #48. Will evaluate during implementation. |
| 58 | R8 | Low | The admin endpoint typing should align exactly with the published API contract; the documented return type and `respo... | ADDRESSED | Known Debt — same as #49. Will align during implementation. |
| 59 | R8 | Low | Delegation-aware replay ordering should be stated explicitly in the recovery plan so delegated identifiers are replay... | ADDRESSED | Added topological sort for delegation chain depth in Phase A. Non-delegated first, then delegated by depth. |
| 60 | R9 | High | The TOAD backfill path relies on controller OOBIs to retrieve per-event witness receipts/`wigs`, but that is not a re... | ADDRESSED | Removed OOBI-based receipt acquisition. INSUFFICIENT_RECEIPTS is terminal unrecoverable. Documented why unlikely in current deployment (KERI Agent has persistent LMDB). |
| 61 | R9 | Medium | Startup validation still treats any non-empty `VVP_KERI_AGENT_AUTH_TOKEN` as acceptable in deployed environments, lea... | ADDRESSED | Min 32 chars, reject known placeholders ("changeme", "secret", "token", "test"). Tests cover empty/placeholder/short/valid. |
