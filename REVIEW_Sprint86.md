## Plan Review: Sprint 86 - Witness State Resilience (R9)

**Round:** 9  
**Verdict:** CHANGES_REQUESTED  
**Review Method:** Council of Experts (7 reviewers + consolidator)

### Spec Compliance
The plan is largely aligned with the sprint goal: it centralizes witness recovery, keeps the admin contract typed, scopes deployment/docs updates, and adds operational guardrails. The remaining blocker is protocol correctness: the documented TOAD-repair fallback depends on a receipt source that does not reliably provide the per-event witness signatures needed to restore `fullyWitnessed()` state.

### Design Assessment
The overall direction is sound: targeted per-witness recovery, fail-closed health checks, shared DTOs, and explicit deployment hooks are all improvements over earlier rounds. The main design issue is that the receipt-repair path currently mixes a valid goal with an invalid retrieval mechanism. Most other comments at R9 are now maintainability, documentation, or hardening debt rather than release blockers.

### Findings
- **[High]** The TOAD backfill path relies on controller OOBIs to retrieve per-event witness receipts/`wigs`, but that is not a reliable KERI receipt export mechanism; if local LMDB lacks sufficient receipt material, the documented fallback cannot safely complete recovery. (File: `PLAN_Sprint86.md`, Location: `Component 1: WitnessRecoveryService -> TOAD sufficiency check`) (Source: Domain Expert, Cost Modeller)
- **[Medium]** Startup validation still treats any non-empty `VVP_KERI_AGENT_AUTH_TOKEN` as acceptable in deployed environments, leaving privileged admin access easy to misconfigure with placeholder or weak secrets. (File: `services/keri-agent/app/main.py`, Location: startup validation for `VVP_KERI_AGENT_AUTH_TOKEN`) (Source: Security Expert)

### Excluded Findings
- Same-sequence-number/different-SAID divergence handling — Reason: this appears to be a possible incomplete resolution of previously addressed health-predicate work, not a genuinely new R9 blocker under the escalation rule. It should be rechecked during editing, but is not re-blocked here. (Source: Domain Expert)
- `WitnessRecoveryService` breadth, startup coupling, and report-model sprawl — Reason: already tracked as maintainability debt in prior rounds; no new concrete defect was shown at R9. (Source: Code Simplicity Expert)
- Endpoint typing/docs/config-reference/terminology drift — Reason: documentation contract cleanup remains important, but these are prior known-debt items rather than new blockers. (Source: Documentation Expert)
- Fixed CI sleeps, unconditional forced republish after deploy, and log-ingestion cost growth — Reason: operational inefficiency and cost debt, but previously acknowledged and not blocking at R9. (Source: User Experience Expert, Cost Modeller)
- Missing explicit CORS regression tests and HSTS/header enforcement — Reason: valid hardening recommendations, but not shown as an immediate shipped vulnerability in the current plan text. (Source: Security Expert)

### Answers to Open Questions
No open questions.

### Required Changes (if CHANGES_REQUESTED)
1. **File**: `PLAN_Sprint86.md`  
   **Location**: `Component 1: WitnessRecoveryService -> TOAD sufficiency check`  
   **Current behavior**: The plan says that when local `wigers` are insufficient, recovery can query healthy witnesses via controller OOBIs, parse returned CESR, extract receipt material for `(sn, said)`, and use that to repair TOAD.  
   **Required change**: Remove controller OOBIs as the receipt-acquisition mechanism. Either constrain recovery to locally persisted receipt material only and fail with a documented unrecoverable outcome, or define a separate explicit receipt-retrieval interface that actually returns per-event witness indexed signatures for the target establishment event.  
   **Acceptance criteria**: The plan no longer claims controller OOBIs provide the needed receipt material; the fallback path is protocol-valid; `INSUFFICIENT_RECEIPTS` is documented as terminal unless a real receipt source exists.

2. **File**: `services/keri-agent/app/main.py`  
   **Location**: startup validation for `VVP_KERI_AGENT_AUTH_TOKEN`  
   **Current behavior**: Non-local/test startup rejects only an empty token.  
   **Required change**: Enforce minimum secret quality in deployed environments: reject known placeholder values and require a strong minimum length/entropy standard. Add tests covering empty, placeholder, and too-short tokens.  
   **Acceptance criteria**: Startup fails for weak/default tokens outside `local`/`test`; tests cover accepted and rejected cases; deployment docs state the strength requirement.

### Known Debt
- CI republish orchestration still appears more bespoke than necessary; replace fixed sleeps and unconditional `force=true` with a health-gated preflight when implementation settles.
- If any cross-witness receipt fetch is retained via a valid mechanism, add explicit performance/cost budgets for LMDB reads, request fan-out, bytes transferred, and cutoff behavior.
- Consolidate docs for endpoint typing, config variables/defaults, and the `WitnessRepublishResponse.error_codes` vocabulary in one authoritative reference.
- Standardize user-facing terminology on `republish` and reserve `recovery` for internal flow language.
- Add regression coverage proving the issuer admin endpoint remains outside CORS scope, and clarify whether HSTS/security headers are enforced in app code or at ingress.
- Recheck that same-`sn`/different-`said` is treated as divergent/duplicitous state, not as recoverable corruption.

### Recommendations
- Keep `WitnessRecoveryService` thin if implementation complexity grows; probing, replay, and policy are the natural split points.
- Prefer one internal recovery report plus one API projection to reduce mapping drift.
- Keep telemetry aggregated per recovery/per witness rather than per identity/event unless deeper detail is needed for debugging.

### Expert Concordance
| Area | Experts Agreeing | Key Theme |
|------|-----------------|-----------|
| Receipt repair semantics | Domain Expert, Cost Modeller, Performance Expert | The TOAD/receipt recovery path needs a valid and bounded source of receipt material |
| Deployment workflow | User Experience Expert, Cost Modeller | CI republish flow is still brittle and more expensive than necessary |
| Security hardening | Security Expert | Admin-plane protections need stronger secret validation and regression safeguards |
| Documentation clarity | Documentation Expert | Public contract, config, and error vocabulary should be documented in one consistent place |
| Maintainability | Code Simplicity Expert | Recovery logic is still broader and more coupled than ideal |