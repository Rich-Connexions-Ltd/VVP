# Sprint 62: Multichannel Vetter Constraints — End-to-End

## Problem Statement

The VVP ecosystem allows vetters to certify organizations' right to use telephone numbers, brand assets, and legal entity identities. However, there's currently no enforcement that a vetter is *authorized* to certify in a particular geographic region. A vetter certified only for France could issue a TN credential for a UK number (+44), and the system would accept it without question.

Sprint 40 built the verifier-side constraint validation. Sprint 61 built the issuer-side VetterCertification CRUD and mock GSMA identity. This sprint completes the chain: GSMA governance credential → VetterCert trust chain, issuer-side enforcement at issuance/dossier/signing time, SIP header propagation, and WebRTC client display.

## Spec References

- `Documentation/Specs/How To Constrain Multichannel Vetters.pdf` — normative spec
- SPRINTS.md Sprint 62 definition — full spec text embedded in sprint definition
- §5 Verification Algorithm: 3 constraint checks (Identity/Jurisdiction, TN/ECC, Brand/Jurisdiction)
- §6 Status Reporting: Status bits communicated as informational signals
- §8.4 Multiple enforcement points: verification (MUST), signing/dossier/issuance (SHOULD)

## Current State

### Already Complete (Sprint 40 + 61)

| Component | Sprint | Location |
|-----------|--------|----------|
| Verifier constraint validation (Phase 11) | 40 | `services/verifier/app/vvp/vetter/` |
| VetterConstraintInfo in VerifyResponse | 40 | `services/verifier/app/vvp/api_models.py:198` |
| Country code utilities (E.164 ↔ ISO 3166-1) | 40 | `services/verifier/app/vvp/vetter/country_codes.py` |
| VetterCert CRUD API | 61 | `services/issuer/app/api/vetter_certification.py` |
| VetterCert service layer | 61 | `services/issuer/app/vetter/service.py` |
| Mock GSMA identity + registry | 61 | `services/issuer/app/org/mock_vlei.py` |
| Certification edge auto-injection | 61 | `services/issuer/app/api/credential.py:75-128` |
| VetterCert schema (with optional `issuer` edge) | 40 | `services/issuer/app/schema/schemas/vetter-certification-credential.json` |
| Extended LE/Brand/TNAlloc schemas | 40 | `services/issuer/app/schema/schemas/extended-*.json` |
| SIP verify handler + X-VVP headers | 44 | `services/sip-verify/app/verify/handler.py` |
| WebRTC VVP display | 43 | `services/pbx/webrtc/vvp-phone/js/vvp-display.js` |
| Bootstrap VetterCert issuance | 61 | `scripts/bootstrap-issuer.py` |

### What's Missing (This Sprint)

1. **No GSMA governance credential** — VetterCerts lack `issuer` edge to a governance credential; trust chain incomplete
2. **No GSMA AID in verifier trusted roots** — verifier doesn't know to trust GSMA
3. **No issuance-time constraint validation** — credentials issued regardless of vetter authority scope
4. **No dossier-creation-time constraint validation** — dossier builder doesn't check constraints
5. **No signing-time constraint validation** — `/vvp/create` doesn't check constraints before signing
6. **No `X-VVP-Vetter-Status` SIP header** — verifier returns `vetter_constraints` in JSON but it's not propagated
7. **No WebRTC vetter badge display** — `vvp-display.js` has no UI for vetter constraint warnings
8. **No `ENFORCE_VETTER_CONSTRAINTS` config on issuer** — no configurable enforcement mode

## Proposed Solution

### Approach

Nine components across the full stack:

1. **GSMA Governance Credential** — Create a governance credential schema, issue from GSMA AID, add `issuer` edge to VetterCerts, register GSMA AID in verifier trusted roots
2. **Constraint Validator** — Reusable module with credential-level (edge-resolved) and org-level constraint checks
3. **Issuance-Time Enforcement** — Validate ECC/jurisdiction constraints before issuing extended credentials
4. **Dossier-Creation-Time Enforcement** — Resolve VetterCert from each credential's `certification` edge, validate constraints
5. **Signing-Time Enforcement** — Validate TN ECC AND dossier jurisdiction constraints before PASSporT creation
5b. **Verifier Callee Flow** — Port Phase 11 vetter constraint evaluation to `verify_callee.py` (enables SIP propagation)
6. **SIP Header Propagation** — Map verifier `vetter_constraints` → `X-VVP-Vetter-Status` header
7. **WebRTC Display** — Vetter constraint badge with amber/orange warning styling
8. **Issuer Config** — `ENFORCE_VETTER_CONSTRAINTS` + `ALLOW_CONSTRAINT_BYPASS` env vars
9. **GSMA Trusted-Root Rollout** — Deterministic GSMA AID configuration across environments

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Enforce only at verification time (verifier-side) | Simplest, already done | Late detection, wasted resources on mis-vetted calls | Spec says enforcement SHOULD happen at all points |
| Hard-fail only (no soft mode) | Simpler, no config | Breaking change for existing flows | Spec says these are status bits, not hard blocks |
| Org-level-only cert resolution everywhere | Simpler than edge-resolved | Doesn't handle mixed-vetter dossiers per spec | Spec requires per-credential certification edge |
| Skip governance credential | Less work | Violates Sprint 62 Phase 1/2 requirements | Must implement for sprint completion |

### Detailed Design

#### Component 1: GSMA Governance Credential + Trust Chain

**1a. GSMA governance credential schema** — `services/issuer/app/schema/schemas/gsma-governance-credential.json` (NEW)

Lightweight ACDC schema for the GSMA self-issued governance credential:

```json
{
  "$id": "<SAID computed at creation>",
  "title": "GSMA Governance Credential",
  "description": "Self-issued credential identifying GSMA as the vetter certification governance authority.",
  "credentialType": "GSMAGovernanceCredential",
  "properties": {
    "a": {
      "oneOf": [
        { "type": "string" },
        {
          "type": "object",
          "required": ["d", "i", "dt", "name", "role"],
          "properties": {
            "d": { "type": "string" },
            "i": { "type": "string", "description": "GSMA AID (self-referencing)" },
            "dt": { "type": "string", "format": "date-time" },
            "name": { "type": "string", "const": "GSMA" },
            "role": { "type": "string", "const": "Vetter Governance Authority" }
          }
        }
      ]
    }
  }
}
```

Register SAID in `common/common/vvp/schema/registry.py`.

**1b. Issue governance credential at bootstrap** — `scripts/bootstrap-issuer.py`

After creating the GSMA AID and registry (Sprint 61), issue a governance credential from the GSMA AID to itself (`a.i = gsma_aid`). Store the credential SAID in `MockVLEIState.gsma_governance_said`.

**1c. VetterCert `issuer` edge** — `services/issuer/app/org/mock_vlei.py`

When issuing VetterCertification credentials via `issue_vetter_certification()`, add the `issuer` edge pointing to the GSMA governance credential:

```python
edges = {
    "d": "",  # SAID placeholder
    "issuer": {
        "n": self.state.gsma_governance_said,
        "s": GSMA_GOVERNANCE_SCHEMA_SAID,
        "o": "I2I",
    }
}
```

The VetterCert schema already defines an optional `issuer` edge (lines 115-160 of the schema JSON). Adding it to issuance makes the trust chain explicit.

**1d. GSMA AID in verifier trusted roots** — `services/verifier/app/core/config.py`

Add the GSMA AID to `VVP_TRUSTED_ROOT_AIDS` default value for local dev. For production, the AID will be added to Azure Container App env vars via CI/CD (`deploy.yml`).

**Governance trust chain enforcement:** The existing verifier validates all ACDC credentials in the dossier via signature verification (phases 1-10). When the VetterCert is discovered via edge traversal in Phase 11, its `i` (issuer) field is the GSMA AID. Adding GSMA to `TRUSTED_ROOT_AIDS` means the verifier's general chain walker recognizes this AID as trusted. The `issuer` edge from VetterCert → governance credential provides additional provenance transparency (the governance credential proves GSMA's self-asserted role), but the fundamental trust mechanism in KERI is AID-based signature verification, not edge-based chain depth.

The verifier's Phase 11 vetter code (`services/verifier/app/vvp/vetter/traversal.py`) already validates that each VetterCert found via edge traversal is signed by a trusted AID. If the VetterCert issuer AID is NOT in `TRUSTED_ROOT_AIDS`, the constraint check returns `vetter_certification_said=None` and status `INDETERMINATE` — the governance chain is considered unresolved.

**1e. MockVLEIState schema update** — `services/issuer/app/db/models.py`

Add `gsma_governance_said` column (nullable VARCHAR(44)) to `MockVLEIState`. Create migration `services/issuer/app/db/migrations/sprint62_gsma_governance.py`.

**Migration wiring:** Update `services/issuer/app/db/session.py` `init_database()` function to execute Sprint 62 migrations alongside Sprint 61 migrations. Follow the existing pattern — `init_database()` calls migration functions in order.

**1f. Bootstrap backward compatibility** — `_bootstrap_gsma()` in `mock_vlei.py`

If `MockVLEIState` exists but `gsma_governance_said` is None (pre-Sprint 62 state), auto-issue the governance credential and populate the field. This mirrors the Sprint 61 pattern where GSMA AID was auto-created for pre-Sprint-61 state.

#### Component 2: Vetter Constraint Validator

**Location:** `services/issuer/app/vetter/constraints.py` (NEW)

Two layers of constraint evaluation:

**Layer 1: Pure constraint checks (no KERI dependency)**

```python
@dataclass
class ConstraintCheckResult:
    check_type: str           # "ecc" | "jurisdiction"
    credential_type: str      # "TN" | "Identity" | "Brand"
    target_value: str         # e.g., "44" or "GBR"
    allowed_values: list[str] # from VetterCert
    is_authorized: bool
    reason: str

def extract_ecc_from_tn(tn: str) -> str | None:
    """Extract E.164 country code from a phone number.
    Strip leading '+', longest-prefix match against VALID_ECC_CODES."""

def check_tn_ecc_constraint(tn: str, ecc_targets: list[str]) -> ConstraintCheckResult:
    """§5 check 8: TN country code in ecc_targets?"""

def check_jurisdiction_constraint(
    code: str, jurisdiction_targets: list[str], credential_type: str
) -> ConstraintCheckResult:
    """§5 checks 7 & 9: jurisdiction in jurisdiction_targets?"""
```

**Layer 2: Endpoint adapters (resolve context, call layer 1)**

```python
async def validate_issuance_constraints(
    schema_said: str,
    attributes: dict,
    org: Organization,
) -> list[ConstraintCheckResult]:
    """Issuance-time: resolve org's active VetterCert, check attribute values.

    Schema dispatch:
    - Extended TNAlloc: extract TN from attributes.numbers → check ECC
    - Extended LE: extract attributes.country → check jurisdiction
    - Extended Brand: extract attributes.assertionCountry → check jurisdiction
    Returns empty list if schema not extended or no active cert.
    """

async def validate_credential_edge_constraints(
    credential_said: str,
) -> list[ConstraintCheckResult]:
    """Credential-edge-level: resolve VetterCert from credential's 'certification' edge.

    1. Load credential from KERI store
    2. Extract 'certification' edge SAID
    3. Load VetterCert credential, parse ecc_targets and jurisdiction_targets
    4. Determine credential type from schema SAID
    5. Extract target value (TN/country/assertionCountry) from attributes
    6. Run appropriate constraint check
    """

async def validate_dossier_constraints(
    credential_saids: list[str],
) -> list[ConstraintCheckResult]:
    """Dossier-creation-time: for each credential in dossier, resolve
    VetterCert via its 'certification' edge and validate constraints.

    This is credential-edge-centric, not org-centric — preserving spec
    semantics for mixed-vetter dossiers.
    """

async def validate_signing_constraints(
    orig_tn: str,
    dossier_said: str,
) -> list[ConstraintCheckResult]:
    """Signing-time: resolve dossier's credential chain, check ALL constraints:
    - TN/ECC: orig_tn country code against each TN credential's VetterCert ECC targets
    - Identity/Jurisdiction: LE credential jurisdiction against VetterCert
    - Brand/Jurisdiction: Brand credential assertionCountry against VetterCert

    This walks the dossier to find all credentials with certification edges,
    then validates each one. NOT org-centric.
    """
```

Key design decision: **dossier and signing validation resolve constraints from credential edges**, not from the org's active VetterCert pointer. This handles the mixed-vetter scenario correctly (per spec §3-4: different credentials may chain to different VetterCerts from different vetters).

Issuance-time validation uses the org's active cert because the credential being issued hasn't been created yet and has no edge to resolve.

#### Component 3: Issuance-Time Enforcement

**Location:** `services/issuer/app/api/credential.py` — modify `issue_credential()`

After the existing certification edge injection (line 184), add constraint validation:

```python
# Sprint 62: Pre-issuance constraint validation
if schema_requires_certification_edge(request.schema_said) and resolved_org:
    from app.vetter.constraints import validate_issuance_constraints
    from app.config import ENFORCE_VETTER_CONSTRAINTS

    skip = getattr(request, "skip_vetter_constraints", False)
    violations = await validate_issuance_constraints(
        schema_said=request.schema_said,
        attributes=request.attributes,
        org=resolved_org,
    )
    failed = [v for v in violations if not v.is_authorized]
    if failed:
        detail = "; ".join(f"{v.credential_type} {v.check_type}: {v.reason}" for v in failed)
        if skip:
            log.info(f"Vetter constraint violation SKIPPED (per request): {detail}")
        elif ENFORCE_VETTER_CONSTRAINTS:
            raise HTTPException(status_code=403, detail=f"Vetter constraint violation: {detail}")
        else:
            log.warning(f"Vetter constraint warning (soft): {detail}")
```

**Per-request bypass:** Add `skip_vetter_constraints: bool = False` to `IssueCredentialRequest` in `models.py`. When `True`, constraint violations are logged but the credential is always issued. This enables deliberately issuing mis-vetted credentials for E2E testing — e.g., issuing a TN credential for a country code the vetter is NOT certified to vet, then observing the verifier detect and report the violation via `X-VVP-Vetter-Status: FAIL-ECC`.

**Access control:** `skip_vetter_constraints=True` requires ALL of the following:
1. **Admin role**: Caller must have `issuer:admin` role. Non-admin callers who set this flag receive a 403 error.
2. **Config gate**: `ALLOW_CONSTRAINT_BYPASS` env var must be `true` (default: `false`). When `false`, ANY request with `skip_vetter_constraints=True` is rejected with 403 regardless of role. This provides an infrastructure-level kill switch for production environments.

**Config:** `services/issuer/app/config.py`:
```python
ALLOW_CONSTRAINT_BYPASS: bool = os.getenv("VVP_ALLOW_CONSTRAINT_BYPASS", "false").lower() == "true"
```

**Audit logging:** Every use of `skip_vetter_constraints=True` is recorded via structured logging with mandatory fields:
```python
log.warning(
    "CONSTRAINT_BYPASS",
    extra={
        "action": "credential.issue.constraint_bypass",
        "principal_id": principal.key_id,
        "principal_roles": principal.roles,
        "credential_said": cred_info.said,
        "schema_said": request.schema_said,
        "violation_count": len(failed),
        "violations": [{"type": v.check_type, "target": v.target_value, "reason": v.reason} for v in failed],
        "client_ip": http_request.client.host if http_request.client else "unknown",
    },
)
```

**Enforcement precedence:**
1. `skip_vetter_constraints=True` on request + `ALLOW_CONSTRAINT_BYPASS=true` + `issuer:admin` role → always issue (audit log + warning)
2. `skip_vetter_constraints=True` but gate or role check fails → reject 403
3. `ENFORCE_VETTER_CONSTRAINTS=true` globally → reject 403
4. `ENFORCE_VETTER_CONSTRAINTS=false` (default) → warn + issue

**Attribute extraction by schema:**
- **Extended TNAlloc** (`EGUh_fVL...`): `attributes.get("numbers", {})` → extract TN from `tn` or `rangeStart` field → `extract_ecc_from_tn()`
- **Extended LE** (`EPknTwPp...`): `attributes.get("country")` → direct ISO 3166-1 alpha-3 code
- **Extended Brand** (`EK7kPhs5...`): `attributes.get("assertionCountry")` → direct ISO 3166-1 alpha-3 code

#### Component 4: Dossier-Creation-Time Enforcement

**Location:** `services/issuer/app/api/dossier.py` — modify `create_dossier()` endpoint

After existing edge validation, add constraint checking using credential-edge resolution:

```python
# Sprint 62: Validate vetter constraints via credential certification edges
from app.vetter.constraints import validate_dossier_constraints
from app.config import ENFORCE_VETTER_CONSTRAINTS

all_cred_saids = [v for v in resolved_edges.values() if v]  # collect all resolved SAIDs
constraint_violations = await validate_dossier_constraints(
    credential_saids=all_cred_saids,
)
failed = [v for v in constraint_violations if not v.is_authorized]
if failed:
    detail = "; ".join(f"{v.credential_type} {v.check_type}: {v.reason}" for v in failed)
    if ENFORCE_VETTER_CONSTRAINTS:
        raise HTTPException(status_code=403, detail=f"Dossier constraint violation: {detail}")
    else:
        log.warning(f"Dossier constraint warning (soft): {detail}")
```

Note: credentials without a `certification` edge (base schemas) are silently skipped — no constraint check performed. The `skip_vetter_constraints` bypass from `IssueCredentialRequest` does NOT apply at dossier creation — dossier assembly should always evaluate constraints (soft-fail mode logs warnings).

#### Component 5: Signing-Time Enforcement

**Location:** `services/issuer/app/api/vvp.py` — modify `create_vvp_attestation()`

Before signing the PASSporT (line ~157), add full constraint validation including BOTH ECC and jurisdiction checks by walking the dossier:

```python
# Sprint 62: Signing-time constraint validation (ECC + jurisdiction)
from app.vetter.constraints import validate_signing_constraints
from app.config import ENFORCE_VETTER_CONSTRAINTS

signing_violations = await validate_signing_constraints(
    orig_tn=body.orig_tn,
    dossier_said=body.dossier_said,
)
failed = [v for v in signing_violations if not v.is_authorized]
if failed:
    detail = "; ".join(f"{v.credential_type} {v.check_type}: {v.reason}" for v in failed)
    if ENFORCE_VETTER_CONSTRAINTS:
        raise HTTPException(status_code=403, detail=f"Signing constraint violation: {detail}")
    else:
        log.warning(f"Signing constraint warning (soft): {detail}")
```

`validate_signing_constraints()` walks the dossier credential chain, finds all credentials with `certification` edges, and performs:
- **TN/ECC check**: orig_tn country code vs VetterCert `ecc_targets` (for each TN credential)
- **Identity/Jurisdiction check**: LE credential `country` vs VetterCert `jurisdiction_targets`
- **Brand/Jurisdiction check**: Brand credential `assertionCountry` vs VetterCert `jurisdiction_targets`

The dossier builder (`get_dossier_builder()`) is already called at line 137 for card claim extraction — we reuse that `content` object to avoid a second dossier walk.

No DB session dependency needed — constraint validation uses the KERI store directly, not the Organization table.

#### Component 5b: Verifier Callee Flow — Add Vetter Constraints

**Problem:** `sip-verify` calls the verifier's `/verify-callee` endpoint, which is handled by `verify_callee_vvp()` in `services/verifier/app/vvp/verify_callee.py`. This function does NOT include Phase 11 vetter constraint evaluation — only the general `verify_vvp()` in `services/verifier/app/vvp/verify.py` (lines 1560-1712) does. Without this fix, `vetter_constraints` in the `/verify-callee` response will always be `None`, making the entire SIP propagation chain dead on arrival.

**Location:** `services/verifier/app/vvp/verify_callee.py` — modify `verify_callee_vvp()`

**Changes:**

1. **Import Phase 11 logic**: Import the vetter constraint evaluation functions from `services/verifier/app/vvp/vetter/`:
   ```python
   from app.vvp.vetter.traversal import find_vetter_certifications
   from app.vvp.vetter.evaluation import verify_vetter_constraints
   ```

2. **Add Phase 11 block** after the existing Phase 10 (final validation) and before the `VerifyResponse` construction (~line 1174). Port the exact pattern from `verify.py` lines 1560-1712:
   ```python
   # Phase 11: Vetter constraint evaluation (Sprint 62)
   vetter_constraints = None
   try:
       if dossier and dossier.credentials:
           orig_tn = passport_claims.get("orig", {}).get("tn")
           dest_tn = passport_claims.get("dest", {}).get("tn", [None])[0] if passport_claims.get("dest") else None
           vetter_certs = await find_vetter_certifications(dossier.credentials)
           if vetter_certs:
               vetter_constraints = verify_vetter_constraints(
                   vetter_certs=vetter_certs,
                   credentials=dossier.credentials,
                   orig_tn=orig_tn,
                   dest_tn=dest_tn,
               )
   except Exception as e:
       log.warning(f"Phase 11 vetter constraint evaluation failed: {e}")
       # Non-fatal — vetter constraints are informational
   ```

3. **Include in VerifyResponse**: Add `vetter_constraints=vetter_constraints` to the `VerifyResponse(...)` constructor at line ~1174.

**Key notes:**
- The callee flow already has `dossier` and `passport_claims` available from earlier phases — no new data fetching needed.
- Phase 11 is non-fatal: exceptions are caught and logged, allowing verification to complete even if vetter evaluation fails.
- The `VerifyResponse` model already has `vetter_constraints: Optional[Dict[str, VetterConstraintInfo]]` from Sprint 40.

**Tests:** `services/verifier/tests/test_verify_callee_vetter.py` (NEW) — see Test Strategy item 10.

#### Component 6: SIP Header Propagation — `X-VVP-Vetter-Status`

**6a. SIPResponse model** — `common/common/vvp/sip/models.py`

Add `vetter_status` field to `SIPResponse`:
```python
vetter_status: Optional[str] = None  # X-VVP-Vetter-Status
```

Add serialization in `to_bytes()` (after `X-VVP-Status` line):
```python
if self.vetter_status:
    lines.append(f"X-VVP-Vetter-Status: {self.vetter_status}")
```

**6b. VerifyResult model** — `services/sip-verify/app/verify/client.py`

Add `vetter_status` field to `VerifyResult`:
```python
vetter_status: Optional[str] = None
```

In `_parse_response()`, map `vetter_constraints` → `vetter_status`:
```python
vetter_constraints = data.get("vetter_constraints")
vetter_status = None
if vetter_constraints is not None and len(vetter_constraints) > 0:
    # Non-empty dict: evaluate constraint results
    ecc_fail = False
    jurisdiction_fail = False
    has_unresolved = False
    for cred_said, info in vetter_constraints.items():
        if info.get("vetter_certification_said") is None:
            has_unresolved = True
        elif not info.get("is_authorized", True):
            ct = info.get("constraint_type", "")
            if ct == "ecc":
                ecc_fail = True
            elif ct == "jurisdiction":
                jurisdiction_fail = True
    if has_unresolved and not ecc_fail and not jurisdiction_fail:
        vetter_status = "INDETERMINATE"
    elif ecc_fail and jurisdiction_fail:
        vetter_status = "FAIL-ECC-JURISDICTION"
    elif ecc_fail:
        vetter_status = "FAIL-ECC"
    elif jurisdiction_fail:
        vetter_status = "FAIL-JURISDICTION"
    else:
        vetter_status = "PASS"
# vetter_constraints is None → legacy dossier → no header (vetter_status stays None)
# vetter_constraints is {} → no extended creds evaluated → no header
```

**Mapping semantics (corrected per review):**
| `vetter_constraints` value | `vetter_status` | `X-VVP-Vetter-Status` header |
|----------------------------|-----------------|------------------------------|
| `None` | `None` | Not set (legacy dossier) |
| `{}` (empty dict) | `None` | Not set (no extended creds) |
| Non-empty, all `is_authorized=True` | `"PASS"` | `PASS` |
| Non-empty, ECC fail | `"FAIL-ECC"` | `FAIL-ECC` |
| Non-empty, jurisdiction fail | `"FAIL-JURISDICTION"` | `FAIL-JURISDICTION` |
| Non-empty, both fail | `"FAIL-ECC-JURISDICTION"` | `FAIL-ECC-JURISDICTION` |
| Non-empty, `vetter_certification_said=None` (only) | `"INDETERMINATE"` | `INDETERMINATE` |
| Non-empty, mixed unresolved + fail | `"FAIL-*"` | Fails take precedence |

**Deterministic precedence for mixed results (multiple credentials in dossier):**
1. Scan all constraint entries for failures (`is_authorized=False`) and unresolved (`vetter_certification_said=None`)
2. **FAIL takes precedence over INDETERMINATE** — if any entry is a definitive fail, the overall status reflects the fail type (ECC/jurisdiction/both)
3. **INDETERMINATE only when no definitive fail** — if all entries are either authorized or unresolved (no explicit fail), return INDETERMINATE
4. **PASS only when all entries are authorized** — no unresolved, no fails

**6c. SIP builder** — `common/common/vvp/sip/builder.py`

Add `vetter_status` parameter to `build_302_redirect()`:
```python
def build_302_redirect(
    request, contact_uri, ...,
    vetter_status: Optional[str] = None,  # NEW
) -> SIPResponse:
    response = SIPResponse(
        ...,
        vetter_status=vetter_status,  # NEW
    )
```

**6d. SIP verify handler** — `services/sip-verify/app/verify/handler.py`

Pass `vetter_status` through to `build_302_redirect()`:
```python
response = build_302_redirect(
    request,
    contact_uri=contact_uri,
    ...
    vetter_status=result.vetter_status,
)
```

Also add `vetter_status` to the monitor event capture in `_capture_event()`:
```python
if response.vetter_status:
    response_vvp_headers["X-VVP-Vetter-Status"] = response.vetter_status
```

#### Component 7: WebRTC Client Display

**7a. Extract `X-VVP-Vetter-Status`** — `services/pbx/webrtc/vvp-phone/js/vvp-display.js`

In `extractVVPData()`, add vetter status extraction:
```javascript
const vetterStatus = (
    params.vvp_vetter_status ||
    params['vvp_vetter_status'] ||
    null
);
```
Return: `vetter_status: vetterStatus`

**7b. Vetter constraint badge and config** — `services/pbx/webrtc/vvp-phone/js/vvp-display.js`

Add vetter status configuration object:
```javascript
vetterStatusConfig: {
    'PASS':                  { label: 'Vetter Verified',                className: 'vvp-vetter-pass',          icon: '✓' },
    'FAIL-ECC':              { label: 'Mis-vetted TN',                  className: 'vvp-vetter-fail',          icon: '⚠' },
    'FAIL-JURISDICTION':     { label: 'Unauthorized Jurisdiction',      className: 'vvp-vetter-fail',          icon: '⚠' },
    'FAIL-ECC-JURISDICTION': { label: 'Mis-vetted TN & Jurisdiction',   className: 'vvp-vetter-fail',          icon: '⚠' },
    'INDETERMINATE':         { label: 'Vetter Unknown',                 className: 'vvp-vetter-indeterminate', icon: '?' },
},
```

Add `createVetterBadge(vetterStatus)` method — creates an amber/orange warning badge distinct from the red "Not Verified" badge. FAIL-* badges use amber styling per spec: "vetter constraint failures are informational warnings, not hard failures."

Add to `createDisplayPanel()` — if `vvpData.vetter_status` is present and not null, append the vetter badge below the main status badge.

**7c. SIP phone HTML** — `services/pbx/webrtc/vvp-phone/sip-phone.html`

In `extractVVPFromSIP()` (or equivalent SIP.js extraction function), add extraction of `X-VVP-Vetter-Status` from incoming SIP headers and pass to `VVPDisplay.handleIncomingCall()`.

**7d. FreeSWITCH dialplan** — `services/pbx/config/public-sip.xml`

Add `X-VVP-Vetter-Status` header passthrough in the `redirected` context:
```xml
<action application="set" data="vvp_vetter_status=${sip_h_X-VVP-Vetter-Status}"/>
```

#### Component 8: Issuer Config

**Location:** `services/issuer/app/config.py`

Add environment variables:
```python
# Vetter constraint enforcement (Sprint 62)
ENFORCE_VETTER_CONSTRAINTS: bool = os.getenv("VVP_ENFORCE_VETTER_CONSTRAINTS", "false").lower() == "true"

# Constraint bypass gate — must be explicitly enabled for skip_vetter_constraints to work
ALLOW_CONSTRAINT_BYPASS: bool = os.getenv("VVP_ALLOW_CONSTRAINT_BYPASS", "false").lower() == "true"
```

`ENFORCE_VETTER_CONSTRAINTS` default `false` matches verifier behavior. When `false`: log warnings, proceed. When `true`: reject with 403.

`ALLOW_CONSTRAINT_BYPASS` default `false`. Only set to `true` in test/staging environments where deliberately issuing mis-vetted credentials is needed for E2E testing. Production environments should never enable this.

#### Component 9: GSMA Trusted-Root Rollout Strategy

The verifier's `TRUSTED_ROOT_AIDS` determines which AIDs are recognized as roots of trust. Adding the GSMA AID to this set is required for vetter constraint validation to resolve governance chains.

**Source of truth:** The GSMA AID is generated deterministically by `scripts/bootstrap-issuer.py` using the GSMA identity name (`mock-gsma`) and stored in `MockVLEIState.gsma_aid`. For mock environments, the AID is stable as long as the LMDB keystore is not wiped.

**Environment-specific configuration:**

| Environment | GSMA AID Source | Config Mechanism |
|-------------|-----------------|-------------------|
| **Local dev** | Auto-discovered from `MockVLEIState.gsma_aid` | Added to verifier `TRUSTED_ROOT_AIDS` default in `config.py` |
| **Docker compose** | Bootstrap script output | `VVP_TRUSTED_ROOT_AIDS` env var in `docker-compose.yml` |
| **Azure (production)** | `MockVLEIState.gsma_aid` from issuer DB | `VVP_TRUSTED_ROOT_AIDS` in Container App env vars via `deploy.yml` |

**Bootstrap flow:**
1. `bootstrap-issuer.py` creates GSMA identity → stores `gsma_aid` in DB
2. Bootstrap script prints the GSMA AID to stdout
3. For Azure: AID is stored as a GitHub repository secret (`VVP_GSMA_AID`) and injected into both issuer and verifier Container App env vars via `deploy.yml`
4. For local dev: The local `config.py` default includes the mock GSMA AID

**AID rotation:** If the issuer LMDB is wiped and bootstrap runs again, a new GSMA AID is generated. The operator must:
1. Note the new GSMA AID from bootstrap output
2. Update the GitHub secret `VVP_GSMA_AID`
3. Re-deploy verifier (picks up new `VVP_TRUSTED_ROOT_AIDS`)

This is the same pattern used for the existing mock GLEIF/QVI AIDs — no new operational burden.

**Health check:** The verifier's `/healthz` endpoint already reports `trusted_root_count`. Sprint 62 adds a test that validates the GSMA AID is present in the verifier's trusted roots after bootstrap + deploy.

**Rollback:** Remove the GSMA AID from `VVP_TRUSTED_ROOT_AIDS`. Verifier stops recognizing GSMA as a root → all VetterCert governance chains become unresolvable → `vetter_constraints` returns `INDETERMINATE` for all credentials. This is a safe degradation (informational only).

### Data Flow

```
    Trust Chain (GSMA → VetterCert → Extended Creds):
    ┌─────────────────────────────────────────────────────────────┐
    │ GSMA AID                                                     │
    │   └─ signs GSMA Governance Credential (self-issued)         │
    │        └─ VetterCert has 'issuer' edge → Governance Cred    │
    │             └─ Extended TN/LE/Brand have 'certification'    │
    │                  edge → VetterCert                          │
    └─────────────────────────────────────────────────────────────┘

    Constraint Enforcement Points:
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │  Issuance   │    │   Dossier   │    │   Signing   │
    │  (org-cert) │    │ (edge-cert) │    │ (edge-cert) │
    │             │    │             │    │             │
    │ Extract attr│    │ Walk edges  │    │ Walk dossier│
    │ → check vs  │    │ → resolve   │    │ → resolve   │
    │ org's cert  │    │ VetterCert  │    │ VetterCerts │
    │ ECC/Jur     │    │ per cred    │    │ → check ALL │
    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
           │                  │                  │
           ▼                  ▼                  ▼
    ┌──────────────────────────────────────────────────┐
    │         ENFORCE_VETTER_CONSTRAINTS                │
    │         false → warn + proceed                   │
    │         true  → reject 403                       │
    └──────────────────────────────────────────────────┘

    SIP Propagation:
    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
    │  Verifier   │    │ SIP Verify   │    │   WebRTC     │
    │  /verify-   │──▶ │ handler      │──▶ │   Display    │
    │  callee     │    │              │    │              │
    │ vetter_     │    │ Map to       │    │ Vetter badge │
    │ constraints │    │ X-VVP-Vetter │    │ (amber)      │
    │ (JSON)      │    │ -Status hdr  │    │              │
    └─────────────┘    └──────────────┘    └──────────────┘
```

### Compatibility Matrix

| Enforcement Point | Base Schema (no cert edge) | Extended Schema (cert edge present) | Extended Schema (cert edge MISSING on extended) | Stale/expired VetterCert |
|-------------------|---------------------------|--------------------------------------|------------------------------------------------|--------------------------|
| **Issuance** | No check | Check ECC/jurisdiction vs org cert | Error: cert edge required (existing Sprint 61 logic) | Violation: warn or 403 per enforce mode |
| **Dossier creation** | No check (skip) | Check via credential edge → VetterCert | **Violation**: warn or 403 per enforce mode (extended schema MUST have cert edge) | **Violation**: warn or 403 per enforce mode |
| **Signing** | No check (skip) | Walk dossier, check via edges | **Violation**: warn or 403 per enforce mode | **Violation**: warn or 403 per enforce mode |
| **Verifier** | `vetter_constraints=None` | Full Phase 11 evaluation | `INDETERMINATE` (cert could not be resolved) | `INDETERMINATE` |
| **SIP header** | No `X-VVP-Vetter-Status` | Header set per mapping | `INDETERMINATE` | `INDETERMINATE` |
| **WebRTC badge** | No badge shown | Badge shown per status | "Vetter Unknown" badge | "Vetter Unknown" badge |

**Rationale for missing-cert-edge-on-extended = violation:** Sprint 40 established the principle that extended schemas carry explicit certification backlinks ("no fallback"). If an extended credential somehow reaches dossier/signing without a `certification` edge, this is an anomalous state — the credential was either tampered with or issued incorrectly. Treating it as a silent skip would create a bypass path where constrained credentials evade enforcement simply by omitting the edge. Instead, missing cert edges on extended schemas produce a violation (warn in soft mode, 403 in enforce mode).

### Error Handling

- **Constraint failures + `ENFORCE_VETTER_CONSTRAINTS=false`**: Log warning, proceed normally
- **Constraint failures + `ENFORCE_VETTER_CONSTRAINTS=true`**: Return HTTP 403 with descriptive error
- **No VetterCert on org** (issuance-time): Skip constraint checks, no warning (org hasn't onboarded to vetter constraints yet)
- **No `certification` edge on credential — BASE SCHEMA** (dossier/signing-time): Skip that credential, no warning (backward compatible)
- **No `certification` edge on credential — EXTENDED SCHEMA** (dossier/signing-time): **Violation** — extended schemas MUST have certification edges per Sprint 40. Generate a `ConstraintCheckResult(is_authorized=False, reason="Extended credential missing required certification edge")`. This follows the "no fallback" principle.
- **Stale/expired VetterCert** (any enforcement point): **Violation** — generate `ConstraintCheckResult(is_authorized=False, reason="VetterCertification expired or revoked")`. A valid cert must be resolvable; an expired cert means the vetter's authority has lapsed.
- **Unresolvable VetterCert** (cert edge points to non-existent credential): **Violation** — same treatment as stale/expired.
- **Invalid TN format** (can't extract country code): Skip ECC check, log warning
- **Missing attribute** (no `country` on LE, no `assertionCountry` on Brand): Skip that check, log debug

**Schema-type detection for edge resolution:** `validate_credential_edge_constraints()` and `validate_dossier_constraints()` must distinguish base from extended schemas when encountering a credential without a `certification` edge. The check uses `KNOWN_EXTENDED_SCHEMA_SAIDS` from `services/issuer/app/vetter/constants.py` — if the credential's schema SAID is in this set and has no certification edge, it's a violation. If the schema SAID is NOT in this set, it's a base schema and is silently skipped.

### Test Strategy

1. **GSMA governance credential tests** (`services/issuer/tests/test_gsma_governance.py`):
   - Bootstrap creates GSMA AID + governance credential
   - Governance credential has correct schema SAID, name="GSMA", role="Vetter Governance Authority"
   - VetterCert `issuer` edge points to governance credential SAID
   - GSMA AID is registered in verifier trusted roots

2. **Constraint validator unit tests** (`services/issuer/tests/test_vetter_constraints.py`):
   - `extract_ecc_from_tn()` — various formats (+44..., 44..., +1..., +971..., invalid, empty)
   - `check_tn_ecc_constraint()` — pass and fail cases
   - `check_jurisdiction_constraint()` — pass and fail cases for Identity and Brand types
   - `validate_issuance_constraints()` — per schema type (TNAlloc, LE, Brand)
   - Edge cases: no vetter cert, expired cert, missing attributes

3. **Issuance-time enforcement tests** (`services/issuer/tests/test_credential_constraints.py`):
   - Issue Extended TNAlloc with matching ECC → passes
   - Issue Extended TNAlloc with non-matching ECC → warn (enforce=false) / reject 403 (enforce=true)
   - Issue Extended LE with matching jurisdiction → passes
   - Issue Extended Brand with non-matching jurisdiction → warn/reject
   - **`skip_vetter_constraints=True` + non-matching ECC + enforce=true → credential STILL issued** (per-request bypass)
   - **Issue base-schema credential → no constraint check (backward compat regression test)**

4. **Dossier-creation-time enforcement tests** (`services/issuer/tests/test_dossier_constraints.py`):
   - Dossier with credentials having matching certification edges → passes
   - Dossier with TN credential whose VetterCert lacks ECC → warn/reject
   - Dossier with credentials using base schemas (no certification edge) → no constraint check
   - **Mixed-vetter dossier** — credentials from different vetters, each checked against own cert

5. **Signing-time enforcement tests** (`services/issuer/tests/test_vvp_constraints.py`):
   - Sign with orig TN in ECC targets → passes
   - Sign with orig TN NOT in ECC targets → warn/reject
   - **Signing with jurisdiction mismatch in dossier → warn/reject**
   - Sign with legacy dossier (no certification edges) → no constraint check

6. **SIP header propagation tests** (`services/sip-verify/tests/test_vetter_header.py`):
   - `vetter_constraints` all pass → `X-VVP-Vetter-Status: PASS`
   - ECC fail only → `FAIL-ECC`
   - Jurisdiction fail only → `FAIL-JURISDICTION`
   - Both fail → `FAIL-ECC-JURISDICTION`
   - `vetter_constraints=None` (legacy) → **no header set**
   - `vetter_constraints={}` (empty) → **no header set**
   - Constraints present, cert SAID is None → `INDETERMINATE`

7. **SIPResponse serialization tests** (extend existing):
   - `vetter_status` present → header appears in `to_bytes()` output
   - `vetter_status=None` → no header line in output

8. **Legacy regression tests** (across all enforcement points):
   - Base-schema TNAlloc/LE/Brand → issuance proceeds without constraint check
   - Legacy dossier → creation proceeds without constraint check
   - Legacy dossier signing → PASSporT created without constraint check
   - Legacy dossier verification → no `X-VVP-Vetter-Status` header, no badge

9. **Missing-certification and expired-cert enforcement tests** (`services/issuer/tests/test_constraint_violations.py`):
   - Extended TNAlloc credential without `certification` edge at dossier creation → violation (warn if enforce=false, 403 if enforce=true)
   - Extended LE credential without `certification` edge at signing time → violation (warn/403)
   - Extended Brand credential with expired VetterCert at dossier creation → violation (warn/403)
   - Extended credential with cert edge pointing to non-existent credential → violation (warn/403)
   - Base-schema credential without `certification` edge → no check (silent skip, backward compat)
   - `skip_vetter_constraints=True` but `ALLOW_CONSTRAINT_BYPASS=false` → 403
   - `skip_vetter_constraints=True` with non-admin role → 403

10. **Verifier callee flow vetter constraint tests** (`services/verifier/tests/test_verify_callee_vetter.py`):
    - `/verify-callee` with extended dossier containing matching VetterCert → `vetter_constraints` populated in response, all `is_authorized=True`
    - `/verify-callee` with extended dossier containing non-matching ECC → `vetter_constraints` shows `is_authorized=False` with `constraint_type="ecc"`
    - `/verify-callee` with base-schema dossier → `vetter_constraints=None`
    - `/verify-callee` Phase 11 failure (exception in vetter eval) → non-fatal, `vetter_constraints=None`, rest of response intact

11. **Callee → SIP → WebRTC integration test** (`services/sip-verify/tests/test_vetter_e2e_flow.py`):
    - Mock verifier `/verify-callee` response with `vetter_constraints` (all pass) → SIP verify handler maps to `X-VVP-Vetter-Status: PASS` → `SIPResponse.to_bytes()` includes the header
    - Mock verifier response with ECC fail → `X-VVP-Vetter-Status: FAIL-ECC` in SIP response
    - Mock verifier response with no `vetter_constraints` → no `X-VVP-Vetter-Status` header in SIP response

12. **E2E integration test** (conceptual, uses existing test patterns):
    - **Happy path**: GSMA issues VetterCert (ecc_targets=["44"]) → vetter issues Extended TN for +44xxx with certification edge → dossier created → PASSporT signed → verifier validates → `vetter_constraints` all pass → SIP verify maps to `X-VVP-Vetter-Status: PASS` → WebRTC displays "Vetter Verified" badge
    - **Mis-vetted TN (key demo scenario)**: GSMA issues VetterCert (ecc_targets=["33"]) → vetter issues Extended TN for +44xxx using `skip_vetter_constraints=true` (TN outside vetter's scope) → dossier created → PASSporT signed → verifier detects constraint violation → SIP verify maps to `X-VVP-Vetter-Status: FAIL-ECC` → WebRTC displays "Mis-vetted TN" amber badge

13. **GSMA trusted-root health check test**:
    - After bootstrap, verifier `/healthz` reports `trusted_root_count` including GSMA AID
    - Verifier constraint evaluation with GSMA AID in trusted roots → governance chain resolves
    - Verifier constraint evaluation with GSMA AID NOT in trusted roots → `INDETERMINATE`

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/schema/schemas/gsma-governance-credential.json` | Create | GSMA governance credential schema |
| `common/common/vvp/schema/registry.py` | Modify | Register GSMA governance schema SAID |
| `services/issuer/app/db/models.py` | Modify | Add `gsma_governance_said` to MockVLEIState |
| `services/issuer/app/db/migrations/sprint62_gsma_governance.py` | Create | DB migration for new column |
| `services/issuer/app/org/mock_vlei.py` | Modify | Issue governance credential, add issuer edge to VetterCerts |
| `services/issuer/app/vetter/constants.py` | Modify | Add GSMA_GOVERNANCE_SCHEMA_SAID |
| `scripts/bootstrap-issuer.py` | Modify | Issue GSMA governance credential |
| `services/verifier/app/core/config.py` | Modify | Add GSMA AID to TRUSTED_ROOT_AIDS default |
| `.github/workflows/deploy.yml` | Modify | Add GSMA AID to verifier env vars |
| `services/issuer/app/vetter/constraints.py` | Create | Constraint validation logic (edge-resolved + org-level) |
| `services/issuer/app/config.py` | Modify | Add `ENFORCE_VETTER_CONSTRAINTS` and `ALLOW_CONSTRAINT_BYPASS` |
| `services/issuer/app/api/credential.py` | Modify | Add issuance-time constraint check |
| `services/issuer/app/api/dossier.py` | Modify | Add dossier-creation-time constraint check |
| `services/issuer/app/api/vvp.py` | Modify | Add signing-time constraint check (ECC + jurisdiction) |
| `common/common/vvp/sip/models.py` | Modify | Add `vetter_status` field + serialization |
| `common/common/vvp/sip/builder.py` | Modify | Add `vetter_status` param to `build_302_redirect` |
| `services/sip-verify/app/verify/client.py` | Modify | Map `vetter_constraints` → `vetter_status` |
| `services/sip-verify/app/verify/handler.py` | Modify | Pass `vetter_status` to SIP response + monitor |
| `services/pbx/webrtc/vvp-phone/js/vvp-display.js` | Modify | Vetter badge, status config, createVetterBadge() |
| `services/pbx/webrtc/vvp-phone/sip-phone.html` | Modify | Extract X-VVP-Vetter-Status from SIP headers |
| `services/pbx/config/public-sip.xml` | Modify | Passthrough X-VVP-Vetter-Status |
| `services/verifier/app/vvp/verify_callee.py` | Modify | Add Phase 11 vetter constraint evaluation to callee flow |
| `services/issuer/tests/test_gsma_governance.py` | Create | GSMA governance + trust chain tests |
| `services/issuer/tests/test_vetter_constraints.py` | Create | Constraint validator unit tests |
| `services/issuer/tests/test_credential_constraints.py` | Create | Issuance enforcement tests |
| `services/issuer/tests/test_dossier_constraints.py` | Create | Dossier enforcement tests |
| `services/issuer/tests/test_vvp_constraints.py` | Create | Signing enforcement tests |
| `services/issuer/tests/test_constraint_violations.py` | Create | Missing-cert/expired-cert enforcement tests |
| `services/verifier/tests/test_verify_callee_vetter.py` | Create | Verifier callee flow vetter constraint tests |
| `services/sip-verify/tests/test_vetter_header.py` | Create | SIP header mapping tests |
| `services/sip-verify/tests/test_vetter_e2e_flow.py` | Create | Callee → SIP propagation integration tests |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Backward compatibility regression — existing dossiers without cert edges break | Medium | High | Base-schema credentials skip all constraint checks. No certification edge → no check. Explicit legacy regression tests. |
| E.164 country code extraction fails on edge-case numbers | Low | Medium | Longest-prefix matching against known ITU-T codes; log warning on unrecognized codes; skip check rather than fail |
| GSMA governance credential changes VetterCert SAID (adding edge changes digest) | Medium | Medium | Existing VetterCerts (Sprint 61 bootstrap) will need re-issuance. Bootstrap script handles this idempotently. |
| FreeSWITCH doesn't propagate custom X-VVP-Vetter-Status header | Low | Medium | Follow exact same pattern as X-VVP-Brand-Name/Brand-Logo which already works |
| Mixed-vetter dossier edge resolution is complex | Medium | Medium | Clear separation: issuance uses org-cert, dossier/signing use edge-cert. Unit tests for each path. |

## Prerequisites

**Sprint 61 must be marked COMPLETE before implementation begins.** Sprint 61's VetterCert CRUD, mock GSMA identity, and certification edge injection code are currently uncommitted changes in the working tree. These must be committed and Sprint 61 closed before Sprint 62 implementation starts. Planning can proceed in parallel.

### Telemetry

Per reviewer recommendation, add structured log counters to `constraints.py` for rollout observability:

```python
log.info(
    "VETTER_CONSTRAINT_EVALUATED",
    extra={
        "schema_said": schema_said,
        "schema_type": "extended" if schema_said in KNOWN_EXTENDED_SCHEMA_SAIDS else "base",
        "check_type": result.check_type,
        "is_authorized": result.is_authorized,
        "enforcement_mode": "enforce" if ENFORCE_VETTER_CONSTRAINTS else "soft",
    },
)
```

For base-schema credentials that skip constraint checks:
```python
log.debug(
    "VETTER_CONSTRAINT_SKIPPED",
    extra={"schema_said": schema_said, "reason": "base_schema"},
)
```

This enables querying logs for "constraints skipped due to legacy/base schema" vs "constraints evaluated" to measure rollout safety.

## Open Questions

None — the spec is unambiguous and all reviewer findings have been addressed.
