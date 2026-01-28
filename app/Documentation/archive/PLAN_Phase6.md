# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 6: Verification Orchestration and Claim Derivation (Tier 1)

### Overview

Implement the full VVP verification orchestration engine per spec §9, wiring together all verification phases (VVP-Identity parsing, PASSporT validation, signature verification, dossier fetching) and building a claim tree with status propagation per §3.3A.

### Spec References

- **§3.3A** - Child Status Propagation (REQUIRED children affect parent)
- **§4.3A** - overall_status Derivation
- **§9** - Verification Pseudocode and Orchestration

### Tier 1 Scope

**Implemented:**
- ClaimBuilder helper for accumulating evidence and failures
- Fixed claim tree structure: `caller_authorised` → [`passport_verified`, `dossier_verified`]
- Status propagation per §3.3A (REQUIRED children affect parent)
- Error-to-ErrorDetail conversion with recoverability lookup
- Early exit on VVP-Identity failure
- Skip dossier fetch on non-recoverable passport failure

**Tier 1 Claim Tree:**
```
caller_authorised (REQUIRED root)
├── passport_verified (REQUIRED)
└── dossier_verified (REQUIRED)
```

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Rewrite | Full orchestration engine |
| `app/main.py` | Modify | Wire up async verify endpoint |
| `tests/test_verify.py` | Create | Unit tests for orchestration |

### Implementation Approach

#### 1. ClaimBuilder

```python
@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim."""
    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""

    def build(self, children: List[ChildLink] = None) -> ClaimNode:
        """Build the final ClaimNode."""
```

#### 2. Error Conversion

```python
def to_error_detail(exc: Exception) -> ErrorDetail:
    """Convert domain exception to ErrorDetail for API response.

    Extracts error code and message from exception attributes,
    and looks up recoverability from ERROR_RECOVERABILITY mapping.
    """
```

#### 3. Status Propagation (§3.3A)

```python
def _worse_status(a: ClaimStatus, b: ClaimStatus) -> ClaimStatus:
    """Return the worse of two statuses.
    Precedence: INVALID > INDETERMINATE > VALID
    """

def propagate_status(node: ClaimNode) -> ClaimStatus:
    """Compute effective status considering REQUIRED children per §3.3A.

    Rules:
    - REQUIRED children: parent status is worst of own + all required children
    - OPTIONAL children: do not affect parent status
    """
```

#### 4. Main Orchestrator

```python
async def verify_vvp(
    req: VerifyRequest,
    vvp_identity_header: Optional[str] = None,
    raw_dossier: Optional[bytes] = None,  # For testing
) -> VerifyResponse:
    """Main verification orchestration per §9.

    Flow:
    1. Generate request_id
    2. Parse VVP-Identity header → early exit if fails
    3. Parse PASSporT JWT
    4. Validate PASSporT binding with VVP-Identity
    5. Verify PASSporT signature
    6. Fetch and validate dossier (skip on non-recoverable passport failure)
    7. Build claim tree with status propagation
    8. Derive overall_status from root claim
    9. Return VerifyResponse
    """
```

### Orchestration Flow

```
1. Parse VVP-Identity
   └── Failure → Early exit with errors[], overall_status = INVALID/INDETERMINATE

2. Parse PASSporT
   └── Failure → passport_verified = INVALID/INDETERMINATE

3. Validate PASSporT binding
   └── Failure → passport_verified = INVALID

4. Verify signature
   └── Failure → passport_verified = INVALID/INDETERMINATE

5. Fetch dossier (skip if passport non-recoverable failure)
   └── Failure → dossier_verified = INVALID/INDETERMINATE

6. Parse dossier
   └── Failure → dossier_verified = INVALID

7. Validate DAG
   └── Failure → dossier_verified = INVALID

8. Build claim tree
   └── caller_authorised = propagate_status(children)

9. Derive overall_status
   └── overall_status = propagate_status(root)
```

### Error Handling Rules

| Phase | Exception Type | Claim Affected | Recoverability |
|-------|---------------|----------------|----------------|
| VVP-Identity | VVPIdentityError | (early exit) | Depends on code |
| PASSporT parse | PassportError | passport_verified | Non-recoverable |
| Signature | SignatureInvalidError | passport_verified | Non-recoverable |
| Signature | ResolutionFailedError | passport_verified | Recoverable |
| Dossier fetch | FetchError | dossier_verified | Recoverable |
| Dossier parse | ParseError | dossier_verified | Non-recoverable |
| Dossier graph | GraphError | dossier_verified | Non-recoverable |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **VVP-Identity** | |
| Missing VVP-Identity | Early exit, INDETERMINATE, VVP_IDENTITY_MISSING |
| Invalid VVP-Identity | Early exit, INVALID, VVP_IDENTITY_INVALID |
| **PASSporT** | |
| Missing PASSporT | passport_verified = INVALID |
| Parse failure | passport_verified = INVALID |
| Forbidden algorithm | passport_verified = INVALID |
| Expired | passport_verified = INVALID |
| Binding mismatch | passport_verified = INVALID |
| **Signature** | |
| Invalid signature | passport_verified = INVALID |
| Resolution failed | passport_verified = INDETERMINATE |
| Valid signature | passport_verified = VALID |
| **Dossier** | |
| Fetch timeout | dossier_verified = INDETERMINATE |
| Fetch HTTP error | dossier_verified = INDETERMINATE |
| Parse failure | dossier_verified = INVALID |
| Graph invalid | dossier_verified = INVALID |
| Valid dossier | dossier_verified = VALID |
| **Propagation** | |
| All valid | overall = VALID |
| Passport invalid | overall = INVALID |
| Passport indeterminate | overall = INDETERMINATE |
| Dossier invalid | overall = INVALID |
| Dossier indeterminate | overall = INDETERMINATE |
| Skip dossier on fatal passport | dossier_verified = INDETERMINATE (skipped) |

### Checklist Tasks Covered

- [x] 6.1 - Create engine.py module (integrated into verify.py)
- [x] 6.3 - Implement claim tree construction from dossier
- [x] 6.4 - Validate children have explicit required/optional flag
- [x] 6.5 - Implement REQUIRED child propagation: INVALID → parent INVALID
- [x] 6.6 - Implement REQUIRED child propagation: INDETERMINATE → parent INDETERMINATE
- [x] 6.7 - Implement OPTIONAL child handling (never invalidates parent)
- [x] 6.8 - Implement overall_status derivation from root claims
- [x] 6.9 - Support partial trees for recoverable failures
- [x] 6.10 - Implement short-circuit on fatal PASSporT failures
- [x] 6.13 - Unit tests for claim propagation

### Test Results

```
264 passed (222 prior + 42 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `6f6a0cb`
