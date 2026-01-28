# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from CHANGES.md and implementation code -->

## Phase 1: Core Infrastructure

### Overview

Define foundational models, enums, and configuration constants per VVP Specification v1.4 §3.2, §4.1-§4.3, §4.2A. This phase establishes the data structures used throughout the verification pipeline.

### Spec References

- **§3.2** - Claim Status (VALID, INVALID, INDETERMINATE)
- **§4.1** - Request Models (CallContext, VerifyRequest)
- **§4.2** - Error Envelope (ErrorDetail)
- **§4.2A** - Error Code Registry (18 codes with recoverability)
- **§4.3** - Response Models (VerifyResponse, ClaimNode)
- **§4.3A** - overall_status Derivation (precedence rules)
- **§4.3B** - Claim Node Schema (children with required/optional flags)

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/core/__init__.py` | Create | Empty package init |
| `app/core/config.py` | Create | Configuration constants per §4.1A, §5.2A/B |
| `app/vvp/api_models.py` | Create | Pydantic models per §3.2, §4.1-4.3, §4.2A |
| `app/vvp/verify.py` | Update | Use new models (placeholder returns INDETERMINATE) |
| `tests/test_models.py` | Create | Unit tests for Phase 1 models |

### Implementation Approach

#### 1. ClaimStatus Enum (§3.2)

```python
class ClaimStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"
```

#### 2. ClaimNode Model (§4.3B)

```python
class ChildLink(BaseModel):
    required: bool
    node: "ClaimNode"

class ClaimNode(BaseModel):
    name: str
    status: ClaimStatus
    reasons: List[str] = []
    evidence: List[str] = []
    children: List[ChildLink] = []
```

#### 3. Request Models (§4.1)

```python
class CallContext(BaseModel):
    source: Optional[str] = None
    destination: Optional[str] = None
    timestamp: Optional[int] = None

class VerifyRequest(BaseModel):
    passport_jwt: str
    context: CallContext
```

#### 4. Response Models (§4.2, §4.3)

```python
class ErrorDetail(BaseModel):
    code: str
    message: str
    recoverable: bool

class VerifyResponse(BaseModel):
    request_id: str
    overall_status: ClaimStatus
    claims: Optional[ClaimNode] = None
    errors: List[ErrorDetail] = []
```

#### 5. Error Code Registry (§4.2A)

18 error codes with recoverability mapping:

| Code | Recoverable | Layer |
|------|-------------|-------|
| VVP_IDENTITY_MISSING | No | Protocol |
| VVP_IDENTITY_INVALID | No | Protocol |
| VVP_OOBI_FETCH_FAILED | Yes | Protocol |
| VVP_OOBI_CONTENT_INVALID | No | Protocol |
| PASSPORT_MISSING | No | Protocol |
| PASSPORT_PARSE_FAILED | No | Protocol |
| PASSPORT_SIG_INVALID | No | Crypto |
| PASSPORT_FORBIDDEN_ALG | No | Crypto |
| PASSPORT_EXPIRED | No | Protocol |
| DOSSIER_URL_MISSING | No | Evidence |
| DOSSIER_FETCH_FAILED | Yes | Evidence |
| DOSSIER_PARSE_FAILED | No | Evidence |
| DOSSIER_GRAPH_INVALID | No | Evidence |
| ACDC_SAID_MISMATCH | No | Crypto |
| ACDC_PROOF_MISSING | No | Crypto |
| KERI_RESOLUTION_FAILED | Yes | KERI |
| KERI_STATE_INVALID | No | KERI |
| INTERNAL_ERROR | Yes | Verifier |

#### 6. Configuration Constants

```python
CLOCK_SKEW_SECONDS = 300          # ±5 minutes per §4.1A
MAX_TOKEN_AGE_SECONDS = 300       # 5 minutes per §5.2B
MAX_IAT_DRIFT_SECONDS = 5         # ≤5 seconds per §5.2A (normative)
ALLOWED_ALGORITHMS = frozenset({"EdDSA"})  # Per §5.0, §5.1
```

#### 7. overall_status Derivation (§4.3A)

```python
def derive_overall_status(claims: ClaimNode) -> ClaimStatus:
    """Derive overall status from root claims.

    Precedence: INVALID > INDETERMINATE > VALID
    """
```

### Checklist Tasks Covered

- [x] 1.1 - Create `app/core/config.py`
- [x] 1.2 - Define `ClaimStatus` enum
- [x] 1.3 - Define `ClaimNode` model with ChildLink
- [x] 1.4 - Define `VerifyRequest` model
- [x] 1.5 - Define `VerifyResponse` model
- [x] 1.6 - Define `ErrorDetail` model
- [x] 1.7 - Create error code constants (18 codes per §4.2A)
- [x] 1.8 - Implement `overall_status` derivation per §4.3A

### Test Results

```
33 passed in 0.14s
```

---

**Status:** IMPLEMENTED
**Commit:** `9546f37`
