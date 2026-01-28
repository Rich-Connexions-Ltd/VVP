# Current Plan

<!-- STATUS: IMPLEMENTED -->

## Phase 3: PASSporT JWT Verification

### Overview

Implement parsing and validation of VVP PASSporT JWTs per spec §5.0-§5.4. This phase covers JWT structure parsing, algorithm enforcement, header/payload extraction, and binding validation between PASSporT and VVP-Identity. Signature verification is deferred to Phase 4 (requires KERI key state).

### Spec References

- **§5.0** - Non-compliance note: VVP mandates EdDSA, forbids ES256/HMAC/RSA
- **§5.1** - Allowed Algorithms: reject `none`, ES256, HMAC, RSA; require EdDSA
- **§5.2** - Header Binding Rules: `ppt` must be "vvp" and match VVP-Identity; `kid` binding
- **§5.2A** - Temporal Binding Rules: iat drift ≤ 5 seconds (NORMATIVE per spec)
- **§5.2B** - PASSporT Expiry Policy: max validity 300s (configurable per spec)
- **§5.4** - Failure Mapping: parse/algorithm failures → INVALID

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/passport.py` | Create | PASSporT JWT parser and validator |
| `app/vvp/exceptions.py` | Modify | Add PASSporT-specific exceptions |
| `tests/test_passport.py` | Create | Unit tests for PASSporT parsing |

### PASSporT JWT Structure

A VVP PASSporT is a JWS (JSON Web Signature) with three base64url-encoded parts:

```
header.payload.signature
```

#### Header Claims (per §5.1, §5.2)

```json
{
  "alg": "EdDSA",
  "typ": "passport",
  "ppt": "vvp",
  "kid": "did:keri:..."
}
```

| Field | Required | Validation | Source |
|-------|----------|------------|--------|
| `alg` | Yes | Must be "EdDSA"; reject "none", ES256, HMAC, RSA | §5.0, §5.1 (Normative) |
| `typ` | No | Ignored (not validated) | Not in v1.4 |
| `ppt` | Yes | Must be "vvp" per §5.2; must match VVP-Identity ppt | §5.2 (Normative) |
| `kid` | Yes | Must match VVP-Identity kid (strict equality in Phase 3) | §5.2 (Normative) |

**Note on `kid` binding:** §5.2 states kid must "match (or be resolvable from)" VVP-Identity kid. Phase 3 implements strict equality only. OOBI resolution will be added in Phase 4.

#### Payload Claims

```json
{
  "iat": 1737500000,
  "orig": {"tn": "+12025551234"},
  "dest": {"tn": ["+12025555678"]},
  "evd": "oobi:..."
}
```

| Field | Required | Validation | Source |
|-------|----------|------------|--------|
| `iat` | Yes | Must align with VVP-Identity iat ±5s | §5.2A (Normative) |
| `orig` | Yes* | Originator claim | VVP-draft (Local Policy) |
| `dest` | Yes* | Destination claim | VVP-draft (Local Policy) |
| `evd` | Yes* | Evidence/dossier OOBI reference | VVP-draft (Local Policy) |
| `iss` | No | Issuer identifier (if present) | VVP-draft (Local Policy) |
| `exp` | No | Expiry timestamp (validate per §5.2A/§5.2B if present) | §5.2A/B (Normative) |
| `card` | No | Card claim (VVP extension) | VVP-draft |
| `goal` | No | Goal claim (VVP extension) | VVP-draft |
| `call-reason` | No | Call reason (VVP extension) | VVP-draft |
| `origid` | No | Original call ID (VVP extension) | VVP-draft |

*Note: `orig`, `dest`, and `evd` are required by VVP-draft but not mandated by v1.4 spec. Treated as **local policy**.

### Implementation Approach

#### 1. Custom Exceptions

Extend `app/vvp/exceptions.py`:

```python
class PassportError(Exception):
    """Base exception for PASSporT parsing/validation errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "PassportError":
        """Factory for PASSPORT_MISSING error."""

    @classmethod
    def parse_failed(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_PARSE_FAILED error."""

    @classmethod
    def forbidden_alg(cls, alg: str) -> "PassportError":
        """Factory for PASSPORT_FORBIDDEN_ALG error."""

    @classmethod
    def expired(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_EXPIRED error."""
```

#### 2. Data Models

```python
@dataclass(frozen=True)
class PassportHeader:
    """Decoded PASSporT JWT header."""
    alg: str
    ppt: str
    kid: str
    typ: Optional[str] = None  # Not validated

@dataclass(frozen=True)
class PassportPayload:
    """Decoded PASSporT JWT payload."""
    iat: int
    orig: Optional[dict] = None    # Required by local policy
    dest: Optional[dict] = None    # Required by local policy
    evd: Optional[str] = None      # Required by local policy
    iss: Optional[str] = None
    exp: Optional[int] = None
    card: Optional[dict] = None
    goal: Optional[str] = None
    call_reason: Optional[str] = None  # Mapped from "call-reason"
    origid: Optional[str] = None

@dataclass(frozen=True)
class Passport:
    """Parsed VVP PASSporT."""
    header: PassportHeader
    payload: PassportPayload
    signature: bytes
    raw_header: str      # Base64url-encoded header (for signature verification)
    raw_payload: str     # Base64url-encoded payload (for signature verification)
```

#### 3. Parser Function

```python
def parse_passport(jwt: Optional[str]) -> Passport:
    """Parse and validate a VVP PASSporT JWT.

    Args:
        jwt: The PASSporT JWT string (header.payload.signature).

    Returns:
        Passport dataclass with parsed header, payload, and signature.

    Raises:
        PassportError: With appropriate error code on failure.

    Note:
        Signature verification is NOT performed here (deferred to Phase 4).
        This function validates structure, algorithm, and required field presence.
    """
```

#### 4. Binding Validator

```python
def validate_passport_binding(
    passport: Passport,
    vvp_identity: VVPIdentity,
    now: Optional[int] = None
) -> None:
    """Validate binding between PASSporT and VVP-Identity per §5.2.

    Args:
        passport: Parsed PASSporT.
        vvp_identity: Parsed VVP-Identity header.
        now: Current timestamp (defaults to time.time()).

    Raises:
        PassportError: If binding validation fails.

    Validates (Normative per spec):
        - ppt in PASSporT == "vvp" (§5.2)
        - ppt in PASSporT matches VVP-Identity ppt (§5.2)
        - kid in PASSporT matches VVP-Identity kid (§5.2) - strict equality
        - iat drift ≤ 5 seconds (§5.2A) - binding violation
        - exp consistency (§5.2A) - binding violation
        - PASSporT not expired (§5.2B) - expiry policy
    """
```

### Validation Rules

#### Algorithm Validation (§5.0, §5.1) - NORMATIVE

| Algorithm | Action | Error Code |
|-----------|--------|------------|
| `none` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `ES256` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `HS256`, `HS384`, `HS512` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `RS256`, `RS384`, `RS512` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `EdDSA` | Accept | - |
| Any other | Reject | `PASSPORT_FORBIDDEN_ALG` |

#### Header Binding (§5.2) - NORMATIVE

| Rule | Validation | Error Code |
|------|------------|------------|
| `ppt` value | Must be exactly "vvp" | `PASSPORT_PARSE_FAILED` |
| `ppt` match | PASSporT ppt must equal VVP-Identity ppt | `PASSPORT_PARSE_FAILED` |
| `kid` match | PASSporT kid must equal VVP-Identity kid (strict) | `PASSPORT_PARSE_FAILED` |

**Note:** Binding failures use `PASSPORT_PARSE_FAILED` (protocol layer) per §4.2A.

#### Temporal Binding (§5.2A) - NORMATIVE

| Rule | Validation | Error Code | Rationale |
|------|------------|------------|-----------|
| PASSporT iat present | Required | `PASSPORT_PARSE_FAILED` | Missing field |
| PASSporT exp > iat | If exp present, must be > iat | `PASSPORT_PARSE_FAILED` | Invalid structure |
| iat drift | `|PASSporT.iat - VVPIdentity.iat|` ≤ 5 seconds | `PASSPORT_PARSE_FAILED` | Binding violation |
| Both exp present | `|PASSporT.exp - VVPIdentity.exp|` ≤ 5 seconds | `PASSPORT_PARSE_FAILED` | Binding violation |
| VVP-Identity exp present, PASSporT exp absent | Reject (unless configured) | `PASSPORT_PARSE_FAILED` | Binding violation |

**Note:** Temporal binding violations (iat drift, exp mismatch) use `PASSPORT_PARSE_FAILED` because they are binding/protocol errors, not expiry policy failures.

#### Expiry Policy (§5.2B) - NORMATIVE (with configurable defaults)

| Rule | Validation | Error Code | Rationale |
|------|------------|------------|-----------|
| exp present | `(exp - iat)` ≤ MAX_PASSPORT_VALIDITY_SECONDS (default 300) | `PASSPORT_EXPIRED` | Validity window |
| Expiry check | `now > exp + CLOCK_SKEW_SECONDS` | `PASSPORT_EXPIRED` | Token expired |
| exp absent | `now > iat + MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS` | `PASSPORT_EXPIRED` | Max-age exceeded |

**Note:** `PASSPORT_EXPIRED` is reserved for actual expiry policy failures per §4.2A.

### Spec-Mandated vs Local Policy

| Check | Source | Treatment | Error Code |
|-------|--------|-----------|------------|
| Algorithm = EdDSA | §5.0, §5.1 | **Normative** - must enforce | `PASSPORT_FORBIDDEN_ALG` |
| ppt = "vvp" | §5.2 | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| ppt match | §5.2 | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| kid match (strict) | §5.2 | **Normative** - strict equality in Phase 3 | `PASSPORT_PARSE_FAILED` |
| iat present | §5.2A | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| iat drift ≤ 5s | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| exp > iat | §5.2A | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| exp drift ≤ 5s | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| exp consistency | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| Max validity 300s | §5.2B | **Configurable** - default 300s | `PASSPORT_EXPIRED` |
| Clock skew ±300s | §5.2B | **Configurable** - default 300s | `PASSPORT_EXPIRED` |
| Expiry check | §5.2B | **Normative** - expiry policy | `PASSPORT_EXPIRED` |
| typ field | Not in v1.4 | **Ignored** - not validated | - |
| iss field | VVP-draft | **Local Policy** - optional | - |
| orig required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |
| dest required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |
| evd required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Parsing** | |
| Missing JWT (None) | `PASSPORT_MISSING` |
| Empty JWT ("") | `PASSPORT_MISSING` |
| Malformed JWT (wrong parts count) | `PASSPORT_PARSE_FAILED` |
| Invalid base64 in header | `PASSPORT_PARSE_FAILED` |
| Invalid JSON in header | `PASSPORT_PARSE_FAILED` |
| Invalid base64 in payload | `PASSPORT_PARSE_FAILED` |
| Invalid JSON in payload | `PASSPORT_PARSE_FAILED` |
| **Algorithm (§5.0, §5.1)** | |
| `alg: "none"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "ES256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "HS256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "RS256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "EdDSA"` | Valid |
| Unknown algorithm | `PASSPORT_FORBIDDEN_ALG` |
| **Header Fields** | |
| Missing `alg` | `PASSPORT_PARSE_FAILED` |
| Missing `ppt` | `PASSPORT_PARSE_FAILED` |
| Missing `kid` | `PASSPORT_PARSE_FAILED` |
| ppt = "vvp" | Valid |
| ppt != "vvp" (e.g., "shaken") | `PASSPORT_PARSE_FAILED` |
| Missing `typ` | Valid (not required) |
| **Payload Fields** | |
| Missing `iat` | `PASSPORT_PARSE_FAILED` |
| Missing `orig` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `dest` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `evd` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `iss` | Valid (optional) |
| Valid with all optional fields | Valid |
| Valid without optional fields | Valid |
| **Binding (§5.2)** | |
| ppt mismatch with VVP-Identity | `PASSPORT_PARSE_FAILED` |
| kid mismatch with VVP-Identity | `PASSPORT_PARSE_FAILED` |
| ppt = "vvp" and matches VVP-Identity | Valid |
| **Temporal Binding (§5.2A)** | |
| iat drift > 5 seconds | `PASSPORT_PARSE_FAILED` |
| iat drift ≤ 5 seconds | Valid |
| exp < iat | `PASSPORT_PARSE_FAILED` |
| exp drift > 5 seconds (both present) | `PASSPORT_PARSE_FAILED` |
| VVP-Identity exp present, PASSporT exp absent | `PASSPORT_PARSE_FAILED` |
| **Expiry Policy (§5.2B)** | |
| exp - iat > 300 seconds | `PASSPORT_EXPIRED` |
| PASSporT expired (now > exp + skew) | `PASSPORT_EXPIRED` |
| PASSporT not expired | Valid |
| exp absent, max-age exceeded | `PASSPORT_EXPIRED` |

### Resolved Questions

1. **`typ` validation**: Not validated. The `typ` field is ignored entirely as it is not mandated by v1.4 spec.

2. **Binding failure error code**:
   - Use `PASSPORT_PARSE_FAILED` for all binding violations (ppt/kid mismatch, iat drift, exp mismatch)
   - Reserve `PASSPORT_EXPIRED` only for actual expiry policy failures (token too old, validity window exceeded)

3. **`call-reason` field mapping**: Map `call-reason` → `call_reason` in the dataclass. Store raw payload for logging/signature verification.

4. **`kid` binding**: Phase 3 implements strict equality. §5.2 allows "match or be resolvable from" - OOBI resolution will be added in Phase 4.

### Checklist Tasks Covered

- [x] 3.1 - Create `app/vvp/passport.py` module
- [x] 3.2 - Parse JWT structure (header.payload.signature)
- [x] 3.3 - Reject `alg=none`
- [x] 3.4 - Reject ES256, HMAC, RSA algorithms
- [x] 3.5 - Accept only EdDSA (Ed25519)
- [x] 3.6 - Return PASSPORT_FORBIDDEN_ALG for algorithm violations
- [x] 3.7 - Extract header claims: `alg`, `typ` (ignored), `ppt`, `kid`
- [x] 3.8 - Extract VVP payload claims: `iat` (required), `orig`, `dest`, `evd` (local policy)
- [x] 3.9 - Extract optional VVP claims: `iss`, `card`, `goal`, `call-reason`, `origid`, `exp`
- [x] 3.10 - Validate `ppt` = "vvp" and matches VVP-Identity ppt (§5.2)
- [x] 3.11 - Validate `kid` binding (strict equality in Phase 3) (§5.2)
- [x] 3.12 - Defer signature verification (placeholder for Phase 4)
- [x] 3.13 - Unit tests for PASSporT parsing

---

**Status:** IMPLEMENTED (139 tests passing)
