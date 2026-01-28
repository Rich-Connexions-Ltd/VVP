# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 4: Ed25519 Signature Verification (Tier 1)

### Overview

Implement PASSporT signature verification using Ed25519 (pysodium). This is a Tier 1 implementation that directly extracts the public key from the KERI AID embedded in the `kid` field. Full KERI integration (historical key state lookup, KEL validation, witness receipts) is deferred to Tier 2.

### Spec References

- **§5.0** - VVP mandates EdDSA (Ed25519) for PASSporT signatures
- **§5.3** - Historical key state at reference time T (deferred to Tier 2)
- **§4.2A** - Error codes: PASSPORT_SIG_INVALID, KERI_RESOLUTION_FAILED

### Tier 1 Scope

**Implemented:**
- Parse KERI AID to extract Ed25519 public key
- Verify Ed25519 signature using pysodium
- Support B (transferable) and D (non-transferable) prefix codes

**Deferred to Tier 2:**
- Historical key state lookup at time T
- KEL/witness receipt validation
- Key rotation/revocation checking
- OOBI dereferencing with `application/json+cesr`

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/keri/__init__.py` | Create | Package init with exports |
| `app/vvp/keri/exceptions.py` | Create | KeriError, SignatureInvalidError, ResolutionFailedError |
| `app/vvp/keri/key_parser.py` | Create | parse_kid_to_verkey() |
| `app/vvp/keri/signature.py` | Create | verify_passport_signature() |
| `tests/test_signature.py` | Create | Unit tests for signature verification |
| `pyproject.toml` | Modify | Add pysodium dependency |

### Implementation Approach

#### 1. Exception Hierarchy

```python
class KeriError(Exception):
    """Base exception for KERI-related errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

class SignatureInvalidError(KeriError):
    """Signature cryptographically invalid → INVALID (non-recoverable)."""

class ResolutionFailedError(KeriError):
    """Could not resolve/parse identifier → INDETERMINATE (recoverable)."""
```

#### 2. Key Parser

KERI AID format: `<derivation_code><base64url_key>`
- `B` prefix = Ed25519 transferable (43 chars key)
- `D` prefix = Ed25519 non-transferable (43 chars key)

```python
@dataclass(frozen=True)
class VerificationKey:
    raw: bytes    # 32-byte Ed25519 public key
    aid: str      # Original AID (for logging)
    code: str     # KERI derivation code

def parse_kid_to_verkey(kid: str) -> VerificationKey:
    """Parse kid (KERI AID) to extract Ed25519 public key.

    Raises:
        ResolutionFailedError: Format invalid or unsupported algorithm
    """
```

#### 3. Signature Verification

JWT signing input: `base64url(header).base64url(payload)`

```python
def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT Ed25519 signature.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID)
        ResolutionFailedError: Could not resolve kid to key (→ INDETERMINATE)
    """
```

### Validation Rules

| Check | Action | Error Code |
|-------|--------|------------|
| kid format invalid | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Unsupported derivation code | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Invalid base64 in kid | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Key length ≠ 32 bytes | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Signature verification fails | Reject | PASSPORT_SIG_INVALID (non-recoverable) |
| Signature valid | Accept | - |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Key Parsing** | |
| Valid B-prefix AID | Returns VerificationKey |
| Valid D-prefix AID | Returns VerificationKey |
| Unsupported prefix (E, F, etc.) | KERI_RESOLUTION_FAILED |
| Invalid base64 in AID | KERI_RESOLUTION_FAILED |
| Too short AID | KERI_RESOLUTION_FAILED |
| Wrong key length | KERI_RESOLUTION_FAILED |
| **Signature Verification** | |
| Valid signature | Passes |
| Invalid signature | PASSPORT_SIG_INVALID |
| Tampered header | PASSPORT_SIG_INVALID |
| Tampered payload | PASSPORT_SIG_INVALID |
| Wrong key | PASSPORT_SIG_INVALID |
| Malformed kid | KERI_RESOLUTION_FAILED |

### Checklist Tasks Covered

- [x] 4.1 - Add pysodium to dependencies
- [x] 4.13 - Implement Ed25519 signature verification
- [x] 4.14 - Handle transient failures → INDETERMINATE
- [x] 4.15 - Handle cryptographically invalid state → INVALID
- [x] 4.16 - Unit tests for signature verification

### Deferred Tasks (Tier 2)

- [ ] 4.2 - Create resolver.py module
- [ ] 4.3 - Initialize KERI database (Habery context)
- [ ] 4.4 - Implement KeriResolver.resolve() for historical key state
- [ ] 4.5 - Implement OOBI dereferencing for kid field
- [ ] 4.6 - Validate OOBI content-type is application/json+cesr
- [ ] 4.7 - Handle OOBI fetch failures
- [ ] 4.8 - Implement KEL parsing
- [ ] 4.9 - Implement KERI/CESR version handling
- [ ] 4.10 - Historical key state lookup at reference time T
- [ ] 4.11 - Validate witness receipts at reference time T
- [ ] 4.12 - Check for key rotation/revocation prior to T

### Test Results

```
161 passed (141 prior + 20 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `9c1900a`
