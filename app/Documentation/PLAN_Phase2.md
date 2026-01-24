# Current Plan

<!-- STATUS: IMPLEMENTED -->

## Phase 2: VVP-Identity Header Parser

### Overview

Implement parsing and validation of the VVP-Identity HTTP header per spec §4.1A and §4.1B.

### Spec References

- **§4.1A** - VVP-Identity Header (Decoded) structure and validation rules
- **§4.1B** - OOBI semantics for `kid` and `evd` fields
- **§4.2A** - Error codes: `VVP_IDENTITY_MISSING`, `VVP_IDENTITY_INVALID`

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/header.py` | Create | VVP-Identity header parser |
| `app/vvp/exceptions.py` | Create | Typed exceptions for error codes |
| `tests/test_header.py` | Create | Unit tests for header parsing |

### Decoded Header Structure (§4.1A)

```json
{
  "ppt": "shaken",
  "kid": "oobi:...",
  "evd": "oobi:...",
  "iat": 1737500000,
  "exp": 1737503600
}
```

**Note:** Field values shown are illustrative per §4.1A. The `ppt` value is not validated in Phase 2; only field presence is checked. Value validation (e.g., binding `ppt` to VVP PASSporT) is deferred to Phase 3/5 per §5.2.

### Implementation Approach

#### 1. Custom Exception: `VVPIdentityError`

Per reviewer recommendation, use typed exceptions to keep the parsing API clean:

```python
class VVPIdentityError(Exception):
    """Base exception for VVP-Identity parsing errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)
```

This allows the caller to convert exceptions to `ErrorDetail` while keeping the parser return type simple.

#### 2. Data Model: `VVPIdentity`

```python
@dataclass
class VVPIdentity:
    ppt: str           # PASSporT profile (value not validated in Phase 2)
    kid: str           # Key identifier (opaque OOBI reference)
    evd: str           # Evidence/dossier URL (opaque OOBI reference)
    iat: int           # Issued-at timestamp (seconds since epoch)
    exp: int           # Expiry timestamp (computed if absent in header)
```

#### 3. Parser Function: `parse_vvp_identity(header: Optional[str]) -> VVPIdentity`

Steps:
1. If `header` is `None` or empty, raise `VVPIdentityError` with `VVP_IDENTITY_MISSING`
2. Base64url decode the header string
3. Parse as JSON
4. Validate required fields exist: `ppt`, `kid`, `evd`, `iat`
5. Validate `iat` is not in the future beyond clock skew
6. Handle optional `exp`; if absent, compute default expiry as `iat + MAX_TOKEN_AGE_SECONDS`
7. Return `VVPIdentity` dataclass

On any decode/parse/validation failure (steps 2-6), raise `VVPIdentityError` with `VVP_IDENTITY_INVALID`.

#### 4. Validation Rules (§4.1A)

| Rule | Implementation | Error Code |
|------|----------------|------------|
| Header absent/empty | Raise before decoding | `VVP_IDENTITY_MISSING` |
| Base64url decode failure | `base64.urlsafe_b64decode()` with padding fix | `VVP_IDENTITY_INVALID` |
| Malformed JSON | `json.loads()` | `VVP_IDENTITY_INVALID` |
| Missing required field | Check `ppt`, `kid`, `evd`, `iat` exist | `VVP_IDENTITY_INVALID` |
| `iat` in future beyond skew | Compare to `now + CLOCK_SKEW_SECONDS` | `VVP_IDENTITY_INVALID` |
| `exp` absent | Compute as `iat + MAX_TOKEN_AGE_SECONDS` | N/A (valid) |

#### 5. OOBI Field Handling (§4.1B)

**Critical:** `kid` and `evd` fields are OOBI (Out-Of-Band Introduction) references per §4.1B. In Phase 2:

- Treat `kid` and `evd` as **opaque strings**
- **DO NOT** apply URL normalization
- **DO NOT** apply generic URL validation that could reject OOBI schemes
- Only validate that the fields are **present and non-empty strings**
- Deep OOBI validation (KERI/CESR parsing, `application/json+cesr` support) is deferred to Phase 4

This ensures we don't reject valid OOBI references that don't conform to standard URL patterns.

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| Missing header (None) | `VVP_IDENTITY_MISSING` |
| Empty header ("") | `VVP_IDENTITY_MISSING` |
| Valid header with all fields | Returns `VVPIdentity` |
| Valid header without `exp` | Returns `VVPIdentity` with computed expiry |
| Invalid base64 | `VVP_IDENTITY_INVALID` |
| Invalid JSON | `VVP_IDENTITY_INVALID` |
| Missing `ppt` | `VVP_IDENTITY_INVALID` |
| Missing `kid` | `VVP_IDENTITY_INVALID` |
| Missing `evd` | `VVP_IDENTITY_INVALID` |
| Missing `iat` | `VVP_IDENTITY_INVALID` |
| `iat` in future beyond skew | `VVP_IDENTITY_INVALID` |
| `iat` in future within skew | Valid (accepted) |
| `ppt` with any string value | Valid (value not validated in Phase 2) |
| `kid`/`evd` with non-URL OOBI format | Valid (treated as opaque) |

### Resolved Questions

Based on reviewer feedback:

1. **OOBI validation**: Defer KERI/CESR parsing to Phase 4. In Phase 2, treat `kid`/`evd` as opaque OOBI references. Avoid URL-specific validation that could reject valid OOBI schemes.

2. **Error return style**: Raise typed `VVPIdentityError` exceptions carrying error codes. This keeps the parser API clean (`-> VVPIdentity`) and allows the caller to convert to `ErrorDetail`.

3. **`ppt` value validation**: Only require presence in Phase 2. Actual value checks (`ppt == "vvp"` for VVP PASSporTs) must be done in Phase 3/5 when binding PASSporT to VVP-Identity per §5.2.

### Checklist Tasks Covered

- [x] 2.1 - Create `app/vvp/header.py` module
- [x] 2.2 - Implement base64url decoding of VVP-Identity header
- [x] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [x] 2.4 - Validate `ppt` field exists (value validation deferred to Phase 3)
- [x] 2.5 - Validate `kid` and `evd` are present as opaque strings (OOBI validation deferred)
- [x] 2.6 - Implement clock skew validation (±300s) on `iat`
- [x] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [x] 2.8 - Reject future `iat` beyond clock skew
- [x] 2.9 - Return structured errors: `VVP_IDENTITY_MISSING` vs `VVP_IDENTITY_INVALID`
- [x] 2.10 - Unit tests for header parsing

---

**Status:** Implemented
