# Current Plan

<!-- STATUS: READY_FOR_REVIEW -->

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
| `tests/test_header.py` | Create | Unit tests for header parsing |

### Decoded Header Structure (§4.1A)

```json
{
  "ppt": "vvp",
  "kid": "oobi:...",
  "evd": "oobi:...",
  "iat": 1737500000,
  "exp": 1737503600
}
```

### Implementation Approach

#### 1. Data Model: `VVPIdentity`

```python
@dataclass
class VVPIdentity:
    ppt: str           # PASSporT profile (e.g., "vvp")
    kid: str           # Key identifier (OOBI reference)
    evd: str           # Evidence/dossier URL (OOBI reference)
    iat: int           # Issued-at timestamp (seconds since epoch)
    exp: Optional[int] # Optional expiry timestamp
```

#### 2. Parser Function: `parse_vvp_identity(header: str) -> VVPIdentity`

Steps:
1. Base64url decode the header string
2. Parse as JSON
3. Validate required fields exist: `ppt`, `kid`, `evd`, `iat`
4. Validate `iat` is not in the future beyond clock skew
5. Handle optional `exp`; if absent, compute default expiry as `iat + MAX_TOKEN_AGE_SECONDS`
6. Return `VVPIdentity` dataclass or raise appropriate error

#### 3. Validation Rules (§4.1A)

| Rule | Implementation |
|------|----------------|
| Base64url decode | `base64.urlsafe_b64decode()` with padding fix |
| Malformed JSON | Return `VVP_IDENTITY_INVALID` |
| Missing required field | Return `VVP_IDENTITY_INVALID` |
| `iat` in future beyond skew | Return `VVP_IDENTITY_INVALID` |
| `exp` absent | Use `iat + 300` as effective expiry |

#### 4. Error Handling

```python
def parse_vvp_identity(header: str) -> Union[VVPIdentity, ErrorDetail]:
    # Returns VVPIdentity on success, ErrorDetail on failure
```

Or alternatively, raise custom exceptions that map to error codes.

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
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

### Open Questions

1. **OOBI validation**: Should we validate that `kid` and `evd` look like OOBI references in Phase 2, or defer to Phase 4 (KERI Integration)?
   - Recommendation: Defer deep OOBI validation to Phase 4; in Phase 2, just ensure they're non-empty strings.

2. **Error return style**: Return `Union[VVPIdentity, ErrorDetail]` or raise exceptions?
   - Recommendation: Raise exceptions with error codes; caller converts to `ErrorDetail`.

3. **`ppt` value validation**: §4.1A shows `"ppt": "vvp"` but earlier versions showed `"shaken"`. Should we validate the value or just ensure it exists?
   - Recommendation: Per §5.2, `ppt` must be `"vvp"` for VVP passports. Validate in Phase 3 when binding to PASSporT.

### Checklist Tasks Covered

- [ ] 2.1 - Create `app/vvp/header.py` module
- [ ] 2.2 - Implement base64url decoding of VVP-Identity header
- [ ] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [ ] 2.4 - Validate `ppt` field exists
- [ ] 2.5 - Validate `kid` and `evd` are present (OOBI validation deferred)
- [ ] 2.6 - Implement clock skew validation (±300s) on `iat`
- [ ] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [ ] 2.8 - Reject future `iat` beyond clock skew
- [ ] 2.9 - Return structured errors for all failure modes
- [ ] 2.10 - Unit tests for header parsing

---

**Status:** Ready for reviewer feedback
