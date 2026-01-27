# Dossier Issues and Workarounds

This document tracks issues discovered during testing with real-world dossiers, along with any workarounds implemented. These workarounds may need to be revisited as the VVP ecosystem matures.

## Document History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-27 | 1.1 | Added DE schema, attest.creds, did:web support |
| 2026-01-27 | 1.0 | Initial document |

---

## 1. LE Schema SAID Mismatch

### Issue
The test dossier from Provenant demo (`https://origin.demo.provenant.net/`) uses an LE (Legal Entity) credential with schema SAID `EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6`, which differs from the vLEI Governance Framework's official LE schema SAID `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao`.

### Impact
Without this workaround, the vetting credential in the dossier fails schema validation, causing `DOSSIER_GRAPH_INVALID` errors.

### Workaround Applied
Added the Provenant demo LE schema SAID to the schema registry in `app/vvp/acdc/schema_registry.py`:

```python
"LE": frozenset({
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # vLEI QVI LE schema
    "EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6",  # Provenant demo LE schema
}),
```

### Future Consideration
Once vLEI governance publishes the official LE schema(s) for VVP, the registry should be audited to ensure only governance-approved SAIDs are accepted. The Provenant demo schema may need to be removed if it doesn't match the official schema.

**Registry Location**: `app/vvp/acdc/schema_registry.py`
**Registry Version**: 1.2.0

---

## 1B. DE Schema SAID Addition

### Issue
The test dossier from Provenant demo uses DE (Delegate Entity) credentials with schema SAID `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o`, which was not in the schema registry.

### Impact
Without this, DE credentials in delegation chains were classified as "unknown" type, causing `AUTHORIZATION_FAILED` errors with message "Unexpected credential type unknown in delegation chain".

### Workaround Applied
Added the Provenant demo DE schema SAID to the schema registry:

```python
"DE": frozenset({
    "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",  # Provenant demo DE schema
}),
```

**Registry Version**: 1.2.0

---

## 2. Reference Time for JWT Expiry Validation

### Issue
Test JWTs have `iat` (issued-at) timestamps from the past. The default expiry validation uses current time, causing valid-at-issuance JWTs to fail with `PASSPORT_EXPIRED` errors.

Example: A JWT with `iat=1769183302` (Jan 2025) expires after 300 seconds, so validation in Jan 2026 fails.

### Impact
Unable to test verification flow with existing test JWTs without this workaround.

### Workaround Applied
Added `reference_time` parameter to `verify_vvp()` function that allows expiry validation against a specific timestamp instead of current time:

1. **Backend**: `app/vvp/verify.py` accepts optional `reference_time` parameter
2. **UI**: Checkbox "Use JWT time for expiry check" on main page
3. **Endpoint**: `/ui/verify-result` accepts `use_jwt_time` form parameter

### UI Location
The checkbox appears in the "Full Verification" section on the main page (`/`):
```html
<input type="checkbox" id="use-jwt-time-setting" name="use_jwt_time" value="on">
<span>Use JWT time for expiry check (testing mode for old JWTs)</span>
```

### Future Consideration
This is a testing/debugging feature. In production:
- The checkbox should likely be hidden or require authentication
- Real-time verification should always use current time
- Consider adding a "freshness" threshold even when using JWT time

---

## 3. E.164 Phone Number Format Warnings

### Issue
Test PASSporTs may contain phone numbers that don't strictly conform to E.164 format (e.g., numbers with spaces, dashes, or local formatting).

### Impact
Originally caused validation errors that blocked parsing. This was overly strict for interoperability.

### Workaround Applied
Changed E.164 validation from errors to warnings:
- Non-E.164 formatted numbers now generate `SHOULD` warnings instead of `MUST` errors
- PASSporT parsing succeeds with format recommendations displayed

**Spec Reference**: VVP Spec describes E.164 as recommended format, not strictly required.

### File Modified
`app/vvp/passport.py` - `validate_passport()` function

### Future Consideration
May want to make this configurable:
- Strict mode for production (errors)
- Lenient mode for testing (warnings)

---

## 4. Dossier Structure Observations

### Test Dossier Structure
The Provenant demo dossier contains 6 ACDC credentials in this structure:

```
APE (Auth Phone Entity)
├── vetting (LE credential - Legal Entity vetting)
├── alloc (DE credential - Delegate Entity)
├── tnalloc (TNAlloc credential - TN Allocation)
├── delsig (DE credential - Delegation signature)
└── bownr (Brand Owner credential)
```

### Observed Patterns

1. **Signer Identity Path**: The PASSporT signer (`EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF`) is the `issuee` of the `delsig` credential, not directly the `issuee` of the APE.

2. **Delegation Chain**: The signer's authority derives from a delegation chain:
   - APE credential authorizes a delegate
   - Delegate issues `delsig` credential to actual signer
   - Signer signs the PASSporT

3. **Credential Types**: The dossier uses multiple credential types:
   - `vetting`: LE credential (Legal Entity vetting by QVI)
   - `alloc`, `delsig`: DE credentials (Delegate Entity)
   - `tnalloc`: TNAlloc credential (TN Allocation)
   - `bownr`: Brand credential (Brand Owner)

### Potential Issues
- `AUTHORIZATION_FAILED` errors may occur if the verifier doesn't properly traverse the delegation path through `delsig`
- The graph validation must understand that signer authorization can come through intermediate delegation credentials

---

## 5. KERI Resolution Issues

### Issue
Some credentials in the dossier may reference AIDs that cannot be resolved via OOBI.

### Observed Error
```
KERI_RESOLUTION_FAILED: Unknown signature derivation code at offset 627
```

### Impact
Credentials with unresolvable issuers are marked as having signature verification failures.

### Current Behavior
These errors are marked as `RECOVERABLE` - verification continues but the credential is flagged.

### Future Consideration
- Need to ensure OOBI endpoints are available and responsive
- May need retry logic for transient resolution failures
- Consider caching resolved key states to reduce network calls

---

## Summary Table

| Issue | Workaround | File(s) | Reversible? |
|-------|------------|---------|-------------|
| LE Schema SAID | Added to registry | `schema_registry.py` | Yes - remove SAID |
| JWT Expiry | Reference time param | `verify.py`, `main.py` | Yes - remove param |
| E.164 Format | Warnings not errors | `passport.py` | Yes - change back |
| Delegation Path | Under investigation | `verify.py` | N/A |
| KERI Resolution | Marked recoverable | `verify.py` | N/A |

---

## 6. PASSporT attest.creds Format

### Issue
The Provenant demo JWT uses `attest.creds` array format for the evidence URL instead of a top-level `evd` field:

```json
{
  "attest": {
    "creds": ["evd:https://origin.demo.provenant.net/dossier/..."]
  }
}
```

### Impact
Without this, PASSporT parsing fails with `PASSPORT_PARSE_FAILED: payload missing required field: evd`.

### Workaround Applied
Updated `app/vvp/passport.py` `_parse_payload()` to support both formats:
1. Top-level `evd` field (simple format)
2. `attest.creds[0]` with "evd:" prefix (VVP 1.0 format)

```python
evd = data.get("evd")
if evd is None:
    attest = data.get("attest")
    if isinstance(attest, dict):
        creds = attest.get("creds")
        if isinstance(creds, list) and len(creds) > 0:
            cred = creds[0]
            if isinstance(cred, str) and cred.startswith("evd:"):
                evd = cred[4:]  # Strip "evd:" prefix
```

---

## 7. DID Web to OOBI URL Conversion

### Issue
The Provenant demo JWT uses `did:web:` format for the `kid` header:
```
did:web:demo.provenant.net#EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF
```

The verifier expected an OOBI URL (starting with http:// or https://).

### Impact
Without this, signature verification fails with `kid must be an OOBI URL per §4.2, got bare AID: did:web:...`.

### Workaround Applied
1. Added `_convert_did_web_to_oobi()` helper in `app/vvp/verify.py`
2. Updated `_extract_aid_from_kid()` in `app/vvp/keri/kel_resolver.py` to handle `did:web:` format

For Provenant domain, `did:web:demo.provenant.net#AID` is converted to:
```
http://witness5.stage.provenant.net:5631/oobi/{AID}/witness
```

### Future Consideration
- Consider a configurable DID Web resolver registry
- Support other witness configurations beyond Provenant staging

---

## 8. DE Credential "issuer" Edge

### Issue
The `delsig` credential in Provenant dossiers uses an "issuer" edge instead of "delegation" edge for the delegation reference.

### Impact
Without this, the delegation chain walker couldn't find the delegation target, causing `AUTHORIZATION_FAILED: DE ... delegation edge target not found in dossier`.

### Workaround Applied
Added "issuer" to the list of recognized delegation edge names in:
1. `app/vvp/acdc/models.py` - `credential_type` property detection
2. `app/vvp/authorization.py` - `_find_delegation_target()` function

```python
if edge_name.lower() in ('delegation', 'd', 'delegate', 'delegator', 'issuer'):
```

---

## 9. Provenant Demo Dossier Unavailable

### Issue
As of 2026-01-27, the Provenant demo dossier endpoint returns HTTP 404:
```
https://origin.demo.provenant.net/dossier/EISxlyM2KTIf70TKBzaKWNKCrXomZ2YaJe-gYkR0UHY
```

### Impact
Cannot perform full verification with the test JWT as the dossier cannot be fetched.

### Current Status
- OOBI witness endpoints still work (witness4-6.stage.provenant.net:5631)
- The AID `EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF` is resolvable
- Test fixtures with dossier data exist in `tests/fixtures/trial_dossier.json`

### Future Consideration
- Need to obtain fresh test data from Provenant demo
- Consider setting up local test infrastructure for integration testing
- May need to mock dossier fetch for automated testing

---

## Summary Table

| Issue | Workaround | File(s) | Reversible? |
|-------|------------|---------|-------------|
| LE Schema SAID | Added to registry | `schema_registry.py` | Yes - remove SAID |
| DE Schema SAID | Added to registry | `schema_registry.py` | Yes - remove SAID |
| JWT Expiry | Reference time param | `verify.py`, `main.py` | Yes - remove param |
| E.164 Format | Warnings not errors | `passport.py` | Yes - change back |
| attest.creds format | Dual format support | `passport.py` | Yes - remove fallback |
| did:web kid format | OOBI conversion | `verify.py`, `kel_resolver.py` | Yes - remove conversion |
| "issuer" DE edge | Added to edge list | `models.py`, `authorization.py` | Yes - remove edge name |
| Dossier unavailable | None - external issue | N/A | N/A |
| Delegation Path | Full chain traversal | `verify.py` | N/A |
| KERI Resolution | Marked recoverable | `verify.py` | N/A |

---

## Notes for Future Development

1. **Schema Governance**: Monitor vLEI governance publications for official VVP schema SAIDs
2. **Test Data**: Maintain a set of known-good test vectors with expected validation results
3. **Error Categorization**: Continue refining which errors are recoverable vs fatal
4. **Delegation Validation**: Ensure full delegation chain traversal is working correctly
5. **DID Resolution**: Consider implementing proper DID Web resolution per spec
6. **Witness Discovery**: Add configurable witness endpoint discovery for different environments
