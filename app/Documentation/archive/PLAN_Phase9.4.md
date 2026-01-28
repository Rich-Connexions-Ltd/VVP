# Phase 9.4: TEL Resolution Architecture Fix

## Problem Statement

The TEL client is querying the **wrong endpoints** for credential revocation status. Currently:

1. The OOBI URL passed to TEL client (`https://origin.demo.provenant.net/v1/agent/public/...`) is a **KERIA agent endpoint**
2. The client derives endpoint paths like `/tels/{registry_said}` from this base URL
3. KERIA agents don't serve TEL data at these paths → all queries return **404 Not Found**
4. Fallback to hardcoded GLEIF testnet witnesses also fails (those witnesses don't have the credential's TEL)

**Observed behavior:**
```
[TEL] Querying: https://origin.demo.provenant.net/tels/EIq8De62NNDz3oXZxzHm-EW9... → 404
[TEL] Querying: https://origin.demo.provenant.net/credentials/EFraNIE0qvXSojKskl9m... → 404
[TEL] Querying: https://wit1.testnet.gleif.org:5641/tels/EIq8De62NNDz3oXZxzHm-EW9... → 404
[TEL] Final result: UNKNOWN
```

This means **revocation checking always returns INDETERMINATE** even for valid credentials with published TEL data.

## Spec References

- **§5.1.1-2.9 (Revocation Status Check)**: "Query TEL for each credential in the dossier"
- **§6.1B (Dossier Format)**: "Dossier MAY include TEL events alongside ACDCs in CESR format"
- **KERI TEL Spec**: TEL events are managed by credential registry controllers, not by the credential issuer's agent

## Current Architecture

### Data Flow (Current - Broken)
```
verify_vvp()
    │
    ├─ Dossier fetch from evd URL
    │   └─ raw_dossier: bytes (may contain TEL events - IGNORED)
    │
    ├─ parse_dossier(raw_dossier)
    │   └─ Extracts ACDCs only (JSON parsing)
    │   └─ TEL events in CESR stream are DISCARDED
    │
    └─ check_dossier_revocations(dag, oobi_url=passport.kid)
        │
        └─ TELClient.check_revocation()
            ├─ Derives base URL from passport.kid OOBI
            │   └─ WRONG: This is the PASSporT signer's agent, not TEL host
            ├─ Tries /tels/{registry} → 404
            ├─ Tries /credentials/{said} → 404
            └─ Falls back to hardcoded witnesses → 404
```

### Key Issues

1. **Wrong OOBI**: We pass `passport.header.kid` (PASSporT signer's OOBI) but credentials may have different issuers with different infrastructure

2. **Inline TEL ignored**: Raw dossier bytes may contain TEL events in CESR format, but we only parse JSON ACDCs

3. **No registry OOBI resolution**: Each credential's registry (`ri` field) has its own controller that publishes TEL - we don't discover this

4. **Witness discovery gap**: During KEL resolution we discover witness AIDs (`b` field), but not their URLs

---

## Proposed Solution

### Combined Approach: Inline TEL + Registry OOBI Discovery

Per reviewer feedback, implementing **only** inline TEL parsing is insufficient because it leaves the 404 issue unresolved for dossiers without inline TEL. This phase implements **both**:

1. **Step 1: Inline TEL Parsing** - Check if TEL events are embedded in the raw dossier (no network required)
2. **Step 2: Registry OOBI Discovery** - For credentials without inline TEL, resolve the registry's OOBI to find TEL-serving witnesses

This ensures revocation checking works for:
- Self-contained CESR dossiers with inline TEL (Step 1)
- Dossiers that reference externally-hosted TEL (Step 2)

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Inline TEL only | Simple, fast | Doesn't fix 404s for non-inline TEL | Reviewer: insufficient as sole fix |
| PASSporT signer OOBI for TEL | No extra resolution | Wrong endpoint (agent, not registry) | Root cause of 404s |
| Hardcoded witnesses only | Simple fallback | Witnesses don't have all TELs | Current broken behavior |

---

## Detailed Design

### Component 1: Binary-Safe Inline TEL Parsing

**Location**: `app/vvp/verify.py`

**Issue**: CESR dossiers may be binary (e.g., `application/octet-stream`). Naive UTF-8 decoding with `errors="replace"` can corrupt binary CESR data or miss embedded TEL events.

**Solution**: Parse raw bytes directly, looking for JSON objects within the CESR stream. The existing `_extract_tel_events()` method already handles this pattern - it searches for `{"v":"KERI` markers in text.

```python
def _parse_raw_dossier_for_tel(raw_dossier: bytes) -> str:
    """Convert raw dossier bytes to text for TEL parsing.

    CESR streams are ASCII-safe for JSON portions. Binary attachments
    (signatures, receipts) use Base64 encoding which is also ASCII-safe.
    We decode as latin-1 to preserve all byte values without replacement.
    """
    # latin-1 is byte-transparent: every byte 0x00-0xFF maps to a character
    # This preserves all data while allowing string operations for JSON extraction
    return raw_dossier.decode("latin-1")
```

### Component 2: Update `check_dossier_revocations()` Signature

**Location**: `app/vvp/verify.py`

**Current**:
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    oobi_url: Optional[str] = None
) -> Tuple[ClaimBuilder, List[str]]:
```

**Proposed**:
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    raw_dossier: Optional[bytes] = None,
    oobi_url: Optional[str] = None  # Used only for registry OOBI base URL derivation
) -> Tuple[ClaimBuilder, List[str]]:
```

### Component 3: Inline TEL + Registry OOBI Logic

**Location**: `app/vvp/verify.py` (within `check_dossier_revocations()`)

```python
async def check_dossier_revocations(
    dag: DossierDAG,
    raw_dossier: Optional[bytes] = None,
    oobi_url: Optional[str] = None
) -> Tuple[ClaimBuilder, List[str]]:
    """Check revocation status for all credentials in a dossier DAG.

    Strategy (per reviewer feedback):
    1. First check if TEL events are included inline in raw_dossier
    2. If found, use inline TEL to determine status (no network required)
    3. If not found, resolve registry OOBI to discover TEL-serving witnesses
    4. Query registry witnesses for TEL events

    The PASSporT signer's OOBI (oobi_url) is NOT used for TEL queries because
    it points to the signer's agent, not the credential registry controller.
    """
    from .keri.tel_client import get_tel_client, CredentialStatus

    claim = ClaimBuilder("revocation_clear")
    client = get_tel_client()
    revoked_saids: List[str] = []

    # Step 1: Try to extract TEL events from inline dossier (binary-safe)
    inline_tel_results: Dict[str, RevocationResult] = {}
    if raw_dossier:
        log.info("check_dossier_revocations: checking for inline TEL events")
        # Use latin-1 for byte-transparent decoding (preserves all bytes)
        dossier_text = raw_dossier.decode("latin-1")
        for said, node in dag.nodes.items():
            registry_said = node.raw.get("ri")
            result = client.parse_dossier_tel(
                dossier_text,
                credential_said=said,
                registry_said=registry_said
            )
            if result.status != CredentialStatus.UNKNOWN:
                inline_tel_results[said] = result
                log.info(f"  found inline TEL for {said[:20]}...: {result.status.value}")

    # Step 2: Check each credential
    for said, node in dag.nodes.items():
        registry_said = node.raw.get("ri")

        # Use inline result if available
        if said in inline_tel_results:
            result = inline_tel_results[said]
            log.info(f"  using inline TEL for {said[:20]}...: {result.status.value}")
        else:
            # Step 3: Resolve registry OOBI and query its witnesses
            log.info(f"  no inline TEL for {said[:20]}..., resolving registry OOBI")
            result = await _query_registry_tel(
                client,
                credential_said=said,
                registry_said=registry_said,
                base_oobi_url=oobi_url  # Used to derive registry OOBI pattern
            )

        # Process result with consistent evidence format
        if result.status == CredentialStatus.REVOKED:
            revoked_saids.append(said)
            claim.fail(ClaimStatus.INVALID, f"Credential {said[:20]}... is revoked")
            claim.add_evidence(f"revocation_source:{result.source}")
        elif result.status in (CredentialStatus.UNKNOWN, CredentialStatus.ERROR):
            if claim.status != ClaimStatus.INVALID:
                claim.fail(ClaimStatus.INDETERMINATE,
                    f"Could not determine revocation status for {said[:20]}...: {result.error or 'unknown'}")
        else:
            claim.add_evidence(f"active:{said[:16]}...|revocation_source:{result.source}")

    # Summary evidence
    total = len(dag.nodes)
    inline_count = len(inline_tel_results)
    claim.add_evidence(f"checked:{total},inline:{inline_count},queried:{total - inline_count}")

    return claim, revoked_saids
```

### Component 4: Registry OOBI Resolution

**Location**: `app/vvp/verify.py` (new helper function)

```python
async def _query_registry_tel(
    client: TELClient,
    credential_said: str,
    registry_said: Optional[str],
    base_oobi_url: Optional[str]
) -> RevocationResult:
    """Query TEL via registry OOBI resolution.

    Strategy:
    1. Construct registry OOBI URL from base OOBI pattern
    2. Resolve registry OOBI to get registry controller's witnesses
    3. Query those witnesses for TEL events

    Args:
        client: TEL client instance
        credential_said: Credential SAID to check
        registry_said: Registry SAID (from ACDC 'ri' field)
        base_oobi_url: Base OOBI URL to derive registry OOBI pattern

    Returns:
        RevocationResult from registry witnesses
    """
    if not registry_said:
        log.info(f"    no registry SAID for {credential_said[:20]}..., cannot resolve registry OOBI")
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="No registry SAID in credential",
            source="none"
        )

    # Derive registry OOBI URL from base OOBI pattern
    # Pattern: replace AID in OOBI path with registry SAID
    registry_oobi_url = None
    if base_oobi_url:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_oobi_url)
        # Construct registry OOBI: {scheme}://{netloc}/oobi/{registry_said}
        registry_oobi_url = f"{parsed.scheme}://{parsed.netloc}/oobi/{registry_said}"
        log.info(f"    constructed registry OOBI: {registry_oobi_url}")

    # Query via registry OOBI
    if registry_oobi_url:
        result = await client.check_revocation(
            credential_said=credential_said,
            registry_said=registry_said,
            oobi_url=registry_oobi_url
        )
        if result.status != CredentialStatus.ERROR:
            return result
        log.info(f"    registry OOBI query failed: {result.error}")

    # Fallback: try direct witness queries (existing behavior)
    log.info(f"    falling back to default witness queries")
    return await client.check_revocation(
        credential_said=credential_said,
        registry_said=registry_said,
        oobi_url=None  # Use default witnesses
    )
```

### Component 5: Update `verify_vvp()` Call Site

**Location**: `app/vvp/verify.py` (within `verify_vvp()`)

**Current**:
```python
if dag is not None:
    revocation_claim, revoked_saids = await check_dossier_revocations(
        dag,
        oobi_url=passport.header.kid if passport else None
    )
```

**Proposed**:
```python
if dag is not None:
    revocation_claim, revoked_saids = await check_dossier_revocations(
        dag,
        raw_dossier=raw_dossier,  # Pass raw bytes for inline TEL parsing
        oobi_url=passport.header.kid if passport else None  # For registry OOBI derivation
    )
```

### Component 6: Enhance TEL Client Logging

**Location**: `app/vvp/keri/tel_client.py`

```python
def parse_dossier_tel(
    self,
    dossier_data: str,
    credential_said: str,
    registry_said: Optional[str] = None
) -> RevocationResult:
    """Parse TEL events from a dossier CESR stream (no network request)."""
    log.info(f"parse_dossier_tel: scanning for TEL events for {credential_said[:20]}...")

    result = self._parse_tel_response(
        credential_said, registry_said, dossier_data, "dossier"
    )

    log.info(f"parse_dossier_tel: result={result.status.value} "
             f"issuance={result.issuance_event is not None} "
             f"revocation={result.revocation_event is not None}")

    return result
```

---

## Data Flow (After Fix)

```
verify_vvp()
    │
    ├─ Dossier fetch from evd URL
    │   └─ raw_dossier: bytes
    │
    ├─ parse_dossier(raw_dossier)
    │   └─ Extracts ACDCs → dag
    │
    └─ check_dossier_revocations(dag, raw_dossier, oobi_url)
        │
        ├─ Step 1: Parse raw_dossier for inline TEL events (binary-safe)
        │   └─ TELClient.parse_dossier_tel() for each credential
        │   └─ If TEL found → use it (no network needed)
        │
        └─ Step 2: For credentials without inline TEL
            ├─ Derive registry OOBI URL from base OOBI
            │   └─ {scheme}://{netloc}/oobi/{registry_said}
            ├─ Query registry OOBI for TEL events
            └─ Fallback to default witnesses if registry OOBI fails
```

---

## Test Strategy

### Unit Tests (`tests/test_revocation_checker.py`)

```python
class TestInlineTELParsing:
    """Tests for inline TEL extraction from dossier."""

    @pytest.mark.asyncio
    async def test_inline_tel_active(self):
        """Inline TEL showing ACTIVE status → VALID claim."""

    @pytest.mark.asyncio
    async def test_inline_tel_revoked(self):
        """Inline TEL showing revocation → INVALID claim."""

    @pytest.mark.asyncio
    async def test_binary_cesr_dossier(self):
        """Binary CESR dossier with TEL events parsed correctly."""


class TestRegistryOOBIDiscovery:
    """Tests for registry OOBI resolution."""

    @pytest.mark.asyncio
    async def test_registry_oobi_derived_correctly(self):
        """Registry OOBI URL constructed from base OOBI pattern."""

    @pytest.mark.asyncio
    async def test_registry_oobi_query_success(self):
        """Registry OOBI query returns TEL status."""

    @pytest.mark.asyncio
    async def test_fallback_to_default_witnesses(self):
        """Falls back to default witnesses when registry OOBI fails."""

    @pytest.mark.asyncio
    async def test_no_registry_said_returns_unknown(self):
        """Credential without registry SAID returns UNKNOWN."""


class TestEvidenceFormat:
    """Tests for consistent evidence formatting."""

    @pytest.mark.asyncio
    async def test_evidence_shows_revocation_source_dossier(self):
        """Evidence includes revocation_source:dossier for inline TEL."""

    @pytest.mark.asyncio
    async def test_evidence_shows_revocation_source_witness(self):
        """Evidence includes revocation_source:witness for queried TEL."""

    @pytest.mark.asyncio
    async def test_evidence_summary_counts(self):
        """Summary evidence shows checked, inline, queried counts."""
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify.py` | Modify | Add `raw_dossier` param, inline TEL check, registry OOBI discovery |
| `app/vvp/keri/tel_client.py` | Modify | Add logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | Modify | Add inline TEL and registry OOBI tests |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Dossier doesn't include TEL | Medium | Medium | Registry OOBI discovery as fallback |
| Registry OOBI pattern varies | Medium | Medium | Fallback to default witnesses |
| Binary CESR parsing fails | Low | Low | Use latin-1 for byte-transparent decoding |
| Registry OOBI returns 404 | Medium | Low | Fallback chain with clear logging |

---

## Resolved Questions (per Reviewer)

1. **Should we cache inline TEL results?**
   - **Answer**: No—inline parsing is cheap and dossier-specific; cache only witness queries.

2. **What if inline TEL contradicts witness TEL?**
   - **Answer**: Prefer inline TEL if it is part of the fetched dossier; if conflict is detected, surface INDETERMINATE with both sources in reasons.

3. **Should we log when falling back to witness queries?**
   - **Answer**: Yes, log at INFO with credential SAID and registry SAID.

---

## Exit Criteria

- [ ] `check_dossier_revocations()` accepts `raw_dossier` parameter
- [ ] Inline TEL events are parsed using binary-safe decoding (latin-1)
- [ ] Inline TEL status is used when available
- [ ] Registry OOBI is derived and queried when inline TEL is absent
- [ ] Fallback to default witnesses when registry OOBI fails
- [ ] Evidence uses consistent format: `revocation_source:{dossier|witness}`
- [ ] Summary evidence shows counts: `checked:{n},inline:{n},queried:{n}`
- [ ] All existing tests pass
- [ ] New inline TEL and registry OOBI tests pass
- [ ] Logging shows clear progression: inline → registry OOBI → fallback

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] Fallback still uses PASSporT signer OOBI which is wrong endpoint | Added registry OOBI discovery: derive `/oobi/{registry_said}` from base URL, query registry witnesses before falling back to defaults |
| [Medium] Naive UTF-8 decode may corrupt binary CESR | Changed to latin-1 decoding which is byte-transparent and preserves all data for JSON extraction |
| [Low] Evidence format inconsistent | Standardized to `revocation_source:{dossier\|witness}` and added summary counts |

---

## Implementation Notes

### Deviations from Plan

1. **Registry SAID handling**: When `registry_said` is None (credential has no `ri` field), the implementation now falls back to default witness queries instead of immediately returning UNKNOWN. This preserves backward compatibility with existing tests.

### Implementation Details

1. **`_query_registry_tel()` helper**: Added as a separate function for clarity. Handles:
   - No registry SAID → fall back to default witnesses
   - Registry OOBI derivation: `{scheme}://{netloc}/oobi/{registry_said}`
   - Registry OOBI query with fallback to default witnesses

2. **Logging**: Added detailed logging to `parse_dossier_tel()` showing:
   - Number of inline TEL events found
   - Event types and sequence numbers
   - Final result status

3. **Evidence format**: Active credentials show `active:{said[:16]}...|revocation_source:{source}` for traceability.

### Test Results

```
tests/test_revocation_checker.py - 20 passed
Full test suite - 440 passed, 2 skipped in 3.69s
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/verify.py` | +60 | Added `_query_registry_tel()` helper, updated `check_dossier_revocations()` with inline TEL + registry OOBI logic |
| `app/vvp/keri/tel_client.py` | +15 | Added logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | +150 | Added 5 new test classes with 7 new tests for inline TEL, registry OOBI, and binary-safe parsing |
