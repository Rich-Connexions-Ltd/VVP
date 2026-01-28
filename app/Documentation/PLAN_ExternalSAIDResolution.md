# Phase: External SAID Resolution from Witnesses

**Status:** IMPLEMENTED
**Date:** 2026-01-28

## Problem Statement

When a compact ACDC has edge references to credentials not included in the dossier, the verifier returns INDETERMINATE per VVP §2.2. However, these external credentials may be resolvable from KERI witnesses via their credential registry endpoints.

**User requirement:** "If the SAIDs are not included in the dossier can we attempt to retrieve those SAIDs from the witness in the dossier?"

## Spec References

- **VVP §2.2**: "Uncertainty must be explicit" - INDETERMINATE when verification cannot determine status definitively
- **VVP §1.4**: Verifiers MUST support ACDC variants (compact, partial, aggregate)
- **VVP §6.3.x**: Credential chain validation rules for APE/DE/TNAlloc

## Current State

### Detection Points (where INDETERMINATE is set)

1. **verifier.py:255-277** - `validate_edge_semantics()`: Edge target SAID not in dossier
2. **verifier.py:566-578** - `walk_chain()`: Parent SAID from edge not in `dossier_acdcs`

### Current behavior
```python
if parent_said not in dossier_acdcs:
    current_variant = getattr(current, 'variant', 'full')
    if current_variant == 'compact':
        errors.append(f"Cannot verify edge target {parent_said[:20]}...")
        chain_status = ClaimStatus.INDETERMINATE
        return None  # Cannot verify chain
```

### Available Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| TELClient | tel_client.py | Has witness query patterns, `/credentials/{said}` endpoint |
| OOBI dereferencing | oobi.py | HTTP client patterns with timeout, error handling |
| Key state cache | cache.py | Two-level caching pattern with TTL and LRU |
| Config | config.py | Environment variable patterns for feature flags |

---

## Implemented Solution

### Approach

Created a **`CredentialResolver`** module that attempts to fetch missing credentials from witnesses BEFORE falling back to INDETERMINATE.

**Why this approach?**
- Separates credential fetching from TEL (revocation) queries
- Keeps verifier.py focused on validation logic
- Testable in isolation with mocked HTTP

### Data Flow

```
1. walk_chain() encounters edge target not in dossier_acdcs
                |
                v
2. Check if credential_resolver is enabled
                |
        +-------+-------+
        |               |
    Disabled        Enabled
        |               |
        v               v
    INDETERMINATE   3. Query witnesses at /credentials/{said}
                           |
                           v
                    4. Parse CESR response, extract ACDC
                           |
                           v
                    5. Validate SAID matches, verify signature
                           |
                    +------+------+
                    |             |
                Valid         Invalid/Not found
                    |             |
                    v             v
            6. Add to dossier_acdcs  7. INDETERMINATE (compact)
               Continue validation       or INVALID (full)
```

---

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/keri/credential_resolver.py` | **Created** | New CredentialResolver class |
| `app/vvp/keri/credential_cache.py` | **Created** | Credential-specific cache |
| `app/core/config.py` | Modified | Add configuration constants |
| `app/vvp/acdc/verifier.py` | Modified | Integrate resolver into chain validation |
| `app/vvp/verify.py` | Modified | Pass resolver and witness URLs |
| `app/vvp/keri/__init__.py` | Modified | Export new components |
| `tests/test_credential_resolver.py` | **Created** | Unit tests for resolver |
| `tests/test_credential_cache.py` | **Created** | Unit tests for cache |
| `tests/test_acdc.py` | Modified | Integration tests for external resolution |

---

## Detailed Design

### 1. Configuration (config.py)

```python
# SPRINT 25: EXTERNAL SAID RESOLUTION (§2.2 / §1.4)
EXTERNAL_SAID_RESOLUTION_ENABLED: bool = os.getenv(
    "VVP_EXTERNAL_SAID_RESOLUTION", "false"
).lower() == "true"

EXTERNAL_SAID_RESOLUTION_TIMEOUT: float = float(
    os.getenv("VVP_EXTERNAL_SAID_TIMEOUT", "5.0")
)

EXTERNAL_SAID_MAX_DEPTH: int = int(
    os.getenv("VVP_EXTERNAL_SAID_MAX_DEPTH", "3")
)

EXTERNAL_SAID_CACHE_TTL_SECONDS: int = int(
    os.getenv("VVP_EXTERNAL_SAID_CACHE_TTL", "300")
)

EXTERNAL_SAID_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_EXTERNAL_SAID_CACHE_MAX_ENTRIES", "500")
)
```

**Default: disabled** - Opt-in feature to avoid unexpected network calls.

### 2. CredentialResolver (credential_resolver.py)

```python
@dataclass
class ResolvedCredential:
    acdc: ACDC
    source_url: str
    signature: Optional[bytes]

class CredentialResolver:
    def __init__(self, config: CredentialResolverConfig = None):
        self._config = config or CredentialResolverConfig()
        self._cache: Dict[str, ResolvedCredential] = {}
        self._in_flight: Set[str] = set()  # Recursion guard

    async def resolve(
        self,
        said: str,
        witness_base_urls: List[str],
    ) -> Optional[ResolvedCredential]:
        """
        Attempt to resolve a credential SAID from witnesses.

        Returns:
            ResolvedCredential if found and valid, None otherwise
        """
        # 1. Check cache
        # 2. Check recursion guard
        # 3. Query witnesses in parallel (first 3)
        # 4. Parse CESR response
        # 5. Validate SAID matches
        # 6. Cache and return
```

### 3. Verifier Integration (verifier.py)

Modified `walk_chain()` at line ~566:

```python
if parent_said not in dossier_acdcs:
    # NEW: Attempt external resolution if enabled
    resolved = False
    if credential_resolver and witness_urls:
        result = await credential_resolver.resolve(parent_said, witness_urls)
        if result:
            dossier_acdcs[parent_said] = result.acdc
            log.info(f"Resolved external credential {parent_said[:20]}...")
            resolved = True
    if not resolved:
        # Resolution failed, fall back to current behavior
        if current_variant == 'compact':
            chain_status = ClaimStatus.INDETERMINATE
            return None
        raise ACDCChainInvalid(...)
```

### 4. Orchestration (verify.py)

Pass resolver to `validate_credential_chain()`:

```python
# Extract witness URL from PASSporT kid
if EXTERNAL_SAID_RESOLUTION_ENABLED and witness_urls:
    credential_resolver = CredentialResolver(
        config=CredentialResolverConfig(
            enabled=True,
            timeout_seconds=EXTERNAL_SAID_RESOLUTION_TIMEOUT,
            max_recursion_depth=EXTERNAL_SAID_MAX_DEPTH,
        )
    )
```

---

## Error Handling Strategy

| Error Type | Behavior | Result |
|------------|----------|--------|
| Network timeout | Log warning | INDETERMINATE |
| HTTP 404 | Credential not found | INDETERMINATE |
| HTTP 5xx | Server error | INDETERMINATE |
| Parse error | Invalid CESR/JSON | INDETERMINATE |
| SAID mismatch | Fetched credential has wrong SAID | INDETERMINATE |
| Signature invalid | Crypto verification failed | **INVALID** |
| Recursion limit | Too many nested externals | INDETERMINATE |

**Key principle:** Only signature verification failure produces INVALID. All other resolution failures are recoverable and produce INDETERMINATE.

---

## Test Results

```
1463 passed in 99.32s
```

---

## Implementation Notes

### Deviations from Plan

None - implementation followed the approved plan.

### Review Fixes Applied

1. **Signature verification for resolved credentials** (verifier.py:589-653)
   - When credential resolved WITH signature: verify against issuer key state
   - Verification success → VALID path possible
   - Verification failure → INVALID (cryptographic failure)
   - Key resolution failure → INDETERMINATE

2. **CESR response parsing** (credential_resolver.py:371-391)
   - Uses `parse_cesr_stream()` for proper attachment handling
   - Extracts signatures from `-A` controller signature attachments
   - Falls back to plain JSON if CESR parsing fails

3. **Cache config wiring** (verify.py:923-975)
   - `EXTERNAL_SAID_CACHE_TTL_SECONDS` and `EXTERNAL_SAID_CACHE_MAX_ENTRIES` now passed to resolver

### Key Technical Details

1. **Async walk_chain**: Made `walk_chain()` async to support async credential resolution
2. **Parallel witness queries**: Up to 3 witnesses queried in parallel for faster resolution
3. **Recursion guard**: `_in_flight` set prevents infinite loops when credentials reference each other
4. **LRU cache with TTL**: Credential cache uses same pattern as key state cache
5. **Signature verification**: Resolved credentials with signatures are cryptographically verified
6. **INDETERMINATE for unverified**: Credentials without signatures cannot produce VALID

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +15 | Added 5 configuration constants |
| `app/vvp/keri/credential_cache.py` | +200 | New credential cache module |
| `app/vvp/keri/credential_resolver.py` | +250 | New credential resolver module with CESR parsing |
| `app/vvp/acdc/verifier.py` | +80 | Added resolver integration with signature verification |
| `app/vvp/verify.py` | +30 | Pass resolver with full cache config when enabled |
| `app/vvp/keri/__init__.py` | +15 | Export new components |
| `tests/test_credential_cache.py` | +276 | Cache unit tests |
| `tests/test_credential_resolver.py` | +520 | Resolver unit tests including CESR parsing |
| `tests/test_acdc.py` | +130 | Integration tests including signature behavior |
