# Sprint 79: Provenant Brand Schema & Logo Integrity

## Problem Statement

The VVP draft spec (§4.1.2) requires the PASSporT `card` claim to include `LOGO;HASH=<SAID>;VALUE=URI:<url>`, where the HASH is a Blake3-256 CESR-encoded digest of the logo image. The canonical Provenant brand-owner schema stores brand data as a `vcard` array of RFC 6350 property strings in the credential attributes — the vetter computes and embeds the logo hash at issuance time, and the ACDC signature covers it.

Our current Extended Brand Credential schema uses separate scalar fields (`brandName`, `logoUrl`, etc.) with **no logo hash**. This creates a security gap:

1. **No cryptographic commitment to the logo at credential issuance** — the logo at `logoUrl` can be swapped after issuance with no detection
2. **No integrity verification at call time** — the SIP verifier passes the raw external URL in `X-VVP-Brand-Logo` without fetching or verifying
3. **Privacy/latency concerns** — the handset must fetch from an arbitrary external CDN

## Spec References

- §4.1.2: `card` claim attributes "MUST conform to the VCard standard [RFC6350]"
- §4.1.2 sample: `"LOGO;HASH=EK2...;VALUE=URI:https://example.com/ico64x48.png"`
- §5A Step 12: "MUST verify brand attributes are justified by brand credential"
- §6.3.7: Brand credential "enumerates brand properties such as a brand name, logo, chatbot URL"
- Provenant schema: `HASH parameter SHOULD be included and MUST be the CESR-encoded value of the content at the URI`

## Current State

### Extended Brand Credential (our schema)
```json
"a": {
  "brandName": "ACME Corp",         // scalar string
  "brandDisplayName": "ACME",        // scalar string
  "logoUrl": "https://cdn.acme.com/logo.png",  // plain URI, no hash
  "websiteUrl": "https://acme.com",  // plain URI
  "assertionCountry": "GBR"
}
```

### Provenant Brand Owner Schema (upstream/canonical)
```json
"a": {
  "i": "<brand-owner-AID>",
  "dt": "2025-01-01T00:00:00.000000+00:00",
  "vcard": [
    "ORG:ACME Corporation",
    "NICKNAME:ACME Corp",
    "LOGO;HASH=EK2r6EnDXre...;VALUE=URI:https://cdn.acme.com/logo.png",
    "URL:https://www.acme.com",
    "TEL;VALUE=URI:tel:+441923311000"
  ],
  "goals": ["sales", "support"]
}
```

### Card Builder (`services/issuer/app/vvp/card.py`)
Currently reads scalar fields and constructs vCard lines:
```python
card.append(f"LOGO;VALUE=URI:{logo_url}")  # No HASH parameter
```

### SIP Verifier (`services/sip-verify/app/verify/handler.py`)
Passes raw external URL directly:
```python
response_vvp_headers["X-VVP-Brand-Logo"] = response.brand_logo_url
```

### Verifier Brand Detection (`services/verifier/app/vvp/brand.py`)
Detects brand credentials by presence of `BRAND_INDICATOR_FIELDS = {"fn", "org", "logo", "url", "photo", "brandName", "brandDisplayName", "logoUrl", "websiteUrl"}`. Does not recognize `vcard` array.

## Proposed Solution

### Approach

Adopt the Provenant brand-owner schema's `vcard` array approach for brand credentials, compute and embed a Blake3-256 SAID of the logo image at credential issuance time, and implement a logo integrity proxy in the SIP verification service.

This is a three-phase change:
1. **Schema migration** — Brand credentials store vCard lines (including logo hash) instead of scalar fields
2. **Logo proxy** — SIP verifier fetches, verifies, and caches logos before delivering to handsets
3. **Backward compatibility** — Old scalar-attribute credentials continue to work (without hash verification)

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Add `logoHash` field to existing schema | Minimal schema change | Diverges from upstream Provenant schema; still uses non-standard scalar layout | Non-standard; would need to be changed again to align with ecosystem |
| Embed logo as base64 in credential | No external fetch needed | Bloats credential (logos can be 10-100KB); CESR size limits | Impractical for image data |
| Keep scalar fields, add hash at PASSporT creation only | No schema change | Hash not in credential — signed by caller, not vetter; no integrity commitment at issuance | Defeats purpose: vetter attestation should cover the logo |

### Detailed Design

#### Component 1: Shared Utilities in `common/`

**Purpose**: Centralize vCard parsing, logo fetching/hashing, and brand normalization to avoid duplication across services. All services import from `common/` — no service-local implementations of these primitives.

**Terminology**: "vCard" refers to the RFC 6350 standard; `vcard` (lowercase, monospace) refers to the JSON attribute name in credential schemas.

##### 1a: vCard Parser (`common/common/vvp/vcard/parser.py`)

Focused on syntax only — no domain/brand logic:
```python
@dataclass
class VCardProperty:
    name: str           # e.g. "LOGO", "ORG" (normalized to uppercase)
    value: str          # e.g. "https://cdn.acme.com/logo.png"
    params: dict[str, str]  # e.g. {"HASH": "EK2r...", "VALUE": "URI"}

def parse_vcard_lines(lines: list[str]) -> list[VCardProperty]:
    """Parse RFC 6350 vCard property lines into structured objects.
    Case-insensitive property name matching. Parameter order irrelevant.
    Supports multi-value properties (multiple lines with same name).
    """

def parse_vcard_line(line: str) -> VCardProperty:
    """Parse a single vCard property line."""

def find_property(properties: list[VCardProperty], name: str) -> VCardProperty | None:
    """Find first property by name (case-insensitive)."""

def find_all_properties(properties: list[VCardProperty], name: str) -> list[VCardProperty]:
    """Find all properties by name (case-insensitive). For multi-value (TEL, URL)."""
```

##### 1b: Brand Projection (`common/common/vvp/vcard/brand.py`)

Domain-specific brand extraction from vCard data:
```python
@dataclass
class NormalizedBrand:
    """Normalized brand data from any credential format."""
    name: str
    display_name: str | None = None
    logo_url: str | None = None
    logo_hash: str | None = None  # SAID from LOGO HASH param
    website_url: str | None = None

def normalize_brand(attributes: dict, schema_said: str | None = None) -> NormalizedBrand | None:
    """Normalize brand data from either vcard-array or scalar-attribute credentials.
    Single entry point — all downstream code consumes NormalizedBrand only.
    Returns None if attributes don't contain brand data."""

def extract_brand_from_vcard(lines: list[str]) -> NormalizedBrand:
    """Extract brand fields from vCard lines."""

def extract_brand_from_scalars(attributes: dict) -> NormalizedBrand:
    """Extract brand fields from legacy scalar attributes (backward compat)."""
```

##### 1c: vCard Comparison (`common/common/vvp/vcard/comparison.py`)

Credential vs PASSporT card claim matching:
```python
@dataclass
class ComparisonResult:
    match: bool
    mismatches: list[str]  # Human-readable diff descriptions
    hash_integrity: str    # "verified" | "missing" | "omitted_from_card"

def vcard_properties_match(
    credential_lines: list[str], card_claim_lines: list[str]
) -> ComparisonResult:
    """Compare credential vCard lines against PASSporT card claim lines.
    Case-insensitive property name matching.
    Multi-value properties compared as sets (order-independent).
    If credential has HASH but card claim omits it → match=False (HASH downgrade attack).
    Returns ComparisonResult with explicit hash_integrity status.
    """
```

**HASH enforcement**: If the credential LOGO line contains a HASH parameter but the card claim LOGO line omits it, `match` is `False` and `hash_integrity` is `"omitted_from_card"`. This prevents a HASH-downgrade attack where a malicious OP strips the hash to bypass logo integrity verification.

##### 1d: Logo Hash & Fetch (`common/common/vvp/logo_hash.py`)

Shared hashing and logo fetch pipeline:
```python
def compute_said_from_bytes(data: bytes) -> str:
    """Compute Blake3-256 SAID from raw bytes.
    Uses existing KERI/CESR digest primitives — no hand-rolled encoding.
    Returns 44-character CESR-encoded string with E prefix.
    Validates result starts with 'E' (Blake3 derivation code).
    """

LOGO_CONTENT_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}

def validate_logo_content_type(content_type: str) -> bool:
    """Check content-type is in allowlist. SVG excluded (script risk)."""

SAID_PATTERN = re.compile(r'^E[A-Za-z0-9_-]{43}$')  # Must start with E (Blake3)

def validate_said_format(said: str) -> bool:
    """Validate SAID starts with E, is exactly 44 chars, base64url-safe alphabet."""

LOGO_MAX_BYTES = 2 * 1024 * 1024  # 2MB

async def fetch_validate_hash(
    logo_url: str, http_client: httpx.AsyncClient,
    expected_said: str | None = None, timeout: float = 10.0
) -> tuple[bytes, str]:
    """Shared fetch→validate→hash pipeline for logo images.

    Used by both issuer (at issuance) and sip-verify (at verification).
    1. SSRF validation on URL
    2. Stream response with LOGO_MAX_BYTES hard limit
    3. Validate Content-Type against LOGO_CONTENT_TYPES
    4. Compute Blake3-256 SAID
    5. If expected_said provided, verify match
    6. Redact query/fragment from URL in all log messages

    Args:
        logo_url: URL to fetch
        http_client: Shared httpx.AsyncClient (caller provides)
        expected_said: If set, verify computed SAID matches
        timeout: HTTP timeout

    Returns:
        (image_bytes, computed_said)

    Raises:
        LogoFetchError: fetch failure, content-type invalid, size exceeded
        LogoHashMismatchError: computed SAID != expected_said
    """
```

**Key design**: Single `fetch_validate_hash()` function used by both issuer and sip-verify. Caller provides the shared `httpx.AsyncClient` (from `common.vvp.http_client`). Issuer calls without `expected_said` (computing hash for first time). Sip-verify calls with `expected_said` (verifying cached hash matches).

**Behavior**:
- Uses existing KERI CESR digest primitives — no hand-rolled base64url manipulation
- SAID validation enforces `E` prefix (Blake3 derivation code) + 44-char length
- vCard parsing is case-insensitive for property names and parameter-order-independent
- Multi-value properties (multiple TEL, URL lines) parsed as lists, compared as sets
- Content-type validation uses an allowlist — SVG excluded due to script injection risk
- URL logging redacts query/fragment to prevent token leakage

#### Component 2: Provenant Brand Owner Schema Registration

**Purpose**: Register the canonical Provenant brand-owner schema (or a VVP-specific derivative) in the issuer's schema registry.

**Location**: `services/issuer/app/schema/schemas/provenant-brand-owner.json`

**Interface**: Standard ACDC schema with `vcard` array attribute:
```json
{
  "$id": "<computed-SAID>",
  "title": "VVP Brand Owner Credential",
  "description": "Brand credential with vCard attributes and logo hash integrity per Provenant brand-owner schema",
  "properties": {
    "a": {
      "properties": {
        "d": { "type": "string" },
        "u": { "type": "string" },
        "i": { "type": "string", "description": "Brand owner AID" },
        "dt": { "format": "date-time", "type": "string" },
        "vcard": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1,
          "description": "Unfolded VCard content lines per RFC 6350. Property names uppercase, parameters in lexicographic order."
        },
        "goals": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Goal codes for permitted brand activities (optional)"
        }
      },
      "required": ["d", "u", "i", "dt", "vcard"]
    },
    "e": {
      "properties": {
        "d": { "type": "string" },
        "issuer": {
          "description": "Edge to issuer identity credential",
          "properties": {
            "n": { "type": "string" },
            "s": { "type": "string" },
            "o": { "type": "string", "const": "I2I" }
          },
          "required": ["n", "s"]
        },
        "certification": {
          "description": "Edge to vetter certification credential",
          "properties": {
            "n": { "type": "string" },
            "s": { "type": "string" }
          },
          "required": ["n", "s"]
        }
      },
      "required": ["d", "certification"]
    }
  }
}
```

**Behavior**: The Extended Brand Credential schema remains registered for backward compatibility. New credentials should use the Provenant-style schema. The schema registry's `get_schema()` returns whichever schema matches the credential's `s` field.

**Schema SAID**: Registered in the schema registry. The brand-owner schema SAID will be recorded as `VVP_BRAND_OWNER_SCHEMA_SAID` constant in `common/common/vvp/schema/constants.py` for use by brand detection logic.

#### Component 3: Logo Fetch & Hash at Issuance

**Purpose**: Thin wrapper calling shared `fetch_validate_hash()` from `common/`.

**Location**: `services/issuer/app/vvp/logo_hash.py` (new, thin wrapper — ~15 lines)

**Interface**:
```python
async def fetch_and_hash_logo(logo_url: str, timeout: float = 10.0) -> str:
    """Fetch logo and compute SAID. Delegates to common.vvp.logo_hash.fetch_validate_hash().
    Uses shared HTTP client from common.vvp.http_client.
    Returns 44-character SAID string. Raises LogoFetchError on failure.
    """
```

**Behavior**: Calls `fetch_validate_hash(logo_url, get_http_client(), expected_said=None)` and returns the computed SAID. All validation (streaming, content-type, SSRF) handled by the shared function.

#### Component 4: VCard Array Builder

**Purpose**: Build the `vcard` array attribute from UI form inputs, inserting logo hash.

**Location**: `services/issuer/app/vvp/vcard_builder.py` (new)

**Interface**:
```python
async def build_vcard_array(
    brand_name: str,
    display_name: str | None = None,
    logo_url: str | None = None,
    website_url: str | None = None,
    phone: str | None = None,
) -> list[str]:
    """Build RFC 6350 vCard property lines from form inputs.

    If logo_url is provided, fetches the logo and computes its
    Blake3-256 SAID for the HASH parameter.

    Returns list of uppercase vCard property strings, parameters
    in lexicographic order per Provenant convention.
    """
```

**Behavior**:
- Converts friendly form fields to RFC 6350 property strings
- If `logo_url` provided: calls `fetch_and_hash_logo()`, produces `LOGO;HASH=<said>;VALUE=URI:<url>`
- If no `logo_url`: no LOGO line emitted
- Returns lines sorted by property name (lexicographic, per Provenant convention)

#### Component 5: Card Claim Builder Update

**Purpose**: `build_card_claim()` should handle both vcard-array and scalar-attribute brand credentials.

**Location**: `services/issuer/app/vvp/card.py`

**Updated interface**:
```python
def build_card_claim(attributes: dict) -> Optional[list[str]]:
    """Build vCard card claim from credential attributes.

    If attributes contain a 'vcard' array (Provenant schema), pass it
    through directly — it's already in RFC 6350 format with any HASH
    parameters embedded.

    If attributes contain scalar fields (Extended Brand schema), convert
    to RFC 6350 format (backward compatibility, no logo hash).
    """
```

**Behavior**:
- Check for `vcard` key first → if present and non-empty, return it directly
- Otherwise, fall back to current scalar-field conversion logic
- This means the HASH parameter flows through to the PASSporT without any re-computation

**Backward compatibility shim**: The scalar→vcard conversion path in the card builder IS the single compatibility shim. No other consumer needs to branch on schema type — all downstream code operates on vCard lines only. Deprecation: scalar-field brand schema will be marked deprecated in schema registry metadata; migration to vcard-array schema recommended for all new credentials.

#### Component 6: Brand Detection and Verification Updates (Verifier)

**Purpose**: Detect and verify Provenant-style brand credentials that use `vcard` array instead of scalar fields.

**Location**: `services/verifier/app/vvp/brand.py`

**Changes**:

1. **Schema-first classification**: Brand detection checks schema SAID first:
```python
# Known brand schema SAIDs
BRAND_SCHEMA_SAIDS: Set[str] = {
    VVP_BRAND_OWNER_SCHEMA_SAID,      # Provenant-style vcard schema
    VVP_EXTENDED_BRAND_SCHEMA_SAID,    # Legacy scalar-field schema
}

def find_brand_credential(credentials: list[dict]) -> dict | None:
    """Find brand credential by schema SAID first, then heuristic fallback.

    1. Check credential 's' field against BRAND_SCHEMA_SAIDS → definitive match
    2. Fallback: check for 2+ BRAND_INDICATOR_FIELDS (legacy/unknown schemas)
    """
```

2. `"vcard"` added to `BRAND_INDICATOR_FIELDS` as a supporting indicator (not primary classifier).

3. Update `verify_brand_attributes()`: When the credential has a `vcard` attribute, use shared `common.vvp.vcard.comparison.vcard_properties_match()` for comparison. Multi-value properties compared as sets. Case-insensitive. HASH downgrade detection enforced.

4. **Surface mismatches in response**: `BrandVerificationResult` gains a typed `brand_errors` field:
```python
class BrandErrorCode(str, Enum):
    HASH_DOWNGRADE = "HASH_DOWNGRADE"       # Credential has HASH but card omits it
    PROPERTY_MISMATCH = "PROPERTY_MISMATCH" # vCard property value differs
    PROPERTY_MISSING = "PROPERTY_MISSING"   # Card claim has property not in credential
    LOGO_FETCH_FAILED = "LOGO_FETCH_FAILED" # Logo URL unreachable at verification
    LOGO_HASH_MISMATCH = "LOGO_HASH_MISMATCH"  # Computed hash != expected hash

class BrandError(BaseModel):
    code: BrandErrorCode
    message: str
    fields: list[str]  # Affected vCard property names

brand_errors: list[BrandError] | None
```
When `vcard_properties_match()` returns mismatches, they're structured as typed `BrandError` objects in the verification response. All codes documented in `knowledge/api-reference.md`.

#### Component 7: Logo Integrity Proxy (SIP Verifier)

**Purpose**: Fetch logos, verify their hash against the credential, cache locally, and serve via a local endpoint.

**Location**: `services/sip-verify/app/verify/logo_cache.py` (new)

**Interface**:
```python
class LogoCache:
    """Fetches, verifies, and caches brand logos with hash integrity.

    Logos are keyed by their SAID hash. On first access, the logo is
    fetched from the original URL, its Blake3-256 hash is verified
    against the expected SAID, and the image is cached on disk.

    Config:
        VVP_LOGO_CACHE_DIR: Cache directory (default: /tmp/vvp-logo-cache)
        VVP_LOGO_CACHE_MAX_MB: Max cache size (default: 100)
        VVP_LOGO_CACHE_TTL_HOURS: Entry TTL (default: 24)
        VVP_LOGO_BASE_URL: Base URL for serving cached logos
    """

    async def get_or_fetch(
        self, logo_url: str, expected_said: str | None = None
    ) -> LogoCacheResult:
        """Get cached logo or fetch, verify, and cache.

        Args:
            logo_url: URL to fetch the logo from.
            expected_said: Blake3 SAID to verify against (new schema).
                If None (legacy), logo is cached by content hash but
                marked as unverified.

        Per-SAID async lock prevents thundering herd (only one fetch
        per logo, other callers await the same future).
        For legacy logos (said=None), cache key is the computed content
        hash after first fetch — provides content-addressed dedup.

        File I/O offloaded to asyncio.to_thread() to avoid blocking
        the event loop.

        Returns:
            LogoCacheResult with local_url, verified flag, and
            logo_verified signal.
        """
```

**`LogoCacheResult` dataclass**:
```python
@dataclass
class LogoCacheResult:
    local_url: str          # URL to the locally-served logo
    verified: bool          # True if hash matched
    from_cache: bool        # True if served from cache
    original_url: str       # Original external URL
```

**Behavior**:
1. **Validate SAID format**: `validate_said_format(expected_said)` — must match `^E[A-Za-z0-9_-]{43}$` (Blake3 E-prefix); reject otherwise
2. **Per-SAID async lock**: `self._locks[said]` (dict of `asyncio.Lock`) prevents thundering herd — only one fetch per logo; other callers await the same lock then read from cache
3. If HASH present and logo with that SAID is in cache → return cached logo URL
4. If not cached → call shared `common.vvp.logo_hash.fetch_validate_hash(url, http_client, expected_said=said)` — all streaming, content-type validation, SSRF, hashing, and URL redaction handled by shared function
5. If verified → **write to disk via `asyncio.to_thread()`** as `<said>.<ext>`, return local URL
6. If `LogoHashMismatchError` → return unknown-brand placeholder URL
7. If `LogoFetchError` → return unknown-brand placeholder URL

**Shared HTTP client**: Uses `common.vvp.http_client.get_http_client()` — the same long-lived `httpx.AsyncClient` used throughout the codebase (connection pool reuse, no per-request client creation).

**Lock lifecycle**: Guarded lock entries `(lock, refcount, last_used)` behind the index mutex. Refcount incremented on acquire, decremented on release. Only evict entries with `refcount == 0`. Cap at 1000 entries with LRU eviction of idle (refcount=0) locks.

**Cache eviction**: In-memory index tracks `{said: (size, last_access)}`. On write, if total > max, evict least-recently-used entries. No full directory scans. Periodic cleanup (every 10 minutes, max 50 entries per cycle) via background task.

**Index concurrency**: Single `asyncio.Lock` guards all index mutations (size accounting, eviction, add/remove) to prevent races.

**Async file I/O**: All disk reads/writes use `asyncio.to_thread()` to avoid event-loop stalls.

#### Component 8: Logo Serving Endpoint

**Purpose**: HTTP endpoint to serve cached logos to the PBX/handset.

**Location**: `services/sip-verify/app/main.py` (add route)

**Endpoint**: `GET /logo/{said}`

**Behavior**:
- **Validate SAID**: Must match `^E[A-Za-z0-9_-]{43}$` (Blake3 E-prefix) OR be the literal string `"unknown"` → else 404
- **Path traversal protection**: `os.path.realpath(cache_dir / f"{said}.{ext}")` must start with `os.path.realpath(cache_dir)` → else 404
- **Special case `said == "unknown"`**: Serve `unknown-brand.svg` placeholder
- If found: return image bytes with `Content-Type` detected from magic bytes (not URL extension), `Cache-Control: public, max-age=86400`, `X-Content-Type-Options: nosniff`
- If not found: return 404
- **Read via `asyncio.to_thread()`** to avoid blocking event loop
- **CORS**: Not enabled on this endpoint (logos served to same-origin PBX only). If cross-origin needed in future, add explicit allowlist.
- **HTTPS**: `VVP_LOGO_BASE_URL` must be HTTPS for non-localhost deployments; reject plaintext external URLs at startup validation
- **Cache-Control per response class**: Hash-addressed hits → `Cache-Control: public, max-age=86400, immutable`. 404/error/unknown → `Cache-Control: no-store`.
- **Lifespan hooks**: Logo cache cleanup task started at app startup, cancelled on shutdown. Shared HTTP client closed on shutdown. Tests assert no dangling tasks/clients after app stop.

**Note**: This endpoint has no authentication — logos are public brand assets. The SAID in the URL is not guessable (44-char cryptographic hash).

#### Component 9: SIP Verify Handler Update

**Purpose**: **Always** proxy logos via local cache — never pass raw external URLs in SIP headers. Surface logo verification status.

**Location**: `services/sip-verify/app/verify/handler.py`

**Changes**:
After successful verification, before building the SIP 302 response:
1. Extract LOGO data from **verified credential attributes** (dossier), not from card claim (prevents card-claim manipulation). Use `common.vvp.vcard.brand.normalize_brand()` on the credential.
2. If `logo_hash` present (new schema) → call `logo_cache.get_or_fetch(said, url)` → `brand_logo_url = result.local_url`, `X-VVP-Brand-Logo-Verified: true` (if hash matched)
3. If no `logo_hash` (legacy credential) → **still proxy** via `logo_cache.get_or_fetch(url, expected_said=None)` → fetch, cache with computed content hash as key (content-addressed dedup), serve from local URL → `X-VVP-Brand-Logo-Verified: false`, `X-VVP-Brand-Logo-Reason: no-hash`
4. If logo fetch fails → `brand_logo_url = /logo/unknown`, `X-VVP-Brand-Logo-Verified: false`
5. **Never emit raw external URLs** in `X-VVP-Brand-Logo` — all logos served from local proxy

**Rationale**: Always proxying eliminates third-party tracking surface, ensures HTTPS, prevents header injection from arbitrary URLs, and provides consistent CSP-safe `img-src` origins.

#### Component 10: Unknown Brand Placeholder

**Purpose**: Static "?" logo served when logo hash verification fails or logo is unavailable.

**Location**: `services/sip-verify/web/unknown-brand.svg`

**Design**: Simple SVG with a question mark icon in a neutral circle. Approximately 1KB. Served at `/logo/unknown` endpoint (explicit route, not via SAID lookup).

### Data Flow

```
Credential Issuance:
  Vetter UI → [brandName, logoUrl] → vcard_builder → fetch logo (stream, 2MB limit)
    → validate content-type (allowlist) → Blake3 SAID (via KERI CESR primitives)
    → vcard: ["ORG:ACME", "LOGO;HASH=EK2r...;VALUE=URI:https://cdn.acme.com/logo.png"]
    → ACDC credential (hash covered by signature)

PASSporT Creation:
  Issuer → build_card_claim(attrs) → card: ["ORG:ACME", "LOGO;HASH=EK2r...;VALUE=URI:..."]
    → PASSporT JWT (card claim preserved verbatim from vcard array)

SIP Verification:
  sip-verify → call Verifier /verify → get brand_info with logo_url + logo_hash
    → per-SAID async lock → LogoCache.get_or_fetch("EK2r...", "https://cdn/logo.png")
    → fetch (stream, 2MB) → validate content-type → Blake3 SAID → compare → cache via to_thread()
    → X-VVP-Brand-Logo: http://127.0.0.1:5071/logo/EK2r...
    → X-VVP-Brand-Logo-Verified: true

PBX/Handset:
  Phone app → GET http://127.0.0.1:5071/logo/EK2r... → validated SAID, path-safe → cached image
    → Content-Type from magic bytes, X-Content-Type-Options: nosniff
```

### Error Handling

| Error | Handling |
|-------|----------|
| Logo URL unreachable at **issuance** | Credential issuance fails — vetter must provide accessible URL |
| Logo content-type not in allowlist at **issuance** | Credential issuance fails — `LogoFetchError` with content-type detail |
| Logo URL unreachable at **verification** | Use unknown-brand placeholder; `X-VVP-Brand-Logo-Verified: false`; `brand_verified` still VALID |
| Logo hash mismatch at **verification** | Use unknown-brand placeholder; log warning (URL redacted: scheme://host/path only); `X-VVP-Brand-Logo-Verified: false`; `brand_verified` still VALID |
| Logo exceeds 2MB size limit | Stream aborted early → unknown-brand placeholder |
| Logo content-type not in allowlist at **verification** | Treat as fetch failure → unknown-brand placeholder |
| SSRF: logo URL points to private IP | Blocked by `url_validation.py`; unknown-brand placeholder |
| Invalid SAID format in `/logo/{said}` | 404 (SAID must match `^E[A-Za-z0-9_-]{43}$`) |
| Path traversal attempt in `/logo/{said}` | 404 (realpath check blocks escape from cache dir) |

### Test Strategy

**Unit tests (common)**:
- `common/tests/test_vcard.py`: Parse vCard lines; case-insensitive matching; multi-value properties; LOGO extraction; property comparison; parameter-order independence
- `common/tests/test_logo_hash.py`: Blake3-256 SAID computation from known bytes; uses KERI CESR primitives; round-trip test; content-type validation; SAID format validation

**Unit tests (issuer)**:
- `test_logo_hash.py`: `fetch_and_hash_logo()` with mocked HTTP — streaming, content-type rejection, size limit, SSRF blocking
- `test_vcard_builder.py`: Build vcard array from form inputs; LOGO line includes HASH parameter; property ordering
- `test_card.py`: vcard array passthrough; scalar field fallback; mixed credentials

**Unit tests (verifier)**:
- `test_brand.py`: Schema-SAID-first detection; Provenant-style credentials; vcard-array attributes vs card claim comparison; backward compat with scalar attributes; multi-value property matching

**Unit tests (sip-verify)**:
- `test_logo_cache.py`: Cache hit/miss; hash match/mismatch; per-SAID lock (concurrent fetch coalescing); fetch timeout; SSRF blocking; content-type allowlist; async file I/O; in-memory index eviction; unknown-brand fallback; SAID format validation; path traversal protection; URL redaction in logs
- `test_handler.py`: X-VVP-Brand-Logo always uses local proxy URL (never external); X-VVP-Brand-Logo-Verified: true when hash present and verified; X-VVP-Brand-Logo-Verified: false + X-VVP-Brand-Logo-Reason: no-hash for legacy credentials; uses unknown-brand on failure

**Integration test**:
- Issue brand credential with logo hash → create dossier → create PASSporT with card claim → verify → confirm logo proxy URL returned with correct cached image and `X-VVP-Brand-Logo-Verified: true`

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `common/common/vvp/vcard/__init__.py` | Create | vCard package init |
| `common/common/vvp/vcard/parser.py` | Create | Syntax-only vCard parser (parse lines, extract properties) |
| `common/common/vvp/vcard/brand.py` | Create | Brand projection (NormalizedBrand, extract from vcard/scalars) |
| `common/common/vvp/vcard/comparison.py` | Create | Credential vs card claim comparison (HASH enforcement) |
| `common/common/vvp/logo_hash.py` | Create | Shared logo hash + fetch pipeline (Blake3 SAID, content-type, streaming, SSRF) |
| `common/tests/test_vcard_parser.py` | Create | vCard parser tests |
| `common/tests/test_vcard_brand.py` | Create | Brand projection tests |
| `common/tests/test_vcard_comparison.py` | Create | Comparison + HASH enforcement tests |
| `common/tests/test_logo_hash.py` | Create | Logo hash + fetch pipeline tests |
| `common/common/vvp/schema/constants.py` | Modify | Add VVP_BRAND_OWNER_SCHEMA_SAID constant |
| `services/issuer/app/schema/schemas/provenant-brand-owner.json` | Create | Provenant-style brand schema with vcard array |
| `services/issuer/app/vvp/logo_hash.py` | Create | Thin wrapper: fetch + validate + hash (delegates to common/) |
| `services/issuer/app/vvp/vcard_builder.py` | Create | Build vcard array from form inputs |
| `services/issuer/app/vvp/card.py` | Modify | Handle vcard array passthrough + scalar-to-vcard shim |
| `services/issuer/app/api/tn.py` | Modify | Use shared vcard parser for brand extraction |
| `services/issuer/app/keri/issuer.py` | Modify | Use vcard_builder during brand credential issuance |
| `services/issuer/web/credentials.html` | Modify | Brand form submits plain fields; backend converts to `vcard` (no client-side conversion) |
| `services/verifier/app/vvp/brand.py` | Modify | Schema-SAID-first detection + vcard comparison via shared parser |
| `services/sip-verify/app/verify/logo_cache.py` | Create | Logo fetch, hash verify, disk cache (per-SAID locks, async I/O, in-memory index) |
| `services/sip-verify/app/verify/handler.py` | Modify | Use logo proxy URL + X-VVP-Brand-Logo-Verified header |
| `services/sip-verify/app/verify/client.py` | Modify | Add logo_hash to VerifyResult |
| `services/sip-verify/app/main.py` | Modify | Add /logo/{said} + /logo/unknown endpoints (SAID validation, path traversal protection) |
| `services/sip-verify/web/unknown-brand.svg` | Create | "?" placeholder logo |
| `services/issuer/tests/test_logo_hash.py` | Create | Logo fetch+hash tests |
| `services/issuer/tests/test_vcard_builder.py` | Create | VCard array builder tests |
| `services/issuer/tests/test_card.py` | Modify | vcard passthrough tests |
| `services/verifier/tests/test_brand.py` | Modify | Schema-SAID detection + Provenant schema tests |
| `services/sip-verify/tests/test_logo_cache.py` | Create | Logo proxy tests (concurrency, security, eviction) |
| `knowledge/schemas.md` | Modify | Add brand-owner schema SAID, vcard semantics, compatibility notes |
| `knowledge/verification-pipeline.md` | Modify | Add logo hash verification sub-phase description |
| `knowledge/api-reference.md` | Modify | Add /logo/{said} endpoint, X-VVP-Brand-Logo-Verified + Reason headers, BrandError codes |
| `knowledge/deployment.md` | Modify | Add logo cache env vars (VVP_LOGO_CACHE_*, VVP_LOGO_BASE_URL) with defaults and constraints |
| `CHANGES.md` | Modify | Sprint 79 entry: new schema, logo proxy, API surface, SIP headers |

## Open Questions

1. **Should we use the exact Provenant SAID** (`EBpGNZSWwj-btOJMJSMLCVoXbtKdJTcggO-zMevr4vH_`) or create a VVP-specific derivative? Using the exact Provenant schema means interoperability with the broader ecosystem. A derivative lets us keep the `certification` edge (which Provenant calls `brandauth`).

2. **Logo size constraints**: Should we enforce a maximum logo resolution/file size at **issuance** time (e.g., 64x48px per the spec's sample, or up to 256x256)? Or leave that to vetter policy?

3. **Bootstrap script update**: `scripts/bootstrap-issuer.py` creates test credentials — should it be updated to use the new schema in this sprint, or separately?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Blake3 library not available in all envs | Low | Medium | Already used by keripy; `blake3` PyPI package well-maintained |
| Logo fetch at issuance adds latency | Medium | Low | One-time cost at credential issuance; not on call path |
| Logo fetch at verification adds call latency | Medium | Medium | Cache eliminates repeat fetches; first-call adds ~100ms; timeout prevents blocking |
| Existing credentials break | Low | High | Backward compatibility maintained — scalar fields still work, just without hash verification |
| Cache disk exhaustion | Low | Low | LRU eviction with configurable max size; ephemeral /tmp storage |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-05 | Initial draft |
| R2 | 2026-03-05 | Centralized vCard parser + logo hash in `common/`. KERI CESR primitives for SAID. SAID validation + path traversal protection. Content-type allowlist. Per-SAID async lock. `asyncio.to_thread()` for file I/O. In-memory cache index. Streaming + early abort. Schema-SAID-first brand classification. `X-VVP-Brand-Logo-Verified` header. Multi-value vCard comparison. Explicit `/logo/unknown` route. URL redaction. Knowledge doc updates. |
| R3 | 2026-03-05 | Split vcard.py into parser/brand/comparison modules. Shared `fetch_validate_hash()`. `NormalizedBrand` adapter. HASH downgrade enforcement. Always proxy logos. SAID E-prefix. `brand_errors` field. `X-VVP-Brand-Logo-Reason`. Lock cleanup + cap. Index concurrency guard. Shared HTTP client mandate. CHANGES.md + api-reference updates. UI submits plain fields only. |
| R4 | 2026-03-05 | Standardized E-prefix SAID validation (`^E[A-Za-z0-9_-]{43}$`) across ALL components — Components 7, 8, and error handling table now consistent with Component 1d. Fixed test strategy to assert always-proxied logos (never external URL), matching Component 9 design. `get_or_fetch` signature: `expected_said: str | None` for legacy support. Legacy logos cached by computed content hash (content-addressed dedup, not URL-derived key). Typed `BrandErrorCode` enum + `BrandError` model for verifier response. Lock refcounting `(lock, refcount, last_used)` behind index mutex — only evict refcount=0. Lifespan hooks for cleanup task + HTTP client shutdown. Cache-Control per response class (immutable for hits, no-store for errors). `knowledge/deployment.md` added for logo cache env vars. |
