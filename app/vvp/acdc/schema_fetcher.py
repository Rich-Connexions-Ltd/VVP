"""Schema document fetching and caching.

Fetches schema documents from OOBI endpoints or well-known registries.
Implements SAID verification per KERI/CESR spec.

Per VVP §5.1.1-2.8.3, validation must compare data structure and values
against the declared schema.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

from app.core.config import SCHEMA_CACHE_TTL_SECONDS
from app.vvp.api_models import ClaimStatus
from app.vvp.keri.exceptions import ResolutionFailedError

from .exceptions import ACDCChainInvalid
from .models import ACDC

log = logging.getLogger(__name__)

# Schema cache: SAID -> (schema_document, fetch_time)
_schema_cache: Dict[str, Tuple[Dict[str, Any], datetime]] = {}

# Well-known schema endpoints
SCHEMA_REGISTRIES = [
    "https://schema.gleif.org/",
    "https://schema.provenant.net/",
]

# HTTP timeout for schema fetching
SCHEMA_FETCH_TIMEOUT = 10.0


async def fetch_schema(schema_said: str) -> Dict[str, Any]:
    """Fetch schema document by SAID.

    Tries each registry endpoint in order until successful.
    Caches results per SCHEMA_CACHE_TTL_SECONDS.

    Args:
        schema_said: The schema's self-addressing identifier

    Returns:
        Parsed schema document (JSON Schema format)

    Raises:
        ResolutionFailedError: If schema cannot be fetched from any registry
    """
    # Check cache first
    if schema_said in _schema_cache:
        schema_doc, fetch_time = _schema_cache[schema_said]
        age = datetime.now(timezone.utc) - fetch_time
        if age < timedelta(seconds=SCHEMA_CACHE_TTL_SECONDS):
            log.debug(f"Schema cache hit for {schema_said[:20]}...")
            return schema_doc
        else:
            log.debug(f"Schema cache expired for {schema_said[:20]}...")
            del _schema_cache[schema_said]

    # Try each registry
    errors = []
    async with httpx.AsyncClient(timeout=SCHEMA_FETCH_TIMEOUT) as client:
        for registry in SCHEMA_REGISTRIES:
            url = f"{registry.rstrip('/')}/{schema_said}"
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    schema_doc = response.json()
                    # Cache the result
                    _schema_cache[schema_said] = (schema_doc, datetime.now(timezone.utc))
                    log.info(f"Fetched schema {schema_said[:20]}... from {registry}")
                    return schema_doc
                else:
                    errors.append(f"{registry}: HTTP {response.status_code}")
            except httpx.TimeoutException:
                errors.append(f"{registry}: timeout")
            except httpx.RequestError as e:
                errors.append(f"{registry}: {e}")
            except json.JSONDecodeError as e:
                errors.append(f"{registry}: invalid JSON: {e}")

    # All registries failed
    raise ResolutionFailedError(
        f"Failed to fetch schema {schema_said[:20]}...: {'; '.join(errors)}"
    )


def compute_schema_said(schema_doc: Dict[str, Any]) -> str:
    """Compute SAID for a JSON Schema document.

    IMPORTANT: This function uses sorted keys for canonicalization, which is
    CORRECT for JSON Schema documents per the ACDC spec. This is DIFFERENT from:
    - KEL events (use keri.kel_parser.compute_kel_event_said - uses KERI field ordering)
    - ACDC credentials (use parser.compute_acdc_said - uses ACDC field ordering)

    JSON Schemas don't have a defined event type with prescribed field ordering,
    so they use lexicographic (sorted) key ordering as their canonical form.

    Algorithm (per KERI/CESR spec):
    1. Replace '$id' field (schema SAID field) with placeholder of same length
    2. Serialize to canonical JSON:
       - Deterministic key ordering (sorted keys) - CORRECT for schemas
       - No whitespace between elements
       - UTF-8 encoded
    3. Compute Blake3-256 hash of canonical bytes
    4. CESR-encode hash with 'E' prefix (44 chars total)

    Note: Uses same _cesr_encode() from kel_parser.py for consistency.

    Args:
        schema_doc: The JSON Schema document as a dict

    Returns:
        SAID string with 'E' prefix (e.g., "EBfdlu8R27Fbx...")
    """
    # Import helpers - avoid circular imports
    from app.vvp.keri.kel_parser import _cesr_encode

    try:
        import blake3
    except ImportError:
        # Fallback for testing environments without blake3
        import hashlib
        log.warning("blake3 not available, using sha256 (test mode only)")

        def blake3_hash(data: bytes) -> bytes:
            return hashlib.sha256(data).digest()
    else:
        def blake3_hash(data: bytes) -> bytes:
            return blake3.blake3(data).digest()

    # Create copy with placeholder in SAID field
    data_copy = dict(schema_doc)

    # Schema documents use '$id' field for their SAID (JSON Schema convention)
    # Placeholder must match length of declared $id (as in validate_acdc_said)
    original_id = data_copy.get("$id", "")
    placeholder_length = len(original_id) if original_id else 44
    if placeholder_length < 44:
        placeholder_length = 44  # Minimum for Blake3-256 CESR encoding

    # Use derivation code from original SAID, or 'E' for Blake3-256
    code = original_id[0] if original_id else "E"
    placeholder = code + "#" * (placeholder_length - 1)
    data_copy["$id"] = placeholder

    # Canonical JSON: sorted keys, no whitespace, UTF-8
    canonical = json.dumps(data_copy, separators=(",", ":"), sort_keys=True)
    canonical_bytes = canonical.encode("utf-8")

    # Blake3-256 hash
    digest = blake3_hash(canonical_bytes)

    # CESR-encode with derivation code
    computed_said = _cesr_encode(digest, code=code)
    return computed_said


def verify_schema_said(schema_doc: Dict[str, Any], expected_said: str) -> bool:
    """Verify schema document's computed SAID matches expected.

    Args:
        schema_doc: Fetched schema document
        expected_said: The declared schema SAID from ACDC 's' field

    Returns:
        True if computed SAID matches expected
    """
    computed = compute_schema_said(schema_doc)
    return computed == expected_said


async def get_schema_for_validation(
    acdc: ACDC,
) -> Tuple[Dict[str, Any], ClaimStatus]:
    """Get schema document for ACDC validation.

    Handles both embedded schemas (inline) and referenced schemas (by SAID).

    Args:
        acdc: The ACDC to get schema for

    Returns:
        Tuple of (schema_doc, status):
        - (schema, VALID) if schema found and SAID verified
        - ({}, INDETERMINATE) if schema cannot be fetched
        - Raises ACDCChainInvalid if SAID mismatch
    """
    schema_ref = acdc.schema_said

    if not schema_ref:
        # No schema declared - cannot validate
        return ({}, ClaimStatus.INDETERMINATE)

    # Check if schema is embedded (dict) or referenced (string SAID)
    raw_schema = acdc.raw.get("s")
    if isinstance(raw_schema, dict):
        # Embedded schema - compute and verify SAID
        embedded = raw_schema
        computed = compute_schema_said(embedded)
        if computed != schema_ref:
            raise ACDCChainInvalid(
                f"Embedded schema SAID mismatch: declared {schema_ref[:20]}... "
                f"but computed {computed[:20]}..."
            )
        return (embedded, ClaimStatus.VALID)

    # Referenced schema - fetch from registry
    try:
        schema_doc = await fetch_schema(schema_ref)
        if not verify_schema_said(schema_doc, schema_ref):
            raise ACDCChainInvalid(
                f"Fetched schema SAID mismatch for {schema_ref[:20]}..."
            )
        return (schema_doc, ClaimStatus.VALID)
    except ResolutionFailedError as e:
        log.warning(f"Schema fetch failed: {e}")
        return ({}, ClaimStatus.INDETERMINATE)


def clear_schema_cache() -> None:
    """Clear the schema cache. Useful for testing."""
    global _schema_cache
    _schema_cache.clear()


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics for monitoring."""
    return {
        "size": len(_schema_cache),
        "saids": list(_schema_cache.keys())[:10],  # First 10 for debugging
    }
