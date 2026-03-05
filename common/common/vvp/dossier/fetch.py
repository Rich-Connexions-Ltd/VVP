"""HTTP dossier fetch with constraints per spec §6.1B.

Implements dossier fetch with:
- SSRF validation (scheme + DNS + IP range checks)
- Shared HTTP client with connection pooling (Sprint 78)
- Configurable timeout (default 5s)
- Response size limit (default 1MB)
- No redirects (SSRF prevention)
- Content-type validation
"""

import httpx

from .config import (
    DOSSIER_FETCH_TIMEOUT_SECONDS,
    DOSSIER_MAX_SIZE_BYTES,
)
from .exceptions import FetchError

# Content types we accept (§4.1B, §6.1B)
# - application/json+cesr: KERI CESR format (preferred)
# - application/cesr: Raw CESR stream (used by issuer dossier endpoint)
# - application/json: Standard JSON (for compatibility)
ACCEPTED_CONTENT_TYPES = frozenset({
    "application/json+cesr",
    "application/cesr",
    "application/json",
})


async def fetch_dossier(url: str) -> bytes:
    """Fetch dossier from URL with constraints.

    Uses shared HTTP client with connection pooling (Sprint 78).
    SSRF validation blocks private/loopback/link-local IPs.
    Dossier URLs require https (untrusted, external).

    Enforces per spec §6.1B:
    - Timeout: DOSSIER_FETCH_TIMEOUT_SECONDS (5s default)
    - Max size: DOSSIER_MAX_SIZE_BYTES (1MB default)
    - Content-Type validation

    Args:
        url: Dossier URL from evd field

    Returns:
        Raw bytes of dossier content

    Raises:
        FetchError: On network/timeout/size/SSRF errors (recoverable → INDETERMINATE)
    """
    # SSRF validation: scheme + DNS + IP range checks
    from common.vvp.url_validation import URLValidationError, validate_url_target
    try:
        await validate_url_target(url, allow_http=False)
    except URLValidationError as e:
        raise FetchError(str(e))

    try:
        from common.vvp.http_client import get_shared_client
        client = await get_shared_client()
        response = await client.get(url, timeout=DOSSIER_FETCH_TIMEOUT_SECONDS)

        # Check for errors (including 3xx since follow_redirects=False)
        if response.status_code >= 300:
            raise FetchError(
                f"HTTP {response.status_code} fetching {url}"
            )

        # Validate content-type
        content_type = response.headers.get("content-type", "")
        # Extract base type (strip charset and other params)
        base_type = content_type.split(";")[0].strip().lower()
        if base_type not in ACCEPTED_CONTENT_TYPES:
            raise FetchError(
                f"Invalid content-type: {content_type}, "
                f"expected one of {sorted(ACCEPTED_CONTENT_TYPES)}"
            )

        # Check size
        content = response.content
        if len(content) > DOSSIER_MAX_SIZE_BYTES:
            raise FetchError(
                f"Response size {len(content)} bytes exceeds limit "
                f"of {DOSSIER_MAX_SIZE_BYTES} bytes"
            )

        return content

    except FetchError:
        # Re-raise our own errors
        raise
    except httpx.TimeoutException:
        raise FetchError(
            f"Timeout after {DOSSIER_FETCH_TIMEOUT_SECONDS}s fetching {url}"
        )
    except httpx.HTTPStatusError as e:
        raise FetchError(
            f"HTTP {e.response.status_code}: {e.response.reason_phrase}"
        )
    except httpx.RequestError as e:
        raise FetchError(f"Request failed: {e}")
