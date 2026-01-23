"""HTTP dossier fetch with constraints per spec §6.1B.

Implements OOBI dereference with:
- Configurable timeout (default 5s)
- Response size limit (default 1MB)
- Redirect limit (default 3)
- Content-type validation
"""

import httpx

from app.core.config import (
    DOSSIER_FETCH_TIMEOUT_SECONDS,
    DOSSIER_MAX_REDIRECTS,
    DOSSIER_MAX_SIZE_BYTES,
)

from .exceptions import FetchError

# Content types we accept (§4.1B, §6.1B)
# - application/json+cesr: KERI CESR format (preferred)
# - application/json: Standard JSON (for compatibility)
ACCEPTED_CONTENT_TYPES = frozenset({
    "application/json+cesr",
    "application/json",
})


async def fetch_dossier(url: str) -> bytes:
    """Fetch dossier from URL with constraints.

    Enforces per spec §6.1B:
    - Timeout: DOSSIER_FETCH_TIMEOUT_SECONDS (5s default)
    - Max size: DOSSIER_MAX_SIZE_BYTES (1MB default)
    - Max redirects: DOSSIER_MAX_REDIRECTS (3 default)
    - Content-Type validation

    Args:
        url: Dossier URL from evd field

    Returns:
        Raw bytes of dossier content

    Raises:
        FetchError: On network/timeout/size errors (recoverable → INDETERMINATE)
    """
    try:
        async with httpx.AsyncClient(
            timeout=DOSSIER_FETCH_TIMEOUT_SECONDS,
            max_redirects=DOSSIER_MAX_REDIRECTS,
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()

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
    except httpx.TooManyRedirects:
        raise FetchError(
            f"Exceeded {DOSSIER_MAX_REDIRECTS} redirects fetching {url}"
        )
    except httpx.HTTPStatusError as e:
        raise FetchError(
            f"HTTP {e.response.status_code}: {e.response.reason_phrase}"
        )
    except httpx.RequestError as e:
        raise FetchError(f"Request failed: {e}")
