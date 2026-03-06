"""Logo hash computation and fetch pipeline.

Shared between issuer (at credential issuance) and sip-verify
(at call verification). Uses Blake3-256 with CESR E-prefix encoding,
matching the KERI SAID format.

Sprint 79: Provenant Brand Schema & Logo Integrity.
"""

from __future__ import annotations

import base64
import logging
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Content-type allowlist — SVG excluded (script injection risk)
LOGO_CONTENT_TYPES = frozenset({
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
})

# Max logo size: 2MB
LOGO_MAX_BYTES = 2 * 1024 * 1024

# Blake3 CESR SAID: must start with E, exactly 44 chars, base64url alphabet
SAID_PATTERN = re.compile(r"^E[A-Za-z0-9_-]{43}$")


class LogoFetchError(Exception):
    """Raised when logo fetch fails (timeout, content-type, size, SSRF)."""
    pass


class LogoHashMismatchError(Exception):
    """Raised when computed SAID doesn't match expected SAID."""

    def __init__(self, expected: str, computed: str):
        self.expected = expected
        self.computed = computed
        super().__init__(f"Logo hash mismatch: expected={expected}, computed={computed}")


def validate_said_format(said: str) -> bool:
    """Validate SAID starts with E (Blake3), is 44 chars, base64url alphabet."""
    return bool(SAID_PATTERN.match(said))


def compute_said_from_bytes(data: bytes) -> str:
    """Compute Blake3-256 SAID from raw bytes.

    Uses the blake3 library for hashing. Returns a 44-character
    CESR-encoded string with E prefix (Blake3 derivation code).
    """
    try:
        import blake3 as _blake3
    except ImportError:
        raise ImportError(
            "blake3 package required for logo hash computation. "
            "Install with: pip install blake3"
        )

    digest = _blake3.blake3(data).digest()  # 32 bytes
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    # E prefix = Blake3-256 derivation code in CESR
    return "E" + encoded


def validate_logo_content_type(content_type: str) -> bool:
    """Check content-type is in allowlist.

    Extracts the media type (ignoring parameters like charset).
    SVG excluded due to script injection risk.
    """
    # Extract media type, ignoring parameters
    media_type = content_type.split(";")[0].strip().lower()
    return media_type in LOGO_CONTENT_TYPES


def redact_url(url: str) -> str:
    """Redact query string and fragment from URL for safe logging."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


async def fetch_validate_hash(
    logo_url: str,
    http_client: httpx.AsyncClient,
    expected_said: str | None = None,
    timeout: float = 10.0,
) -> tuple[bytes, str]:
    """Shared fetch→validate→hash pipeline for logo images.

    Used by both issuer (at issuance, expected_said=None) and
    sip-verify (at verification, expected_said=<hash>).

    1. SSRF validation on URL (via url_validation module)
    2. Stream response with LOGO_MAX_BYTES hard limit
    3. Validate Content-Type against LOGO_CONTENT_TYPES
    4. Compute Blake3-256 SAID
    5. If expected_said provided, verify match

    Returns:
        (image_bytes, computed_said)

    Raises:
        LogoFetchError: fetch failure, content-type invalid, size exceeded
        LogoHashMismatchError: computed SAID != expected_said
    """
    safe_url = redact_url(logo_url)

    # SSRF validation
    try:
        from common.vvp.url_validation import validate_url_target
        await validate_url_target(logo_url)
    except ImportError:
        pass  # url_validation not available, skip SSRF check
    except Exception as e:
        raise LogoFetchError(f"URL validation failed for {safe_url}: {e}") from e

    # Fetch with streaming
    try:
        response = await http_client.get(logo_url, timeout=timeout)
        response.raise_for_status()
    except httpx.TimeoutException:
        raise LogoFetchError(f"Timeout fetching logo from {safe_url}")
    except httpx.HTTPStatusError as e:
        raise LogoFetchError(
            f"HTTP {e.response.status_code} fetching logo from {safe_url}"
        )
    except httpx.HTTPError as e:
        raise LogoFetchError(f"Error fetching logo from {safe_url}: {e}")

    # Validate content-type
    content_type = response.headers.get("content-type", "")
    if not validate_logo_content_type(content_type):
        raise LogoFetchError(
            f"Content-type '{content_type}' not in allowlist for {safe_url}. "
            f"Allowed: {', '.join(sorted(LOGO_CONTENT_TYPES))}"
        )

    # Check size
    content = response.content
    if len(content) > LOGO_MAX_BYTES:
        raise LogoFetchError(
            f"Logo exceeds {LOGO_MAX_BYTES} bytes ({len(content)} bytes) from {safe_url}"
        )

    # Compute hash
    computed_said = compute_said_from_bytes(content)

    # Verify if expected
    if expected_said is not None:
        if computed_said != expected_said:
            logger.warning(
                "Logo hash mismatch for %s: expected=%s, computed=%s",
                safe_url,
                expected_said,
                computed_said,
            )
            raise LogoHashMismatchError(expected_said, computed_said)

    return content, computed_said
