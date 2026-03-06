"""Build vcard array from form inputs for Provenant brand-owner credentials.

Sprint 79: Converts user-facing form fields (brand name, logo URL, etc.)
into RFC 6350 vCard property lines with HASH parameter on LOGO.
"""

import logging
from typing import Optional

from common.vvp.logo_hash import LogoFetchError, compute_said_from_bytes, fetch_validate_hash

logger = logging.getLogger(__name__)


async def build_vcard_array(
    brand_name: str,
    display_name: Optional[str] = None,
    logo_url: Optional[str] = None,
    website_url: Optional[str] = None,
    phone: Optional[str] = None,
) -> list[str]:
    """Build RFC 6350 vCard property lines from form inputs.

    If logo_url is provided, fetches the logo and computes its
    Blake3-256 SAID for the HASH parameter.

    Returns list of uppercase vCard property strings, parameters
    in lexicographic order per Provenant convention.

    Raises:
        LogoFetchError: If logo_url is provided but unreachable or invalid.
    """
    lines: list[str] = []

    # LOGO — must be before ORG for lexicographic ordering
    if logo_url:
        logo_said = await fetch_and_hash_logo(logo_url)
        lines.append(f"LOGO;HASH={logo_said};VALUE=URI:{logo_url}")

    # NICKNAME — display name
    if display_name:
        lines.append(f"NICKNAME:{display_name}")

    # ORG — organization name
    lines.append(f"ORG:{brand_name}")

    # TEL — phone number
    if phone:
        lines.append(f"TEL;VALUE=URI:tel:{phone}")

    # URL — website
    if website_url:
        lines.append(f"URL:{website_url}")

    return lines


async def fetch_and_hash_logo(logo_url: str, timeout: float = 10.0) -> str:
    """Fetch logo and compute SAID.

    Delegates to common.vvp.logo_hash.fetch_validate_hash().
    Uses shared HTTP client from common.vvp.http_client.

    Returns 44-character SAID string.

    Raises:
        LogoFetchError: On fetch failure, content-type invalid, size exceeded.
    """
    from common.vvp.http_client import get_shared_client

    client = await get_shared_client()
    _bytes, computed_said = await fetch_validate_hash(
        logo_url, client, expected_said=None, timeout=timeout
    )
    return computed_said
