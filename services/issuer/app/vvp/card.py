"""vCard card claim builder for PASSporT JWT.

Sprint 58: Maps Extended Brand Credential attributes to vCard (RFC 6350)
property strings for inclusion as the PASSporT ``card`` claim.

Per VVP spec §4.1.2, the ``card`` claim is an array of RFC 6350 vCard
property strings.  Example::

    "card": ["NICKNAME:ACME Corporation",
             "LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]

Credential → vCard mapping:
    brandName        → ORG       (organization name)
    brandDisplayName → NICKNAME  (display name; falls back to brandName)
    logoUrl          → LOGO      (URI value)
    websiteUrl       → URL       (website URL)
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)


def build_card_claim(attributes: dict) -> Optional[list[str]]:
    """Build a vCard card claim array from credential attributes.

    If attributes contain a ``vcard`` array (Provenant brand-owner schema),
    pass it through directly — it's already in RFC 6350 format with any
    HASH parameters embedded.

    If attributes contain scalar fields (Extended Brand Credential schema),
    convert to RFC 6350 format (backward compatibility, no logo hash).

    Returns ``None`` if the credential does not contain any brand data.

    Args:
        attributes: ACDC credential attributes dict (the ``a`` section).

    Returns:
        List of vCard property strings for PASSporT ``card`` claim,
        or ``None`` if no brand data is present.
    """
    # Provenant-style vcard array — pass through directly
    vcard = attributes.get("vcard")
    if vcard and isinstance(vcard, list) and len(vcard) > 0:
        log.debug(f"Using vcard array from credential ({len(vcard)} properties)")
        return list(vcard)

    # Fall back to scalar fields (Extended Brand Credential)
    brand_name = attributes.get("brandName")
    if not brand_name:
        return None

    card: list[str] = []

    # ORG — organization name (from required brandName)
    card.append(f"ORG:{brand_name}")

    # NICKNAME — display name (prefer brandDisplayName, fall back to brandName)
    display_name = attributes.get("brandDisplayName")
    card.append(f"NICKNAME:{display_name if display_name else brand_name}")

    # LOGO — brand logo URL (VALUE=URI per RFC 6350)
    logo_url = attributes.get("logoUrl")
    if logo_url:
        card.append(f"LOGO;VALUE=URI:{logo_url}")

    # URL — brand website
    website_url = attributes.get("websiteUrl")
    if website_url:
        card.append(f"URL:{website_url}")

    return card
