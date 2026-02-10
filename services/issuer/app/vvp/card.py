"""vCard card claim builder for PASSporT JWT.

Sprint 58: Maps Extended Brand Credential attributes to vCard (RFC 6350)
fields for inclusion as the PASSporT ``card`` claim.

Credential → vCard mapping:
    brandName        → org   (organization name)
    brandDisplayName → fn    (full/display name; falls back to brandName)
    logoUrl          → logo  (direct URL)
    websiteUrl       → url   (website URL)
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)


def build_card_claim(attributes: dict) -> Optional[dict]:
    """Build a vCard card claim dict from credential attributes.

    Maps Extended Brand Credential attribute names to standard vCard
    field names per RFC 6350.  Returns ``None`` if the credential does
    not contain any brand attributes (i.e. ``brandName`` is absent).

    Args:
        attributes: ACDC credential attributes dict (the ``a`` section).

    Returns:
        Dict of vCard fields suitable for PASSporT ``card`` claim,
        or ``None`` if no brand data is present.
    """
    brand_name = attributes.get("brandName")
    if not brand_name:
        return None

    card: dict = {}

    # org — organization name (from required brandName)
    card["org"] = brand_name

    # fn — full/display name (prefer brandDisplayName, fall back to brandName)
    display_name = attributes.get("brandDisplayName")
    card["fn"] = display_name if display_name else brand_name

    # logo — brand logo URL
    logo_url = attributes.get("logoUrl")
    if logo_url:
        card["logo"] = logo_url

    # url — brand website
    website_url = attributes.get("websiteUrl")
    if website_url:
        card["url"] = website_url

    return card
