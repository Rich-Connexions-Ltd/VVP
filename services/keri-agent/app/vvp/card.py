"""vCard card claim builder for PASSporT JWT.

Sprint 58: Maps Extended Brand Credential attributes to vCard (RFC 6350)
property strings for inclusion as the PASSporT ``card`` claim.
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)


def build_card_claim(attributes: dict) -> Optional[list[str]]:
    """Build a vCard card claim array from credential attributes."""
    brand_name = attributes.get("brandName")
    if not brand_name:
        return None

    card: list[str] = []

    card.append(f"ORG:{brand_name}")

    display_name = attributes.get("brandDisplayName")
    card.append(f"NICKNAME:{display_name if display_name else brand_name}")

    logo_url = attributes.get("logoUrl")
    if logo_url:
        card.append(f"LOGO;VALUE=URI:{logo_url}")

    website_url = attributes.get("websiteUrl")
    if website_url:
        card.append(f"URL:{website_url}")

    return card
