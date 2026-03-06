"""Brand data extraction from vCard and scalar credential attributes.

Provides NormalizedBrand as the single canonical representation of brand
data. All downstream consumers (verifier, sip-verify) should operate on
NormalizedBrand only — never on raw credential attributes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .parser import parse_vcard_lines, find_property


@dataclass
class NormalizedBrand:
    """Normalized brand data from any credential format."""

    name: str
    display_name: Optional[str] = None
    logo_url: Optional[str] = None
    logo_hash: Optional[str] = None  # SAID from LOGO HASH parameter
    website_url: Optional[str] = None


def normalize_brand(
    attributes: dict, schema_said: Optional[str] = None
) -> Optional[NormalizedBrand]:
    """Normalize brand data from either vcard-array or scalar-attribute credentials.

    Single entry point — all downstream code consumes NormalizedBrand only.
    Returns None if attributes don't contain brand data.
    """
    # Prefer vcard array (Provenant schema)
    vcard = attributes.get("vcard")
    if vcard and isinstance(vcard, list) and len(vcard) > 0:
        return extract_brand_from_vcard(vcard)

    # Fall back to scalar fields (Extended Brand schema)
    brand_name = attributes.get("brandName") or attributes.get("brandDisplayName")
    if brand_name:
        return extract_brand_from_scalars(attributes)

    return None


def extract_brand_from_vcard(lines: list[str]) -> NormalizedBrand:
    """Extract brand fields from vCard property lines."""
    props = parse_vcard_lines(lines)

    # Brand name from ORG or NICKNAME
    org_prop = find_property(props, "ORG")
    nickname_prop = find_property(props, "NICKNAME")
    name = org_prop.value if org_prop else ""
    display_name = nickname_prop.value if nickname_prop else None

    # Logo URL and hash from LOGO property
    logo_url: Optional[str] = None
    logo_hash: Optional[str] = None
    logo_prop = find_property(props, "LOGO")
    if logo_prop:
        # VALUE=URI means the value is the URI
        if logo_prop.params.get("VALUE") == "URI":
            logo_url = logo_prop.value
        else:
            logo_url = logo_prop.value
        logo_hash = logo_prop.params.get("HASH")

    # Website from URL property
    url_prop = find_property(props, "URL")
    website_url = url_prop.value if url_prop else None

    return NormalizedBrand(
        name=name,
        display_name=display_name,
        logo_url=logo_url,
        logo_hash=logo_hash,
        website_url=website_url,
    )


def extract_brand_from_scalars(attributes: dict) -> NormalizedBrand:
    """Extract brand fields from legacy scalar attributes (backward compat)."""
    return NormalizedBrand(
        name=attributes.get("brandName", ""),
        display_name=attributes.get("brandDisplayName"),
        logo_url=attributes.get("logoUrl"),
        logo_hash=None,  # Scalar schema has no logo hash
        website_url=attributes.get("websiteUrl"),
    )
