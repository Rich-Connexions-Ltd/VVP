"""vCard parsing and brand extraction utilities.

Shared between issuer, verifier, and sip-verify services.
"""

from .parser import VCardProperty, parse_vcard_line, parse_vcard_lines, find_property, find_all_properties
from .brand import NormalizedBrand, normalize_brand, extract_brand_from_vcard, extract_brand_from_scalars
from .comparison import ComparisonResult, vcard_properties_match

__all__ = [
    "VCardProperty",
    "parse_vcard_line",
    "parse_vcard_lines",
    "find_property",
    "find_all_properties",
    "NormalizedBrand",
    "normalize_brand",
    "extract_brand_from_vcard",
    "extract_brand_from_scalars",
    "ComparisonResult",
    "vcard_properties_match",
]
