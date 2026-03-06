"""Brand credential verification per spec §5A Step 12 (Brand Attributes).

This module validates that PASSporT `card` claims are justified by brand
credentials in the dossier. Per §5.1.1-2.12:
- If card present, MUST locate brand credential in dossier
- MUST verify brand attributes are justified by brand credential
- Brand credential MUST include JL (join link) to vetting credential (§6.3.7)
- In delegation scenarios with brand, DE MUST have brand proxy (§6.3.4)

vCard fields follow RFC 6350. Unknown fields log a warning but do not
cause INVALID (per Reviewer guidance).
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from common.vvp.schema.registry import BRAND_SCHEMA_SAIDS, is_brand_schema
from common.vvp.vcard.brand import NormalizedBrand, normalize_brand
from common.vvp.vcard.comparison import ComparisonResult, vcard_properties_match

from .api_models import ClaimStatus, ErrorCode

log = logging.getLogger(__name__)


class BrandErrorCode(str, Enum):
    """Typed error codes for brand verification failures."""
    HASH_DOWNGRADE = "HASH_DOWNGRADE"
    PROPERTY_MISMATCH = "PROPERTY_MISMATCH"
    PROPERTY_MISSING = "PROPERTY_MISSING"
    LOGO_FETCH_FAILED = "LOGO_FETCH_FAILED"
    LOGO_HASH_MISMATCH = "LOGO_HASH_MISMATCH"


@dataclass
class BrandError:
    """Structured brand verification error."""
    code: BrandErrorCode
    message: str
    fields: List[str] = field(default_factory=list)


@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim."""

    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)


@dataclass
class BrandInfo:
    """Extracted brand information from PASSporT card claim.

    Sprint 44: Used by SIP services to populate X-VVP-Brand-* headers.
    Sprint 79: Added logo_hash for logo integrity verification.

    Attributes:
        brand_name: Organization name from card.org or full name from card.fn.
        brand_logo_url: Logo URL from card.logo (parsed from vCard LOGO format).
        brand_logo_hash: Blake3-256 SAID from LOGO HASH parameter (Sprint 79).
    """

    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    brand_logo_hash: Optional[str] = None


# Known vCard fields per RFC 6350 (subset relevant to brand identity)
VCARD_FIELDS: Set[str] = {
    "fn",  # Full name
    "n",  # Structured name
    "nickname",  # Display name / nickname
    "org",  # Organization
    "tel",  # Telephone
    "email",  # Email
    "url",  # URL
    "logo",  # Logo URL/data
    "photo",  # Photo URL/data
    "adr",  # Address
    "title",  # Job title
    "note",  # Notes
    "categories",  # Categories
    "kind",  # vCard kind
    "rev",  # Revision timestamp
}

# Brand-indicative fields - presence of these suggests a brand credential
# Includes both vCard names and Extended Brand Credential attribute names
BRAND_INDICATOR_FIELDS: Set[str] = {
    "fn", "org", "logo", "url", "photo",  # vCard names
    "brandName", "brandDisplayName", "logoUrl", "websiteUrl",  # Extended Brand Credential
    "vcard",  # Provenant-style vcard array
}

# Sprint 58: Mapping from vCard card claim field names to credential attribute names.
# When verifying card attributes against a brand credential, try these names in order.
_VCARD_CREDENTIAL_MAP: Dict[str, List[str]] = {
    "org": ["org", "brandName"],
    "nickname": ["nickname", "brandDisplayName", "brandName"],
    "fn": ["fn", "brandDisplayName", "brandName"],
    "logo": ["logo", "logoUrl"],
    "url": ["url", "websiteUrl"],
}


def parse_vcard_properties(card: List[str]) -> Dict[str, str]:
    """Parse vCard property strings into a name-to-value dict.

    Each string is RFC 6350 format: ``NAME[;PARAM=VALUE]*:value``

    Example input::

        ["ORG:ACME Corp", "LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]

    Returns::

        {"org": "ACME Corp", "logo": "https://cdn.acme.com/logo.png"}

    Property names are lowercased for case-insensitive matching.
    Parameters (e.g. ``VALUE=URI``) are stripped from the key.
    """
    result: Dict[str, str] = {}
    for prop in card:
        if not isinstance(prop, str) or ":" not in prop:
            continue
        # Split on first colon to separate name+params from value
        name_part, value = prop.split(":", 1)
        # Extract base property name (before any parameters like ;VALUE=URI)
        base_name = name_part.split(";")[0].strip().lower()
        if base_name:
            result[base_name] = value
    return result


def extract_brand_info(card: List[str]) -> BrandInfo:
    """Extract brand name, logo URL, and logo hash from PASSporT card claim.

    Sprint 44/58/79: Extracts brand information for SIP header population.
    Card is an array of RFC 6350 vCard property strings per VVP §4.1.2.

    Brand name priority: ORG > NICKNAME > FN.
    Logo URL and HASH: parsed from LOGO property (uses shared vcard parser).

    Args:
        card: List of vCard property strings from PASSporT ``card`` claim.

    Returns:
        BrandInfo with brand_name, brand_logo_url, brand_logo_hash
    """
    # Use shared NormalizedBrand for extraction
    brand = normalize_brand({"vcard": card})
    if brand is not None:
        # Filter non-URL logos (base64 data, etc.)
        logo_url = brand.logo_url
        if logo_url and not logo_url.startswith(("http://", "https://")):
            log.debug(f"Brand logo is not a URL: {logo_url[:50]}...")
            logo_url = None

        info = BrandInfo(
            brand_name=brand.name or None,
            brand_logo_url=logo_url,
            brand_logo_hash=brand.logo_hash if logo_url else None,
        )
        # Fall back to NICKNAME/FN if ORG is empty
        if not info.brand_name:
            props = parse_vcard_properties(card)
            info.brand_name = props.get("nickname") or props.get("fn")
        return info

    # Fallback: use the simple parser for legacy card claims
    props = parse_vcard_properties(card)
    info = BrandInfo()

    org = props.get("org")
    nickname = props.get("nickname")
    fn = props.get("fn")

    if org:
        info.brand_name = org
    elif nickname:
        info.brand_name = nickname
    elif fn:
        info.brand_name = fn

    logo = props.get("logo")
    if logo:
        if logo.startswith(("http://", "https://")):
            info.brand_logo_url = logo

    return info


def validate_vcard_format(card: List[str]) -> List[str]:
    """Validate card property strings conform to vCard format.

    Per VVP §4.2: card attributes MUST conform to vCard format.

    Unknown fields log a warning but do NOT cause INVALID (per Reviewer).

    Args:
        card: List of vCard property strings.

    Returns:
        List of warning messages (empty if all fields known)
    """
    props = parse_vcard_properties(card)
    warnings = []
    for field_name in props.keys():
        if field_name not in VCARD_FIELDS:
            warnings.append(f"Unknown vCard field: {field_name}")
            log.warning(f"Brand validation: unknown vCard field '{field_name}'")
    return warnings


def find_brand_credential(dossier_acdcs: Dict[str, Any]) -> Optional[Any]:
    """Locate brand credential in dossier.

    Detection priority:
    1. Schema SAID match against BRAND_SCHEMA_SAIDS (definitive)
    2. Heuristic: 2+ brand indicator fields or brandName alone (fallback)

    Args:
        dossier_acdcs: Dict mapping SAID to ACDC objects

    Returns:
        ACDC object that appears to be a brand credential, or None
    """
    # Pass 1: Schema SAID match (definitive)
    for said, acdc in dossier_acdcs.items():
        schema = getattr(acdc, "schema", None)
        if schema is None:
            raw = getattr(acdc, "raw", None)
            schema = raw.get("s", "") if isinstance(raw, dict) else ""
        if schema and is_brand_schema(schema):
            log.debug(f"Found brand credential {said[:16]}... by schema SAID {schema[:16]}...")
            return acdc

    # Pass 2: Heuristic fallback (legacy/unknown schemas)
    for said, acdc in dossier_acdcs.items():
        attrs = getattr(acdc, "attributes", None)
        if attrs is None:
            raw = getattr(acdc, "raw", {})
            attrs = raw.get("a", {})

        if not isinstance(attrs, dict):
            continue

        found_indicators = set()
        for indicator in BRAND_INDICATOR_FIELDS:
            if indicator in attrs:
                found_indicators.add(indicator)

        # brandName alone is sufficient (Extended Brand schema).
        # vcard alone is sufficient (Provenant schema).
        # For others, require 2+ indicators.
        has_brand_name = "brandName" in attrs
        has_vcard = "vcard" in attrs and isinstance(attrs.get("vcard"), list) and len(attrs.get("vcard", [])) > 0
        if has_brand_name or has_vcard or len(found_indicators) >= 2:
            log.debug(
                f"Found brand credential {said[:16]}... with indicators: {found_indicators}"
            )
            return acdc

    return None


def verify_brand_attributes(
    card: List[str], brand_credential
) -> Tuple[bool, List[str], List[BrandError]]:
    """Verify card attributes are justified by brand credential.

    Per §5.1.1-2.12: MUST verify brand attributes are justified.

    For vcard-array credentials (Provenant schema), uses shared
    vcard_properties_match() for case-insensitive, multi-value comparison
    with HASH downgrade enforcement.

    For scalar-attribute credentials (legacy), uses the field mapping approach.

    Args:
        card: List of vCard property strings from PASSporT ``card`` claim.
        brand_credential: ACDC brand credential from dossier

    Returns:
        Tuple of (is_valid, list of mismatches or evidence, list of BrandError)
    """
    # Extract attributes from brand credential
    cred_attrs = getattr(brand_credential, "attributes", None)
    if cred_attrs is None:
        raw = getattr(brand_credential, "raw", {})
        cred_attrs = raw.get("a", {})

    if not isinstance(cred_attrs, dict):
        return False, ["Brand credential has no attributes"], []

    # If credential has vcard array, use shared comparison
    vcard_lines = cred_attrs.get("vcard")
    if vcard_lines and isinstance(vcard_lines, list) and len(vcard_lines) > 0:
        return _verify_vcard_attributes(card, vcard_lines)

    # Legacy scalar-attribute comparison
    return _verify_scalar_attributes(card, cred_attrs)


def _verify_vcard_attributes(
    card: List[str], credential_vcard: List[str]
) -> Tuple[bool, List[str], List[BrandError]]:
    """Verify card claim against credential vcard lines using shared comparison."""
    result = vcard_properties_match(credential_vcard, card)
    brand_errors: List[BrandError] = []

    if result.match:
        evidence = ["vcard_comparison:match"]
        if result.hash_integrity == "verified":
            evidence.append("logo_hash:verified")
        elif result.hash_integrity == "missing":
            evidence.append("logo_hash:none")
        return True, evidence, brand_errors

    # Map mismatches to structured errors
    evidence: List[str] = []
    for mismatch in result.mismatches:
        if "downgrade" in mismatch.lower():
            brand_errors.append(BrandError(
                code=BrandErrorCode.HASH_DOWNGRADE,
                message=mismatch,
                fields=["LOGO"],
            ))
        elif "but not in credential" in mismatch and "values" not in mismatch:
            # "Property X in card claim but not in credential" — missing property
            brand_errors.append(BrandError(
                code=BrandErrorCode.PROPERTY_MISSING,
                message=mismatch,
            ))
        else:
            # Value mismatch or "not in credential values" (set comparison)
            brand_errors.append(BrandError(
                code=BrandErrorCode.PROPERTY_MISMATCH,
                message=mismatch,
            ))

    return False, result.mismatches, brand_errors


def _verify_scalar_attributes(
    card: List[str], cred_attrs: dict
) -> Tuple[bool, List[str], List[BrandError]]:
    """Legacy scalar-attribute verification."""
    props = parse_vcard_properties(card)
    mismatches = []
    evidence = []

    for card_field, card_value in props.items():
        search_names = _VCARD_CREDENTIAL_MAP.get(card_field, [card_field])
        cred_value = None
        for name in search_names:
            cred_value = cred_attrs.get(name)
            if cred_value is not None:
                break

        if cred_value is None:
            mismatches.append(f"card.{card_field} not in brand credential")
        elif str(cred_value) != str(card_value):
            mismatches.append(
                f"card.{card_field} '{card_value}' != credential '{cred_value}'"
            )
        else:
            evidence.append(f"card.{card_field}:matched")

    if mismatches:
        return False, mismatches, []
    return True, evidence, []


def verify_brand_jl(
    brand_credential, dossier_acdcs: Dict[str, Any]
) -> Tuple[bool, str]:
    """Verify brand credential has JL (join link) to vetting credential.

    Per §6.3.7: Brand credential MUST include JL to vetting credential.

    Args:
        brand_credential: ACDC brand credential
        dossier_acdcs: All ACDCs in dossier

    Returns:
        Tuple of (has_valid_jl, evidence_or_reason)
    """
    # Get edges from brand credential
    edges = getattr(brand_credential, "edges", None)
    if edges is None:
        raw = getattr(brand_credential, "raw", {})
        edges = raw.get("e", {})

    if not edges or not isinstance(edges, dict):
        return False, "Brand credential has no edges"

    # Look for vetting-related edge (jl, vetting, auth, etc.)
    vetting_edge_names = {"jl", "vetting", "auth", "issuer", "le"}

    for edge_name, edge_ref in edges.items():
        # Skip metadata fields
        if edge_name in ("d", "n"):
            continue

        # Normalize edge name
        if edge_name.lower() in vetting_edge_names:
            # Extract target SAID
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get("n") or edge_ref.get("d")

            if target_said and target_said in dossier_acdcs:
                return True, f"jl_valid:{edge_name}→{target_said[:12]}..."
            elif target_said:
                # Target not in dossier - might be external reference
                log.debug(f"Brand JL target {target_said[:16]}... not in dossier")
                return True, f"jl_present:{edge_name}→{target_said[:12]}...(external)"

    return False, "Brand credential missing JL to vetting"


def verify_brand_proxy(
    de_credential, brand_credential, dossier_acdcs: Dict[str, Any]
) -> Tuple[bool, str]:
    """Verify DE credential has brand proxy for delegation with brand.

    Per §6.3.4: If brand in APE + delegation, DE MUST have brand proxy.

    Args:
        de_credential: Delegation edge credential
        brand_credential: Brand credential from APE
        dossier_acdcs: All ACDCs in dossier

    Returns:
        Tuple of (has_brand_proxy, evidence_or_reason)
    """
    if de_credential is None:
        # No delegation, no proxy needed
        return True, "no_delegation:proxy_not_required"

    # Get edges from DE credential
    edges = getattr(de_credential, "edges", None)
    if edges is None:
        raw = getattr(de_credential, "raw", {})
        edges = raw.get("e", {})

    if not edges or not isinstance(edges, dict):
        return False, "DE credential has no edges for brand proxy"

    # Look for brand proxy edge
    brand_proxy_names = {"brand", "brandProxy", "brand_proxy", "logo", "identity"}

    for edge_name, edge_ref in edges.items():
        if edge_name in ("d", "n"):
            continue

        if edge_name.lower() in brand_proxy_names or "brand" in edge_name.lower():
            # Found brand proxy edge
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get("n") or edge_ref.get("d")

            if target_said:
                return True, f"brand_proxy:{edge_name}→{target_said[:12]}..."

    return False, "DE credential missing brand proxy for delegated brand usage"


def verify_brand(
    passport,  # Passport type
    dossier_acdcs: Dict[str, Any],
    de_credential: Optional[Any] = None,
) -> Tuple[Optional[ClaimBuilder], Optional[BrandInfo]]:
    """Verify brand claims if card present in PASSporT.

    Per §5A Step 12: If passport includes non-null card claim values,
    MUST locate brand credential and verify attributes are justified.

    Sprint 44: Also returns extracted brand info for SIP header population.
    Brand info is extracted even when verification fails (but status is not VALID).

    Args:
        passport: Parsed PASSporT object
        dossier_acdcs: Dict mapping SAID to ACDC objects
        de_credential: Delegation edge credential (if delegation present)

    Returns:
        Tuple of:
        - ClaimBuilder for brand_verified claim, or None if no card
        - BrandInfo with brand_name/brand_logo_url, or None if no card
    """
    # Check if card is present
    card = getattr(passport.payload, "card", None)
    if card is None:
        return None, None  # No card, no verification needed

    claim = ClaimBuilder("brand_verified")
    claim.add_evidence("card:present")

    # Extract brand info from card (Sprint 44/79)
    brand_info = extract_brand_info(card)
    if brand_info.brand_name:
        claim.add_evidence(f"brand_name:{brand_info.brand_name}")
    if brand_info.brand_logo_url:
        claim.add_evidence(f"brand_logo_url:{brand_info.brand_logo_url[:40]}...")
    if brand_info.brand_logo_hash:
        claim.add_evidence(f"brand_logo_hash:{brand_info.brand_logo_hash[:16]}...")

    # Validate vCard format (warn on unknown fields, don't fail)
    warnings = validate_vcard_format(card)
    if warnings:
        for warning in warnings:
            claim.add_evidence(f"warning:{warning}")

    # Find brand credential in dossier
    brand_credential = find_brand_credential(dossier_acdcs)
    if brand_credential is None:
        claim.fail(ClaimStatus.INVALID, "No brand credential found in dossier")
        return claim, brand_info

    brand_said = getattr(brand_credential, "said", "unknown")
    claim.add_evidence(f"brand_credential:{brand_said[:16]}...")

    # Verify brand attributes match
    attrs_valid, attr_result, brand_errors = verify_brand_attributes(card, brand_credential)
    if attrs_valid:
        for ev in attr_result:
            claim.add_evidence(ev)
    else:
        for mismatch in attr_result:
            claim.fail(ClaimStatus.INVALID, mismatch)
        return claim, brand_info

    # Verify brand credential has JL to vetting (§6.3.7)
    jl_valid, jl_evidence = verify_brand_jl(brand_credential, dossier_acdcs)
    if jl_valid:
        claim.add_evidence(jl_evidence)
    else:
        claim.fail(ClaimStatus.INVALID, jl_evidence)
        return claim, brand_info

    # Verify brand proxy in delegation (§6.3.4)
    # If delegation present, DE MUST have brand proxy → INDETERMINATE if missing
    if de_credential is not None:
        proxy_valid, proxy_evidence = verify_brand_proxy(
            de_credential, brand_credential, dossier_acdcs
        )
        if proxy_valid:
            claim.add_evidence(proxy_evidence)
        else:
            # Per Reviewer: INDETERMINATE for missing brand proxy (can't verify)
            claim.fail(ClaimStatus.INDETERMINATE, proxy_evidence)
            return claim, brand_info

    return claim, brand_info
