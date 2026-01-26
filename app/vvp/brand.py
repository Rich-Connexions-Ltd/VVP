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
from typing import Any, Dict, List, Optional, Set, Tuple

from .api_models import ClaimStatus, ErrorCode

log = logging.getLogger(__name__)


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


# Known vCard fields per RFC 6350 (subset relevant to brand identity)
VCARD_FIELDS: Set[str] = {
    "fn",  # Full name
    "n",  # Structured name
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
BRAND_INDICATOR_FIELDS: Set[str] = {"fn", "org", "logo", "url", "photo"}


def validate_vcard_format(card: Dict[str, Any]) -> List[str]:
    """Validate card attributes conform to vCard format.

    Per VVP §4.2: card attributes MUST conform to vCard format.

    Unknown fields log a warning but do NOT cause INVALID (per Reviewer).

    Args:
        card: Dictionary of card attributes

    Returns:
        List of warning messages (empty if all fields known)
    """
    warnings = []
    for field_name in card.keys():
        # Normalize field name (vCard is case-insensitive)
        normalized = field_name.lower()
        if normalized not in VCARD_FIELDS:
            warnings.append(f"Unknown vCard field: {field_name}")
            log.warning(f"Brand validation: unknown vCard field '{field_name}'")
    return warnings


def find_brand_credential(dossier_acdcs: Dict[str, Any]) -> Optional[Any]:
    """Locate brand credential in dossier.

    Brand credentials are identified by having brand-related attributes
    (fn, org, logo, url, photo) in their attributes section.

    Args:
        dossier_acdcs: Dict mapping SAID to ACDC objects

    Returns:
        ACDC object that appears to be a brand credential, or None
    """
    for said, acdc in dossier_acdcs.items():
        # Check if this credential has brand-indicative attributes
        attrs = getattr(acdc, "attributes", None)
        if attrs is None:
            # Try raw dict access
            raw = getattr(acdc, "raw", {})
            attrs = raw.get("a", {})

        if not isinstance(attrs, dict):
            continue

        # Look for brand indicator fields
        found_indicators = set()
        for indicator in BRAND_INDICATOR_FIELDS:
            if indicator in attrs:
                found_indicators.add(indicator)

        # Require at least 2 brand indicators to identify as brand credential
        if len(found_indicators) >= 2:
            log.debug(
                f"Found brand credential {said[:16]}... with indicators: {found_indicators}"
            )
            return acdc

    return None


def verify_brand_attributes(
    card: Dict[str, Any], brand_credential
) -> Tuple[bool, List[str]]:
    """Verify card attributes are justified by brand credential.

    Per §5.1.1-2.12: MUST verify brand attributes are justified.

    Args:
        card: Dictionary of card attributes from PASSporT
        brand_credential: ACDC brand credential from dossier

    Returns:
        Tuple of (is_valid, list of mismatches or evidence)
    """
    # Extract attributes from brand credential
    cred_attrs = getattr(brand_credential, "attributes", None)
    if cred_attrs is None:
        raw = getattr(brand_credential, "raw", {})
        cred_attrs = raw.get("a", {})

    if not isinstance(cred_attrs, dict):
        return False, ["Brand credential has no attributes"]

    mismatches = []
    evidence = []

    for card_field, card_value in card.items():
        # Normalize field name
        normalized = card_field.lower()

        # Check if credential has this attribute
        cred_value = cred_attrs.get(normalized) or cred_attrs.get(card_field)

        if cred_value is None:
            # Card claims attribute not in credential
            mismatches.append(f"card.{card_field} not in brand credential")
        elif str(cred_value) != str(card_value):
            # Values don't match
            mismatches.append(
                f"card.{card_field} '{card_value}' != credential '{cred_value}'"
            )
        else:
            evidence.append(f"card.{card_field}:matched")

    if mismatches:
        return False, mismatches
    return True, evidence


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
) -> Optional[ClaimBuilder]:
    """Verify brand claims if card present in PASSporT.

    Per §5A Step 12: If passport includes non-null card claim values,
    MUST locate brand credential and verify attributes are justified.

    Args:
        passport: Parsed PASSporT object
        dossier_acdcs: Dict mapping SAID to ACDC objects
        de_credential: Delegation edge credential (if delegation present)

    Returns:
        ClaimBuilder for brand_verified claim, or None if no card
    """
    # Check if card is present
    card = getattr(passport.payload, "card", None)
    if card is None:
        return None  # No card, no verification needed

    claim = ClaimBuilder("brand_verified")
    claim.add_evidence("card:present")

    # Validate vCard format (warn on unknown fields, don't fail)
    warnings = validate_vcard_format(card)
    if warnings:
        for warning in warnings:
            claim.add_evidence(f"warning:{warning}")

    # Find brand credential in dossier
    brand_credential = find_brand_credential(dossier_acdcs)
    if brand_credential is None:
        claim.fail(ClaimStatus.INVALID, "No brand credential found in dossier")
        return claim

    brand_said = getattr(brand_credential, "said", "unknown")
    claim.add_evidence(f"brand_credential:{brand_said[:16]}...")

    # Verify brand attributes match
    attrs_valid, attr_result = verify_brand_attributes(card, brand_credential)
    if attrs_valid:
        for ev in attr_result:
            claim.add_evidence(ev)
    else:
        for mismatch in attr_result:
            claim.fail(ClaimStatus.INVALID, mismatch)
        return claim

    # Verify brand credential has JL to vetting (§6.3.7)
    jl_valid, jl_evidence = verify_brand_jl(brand_credential, dossier_acdcs)
    if jl_valid:
        claim.add_evidence(jl_evidence)
    else:
        claim.fail(ClaimStatus.INVALID, jl_evidence)
        return claim

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
            return claim

    return claim
