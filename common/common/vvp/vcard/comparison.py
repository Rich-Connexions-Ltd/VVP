"""Credential vCard vs PASSporT card claim comparison.

Compares vCard lines from the signed credential against the card claim
lines in the PASSporT JWT. Enforces HASH integrity — if the credential
LOGO has a HASH parameter, the card claim must also include it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .parser import VCardProperty, parse_vcard_lines


@dataclass
class ComparisonResult:
    """Result of comparing credential vCard against card claim."""

    match: bool
    mismatches: list[str] = field(default_factory=list)
    hash_integrity: str = "missing"  # "verified" | "missing" | "omitted_from_card"


def vcard_properties_match(
    credential_lines: list[str],
    card_claim_lines: list[str],
) -> ComparisonResult:
    """Compare credential vCard lines against PASSporT card claim lines.

    Rules:
    - Case-insensitive property name matching
    - Multi-value properties compared as sets (order-independent)
    - If credential LOGO has HASH but card claim LOGO omits it → match=False
      (HASH downgrade attack prevention)
    - Card claim may be a subset of credential vcard (credential can have
      more properties than the card claim)
    """
    cred_props = parse_vcard_lines(credential_lines)
    card_props = parse_vcard_lines(card_claim_lines)

    mismatches: list[str] = []
    hash_integrity = "missing"

    # Build lookup: property name -> list of (value, params) from credential
    cred_by_name: dict[str, list[VCardProperty]] = {}
    for p in cred_props:
        cred_by_name.setdefault(p.name, []).append(p)

    # Check each card claim property exists in credential with matching value
    for card_prop in card_props:
        cred_matches = cred_by_name.get(card_prop.name)
        if not cred_matches:
            mismatches.append(
                f"Property {card_prop.name} in card claim but not in credential"
            )
            continue

        if card_prop.name == "LOGO":
            # Special LOGO handling with HASH enforcement
            cred_logo = cred_matches[0]
            result = _compare_logo(cred_logo, card_prop)
            if result.mismatch:
                mismatches.append(result.mismatch)
            hash_integrity = result.hash_integrity
        else:
            # For multi-value properties, check if the card value exists
            # in the credential's set of values for that property
            cred_values = {p.value for p in cred_matches}
            if card_prop.value not in cred_values:
                mismatches.append(
                    f"Property {card_prop.name}: card='{card_prop.value}' "
                    f"not in credential values {cred_values}"
                )

    # Check HASH integrity for LOGO even if not in card claim
    cred_logos = cred_by_name.get("LOGO", [])
    card_logos = [p for p in card_props if p.name == "LOGO"]
    if cred_logos and not card_logos:
        cred_logo = cred_logos[0]
        if cred_logo.params.get("HASH"):
            hash_integrity = "omitted_from_card"
            mismatches.append(
                "Credential LOGO has HASH parameter but LOGO absent from card claim "
                "(potential HASH downgrade)"
            )

    return ComparisonResult(
        match=len(mismatches) == 0,
        mismatches=mismatches,
        hash_integrity=hash_integrity,
    )


@dataclass
class _LogoCompareResult:
    mismatch: Optional[str] = None
    hash_integrity: str = "missing"


def _compare_logo(cred_logo: VCardProperty, card_logo: VCardProperty) -> _LogoCompareResult:
    """Compare LOGO properties with HASH enforcement."""
    # Compare URI values
    cred_url = cred_logo.value
    card_url = card_logo.value
    if cred_url != card_url:
        return _LogoCompareResult(
            mismatch=f"LOGO URL mismatch: credential='{cred_url}', card='{card_url}'",
            hash_integrity="missing",
        )

    cred_hash = cred_logo.params.get("HASH")
    card_hash = card_logo.params.get("HASH")

    if cred_hash and card_hash:
        if cred_hash != card_hash:
            return _LogoCompareResult(
                mismatch=f"LOGO HASH mismatch: credential='{cred_hash}', card='{card_hash}'",
                hash_integrity="missing",
            )
        return _LogoCompareResult(hash_integrity="verified")

    if cred_hash and not card_hash:
        return _LogoCompareResult(
            mismatch=(
                "Credential LOGO has HASH parameter but card claim LOGO omits it "
                "(potential HASH downgrade)"
            ),
            hash_integrity="omitted_from_card",
        )

    # Neither has hash, or only card has hash (unusual but not a security issue)
    return _LogoCompareResult(hash_integrity="missing")
