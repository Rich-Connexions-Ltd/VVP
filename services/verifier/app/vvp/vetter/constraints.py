"""Vetter constraint validation logic.

This module provides functions to validate credentials against
their issuing vetter's certification constraints.

Per the VVP Multichannel Vetters specification:
- TN credentials: country code must be in vetter's ecc_targets
- Identity credentials: incorporation country must be in jurisdiction_targets
- Brand credentials: assertion country must be in jurisdiction_targets
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from app.vvp.api_models import ClaimStatus
from app.vvp.vetter.certification import VetterCertification
from app.vvp.vetter.country_codes import (
    e164_to_iso3166,
    extract_e164_country_code,
    normalize_country_code,
)
from app.vvp.vetter.traversal import find_vetter_certification

log = logging.getLogger(__name__)


class CredentialType(str, Enum):
    """Types of credentials subject to vetter constraints."""

    TN = "TN"
    IDENTITY = "Identity"
    BRAND = "Brand"


class ConstraintType(str, Enum):
    """Types of vetter constraints."""

    ECC = "ecc"  # E.164 Country Code constraint
    JURISDICTION = "jurisdiction"  # ISO 3166-1 jurisdiction constraint


@dataclass
class VetterConstraintResult:
    """Result of vetter constraint validation for a single credential."""

    credential_said: str
    credential_type: CredentialType
    vetter_certification_said: Optional[str]
    constraint_type: ConstraintType
    target_value: str  # The value being checked (e.g., "44" or "GBR")
    allowed_values: list[str] = field(default_factory=list)
    is_authorized: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for API response."""
        return {
            "credential_said": self.credential_said,
            "credential_type": self.credential_type.value,
            "vetter_certification_said": self.vetter_certification_said,
            "constraint_type": self.constraint_type.value,
            "target_value": self.target_value,
            "allowed_values": self.allowed_values,
            "is_authorized": self.is_authorized,
            "reason": self.reason,
        }


def validate_ecc_constraint(
    tn: str,
    certification: VetterCertification,
) -> tuple[ClaimStatus, str]:
    """Validate a telephone number against vetter's ECC targets.

    Per spec: "Does the TN credential say the caller has the right to use
    a TN whose country code also appears in the ECC Targets field?"

    Args:
        tn: E.164 telephone number (e.g., "+447884666200")
        certification: Vetter's certification

    Returns:
        Tuple of (ClaimStatus, reason string)
    """
    country_code = extract_e164_country_code(tn)

    if not country_code:
        return (
            ClaimStatus.INDETERMINATE,
            f"Cannot extract country code from TN: {tn}",
        )

    if certification.has_ecc_target(country_code):
        return (
            ClaimStatus.VALID,
            f"ECC authorized: {country_code} in vetter targets",
        )

    return (
        ClaimStatus.INVALID,
        f"TN country code {country_code} not in vetter ECC targets "
        f"{certification.ecc_targets[:5]}{'...' if len(certification.ecc_targets) > 5 else ''}",
    )


def validate_jurisdiction_constraint(
    country_code: str,
    certification: VetterCertification,
    context: str = "jurisdiction",
) -> tuple[ClaimStatus, str]:
    """Validate a country code against vetter's jurisdiction targets.

    Per spec: "Does the identity credential say the caller is incorporated
    in a country that also appears in the Jurisdiction Targets field?"

    Args:
        country_code: ISO 3166-1 alpha-3 code (e.g., "GBR")
        certification: Vetter's certification
        context: Description of what's being validated (for error messages)

    Returns:
        Tuple of (ClaimStatus, reason string)
    """
    normalized = normalize_country_code(country_code)

    if not normalized:
        return (
            ClaimStatus.INDETERMINATE,
            f"Invalid {context} country code: {country_code}",
        )

    if certification.has_jurisdiction_target(normalized):
        return (
            ClaimStatus.VALID,
            f"Jurisdiction authorized: {normalized} in vetter targets",
        )

    return (
        ClaimStatus.INVALID,
        f"{context.capitalize()} country {normalized} not in vetter jurisdiction targets "
        f"{certification.jurisdiction_targets[:5]}{'...' if len(certification.jurisdiction_targets) > 5 else ''}",
    )


def extract_incorporation_country(credential: Any) -> Optional[str]:
    """Extract incorporation country from an identity credential.

    Looks for:
    1. Direct 'country' attribute (ISO 3166-1 alpha-3)
    2. 'jurisdiction' attribute
    3. LEI-based extraction (future enhancement)

    Args:
        credential: Identity/Legal Entity ACDC

    Returns:
        ISO 3166-1 alpha-3 code or None
    """
    attrs = _get_attributes(credential)
    if not attrs:
        return None

    # Direct country field (preferred)
    if "country" in attrs:
        return normalize_country_code(str(attrs["country"]))

    # Jurisdiction field
    if "jurisdiction" in attrs:
        return normalize_country_code(str(attrs["jurisdiction"]))

    # incorporation_country field
    if "incorporation_country" in attrs:
        return normalize_country_code(str(attrs["incorporation_country"]))

    return None


def extract_tn_from_credential(credential: Any) -> Optional[str]:
    """Extract telephone number from a TN allocation credential.

    Args:
        credential: TN Allocation ACDC

    Returns:
        First E.164 telephone number or None
    """
    attrs = _get_attributes(credential)
    if not attrs:
        return None

    # Look for numbers.tn array
    numbers = attrs.get("numbers", {})
    if isinstance(numbers, dict):
        tn_list = numbers.get("tn", [])
        if isinstance(tn_list, list) and tn_list:
            return tn_list[0]

    # Direct tn field
    if "tn" in attrs:
        tn = attrs["tn"]
        if isinstance(tn, list) and tn:
            return tn[0]
        return str(tn)

    return None


def _get_attributes(credential: Any) -> Optional[dict[str, Any]]:
    """Extract attributes dict from credential."""
    if isinstance(credential, dict):
        attrs = credential.get("a")
    else:
        attrs = getattr(credential, "attributes", None)
        if attrs is None:
            raw = getattr(credential, "raw", {})
            attrs = raw.get("a") if raw else None

    if isinstance(attrs, str):
        # Compact form - attributes is a SAID
        return None

    return attrs if isinstance(attrs, dict) else None


def _get_credential_said(credential: Any) -> str:
    """Extract SAID from credential."""
    if isinstance(credential, dict):
        return credential.get("d", "")
    return getattr(credential, "said", "") or ""


def verify_vetter_constraints(
    dossier_acdcs: dict[str, Any],
    orig_tn: str,
    dest_tn: Optional[str] = None,
    tn_credentials: Optional[list[Any]] = None,
    identity_credentials: Optional[list[Any]] = None,
    brand_credentials: Optional[list[Any]] = None,
) -> dict[str, VetterConstraintResult]:
    """Verify all vetter constraints for credentials in a dossier.

    This is the main entry point for vetter constraint validation.
    Results are returned as status bits that clients can interpret.

    Args:
        dossier_acdcs: All ACDCs in the dossier, keyed by SAID
        orig_tn: Originating telephone number (for ECC validation)
        dest_tn: Destination telephone number (for brand assertion country)
        tn_credentials: List of TN allocation credentials to validate
        identity_credentials: List of identity credentials to validate
        brand_credentials: List of brand credentials to validate

    Returns:
        Dict mapping credential SAIDs to VetterConstraintResult
    """
    results: dict[str, VetterConstraintResult] = {}

    # Derive brand assertion country from destination TN
    assertion_country = None
    if dest_tn:
        dest_e164 = extract_e164_country_code(dest_tn)
        assertion_country = e164_to_iso3166(dest_e164)

    # Validate TN credentials against ECC targets
    for cred in tn_credentials or []:
        cred_said = _get_credential_said(cred)
        cert = find_vetter_certification(cred, dossier_acdcs)

        if not cert:
            results[cred_said] = VetterConstraintResult(
                credential_said=cred_said,
                credential_type=CredentialType.TN,
                vetter_certification_said=None,
                constraint_type=ConstraintType.ECC,
                target_value=extract_e164_country_code(orig_tn) or "",
                allowed_values=[],
                is_authorized=False,
                reason="Vetter certification not found for TN credential",
            )
            continue

        # Use orig_tn for ECC validation
        tn_country = extract_e164_country_code(orig_tn)
        status, reason = validate_ecc_constraint(orig_tn, cert)

        results[cred_said] = VetterConstraintResult(
            credential_said=cred_said,
            credential_type=CredentialType.TN,
            vetter_certification_said=cert.said,
            constraint_type=ConstraintType.ECC,
            target_value=tn_country,
            allowed_values=cert.ecc_targets,
            is_authorized=(status == ClaimStatus.VALID),
            reason=reason,
        )

    # Validate identity credentials against jurisdiction targets
    for cred in identity_credentials or []:
        cred_said = _get_credential_said(cred)
        cert = find_vetter_certification(cred, dossier_acdcs)

        incorporation_country = extract_incorporation_country(cred)

        if not cert:
            results[cred_said] = VetterConstraintResult(
                credential_said=cred_said,
                credential_type=CredentialType.IDENTITY,
                vetter_certification_said=None,
                constraint_type=ConstraintType.JURISDICTION,
                target_value=incorporation_country or "",
                allowed_values=[],
                is_authorized=False,
                reason="Vetter certification not found for identity credential",
            )
            continue

        if not incorporation_country:
            results[cred_said] = VetterConstraintResult(
                credential_said=cred_said,
                credential_type=CredentialType.IDENTITY,
                vetter_certification_said=cert.said,
                constraint_type=ConstraintType.JURISDICTION,
                target_value="",
                allowed_values=cert.jurisdiction_targets,
                is_authorized=False,
                reason="Cannot extract incorporation country from identity credential",
            )
            continue

        status, reason = validate_jurisdiction_constraint(
            incorporation_country, cert, "incorporation"
        )

        results[cred_said] = VetterConstraintResult(
            credential_said=cred_said,
            credential_type=CredentialType.IDENTITY,
            vetter_certification_said=cert.said,
            constraint_type=ConstraintType.JURISDICTION,
            target_value=incorporation_country,
            allowed_values=cert.jurisdiction_targets,
            is_authorized=(status == ClaimStatus.VALID),
            reason=reason,
        )

    # Validate brand credentials against jurisdiction targets
    for cred in brand_credentials or []:
        cred_said = _get_credential_said(cred)
        cert = find_vetter_certification(cred, dossier_acdcs)

        if not cert:
            results[cred_said] = VetterConstraintResult(
                credential_said=cred_said,
                credential_type=CredentialType.BRAND,
                vetter_certification_said=None,
                constraint_type=ConstraintType.JURISDICTION,
                target_value=assertion_country or "",
                allowed_values=[],
                is_authorized=False,
                reason="Vetter certification not found for brand credential",
            )
            continue

        if not assertion_country:
            results[cred_said] = VetterConstraintResult(
                credential_said=cred_said,
                credential_type=CredentialType.BRAND,
                vetter_certification_said=cert.said,
                constraint_type=ConstraintType.JURISDICTION,
                target_value="",
                allowed_values=cert.jurisdiction_targets,
                is_authorized=False,
                reason="Cannot determine brand assertion country (no destination TN)",
            )
            continue

        status, reason = validate_jurisdiction_constraint(
            assertion_country, cert, "brand assertion"
        )

        results[cred_said] = VetterConstraintResult(
            credential_said=cred_said,
            credential_type=CredentialType.BRAND,
            vetter_certification_said=cert.said,
            constraint_type=ConstraintType.JURISDICTION,
            target_value=assertion_country,
            allowed_values=cert.jurisdiction_targets,
            is_authorized=(status == ClaimStatus.VALID),
            reason=reason,
        )

    return results


def get_overall_constraint_status(
    results: dict[str, VetterConstraintResult],
) -> ClaimStatus:
    """Get overall status from constraint results.

    Args:
        results: Dict of constraint results

    Returns:
        VALID if all authorized, INVALID if any unauthorized,
        INDETERMINATE if any missing certification
    """
    if not results:
        return ClaimStatus.VALID

    has_unauthorized = False
    has_missing_cert = False

    for result in results.values():
        if not result.is_authorized:
            if result.vetter_certification_said is None:
                has_missing_cert = True
            else:
                has_unauthorized = True

    if has_unauthorized:
        return ClaimStatus.INVALID
    if has_missing_cert:
        return ClaimStatus.INDETERMINATE

    return ClaimStatus.VALID
