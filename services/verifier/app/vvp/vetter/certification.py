"""Vetter Certification credential model and parsing.

This module defines the VetterCertification dataclass representing
a parsed Vetter Certification credential, and functions to parse
ACDC credentials into this model.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

# Known Vetter Certification schema SAIDs
# Provisional SAID - update when governance publishes official SAIDs
VETTER_CERTIFICATION_SCHEMA_SAIDS = frozenset(
    [
        "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H",  # VVP provisional
    ]
)


@dataclass
class VetterCertification:
    """Parsed Vetter Certification credential.

    Represents a vetter's certification that defines their geographic
    and jurisdictional constraints for credential issuance.

    Attributes:
        said: SAID of the certification credential
        vetter_aid: AID of the certified vetter (issuee of the certification)
        issuer_aid: AID of the certification issuer (e.g., GSMA)
        ecc_targets: List of E.164 country codes for TN right-to-use attestation
        jurisdiction_targets: List of ISO 3166-1 alpha-3 codes for
            incorporation and brand licensure attestation
        name: Optional human-readable name of the vetter
        expiry: Optional certification expiry datetime string
        raw: Original ACDC dict for debugging
    """

    said: str
    vetter_aid: str
    issuer_aid: str
    ecc_targets: list[str] = field(default_factory=list)
    jurisdiction_targets: list[str] = field(default_factory=list)
    name: Optional[str] = None
    expiry: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    def has_ecc_target(self, country_code: str) -> bool:
        """Check if a country code is in the vetter's ECC targets.

        Args:
            country_code: E.164 country code (e.g., "44", "1")

        Returns:
            True if the country code is in ecc_targets
        """
        return country_code in self.ecc_targets

    def has_jurisdiction_target(self, country_code: str) -> bool:
        """Check if a country code is in the vetter's jurisdiction targets.

        Args:
            country_code: ISO 3166-1 alpha-3 code (e.g., "GBR", "USA")

        Returns:
            True if the country code is in jurisdiction_targets
        """
        return country_code.upper() in [t.upper() for t in self.jurisdiction_targets]


def parse_vetter_certification(acdc: Any) -> Optional[VetterCertification]:
    """Parse a Vetter Certification from an ACDC.

    Accepts either a dict or an ACDC-like object with attributes.

    Args:
        acdc: ACDC dict or object representing a Vetter Certification

    Returns:
        VetterCertification if parsing succeeds, None otherwise
    """
    try:
        # Handle both dict and object access patterns
        if isinstance(acdc, dict):
            raw = acdc
            said = acdc.get("d", "")
            issuer_aid = acdc.get("i", "")
            schema = acdc.get("s", "")
            attrs = acdc.get("a", {})
        else:
            raw = getattr(acdc, "raw", {}) or {}
            said = getattr(acdc, "said", "") or raw.get("d", "")
            issuer_aid = getattr(acdc, "issuer_aid", "") or raw.get("i", "")
            schema = getattr(acdc, "schema_said", "") or raw.get("s", "")
            attrs = getattr(acdc, "attributes", None)
            if attrs is None:
                attrs = raw.get("a", {})

        # Handle compact form where attributes is a SAID string
        if isinstance(attrs, str):
            log.warning(
                f"Vetter Certification {said[:16]}... has compact attributes, "
                "cannot extract ecc_targets/jurisdiction_targets"
            )
            return None

        if not isinstance(attrs, dict):
            log.warning(
                f"Vetter Certification {said[:16]}... has invalid attributes type"
            )
            return None

        # Extract vetter AID (issuee) from attributes
        vetter_aid = attrs.get("i", "")
        if not vetter_aid:
            log.warning(
                f"Vetter Certification {said[:16]}... missing issuee (a.i field)"
            )

        # Extract constraint targets
        ecc_targets = attrs.get("ecc_targets", [])
        jurisdiction_targets = attrs.get("jurisdiction_targets", [])

        # Ensure lists
        if not isinstance(ecc_targets, list):
            ecc_targets = [ecc_targets] if ecc_targets else []
        if not isinstance(jurisdiction_targets, list):
            jurisdiction_targets = (
                [jurisdiction_targets] if jurisdiction_targets else []
            )

        # Normalize - ensure strings and uppercase for jurisdiction
        ecc_targets = [str(t) for t in ecc_targets]
        jurisdiction_targets = [str(t).upper() for t in jurisdiction_targets]

        # Extract optional fields
        name = attrs.get("name")
        expiry = attrs.get("certificationExpiry")

        return VetterCertification(
            said=said,
            vetter_aid=vetter_aid,
            issuer_aid=issuer_aid,
            ecc_targets=ecc_targets,
            jurisdiction_targets=jurisdiction_targets,
            name=name,
            expiry=expiry,
            raw=raw if isinstance(raw, dict) else {},
        )

    except Exception as e:
        log.error(f"Failed to parse Vetter Certification: {e}")
        return None


def is_vetter_certification_schema(schema_said: str) -> bool:
    """Check if a schema SAID is a known Vetter Certification schema.

    Args:
        schema_said: Schema SAID to check

    Returns:
        True if the schema is a known Vetter Certification schema
    """
    return schema_said in VETTER_CERTIFICATION_SCHEMA_SAIDS
