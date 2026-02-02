"""Vetter Certification Constraint Validation Module.

This module implements verification of Vetter Certification credentials
to enforce geographic and jurisdictional constraints on credential issuers.

Per the VVP Multichannel Vetters specification:
- Vetters receive a Vetter Certification credential with ECC Targets and
  Jurisdiction Targets that constrain their authority
- Each credential (Identity, Brand, TN) must have a backlink edge to the
  issuing vetter's certification
- During verification, the verifier checks that:
  - TN credential's country code is in the vetter's ecc_targets
  - Identity credential's incorporation country is in jurisdiction_targets
  - Brand credential's assertion country is in jurisdiction_targets

Results are status bits that clients can interpret as errors or warnings.
"""

from app.vvp.vetter.certification import VetterCertification, parse_vetter_certification
from app.vvp.vetter.constraints import (
    VetterConstraintResult,
    validate_ecc_constraint,
    validate_jurisdiction_constraint,
    verify_vetter_constraints,
    get_overall_constraint_status,
)
from app.vvp.vetter.country_codes import (
    E164_COUNTRY_CODES,
    ISO3166_ALPHA3_CODES,
    extract_e164_country_code,
    e164_to_iso3166,
    normalize_country_code,
)
from app.vvp.vetter.traversal import find_vetter_certification

__all__ = [
    # Models
    "VetterCertification",
    "VetterConstraintResult",
    # Parsing
    "parse_vetter_certification",
    # Traversal
    "find_vetter_certification",
    # Validation
    "validate_ecc_constraint",
    "validate_jurisdiction_constraint",
    "verify_vetter_constraints",
    "get_overall_constraint_status",
    # Country code utilities
    "E164_COUNTRY_CODES",
    "ISO3166_ALPHA3_CODES",
    "extract_e164_country_code",
    "e164_to_iso3166",
    "normalize_country_code",
]
