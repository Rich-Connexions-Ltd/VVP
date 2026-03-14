"""ACDC Schema SAID Registry.

Credentials must use recognized schema SAIDs from the vLEI governance
framework. This module provides a versioned registry of known schema SAIDs
for validation.

This module is shared between verifier and issuer services.

Registry Version: 1.3.0
Last Updated: 2026-02-03

Normative Source: https://github.com/WebOfTrust/vLEI/tree/main/schema/acdc

vLEI Credential Chain Hierarchy:
================================
GLEIF (Root AID)
    └── QVI Credential (issued to Qualified vLEI Issuers like Provenant)
            └── LE Credential (issued to Legal Entities)
                    ├── OOR Auth → OOR (Official Organizational Role)
                    └── ECR Auth → ECR (Engagement Context Role)

Edge Structure:
- LE credentials have `e.qvi` edge pointing to QVI credential SAID
- OOR Auth/ECR Auth have `e.le` edge pointing to LE credential SAID
- OOR has `e.auth` edge pointing to OOR Auth credential SAID
- ECR has `e.auth` or `e.le` edge
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet

# Registry version for tracking updates
SCHEMA_REGISTRY_VERSION = "1.4.0"

# Known vLEI governance schema SAIDs
# These are the official schema SAIDs from the vLEI ecosystem
# Source: https://github.com/WebOfTrust/vLEI/tree/main/schema/acdc
KNOWN_SCHEMA_SAIDS: Dict[str, FrozenSet[str]] = {
    # Qualified vLEI Issuer credential
    # Source: https://github.com/WebOfTrust/vLEI - qualified-vLEI-issuer-vLEI-credential.json
    # Issued by GLEIF to QVIs (e.g., Provenant Global)
    "QVI": frozenset({
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # vLEI QVI credential schema
    }),

    # Legal Entity credential
    # Source: https://github.com/WebOfTrust/vLEI - legal-entity-vLEI-credential.json
    # Issued by QVI to legal entities; has e.qvi edge to QVI credential
    "LE": frozenset({
        "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",  # vLEI LE credential schema
        "EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6",  # Provenant demo LE schema
    }),

    # OOR Authorization credential
    # Source: https://github.com/WebOfTrust/vLEI - oor-authorization-vlei-credential.json
    # Issued by LE to QVI; has e.le edge to LE credential
    "OOR_AUTH": frozenset({
        "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E",  # vLEI OOR Auth schema
    }),

    # Official Organizational Role credential
    # Source: https://github.com/WebOfTrust/vLEI - legal-entity-official-organizational-role-vLEI-credential.json
    # Issued by QVI; has e.auth edge to OOR Auth credential
    "OOR": frozenset({
        "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",  # vLEI OOR credential schema
    }),

    # ECR Authorization credential
    # Source: https://github.com/WebOfTrust/vLEI - ecr-authorization-vlei-credential.json
    # Issued by LE to QVI; has e.le edge to LE credential
    "ECR_AUTH": frozenset({
        "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",  # vLEI ECR Auth schema
    }),

    # Engagement Context Role credential
    # Source: https://github.com/WebOfTrust/vLEI - legal-entity-engagement-context-role-vLEI-credential.json
    # Issued by QVI or LE; has e.auth or e.le edge
    "ECR": frozenset({
        "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",  # vLEI ECR credential schema
    }),

    # Auth Phone Entity (APE)
    # Source: VVP Draft - pending vLEI governance publication
    # Policy: Accept any schema until governance publishes official SAIDs
    "APE": frozenset(),

    # Delegate Entity (DE)
    # Source: VVP Draft - pending vLEI governance publication
    "DE": frozenset({
        "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",  # Provenant demo DE schema (TN Allocator, delsig)
    }),

    # TN Allocation
    # Source: VVP Draft - pending vLEI governance publication
    "TNAlloc": frozenset({
        "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # Base TN Allocation
        "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_",  # Extended TN Allocation (numbers + certification edge)
    }),

    # Vetter Certification credential
    # Source: VVP Draft - issued by Vetter Governance Authority to orgs
    # Has e.issuer edge to VetterGov credential and ecc/jurisdiction targets
    "VetterCert": frozenset({
        "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H",  # VVP VetterCert schema
    }),

    # Vetter Governance Authority credential
    # Source: VVP Draft - issued by governance root to vetter authorities (e.g., GSMA)
    # Has name/role attributes, no edges
    "VetterGov": frozenset({
        "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL",  # VVP VetterGov schema
    }),

    # Brand Owner credential (Provenant brand-owner schema with vcard array + logo hash)
    # Source: https://github.com/provenant-dev/public-schema/blob/brand-owner/brand-owner/brand-owner.schema.json
    # Has vcard array with RFC 6350 properties including LOGO;HASH=<SAID>;VALUE=URI:<url>
    # Edges: "issuer" with I2I operator (issuer AID must be issuee of pointed credential)
    # Attributes SAID: EIDYFHkBOgNVWGFRcN1cEXNvRV47-nrNJGx6mKHBA7ia
    # Edges SAID: EKk5ejftEjNwjRhw2lYQAwKwvRWapqCNEOx3gUR7WW7n
    "BrandOwner": frozenset({
        "EFdennObbYoKFHlMbLkskgED-2w-npDO11yDvcNUhjsk",  # Provenant brand-owner v1.0.0
    }),

    # Extended Brand Credential (legacy scalar-field schema)
    # Source: VVP Sprint 58 - scalar attributes (brandName, logoUrl, etc.)
    # Deprecated in favor of BrandOwner vcard schema
    "ExtendedBrand": frozenset({
        "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g",  # Extended brand credential (brandName, logoUrl, assertionCountry)
    }),
}

# Schema source documentation for audit/compliance
SCHEMA_SOURCE: Dict[str, str] = {
    "QVI": "vLEI Governance Framework - qualified-vLEI-issuer-vLEI-credential.json",
    "LE": "vLEI Governance Framework - legal-entity-vLEI-credential.json; Provenant demo",
    "OOR_AUTH": "vLEI Governance Framework - oor-authorization-vlei-credential.json",
    "OOR": "vLEI Governance Framework - legal-entity-official-organizational-role-vLEI-credential.json",
    "ECR_AUTH": "vLEI Governance Framework - ecr-authorization-vlei-credential.json",
    "ECR": "vLEI Governance Framework - legal-entity-engagement-context-role-vLEI-credential.json",
    "APE": "Pending - accept any until governance publishes",
    "DE": "Provenant demo DE schema (EL7irIKYJ...)",
    "TNAlloc": "Pending - accept any until governance publishes",
    "VetterCert": "VVP Draft - vetter certification credential (EOefmhWU2...)",
    "VetterGov": "VVP Draft - vetter governance authority credential (EIBowJmxx...)",
    "BrandOwner": "Provenant brand-owner v1.0.0 with vcard array + logo hash (EFdennOb...)",
    "ExtendedBrand": "VVP Sprint 58 - legacy scalar-field brand credential (EK7kPhs5..., deprecated)",
}


def get_known_schemas(credential_type: str) -> FrozenSet[str]:
    """Get known schema SAIDs for a credential type.

    Args:
        credential_type: The credential type (LE, APE, DE, TNAlloc).

    Returns:
        FrozenSet of known schema SAIDs for the type.
        Empty frozenset if type is unknown or pending governance.
    """
    return KNOWN_SCHEMA_SAIDS.get(credential_type, frozenset())


def is_known_schema(credential_type: str, schema_said: str) -> bool:
    """Check if a schema SAID is known for a credential type.

    Args:
        credential_type: The credential type.
        schema_said: The schema SAID to check.

    Returns:
        True if schema is known, False otherwise.
        Returns True for types with no known schemas (pending governance).
    """
    known = get_known_schemas(credential_type)
    # If no known schemas for this type, accept any (pending governance)
    if not known:
        return True
    return schema_said in known


# All brand-related schema SAIDs (for brand credential detection)
BRAND_SCHEMA_SAIDS: FrozenSet[str] = (
    KNOWN_SCHEMA_SAIDS.get("BrandOwner", frozenset())
    | KNOWN_SCHEMA_SAIDS.get("ExtendedBrand", frozenset())
)


def is_brand_schema(schema_said: str) -> bool:
    """Check if a schema SAID is a known brand credential schema."""
    return schema_said in BRAND_SCHEMA_SAIDS


def has_governance_schemas(credential_type: str) -> bool:
    """Check if a credential type has governance-published schemas.

    Args:
        credential_type: The credential type.

    Returns:
        True if governance has published schemas for this type.
    """
    return bool(get_known_schemas(credential_type))


# ---------------------------------------------------------------------------
# Schema-First Credential Classification (Sprint 88)
# ---------------------------------------------------------------------------

class SchemaGovernanceStatus(str, Enum):
    """Governance status of a credential's schema SAID.

    GOVERNED: Schema SAID found in governance registry — type is authoritative.
    UNCLASSIFIED: Schema SAID not in registry, but type has pending governance
                  (empty frozenset in KNOWN_SCHEMA_SAIDS) — INDETERMINATE.
    UNRECOGNIZED: Schema SAID not in registry and no pending governance match
                  — INDETERMINATE, fail-closed for auth.
    """
    GOVERNED = "governed"
    UNCLASSIFIED = "unclassified"
    UNRECOGNIZED = "unrecognized"


# Reverse index: schema SAID → credential type (built at module load)
_SCHEMA_SAID_TO_TYPE: Dict[str, str] = {}
for _type, _saids in KNOWN_SCHEMA_SAIDS.items():
    for _said in _saids:
        _SCHEMA_SAID_TO_TYPE[_said] = _type

# Types that have no governance SAIDs yet (empty frozenset in registry)
_PENDING_GOVERNANCE_TYPES: FrozenSet[str] = frozenset(
    t for t, s in KNOWN_SCHEMA_SAIDS.items() if not s
)


@dataclass(frozen=True)
class CredentialClassification:
    """Immutable, canonical classification result for an ACDC credential.

    Produced once by classify_credential() and consumed by ALL
    governance-sensitive verifier logic. This REPLACES direct use of
    acdc.credential_type for authorization, delegation, vetter,
    and brand decisions.
    """
    credential_type: str
    governance_status: SchemaGovernanceStatus
    schema_said: str

    @property
    def is_governed(self) -> bool:
        """True only when governance status is GOVERNED."""
        return self.governance_status == SchemaGovernanceStatus.GOVERNED

    @property
    def type_is_reliable(self) -> bool:
        """True when credential type can be trusted for authorization decisions.

        Only GOVERNED credentials have authoritative type identity.
        UNCLASSIFIED and UNRECOGNIZED both fail closed for auth.
        """
        return self.governance_status == SchemaGovernanceStatus.GOVERNED


def classify_credential(
    schema_said: str, heuristic_type_hint: str = "unknown"
) -> CredentialClassification:
    """Schema-authoritative credential classification.

    Step 1: Reverse-lookup schema_said in the governance registry.
            If found → GOVERNED, credential_type from registry (authoritative).
    Step 2: If no match, check if heuristic_type_hint is a pending-governance
            type (has entry in KNOWN_SCHEMA_SAIDS but with empty frozenset).
            If so → UNCLASSIFIED (pending governance, INDETERMINATE).
    Step 3: Otherwise → UNRECOGNIZED (INDETERMINATE, fail-closed for auth).

    The heuristic_type_hint is NEVER used to produce a GOVERNED result.
    Only schema SAID reverse-lookup can produce GOVERNED.

    Neither UNCLASSIFIED nor UNRECOGNIZED produces INVALID. INVALID is
    reserved for definite contradictions (broken signatures, failed SAID
    verification, revoked credentials).
    """
    # Step 1: Schema-authoritative lookup
    governed_type = _SCHEMA_SAID_TO_TYPE.get(schema_said)
    if governed_type is not None:
        return CredentialClassification(
            governed_type, SchemaGovernanceStatus.GOVERNED, schema_said
        )

    # Step 2: Check if heuristic hint indicates a pending-governance type
    if heuristic_type_hint in _PENDING_GOVERNANCE_TYPES:
        return CredentialClassification(
            heuristic_type_hint, SchemaGovernanceStatus.UNCLASSIFIED, schema_said
        )

    # Step 3: No governance match — unrecognized
    return CredentialClassification(
        heuristic_type_hint, SchemaGovernanceStatus.UNRECOGNIZED, schema_said
    )
