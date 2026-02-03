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

from typing import Dict, FrozenSet

# Registry version for tracking updates
SCHEMA_REGISTRY_VERSION = "1.3.0"

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
    # Policy: Accept any schema until governance publishes official SAIDs
    "TNAlloc": frozenset(),
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


def has_governance_schemas(credential_type: str) -> bool:
    """Check if a credential type has governance-published schemas.

    Args:
        credential_type: The credential type.

    Returns:
        True if governance has published schemas for this type.
    """
    return bool(get_known_schemas(credential_type))
