"""ACDC Schema SAID Registry.

Per VVP §6.3.x, credentials must use recognized schema SAIDs from the
vLEI governance framework. This module provides a versioned registry
of known schema SAIDs for validation.

Registry Version: 1.0.0
Last Updated: 2026-01-25
"""

from typing import Dict, FrozenSet

# Registry version for tracking updates
SCHEMA_REGISTRY_VERSION = "1.0.0"

# Known vLEI governance schema SAIDs
# These are the official schema SAIDs from the vLEI ecosystem
KNOWN_SCHEMA_SAIDS: Dict[str, FrozenSet[str]] = {
    # Legal Entity credentials (LE/QVI vetting)
    # Source: vLEI Governance Framework v1.0
    "LE": frozenset({
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # vLEI QVI LE schema
    }),

    # Auth Phone Entity (APE)
    # Source: VVP Draft - pending vLEI governance publication
    # Policy: Accept any schema until governance publishes official SAIDs
    "APE": frozenset(),

    # Delegate Entity (DE)
    # Source: VVP Draft - pending vLEI governance publication
    # Policy: Accept any schema until governance publishes official SAIDs
    "DE": frozenset(),

    # TN Allocation
    # Source: VVP Draft - pending vLEI governance publication
    # Policy: Accept any schema until governance publishes official SAIDs
    "TNAlloc": frozenset(),
}

# Schema source documentation for audit/compliance
SCHEMA_SOURCE: Dict[str, str] = {
    "LE": "vLEI Governance Framework v1.0",
    "APE": "Pending - accept any until governance publishes",
    "DE": "Pending - accept any until governance publishes",
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
