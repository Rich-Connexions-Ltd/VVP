"""vLEI credential chain schema mappings and resolution logic.

Defines normative vLEI credential chain structure using schema SAIDs (not type strings).
This enables deep chain resolution to trace credentials back to GLEIF root.

vLEI Credential Chain (Normative):
    GLEIF Root (issues QVI credentials)
        └── QVI Credential (schema: EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao)
                │         issued to Provenant, Brand assure, etc.
                └── LE Credential (schema: ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY)
                        │     has e.qvi edge → QVI credential SAID
                        └── OOR/ECR/APE/TNAlloc credentials

Source: https://github.com/WebOfTrust/vLEI
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from .models import ACDC
    from ..keri.credential_resolver import CredentialResolver

log = logging.getLogger(__name__)


# =============================================================================
# Normative vLEI Schema SAIDs (from https://github.com/WebOfTrust/vLEI)
# =============================================================================
# These are content-addressed identifiers (Blake3-256 hash) of schema content.
# NOT to be confused with issuer AIDs (derived from key material).

VLEI_SCHEMA_SAIDS = {
    "QVI": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "LE": "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    "OOR_AUTH": "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E",
    "OOR": "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
    "ECR_AUTH": "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",
    "ECR": "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
}


# =============================================================================
# Known QVI Credential SAIDs
# =============================================================================
# Maps QVI issuer AID to their QVI credential SAID. Used as a fallback when
# a dossier doesn't include e.qvi edges but uses a known QVI as issuer.
# This enables chain resolution to GLEIF even for demo/simplified dossiers.

KNOWN_QVI_CREDENTIALS: Dict[str, str] = {
    # Brand assure's QVI credential (issued by GLEIF)
    # AID: EKudJXsXQNzMzEhBHjs5iqZXLSF5fg1Nxs1MD-IAXqDo
    # TODO: Obtain the actual QVI credential SAID from Brand assure/Provenant
}

# Reverse lookup: schema SAID → credential type name
VLEI_SCHEMA_TO_TYPE = {v: k for k, v in VLEI_SCHEMA_SAIDS.items()}


# =============================================================================
# vLEI Credential Chain Requirements
# =============================================================================
# Maps schema SAID → required edges → parent schema expectations.
# Used to determine how to traverse the credential chain.

VLEI_CHAIN_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    # QVI has no edges - issued directly by GLEIF
    VLEI_SCHEMA_SAIDS["QVI"]: {
        "required_edges": [],
        "parent_schema": None,
        "issuer_must_be_root": True,  # QVI must be issued by GLEIF
    },
    # LE requires e.qvi edge pointing to QVI credential
    VLEI_SCHEMA_SAIDS["LE"]: {
        "required_edges": ["qvi"],
        "parent_schema": VLEI_SCHEMA_SAIDS["QVI"],
        "issuer_must_be_root": False,
    },
    # OOR Auth requires e.le edge pointing to LE credential
    VLEI_SCHEMA_SAIDS["OOR_AUTH"]: {
        "required_edges": ["le"],
        "parent_schema": VLEI_SCHEMA_SAIDS["LE"],
        "issuer_must_be_root": False,
    },
    # OOR requires e.auth edge pointing to OOR Auth credential
    VLEI_SCHEMA_SAIDS["OOR"]: {
        "required_edges": ["auth"],
        "parent_schema": VLEI_SCHEMA_SAIDS["OOR_AUTH"],
        "issuer_must_be_root": False,
    },
    # ECR Auth requires e.le edge pointing to LE credential
    VLEI_SCHEMA_SAIDS["ECR_AUTH"]: {
        "required_edges": ["le"],
        "parent_schema": VLEI_SCHEMA_SAIDS["LE"],
        "issuer_must_be_root": False,
    },
    # ECR can have e.auth OR e.le edge
    VLEI_SCHEMA_SAIDS["ECR"]: {
        "required_edges": ["auth", "le"],  # Either one satisfies requirement
        "parent_schema": None,  # Varies based on which edge is present
        "issuer_must_be_root": False,
    },
}


def is_vlei_credential(schema_said: str) -> bool:
    """Check if a credential uses a normative vLEI schema.

    Args:
        schema_said: The schema SAID to check.

    Returns:
        True if this is a recognized vLEI schema.
    """
    return schema_said in VLEI_CHAIN_REQUIREMENTS


def get_required_edges(schema_said: str) -> List[str]:
    """Get required edge names for a vLEI credential schema.

    Args:
        schema_said: The schema SAID to look up.

    Returns:
        List of edge names that are required/optional for this schema.
    """
    req = VLEI_CHAIN_REQUIREMENTS.get(schema_said)
    return req["required_edges"] if req else []


def issuer_must_be_root(schema_said: str) -> bool:
    """Check if this credential's issuer must be a trusted root.

    For QVI credentials, the issuer must be GLEIF (a trusted root AID).

    Args:
        schema_said: The schema SAID to check.

    Returns:
        True if issuer must be in trusted roots set.
    """
    req = VLEI_CHAIN_REQUIREMENTS.get(schema_said)
    return req.get("issuer_must_be_root", False) if req else False


def get_vlei_type(schema_said: str) -> Optional[str]:
    """Get the vLEI credential type name from schema SAID.

    Args:
        schema_said: The schema SAID to look up.

    Returns:
        Type name ("QVI", "LE", "OOR", etc.) or None if not a vLEI schema.
    """
    return VLEI_SCHEMA_TO_TYPE.get(schema_said)


# =============================================================================
# Chain Resolution Result
# =============================================================================

@dataclass
class ChainResolutionResult:
    """Result of vLEI chain resolution.

    Attributes:
        augmented_acdcs: Original + resolved credentials (SAID → ACDC).
        resolved_saids: List of SAIDs that were fetched externally.
        errors: Error messages from resolution failures.
        chain_complete: True if all required edges were resolved.
        root_reached: True if chain reaches a trusted root (GLEIF).
    """
    augmented_acdcs: Dict[str, "ACDC"] = field(default_factory=dict)
    resolved_saids: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    chain_complete: bool = False
    root_reached: bool = False


def _extract_edge_target(edge_ref: Any) -> Optional[str]:
    """Extract target SAID from an edge reference.

    Edge references can be:
    - String: direct SAID reference
    - Dict with 'n' key: nested SAID reference
    - Dict with 'd' key: direct SAID reference

    Args:
        edge_ref: The edge reference (string or dict).

    Returns:
        Target SAID string or None if not extractable.
    """
    if isinstance(edge_ref, str):
        return edge_ref
    if isinstance(edge_ref, dict):
        return edge_ref.get("n") or edge_ref.get("d")
    return None


# =============================================================================
# Chain Resolution Function
# =============================================================================

async def resolve_vlei_chain_edges(
    dossier_acdcs: Dict[str, "ACDC"],
    credential_resolver: "CredentialResolver",
    trusted_roots: Set[str],
    max_depth: int = 3,
    max_concurrent: int = 5,
    max_total_fetches: int = 10,
    timeout: float = 10.0,
) -> ChainResolutionResult:
    """Resolve vLEI chain edges using schema-SAID validation.

    Follows e.qvi, e.le, e.auth edges from dossier credentials to fetch
    parent credentials from witnesses. Continues until reaching GLEIF root
    or hitting resolution limits.

    Uses normative vLEI schema SAIDs to determine chain requirements,
    NOT inferred credential_type strings.

    Resolution Policy:
        - max_concurrent: Max parallel fetch operations
        - max_total_fetches: Budget limit for total external fetches
        - timeout: Overall timeout for resolution phase

    Chain Completion Semantics:
        - chain_complete=True: All vLEI credentials have required edges resolved
        - chain_complete=False: Some edges missing (partial resolution)
        - root_reached=True: At least one chain reaches GLEIF root

    Args:
        dossier_acdcs: ACDCs from the dossier (SAID → ACDC).
        credential_resolver: Resolver for fetching external credentials.
        trusted_roots: Set of trusted root AIDs (GLEIF).
        max_depth: Maximum recursion depth.
        max_concurrent: Maximum concurrent fetch operations.
        max_total_fetches: Maximum total external fetches.
        timeout: Overall timeout in seconds.

    Returns:
        ChainResolutionResult with augmented credentials and metadata.
    """
    augmented = dict(dossier_acdcs)
    errors: List[str] = []
    resolved_saids: List[str] = []
    fetch_count = 0
    semaphore = asyncio.Semaphore(max_concurrent)
    root_reached = False

    async def resolve_credential(said: str, depth: int) -> Optional["ACDC"]:
        """Recursively resolve a credential and its chain edges."""
        nonlocal fetch_count, root_reached

        # Check budget
        if fetch_count >= max_total_fetches:
            if not any("budget exhausted" in e for e in errors):
                errors.append(f"Fetch budget exhausted ({max_total_fetches})")
            return None

        # Check depth
        if depth > max_depth:
            errors.append(f"Max depth exceeded for {said[:16]}...")
            return None

        # Already have it?
        if said in augmented:
            return augmented[said]

        # Fetch from witnesses
        async with semaphore:
            fetch_count += 1
            log.debug(f"Resolving credential {said[:20]}... (depth={depth})")
            result = await credential_resolver.resolve(said)

        if not result or not result.acdc:
            errors.append(f"Could not resolve: {said[:16]}...")
            return None

        acdc = result.acdc
        augmented[said] = acdc
        resolved_saids.append(said)
        log.info(f"Resolved credential {said[:20]}... from {result.source_url}")

        # Schema-SAID-based validation
        schema = acdc.schema_said
        if is_vlei_credential(schema):
            vlei_type = get_vlei_type(schema)
            log.debug(f"Credential {said[:16]}... is vLEI type: {vlei_type}")

            # Check if issuer must be root (QVI issued by GLEIF)
            if issuer_must_be_root(schema):
                if acdc.issuer_aid in trusted_roots:
                    root_reached = True
                    log.info(
                        f"Chain reaches trusted root: {acdc.issuer_aid[:16]}... "
                        f"(credential {said[:16]}...)"
                    )
                else:
                    errors.append(
                        f"{vlei_type} credential {said[:16]}... "
                        f"issuer {acdc.issuer_aid[:16]}... not in trusted roots"
                    )

            # Recursively resolve required edges
            for edge_name in get_required_edges(schema):
                if acdc.edges and edge_name in acdc.edges:
                    target = _extract_edge_target(acdc.edges[edge_name])
                    if target and target not in augmented:
                        await resolve_credential(target, depth + 1)

        return acdc

    # Start resolution from dossier credentials
    try:
        async with asyncio.timeout(timeout):
            # Find credentials with vLEI schemas that have unresolved edges
            for acdc in list(dossier_acdcs.values()):
                if not acdc.edges:
                    continue

                # Check all edges (not just vLEI-specific ones)
                # This allows following e.qvi edges from LE credentials
                for edge_name, edge_ref in acdc.edges.items():
                    if edge_name in ("d", "n"):
                        continue

                    target = _extract_edge_target(edge_ref)
                    if target and target not in augmented:
                        await resolve_credential(target, 0)

    except asyncio.TimeoutError:
        errors.append(f"Resolution timeout after {timeout}s")
    except Exception as e:
        errors.append(f"Resolution error: {e}")
        log.exception(f"vLEI chain resolution failed: {e}")

    # Determine chain_complete: all vLEI credentials have required edges resolved
    chain_complete = True
    for acdc in augmented.values():
        if not is_vlei_credential(acdc.schema_said):
            continue
        for edge_name in get_required_edges(acdc.schema_said):
            if acdc.edges and edge_name in acdc.edges:
                target = _extract_edge_target(acdc.edges[edge_name])
                if target and target not in augmented:
                    chain_complete = False
                    log.debug(
                        f"Incomplete chain: {acdc.said[:16]}... missing {edge_name} edge target"
                    )
                    break

    log.info(
        f"vLEI chain resolution complete: resolved={len(resolved_saids)}, "
        f"chain_complete={chain_complete}, root_reached={root_reached}"
    )

    return ChainResolutionResult(
        augmented_acdcs=augmented,
        resolved_saids=resolved_saids,
        errors=errors,
        chain_complete=chain_complete,
        root_reached=root_reached,
    )
