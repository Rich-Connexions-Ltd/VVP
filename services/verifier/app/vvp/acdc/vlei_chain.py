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
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Set

from common.vvp.models import EdgeOperator, EdgeValidationWarning
from common.vvp.schema.registry import CredentialClassification, SchemaGovernanceStatus

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
        operator_warnings: Edge operator constraint violations (I2I/DI2I/NI2I).
    """
    augmented_acdcs: Dict[str, "ACDC"] = field(default_factory=dict)
    resolved_saids: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    chain_complete: bool = False
    root_reached: bool = False
    operator_warnings: List[EdgeValidationWarning] = field(default_factory=list)


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


def _extract_edge_operator(edge_ref: Any) -> EdgeOperator:
    """Extract edge operator from edge reference.

    Per ACDC spec, the 'o' field specifies the operator constraint.
    Default is I2I (Issuer-to-Issuee) when not specified.

    Args:
        edge_ref: The edge reference (string or dict).

    Returns:
        EdgeOperator enum value (I2I, DI2I, or NI2I).
    """
    if isinstance(edge_ref, dict):
        operator_str = edge_ref.get("o", "I2I")
        try:
            return EdgeOperator(operator_str)
        except ValueError:
            log.warning(f"Unknown edge operator '{operator_str}', defaulting to I2I")
            return EdgeOperator.I2I
    # Bare SAID string - default to I2I
    return EdgeOperator.I2I


def _get_issuee_from_acdc(acdc: "ACDC") -> Optional[str]:
    """Extract issuee AID from ACDC attributes.

    Issuee can be in various field names:
    - 'i': Standard ACDC issuee field
    - 'issuee': Alternative naming
    - 'holder': Alternative naming

    Args:
        acdc: The ACDC to extract issuee from.

    Returns:
        Issuee AID string or None if bearer credential.
    """
    if not acdc.attributes or not isinstance(acdc.attributes, dict):
        return None
    return (
        acdc.attributes.get("i") or
        acdc.attributes.get("issuee") or
        acdc.attributes.get("holder")
    )


def _validate_edge_operator(
    child: "ACDC",
    parent: "ACDC",
    edge_name: str,
    operator: EdgeOperator,
    all_acdcs: Dict[str, "ACDC"],
) -> Optional[EdgeValidationWarning]:
    """Validate edge operator constraint between child and parent credentials.

    Per ACDC spec:
    - I2I: child.issuer == parent.issuee (strict)
    - DI2I: child.issuer == parent.issuee OR delegated from parent.issuee
    - NI2I: No constraint (permissive, reference-only)

    For bearer credentials (no issuee), I2I constraints don't apply.

    Args:
        child: Child credential (contains the edge).
        parent: Parent credential (edge target).
        edge_name: Name of the edge (e.g., "qvi", "le", "auth").
        operator: Edge operator constraint.
        all_acdcs: All known ACDCs (for delegation chain lookup).

    Returns:
        EdgeValidationWarning if constraint violated, None if valid.
    """
    if operator == EdgeOperator.NI2I:
        # NI2I has no constraint - always passes
        return None

    child_issuer = child.issuer_aid
    parent_issuee = _get_issuee_from_acdc(parent)

    if not parent_issuee:
        # Parent is bearer credential - I2I doesn't apply
        log.debug(
            f"Skipping {operator.value} check for edge '{edge_name}': "
            f"parent {parent.said[:16]}... is bearer credential"
        )
        return None

    # Check direct match (satisfies both I2I and DI2I)
    if child_issuer == parent_issuee:
        return None

    if operator == EdgeOperator.I2I:
        # I2I requires exact match
        return EdgeValidationWarning(
            operator=EdgeOperator.I2I,
            edge_name=edge_name,
            child_said=child.said,
            parent_said=parent.said,
            constraint_violated=(
                f"issuer {child_issuer[:16]}... != issuee {parent_issuee[:16]}..."
            ),
        )

    if operator == EdgeOperator.DI2I:
        # DI2I allows delegation - check for DE credential chain
        if _check_delegation_chain(child_issuer, parent_issuee, all_acdcs):
            return None

        return EdgeValidationWarning(
            operator=EdgeOperator.DI2I,
            edge_name=edge_name,
            child_said=child.said,
            parent_said=parent.said,
            constraint_violated=(
                f"issuer {child_issuer[:16]}... not delegated from {parent_issuee[:16]}..."
            ),
        )

    return None


def _check_delegation_chain(
    delegatee_aid: str,
    delegator_aid: str,
    all_acdcs: Dict[str, "ACDC"],
    max_depth: int = 10,
) -> bool:
    """Check if delegatee_aid is delegated from delegator_aid via DE credentials.

    Looks for a chain: DE(issuee=delegatee) -> ... -> credential(issuee=delegator)

    This implements dossier-based delegation checking. KEL-based delegated AID
    verification is deferred to a future phase when KEL integration is complete.

    Args:
        delegatee_aid: AID claiming delegation authority.
        delegator_aid: AID that should have granted delegation.
        all_acdcs: All known ACDCs to search for DE credentials.
        max_depth: Maximum delegation chain depth.

    Returns:
        True if delegation chain exists, False otherwise.
    """
    # Find DE credentials where issuee == delegatee_aid
    for acdc in all_acdcs.values():
        if acdc.credential_type != "DE":
            continue

        de_issuee = _get_issuee_from_acdc(acdc)
        if de_issuee != delegatee_aid:
            continue

        # Walk delegation chain from this DE
        visited = {acdc.said}
        current = acdc
        depth = 0

        while depth < max_depth:
            # Look for delegation edge target
            target_said = None
            if current.edges:
                for edge_name in ("delegation", "issuer", "auth"):
                    if edge_name in current.edges:
                        target_said = _extract_edge_target(current.edges[edge_name])
                        break

            if not target_said or target_said not in all_acdcs:
                break

            target = all_acdcs[target_said]
            if target.said in visited:
                break  # Cycle detected

            visited.add(target.said)
            target_issuee = _get_issuee_from_acdc(target)

            if target_issuee == delegator_aid:
                log.debug(
                    f"Delegation chain found: {delegatee_aid[:16]}... -> "
                    f"{delegator_aid[:16]}... via DE chain"
                )
                return True

            if target.credential_type == "DE":
                current = target
                depth += 1
            else:
                break  # Non-DE terminus

    return False


# =============================================================================
# Chain Resolution Function
# =============================================================================

async def resolve_vlei_chain_edges(
    dossier_acdcs: Dict[str, "ACDC"],
    credential_resolver: "CredentialResolver",
    trusted_roots: Set[str],
    max_depth: int = 10,
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
    operator_warnings: List[EdgeValidationWarning] = []
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

    # Validate edge operator constraints for all resolved credentials
    # Per ACDC spec, edges have operator constraints (I2I/DI2I/NI2I)
    for acdc in augmented.values():
        if not acdc.edges:
            continue

        for edge_name, edge_ref in acdc.edges.items():
            if edge_name in ("d", "n"):
                continue

            target_said = _extract_edge_target(edge_ref)
            if not target_said or target_said not in augmented:
                continue  # Can't validate edges to unresolved credentials

            operator = _extract_edge_operator(edge_ref)
            target_acdc = augmented[target_said]

            warning = _validate_edge_operator(
                child=acdc,
                parent=target_acdc,
                edge_name=edge_name,
                operator=operator,
                all_acdcs=augmented,
            )
            if warning:
                operator_warnings.append(warning)
                log.info(
                    f"Edge operator violation: {operator.value} constraint on "
                    f"'{edge_name}' edge from {acdc.said[:16]}... - "
                    f"{warning.constraint_violated}"
                )

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
        f"chain_complete={chain_complete}, root_reached={root_reached}, "
        f"operator_warnings={len(operator_warnings)}"
    )

    return ChainResolutionResult(
        augmented_acdcs=augmented,
        resolved_saids=resolved_saids,
        errors=errors,
        chain_complete=chain_complete,
        root_reached=root_reached,
        operator_warnings=operator_warnings,
    )


# =============================================================================
# Qualifying Link Validation (Sprint 88, Checklist 8.11)
# Validates LE → QVI chain per §6.3.5 "JL" (Justified Link)
# =============================================================================

@dataclass(frozen=True)
class QualifyingLinkResult:
    """Result of LE→QVI qualifying-link validation."""
    valid: bool
    status: str  # "valid", "indeterminate", "invalid"
    reason: Optional[str] = None


def validate_qualifying_link(
    le_acdc: "ACDC",
    classifications: Dict[str, CredentialClassification],
    resolved_acdcs: Dict[str, "ACDC"],
    trusted_root_aids: FrozenSet[str],
) -> QualifyingLinkResult:
    """Validate that LE has a qualifying link to a governed, trusted-root QVI.

    Runs AFTER external chain resolution, so a QVI that was fetched via
    CredentialResolver is available in resolved_acdcs.

    Checks:
    1. LE has 'qvi' edge
    2. Target credential is found in resolved_acdcs (dossier or external)
    3. Target credential is GOVERNED as QVI type
    4. QVI issuer is in trusted_root_aids (GLEIF root)
    5. I2I semantics: issuer of LE == issuee of QVI

    Args:
        le_acdc: The LE credential to validate.
        classifications: Map of SAID → CredentialClassification.
        resolved_acdcs: Map of SAID → ACDC (dossier + externally resolved).
        trusted_root_aids: Set of trusted root AIDs (GLEIF).

    Returns:
        QualifyingLinkResult with validity status and reason.
    """
    # Step 1: LE must have edges with 'qvi' key
    if not le_acdc.edges:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE credential has no edges",
        )

    qvi_edge = le_acdc.edges.get("qvi")
    if qvi_edge is None:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE credential missing required 'qvi' edge",
        )

    # Step 2: Extract target SAID and find the QVI
    target_said = _extract_edge_target(qvi_edge)
    if not target_said:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE 'qvi' edge has no target SAID",
        )

    qvi_acdc = resolved_acdcs.get(target_said)
    if qvi_acdc is None:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=f"QVI credential {target_said[:20]}... not found in dossier or external resolution",
        )

    # Step 3: QVI must be GOVERNED
    qvi_cls = classifications.get(target_said)
    if qvi_cls is None:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=f"QVI credential {target_said[:20]}... has no classification",
        )
    if not qvi_cls.is_governed:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=(
                f"QVI credential {target_said[:20]}... has non-governed status "
                f"({qvi_cls.governance_status.value})"
            ),
        )
    if qvi_cls.credential_type != "QVI":
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason=(
                f"LE 'qvi' edge target classified as {qvi_cls.credential_type}, "
                f"not QVI"
            ),
        )

    # Step 4: QVI issuer must be a trusted root
    if qvi_acdc.issuer_aid not in trusted_root_aids:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason=(
                f"QVI issuer {qvi_acdc.issuer_aid[:20]}... is not a trusted root AID"
            ),
        )

    # Step 5: I2I operator check — issuer of LE must be issuee of QVI
    qvi_attrs = qvi_acdc.attributes
    if isinstance(qvi_attrs, dict):
        qvi_issuee = qvi_attrs.get("i")
        if qvi_issuee and le_acdc.issuer_aid != qvi_issuee:
            return QualifyingLinkResult(
                valid=False,
                status="invalid",
                reason=(
                    f"I2I violation: LE issuer {le_acdc.issuer_aid[:20]}... "
                    f"!= QVI issuee {qvi_issuee[:20]}..."
                ),
            )

    return QualifyingLinkResult(valid=True, status="valid")
