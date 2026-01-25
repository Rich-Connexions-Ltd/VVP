"""ACDC verification logic.

Per VVP §6.3.x credential verification requirements.
"""

import logging
from typing import Dict, FrozenSet, List, Optional, Set

from .exceptions import ACDCChainInvalid, ACDCSignatureInvalid
from .models import ACDC, ACDCChainResult
from .parser import _acdc_canonical_serialize
from .schema_registry import (
    KNOWN_SCHEMA_SAIDS,
    get_known_schemas,
    has_governance_schemas,
)

log = logging.getLogger(__name__)


def validate_schema_said(
    acdc: ACDC,
    strict: bool = True
) -> None:
    """Validate ACDC schema SAID per §6.3.x requirements.

    Per VVP §6.3.x, credentials MUST use recognized schema SAIDs
    from the vLEI governance framework.

    Args:
        acdc: The ACDC to validate.
        strict: Default True per §6.3.x MUSTs. False is a policy deviation.

    Raises:
        ACDCChainInvalid: If schema validation fails in strict mode.
    """
    if not acdc.schema_said:
        if strict:
            raise ACDCChainInvalid(
                f"ACDC {acdc.said[:20]}... missing schema SAID (§6.3.x requires schema)"
            )
        log.warning(f"ACDC {acdc.said[:20]}... missing schema SAID (non-strict mode)")
        return

    cred_type = acdc.credential_type
    known_schemas = get_known_schemas(cred_type)

    # If no known schemas for this type, accept any (pending governance)
    # This is a documented policy deviation until vLEI governance publishes official SAIDs
    if not known_schemas:
        log.debug(
            f"ACDC {acdc.said[:20]}... has schema {acdc.schema_said[:20]}... "
            f"for type {cred_type} (accepting any - governance pending)"
        )
        return

    # If known schemas exist, validate strictly
    if acdc.schema_said not in known_schemas:
        if strict:
            raise ACDCChainInvalid(
                f"ACDC {acdc.said[:20]}... has unrecognized schema SAID "
                f"{acdc.schema_said[:20]}... for type {cred_type}"
            )
        log.warning(
            f"ACDC {acdc.said[:20]}... has unknown schema SAID "
            f"{acdc.schema_said[:20]}... for type {cred_type} (non-strict mode)"
        )


# Edge rules per credential type for semantic validation
# Per VVP §6.3.x, credentials must have specific edge relationships
EDGE_RULES: Dict[str, List[Dict]] = {
    # APE (Auth Phone Entity) - §6.3.3
    # MUST reference vetting LE credential
    "APE": [
        {
            "name_patterns": ["vetting", "le", "legalentity", "vlei", "qvi"],
            "target_types": ["LE"],
            "required": True,
            "description": "APE must reference vetting LE credential (§6.3.3)",
        }
    ],
    # DE (Delegate Entity) - §6.3.4
    # MUST reference delegating credential (APE or another DE)
    "DE": [
        {
            "name_patterns": ["delegation", "d", "delegate", "delegator"],
            "target_types": ["APE", "DE"],
            "required": True,
            "description": "DE must reference delegating credential (§6.3.4)",
        }
    ],
    # TNAlloc (TN Allocation) - §6.3.6
    # SHOULD have JL to parent TNAlloc (except root allocator/regulator)
    "TNAlloc": [
        {
            "name_patterns": ["jl", "jurisdiction", "parent", "allocator"],
            "target_types": ["TNAlloc"],
            "required": False,  # Root allocators have no parent
            "description": "TNAlloc should reference parent allocation (§6.3.6)",
        }
    ],
}


def validate_edge_semantics(
    acdc: ACDC,
    dossier_acdcs: Dict[str, ACDC],
    is_root: bool = False
) -> List[str]:
    """Validate edge relationships match credential type rules.

    Per VVP §6.3.x, different credential types have specific edge requirements:
    - APE: MUST have vetting edge to LE credential
    - DE: MUST have delegation edge to APE or DE
    - TNAlloc: SHOULD have JL edge to parent TNAlloc

    Args:
        acdc: The ACDC to validate.
        dossier_acdcs: Map of SAID -> ACDC for edge target lookup.
        is_root: If True, relaxes required edge checks for root credentials.

    Returns:
        List of warning messages (empty if valid).

    Raises:
        ACDCChainInvalid: If required edge is missing or points to wrong type.
    """
    warnings = []
    cred_type = acdc.credential_type

    if cred_type not in EDGE_RULES:
        # No rules defined for this credential type
        return warnings

    rules = EDGE_RULES[cred_type]

    for rule in rules:
        name_patterns = rule["name_patterns"]
        target_types = rule["target_types"]
        required = rule["required"]
        description = rule["description"]

        # Find matching edge
        found_edge = None
        found_target = None

        if acdc.edges:
            for edge_name, edge_ref in acdc.edges.items():
                # Skip metadata fields
                if edge_name in ('d', 'n'):
                    continue

                # Check if edge name matches any pattern
                if edge_name.lower() in name_patterns:
                    found_edge = edge_name

                    # Extract target SAID
                    target_said = None
                    if isinstance(edge_ref, str):
                        target_said = edge_ref
                    elif isinstance(edge_ref, dict):
                        target_said = edge_ref.get('n') or edge_ref.get('d')

                    if target_said and target_said in dossier_acdcs:
                        found_target = dossier_acdcs[target_said]
                    break

        # Validate edge presence and target type
        if found_edge is None:
            if required and not is_root:
                raise ACDCChainInvalid(
                    f"{cred_type} credential {acdc.said[:20]}... missing required edge: "
                    f"{description}"
                )
            else:
                warnings.append(f"Optional edge not found: {description}")
        elif found_target is None:
            # Edge exists but target is not in dossier
            if required and not is_root:
                raise ACDCChainInvalid(
                    f"{cred_type} credential {acdc.said[:20]}... edge '{found_edge}' "
                    f"references credential not found in dossier"
                )
            else:
                warnings.append(f"Optional edge target not found in dossier: {found_edge}")
        else:
            # Validate target credential type
            if found_target.credential_type not in target_types:
                raise ACDCChainInvalid(
                    f"{cred_type} credential {acdc.said[:20]}... edge '{found_edge}' "
                    f"points to {found_target.credential_type} but expected one of: "
                    f"{target_types}"
                )

    return warnings


async def resolve_issuer_key_state(issuer_aid: str, oobi_url: Optional[str] = None):
    """Resolve issuer's current key state from OOBI/witness.

    Reuses existing Tier 2 key state resolution.

    Args:
        issuer_aid: The issuer's AID.
        oobi_url: Optional OOBI URL for resolution.

    Returns:
        Resolved KeyState object.

    Raises:
        ResolutionFailedError: If key state cannot be resolved.
    """
    # Import here to avoid circular imports
    from ..keri.kel_resolver import resolve_key_state
    from datetime import datetime, timezone

    # For now, use current time as reference
    # TODO: Use ACDC issuance time from TEL event
    reference_time = datetime.now(timezone.utc)

    return await resolve_key_state(
        kid=issuer_aid,
        reference_time=reference_time,
        oobi_url=oobi_url
    )


def verify_acdc_signature(
    acdc: ACDC,
    signature: bytes,
    issuer_public_key: bytes
) -> None:
    """Verify ACDC signature against issuer's key.

    Signing Input Derivation (per CESR/ACDC spec):
    1. Get canonical ACDC bytes using ACDC field ordering
    2. The signature covers: canonical JSON bytes of full ACDC
    3. Signature format: Ed25519 (64 bytes) from CESR attachment
    4. Verify: crypto_sign_verify_detached(signature, acdc_bytes, pubkey)

    Args:
        acdc: The ACDC to verify.
        signature: Ed25519 signature bytes (64 bytes).
        issuer_public_key: Issuer's Ed25519 public key (32 bytes).

    Raises:
        ACDCSignatureInvalid: If signature doesn't verify.
    """
    # Validate key and signature sizes
    if len(issuer_public_key) != 32:
        raise ACDCSignatureInvalid(
            f"Invalid issuer public key size: {len(issuer_public_key)}, expected 32"
        )

    if len(signature) != 64:
        raise ACDCSignatureInvalid(
            f"Invalid signature size: {len(signature)}, expected 64"
        )

    # Get canonical signing input
    signing_input = _acdc_canonical_serialize(acdc.raw)

    # Verify Ed25519 signature
    import pysodium
    try:
        pysodium.crypto_sign_verify_detached(signature, signing_input, issuer_public_key)
    except Exception as e:
        raise ACDCSignatureInvalid(
            f"ACDC signature verification failed: {e}"
        )


async def validate_credential_chain(
    acdc: ACDC,
    trusted_roots: Set[str],
    dossier_acdcs: Dict[str, ACDC],
    max_depth: int = 10,
    validate_schemas: bool = False,
    pss_signer_aid: Optional[str] = None
) -> ACDCChainResult:
    """Walk the credential chain back to a trusted root.

    Chain Validation Rules (per VVP §6.3.x):

    1. **APE (Auth Phone Entity) - §6.3.3**
       - MUST contain vetting credential reference in edges
       - Vetting credential issuer MUST be in trusted_roots (QVI/GLEIF)
       - Schema: APE schema SAID must match known APE schema

    2. **DE (Delegate Entity) - §6.3.4**
       - MUST contain delegated signer credential reference
       - Edge 'd' points to delegating credential
       - PSS signer MUST match OP AID in delegation chain

    3. **TNAlloc (TN Allocation) - §6.3.6**
       - MUST contain JL (jurisdiction link) to parent TNAlloc
       - Exception: Regulator credentials have no parent
       - Phone number ranges must be subset of parent allocation

    Governance Checks:
    - Each edge 's' field references schema SAID
    - Schema SAIDs must match known vLEI governance schemas
    - Root issuer AID must be in trusted_roots

    Args:
        acdc: The credential to validate.
        trusted_roots: Set of trusted root AIDs (GLEIF, QVIs).
        dossier_acdcs: All ACDCs in dossier for edge resolution (SAID -> ACDC).
        max_depth: Maximum chain depth to prevent infinite loops.
        validate_schemas: If True, validates schema SAIDs against known governance schemas.
        pss_signer_aid: The AID from the PASSporT signer (kid field). Required for DE
            validation per §6.3.4 - PSS signer must match delegate in DE credential.

    Returns:
        ACDCChainResult with chain and validation status.

    Raises:
        ACDCChainInvalid: If chain validation fails:
          - Edge target not found in dossier
          - Schema mismatch for credential type
          - Chain doesn't terminate at trusted root
          - Circular reference detected
    """
    visited: Set[str] = set()
    chain: List[ACDC] = []
    errors: List[str] = []

    def walk_chain(
        current: ACDC,
        depth: int = 0,
        pss_signer_aid: Optional[str] = None
    ) -> Optional[str]:
        """Recursively walk the credential chain.

        Args:
            current: Current credential in chain.
            depth: Current recursion depth.
            pss_signer_aid: AID of PASSporT signer (for DE validation).

        Returns:
            Trusted root AID if chain terminates at root, None otherwise.

        Raises:
            ACDCChainInvalid: If validation fails.
        """
        # Check depth limit
        if depth > max_depth:
            raise ACDCChainInvalid(
                f"Credential chain exceeds maximum depth of {max_depth}"
            )

        # Check for circular reference
        if current.said in visited:
            raise ACDCChainInvalid(
                f"Circular reference detected in credential chain at {current.said[:20]}..."
            )

        visited.add(current.said)
        chain.append(current)

        # Apply credential type-specific validation rules
        cred_type = current.credential_type
        if cred_type == "APE":
            validate_ape_credential(current)
        elif cred_type == "DE":
            # For DE, we need the PSS signer AID from the PASSporT (kid field)
            # This is passed from the caller who has access to the PASSporT
            # Per §6.3.4, PSS signer MUST match delegate AID in DE credential
            if pss_signer_aid:
                validate_de_credential(current, pss_signer_aid)
            # If no pss_signer_aid provided, skip DE signer validation
            # (caller must provide it for full §6.3.4 compliance)
        elif cred_type == "TNAlloc":
            # TNAlloc validation needs parent - handled during edge walk
            pass

        # Validate schema SAID if enabled
        if validate_schemas:
            validate_schema_said(current, strict=True)

        # Check if issuer is a trusted root
        is_at_root = current.issuer_aid in trusted_roots

        # Validate edge semantics per §6.3.3/§6.3.4/§6.3.6
        # This validates that APE has vetting edge to LE, DE has delegation edge, etc.
        validate_edge_semantics(current, dossier_acdcs, is_root=is_at_root)

        # Validate issuee binding per §6.3.5 (non-bearer token check)
        # Root credentials may lack issuee, leaf credentials MUST have it
        validate_issuee_binding(current, is_root_credential=is_at_root)

        if is_at_root:
            return current.issuer_aid

        # If no edges and not trusted root, chain is invalid
        if not current.edges or current.is_root_credential:
            raise ACDCChainInvalid(
                f"Credential chain ends at untrusted issuer: {current.issuer_aid[:20]}..."
            )

        # Walk edges to find parent credentials
        for edge_name, edge_ref in current.edges.items():
            # Skip metadata fields
            if edge_name in ('d', 'n'):
                continue

            # Extract parent SAID from edge reference
            parent_said = None
            if isinstance(edge_ref, str):
                parent_said = edge_ref
            elif isinstance(edge_ref, dict):
                parent_said = edge_ref.get('n') or edge_ref.get('d')

            if not parent_said:
                errors.append(f"Edge '{edge_name}' has no target SAID")
                continue

            # Look up parent credential in dossier
            if parent_said not in dossier_acdcs:
                raise ACDCChainInvalid(
                    f"Edge target {parent_said[:20]}... not found in dossier"
                )

            parent_acdc = dossier_acdcs[parent_said]

            # For TNAlloc, validate TN allocation is subset of parent
            if current.credential_type == "TNAlloc" and parent_acdc.credential_type == "TNAlloc":
                validate_tnalloc_credential(current, parent_acdc)

            # Recursively validate parent
            root_aid = walk_chain(parent_acdc, depth + 1, pss_signer_aid)
            if root_aid:
                return root_aid

        # No path to trusted root found
        raise ACDCChainInvalid(
            f"No path to trusted root from credential {current.said[:20]}..."
        )

    # Start chain walk
    try:
        root_aid = walk_chain(acdc, pss_signer_aid=pss_signer_aid)
        return ACDCChainResult(
            chain=chain,
            root_aid=root_aid,
            validated=True,
            errors=errors
        )
    except ACDCChainInvalid:
        raise
    except Exception as e:
        raise ACDCChainInvalid(f"Chain validation failed: {e}")


def validate_issuee_binding(
    acdc: ACDC,
    is_root_credential: bool = False,
    expected_issuee_aid: Optional[str] = None
) -> None:
    """Validate ACDC has issuee binding (not a bearer token).

    Per VVP §6.3.5, credentials MUST NOT be bearer tokens - they must have
    explicit issuee binding. The issuee field identifies the entity to whom
    the credential was issued.

    Root credentials (from GLEIF/QVIs) may lack issuee as they establish
    the trust anchor. Leaf credentials (APE/DE/TNAlloc) MUST have issuee.

    Args:
        acdc: The ACDC to validate.
        is_root_credential: If True, allows missing issuee for trust anchor.
        expected_issuee_aid: If provided, verifies issuee matches this AID.

    Raises:
        ACDCChainInvalid: If issuee binding is missing or mismatched.
            Maps to ACDC_PROOF_MISSING error code.
    """
    # Root credentials may lack issuee (they establish the trust anchor)
    if is_root_credential:
        return

    if not acdc.attributes:
        raise ACDCChainInvalid(
            f"Credential {acdc.said[:20]}... missing attributes - cannot verify issuee binding"
        )

    # Check for issuee in various field names
    issuee = (
        acdc.attributes.get("i") or
        acdc.attributes.get("issuee") or
        acdc.attributes.get("holder")
    )

    if not issuee:
        cred_type = acdc.credential_type or "unknown"
        raise ACDCChainInvalid(
            f"{cred_type} credential {acdc.said[:20]}... is a bearer token "
            f"(missing issuee binding per §6.3.5)"
        )

    # If expected issuee provided, verify match
    if expected_issuee_aid and issuee != expected_issuee_aid:
        raise ACDCChainInvalid(
            f"Issuee mismatch: expected {expected_issuee_aid[:20]}..., "
            f"got {issuee[:20]}..."
        )


def validate_ape_credential(acdc: ACDC) -> None:
    """Validate APE (Auth Phone Entity) credential structure.

    Per VVP §6.3.3:
    - MUST contain vetting credential reference in edges
    - Vetting credential must be from QVI or GLEIF

    Args:
        acdc: The APE credential to validate.

    Raises:
        ACDCChainInvalid: If APE structure is invalid.
    """
    if not acdc.edges:
        raise ACDCChainInvalid("APE credential must have edges referencing vetting credential")

    # Check for vetting/LE edge
    has_vetting = False
    for edge_name in acdc.edges:
        if edge_name.lower() in ('vetting', 'le', 'legalentity', 'vlei'):
            has_vetting = True
            break

    if not has_vetting:
        raise ACDCChainInvalid(
            "APE credential must have vetting credential reference in edges"
        )


def validate_de_credential(acdc: ACDC, pss_signer_aid: str) -> None:
    """Validate DE (Delegate Entity) credential structure.

    Per VVP §6.3.4:
    - MUST contain delegated signer credential reference
    - PSS signer MUST match OP AID in delegation chain

    Args:
        acdc: The DE credential to validate.
        pss_signer_aid: AID of the PASSporT signer.

    Raises:
        ACDCChainInvalid: If DE structure is invalid.
    """
    if not acdc.edges:
        raise ACDCChainInvalid("DE credential must have edges referencing delegation")

    # Check attributes for delegate AID
    if acdc.attributes:
        delegate_aid = acdc.attributes.get("i") or acdc.attributes.get("delegate")
        if delegate_aid and delegate_aid != pss_signer_aid:
            raise ACDCChainInvalid(
                f"PSS signer {pss_signer_aid[:20]}... doesn't match "
                f"DE delegate {delegate_aid[:20]}..."
            )


def validate_tnalloc_credential(
    acdc: ACDC,
    parent_acdc: Optional[ACDC] = None
) -> None:
    """Validate TNAlloc (TN Allocation) credential structure.

    Per VVP §6.3.6:
    - MUST contain JL to parent TNAlloc (except regulator)
    - Phone number ranges must be subset of parent

    Args:
        acdc: The TNAlloc credential to validate.
        parent_acdc: Parent TNAlloc credential (if any).

    Raises:
        ACDCChainInvalid: If TNAlloc structure is invalid.
    """
    from ..tn_utils import (
        TNParseError,
        find_uncovered_ranges,
        is_subset,
        parse_tn_allocation,
    )

    # Extract TN allocation from attributes
    if not acdc.attributes:
        raise ACDCChainInvalid("TNAlloc credential must have attributes with TN allocation")

    tn_data = acdc.attributes.get("tn") or acdc.attributes.get("phone") or acdc.attributes.get("allocation")

    if not tn_data:
        raise ACDCChainInvalid("TNAlloc credential must specify telephone number allocation")

    # Parse child TN allocation
    try:
        child_ranges = parse_tn_allocation(tn_data)
    except TNParseError as e:
        raise ACDCChainInvalid(
            f"TNAlloc {acdc.said[:20]}... has invalid TN allocation: {e}"
        )

    # If parent provided, validate TN is subset
    if parent_acdc and parent_acdc.attributes:
        parent_tn = (
            parent_acdc.attributes.get("tn") or
            parent_acdc.attributes.get("phone") or
            parent_acdc.attributes.get("allocation")
        )

        if not parent_tn:
            raise ACDCChainInvalid(
                "Parent TNAlloc credential has no TN allocation to validate against"
            )

        # Parse parent TN allocation
        try:
            parent_ranges = parse_tn_allocation(parent_tn)
        except TNParseError as e:
            raise ACDCChainInvalid(
                f"Parent TNAlloc has invalid TN allocation: {e}"
            )

        # Validate child is subset of parent per §6.3.6
        if not is_subset(child_ranges, parent_ranges):
            uncovered = find_uncovered_ranges(child_ranges, parent_ranges)
            uncovered_str = ", ".join(str(r) for r in uncovered[:3])
            if len(uncovered) > 3:
                uncovered_str += f", ... ({len(uncovered)} total)"
            raise ACDCChainInvalid(
                f"TNAlloc {acdc.said[:20]}... allocation is not subset of parent: "
                f"uncovered ranges: {uncovered_str}"
            )
