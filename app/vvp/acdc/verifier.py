"""ACDC verification logic.

Per VVP §6.3.x credential verification requirements.
"""

from typing import Dict, FrozenSet, List, Optional, Set

from .exceptions import ACDCChainInvalid, ACDCSignatureInvalid
from .models import ACDC, ACDCChainResult
from .parser import _acdc_canonical_serialize


# Known vLEI governance schema SAIDs
# These are the official schema SAIDs from the vLEI ecosystem
# Per VVP spec, credentials must use these schemas for validation
KNOWN_SCHEMA_SAIDS: Dict[str, FrozenSet[str]] = {
    # Legal Entity credentials (LE/QVI vetting)
    "LE": frozenset({
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # vLEI QVI LE schema
    }),
    # Auth Phone Entity (APE)
    "APE": frozenset({
        # APE schema SAID - placeholder until official schema defined
    }),
    # Delegate Entity (DE)
    "DE": frozenset({
        # DE schema SAID - placeholder until official schema defined
    }),
    # TN Allocation
    "TNAlloc": frozenset({
        # TNAlloc schema SAID - placeholder until official schema defined
    }),
}


def validate_schema_said(
    acdc: ACDC,
    strict: bool = False
) -> None:
    """Validate ACDC schema SAID matches known governance schemas.

    Per VVP §6.3.x, credentials must use recognized schema SAIDs
    from the vLEI governance framework.

    Args:
        acdc: The ACDC to validate.
        strict: If True, raises on unknown schema. If False, allows unknown.

    Raises:
        ACDCChainInvalid: If schema SAID is invalid (strict mode only).
    """
    if not acdc.schema_said:
        # No schema SAID - allow in non-strict mode
        if strict:
            raise ACDCChainInvalid(
                f"ACDC {acdc.said[:20]}... missing schema SAID"
            )
        return

    cred_type = acdc.credential_type
    known_schemas = KNOWN_SCHEMA_SAIDS.get(cred_type, frozenset())

    # If no known schemas for this type and non-strict, allow
    if not known_schemas and not strict:
        return

    # If known schemas exist, validate
    if known_schemas and acdc.schema_said not in known_schemas:
        if strict:
            raise ACDCChainInvalid(
                f"ACDC {acdc.said[:20]}... has unknown schema SAID "
                f"{acdc.schema_said[:20]}... for credential type {cred_type}"
            )
        # In non-strict mode, log warning but allow
        # TODO: Add logging when logger is available


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
    # Extract TN allocation from attributes
    if not acdc.attributes:
        raise ACDCChainInvalid("TNAlloc credential must have attributes with TN allocation")

    tn_data = acdc.attributes.get("tn") or acdc.attributes.get("phone") or acdc.attributes.get("allocation")

    if not tn_data:
        raise ACDCChainInvalid("TNAlloc credential must specify telephone number allocation")

    # If parent provided, validate TN is subset
    if parent_acdc and parent_acdc.attributes:
        parent_tn = (
            parent_acdc.attributes.get("tn") or
            parent_acdc.attributes.get("phone") or
            parent_acdc.attributes.get("allocation")
        )
        # TODO: Implement proper TN range subset validation
        # For now, just check parent has allocation
        if not parent_tn:
            raise ACDCChainInvalid(
                "Parent TNAlloc credential has no TN allocation to validate against"
            )
