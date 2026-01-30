"""ACDC verification logic.

Per VVP §6.3.x credential verification requirements.
"""

import logging
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .exceptions import ACDCChainInvalid, ACDCSignatureInvalid

if TYPE_CHECKING:
    from ..keri.credential_resolver import CredentialResolver
    from .schema_resolver import SchemaResolver
from .models import ACDC, ACDCChainResult
from .parser import _acdc_canonical_serialize
from .schema_registry import (
    KNOWN_SCHEMA_SAIDS,
    get_known_schemas,
    has_governance_schemas,
    is_known_schema,
)
from .schema_fetcher import get_schema_for_validation, verify_schema_said
from .schema_validator import validate_acdc_against_schema
from ..api_models import ClaimStatus

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


async def validate_schema_document(
    acdc: ACDC,
    schema_resolver: Optional["SchemaResolver"] = None,
    witness_urls: Optional[List[str]] = None,
) -> Tuple[ClaimStatus, List[str]]:
    """Validate ACDC attributes against fetched schema document.

    Per VVP §5.1.1-2.8.3, validation must compare data structure and values
    against the declared schema. This function:
    1. Fetches the schema document (from cache or registry)
    2. Verifies the fetched document's SAID matches declared schema SAID
    3. Validates ACDC attributes conform to the schema structure

    SAID Verification Rules (per ACDC spec):
    - Embedded schema: SAID mismatch → INVALID (not INDETERMINATE)
    - Fetched schema: SAID mismatch → INVALID (not INDETERMINATE)
    - Schema unavailable (network): INDETERMINATE
    - Schema missing $id field: INVALID

    Args:
        acdc: The ACDC to validate.
        schema_resolver: Optional SchemaResolver for multi-source resolution.
            If not provided and SCHEMA_RESOLVER_ENABLED, uses singleton.
        witness_urls: Optional witness URLs for OOBI resolution.

    Returns:
        Tuple of (ClaimStatus, errors):
        - (VALID, []) if schema validates successfully
        - (INDETERMINATE, [...]) if schema cannot be fetched
        - (INVALID via exception) if SAID mismatch or validation fails

    Raises:
        ACDCChainInvalid: If schema SAID mismatch, missing $id, or attributes
            don't match schema.
    """
    from app.core import config

    errors: List[str] = []

    if not acdc.schema_said:
        # No schema declared - cannot validate attributes
        return (ClaimStatus.INDETERMINATE, ["No schema SAID declared"])

    # Check if schema is embedded (dict) or referenced (string SAID)
    raw_schema = acdc.raw.get("s")
    if isinstance(raw_schema, dict):
        # Embedded schema - MUST verify SAID using single source of truth
        if "$id" not in raw_schema:
            raise ACDCChainInvalid(
                f"Embedded schema missing $id field - cannot verify SAID"
            )

        # Use verify_schema_said for consistency with SchemaResolver
        if not verify_schema_said(raw_schema, acdc.schema_said):
            # SAID mismatch is INVALID, not INDETERMINATE
            raise ACDCChainInvalid(
                f"Embedded schema SAID mismatch: declared {acdc.schema_said[:20]}... "
                f"but computed SAID doesn't match"
            )
        schema_doc = raw_schema
    else:
        # Referenced schema - resolve via SchemaResolver or legacy fetcher
        if schema_resolver is None and config.SCHEMA_RESOLVER_ENABLED:
            from .schema_resolver import get_schema_resolver
            schema_resolver = get_schema_resolver()

        if schema_resolver:
            try:
                result = await schema_resolver.resolve(acdc.schema_said, witness_urls)
            except ACDCChainInvalid:
                # SAID mismatch from resolver - propagate as INVALID
                raise

            if result is None:
                # Schema unavailable (network) - INDETERMINATE per §2.2
                log.warning(
                    f"Schema {acdc.schema_said[:20]}... unavailable for ACDC {acdc.said[:20]}..."
                )
                return (ClaimStatus.INDETERMINATE, ["Schema unavailable"])
            schema_doc = result.schema_doc
        else:
            # Fallback to legacy fetcher (which also verifies SAID)
            try:
                schema_doc, fetch_status = await get_schema_for_validation(acdc)
            except ACDCChainInvalid:
                # SAID mismatch - re-raise as INVALID
                raise

            if fetch_status == ClaimStatus.INDETERMINATE or not schema_doc:
                log.warning(
                    f"Schema {acdc.schema_said[:20]}... unavailable for ACDC {acdc.said[:20]}..."
                )
                return (ClaimStatus.INDETERMINATE, ["Schema document unavailable"])

    # Validate ACDC attributes against schema
    if not acdc.attributes or not isinstance(acdc.attributes, dict):
        # Compact variant with SAID reference for attributes - cannot validate
        return (ClaimStatus.INDETERMINATE, ["ACDC attributes not expanded (compact variant)"])

    validation_errors = validate_acdc_against_schema(acdc.attributes, schema_doc)

    if validation_errors:
        # Attribute validation failed - this is INVALID
        raise ACDCChainInvalid(
            f"ACDC {acdc.said[:20]}... attributes don't match schema: "
            f"{'; '.join(validation_errors[:3])}"
        )

    log.debug(f"ACDC {acdc.said[:20]}... validated against schema {acdc.schema_said[:20]}...")
    return (ClaimStatus.VALID, [])


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
) -> Tuple[List[str], ClaimStatus]:
    """Validate edge relationships match credential type rules.

    Per VVP §6.3.x, different credential types have specific edge requirements:
    - APE: MUST have vetting edge to LE credential
    - DE: MUST have delegation edge to APE or DE
    - TNAlloc: SHOULD have JL edge to parent TNAlloc

    Per §2.2 ("Uncertainty must be explicit"), compact variants with external
    edge references (targets not in dossier) return INDETERMINATE status rather
    than raising an exception.

    Args:
        acdc: The ACDC to validate.
        dossier_acdcs: Map of SAID -> ACDC for edge target lookup.
        is_root: If True, relaxes required edge checks for root credentials.

    Returns:
        Tuple of (warning messages, ClaimStatus):
        - VALID if all required edges verified
        - INDETERMINATE if compact variant has unresolvable external refs
        - Raises ACDCChainInvalid (→INVALID) for definite failures

    Raises:
        ACDCChainInvalid: If required edge is missing or points to wrong type
            (not for compact variants with external refs - those get INDETERMINATE).
    """
    warnings = []
    status = ClaimStatus.VALID
    cred_type = acdc.credential_type
    is_compact = getattr(acdc, 'variant', 'full') == 'compact'

    if cred_type not in EDGE_RULES:
        # No rules defined for this credential type
        return warnings, status

    rules = EDGE_RULES[cred_type]

    for rule in rules:
        name_patterns = rule["name_patterns"]
        target_types = rule["target_types"]
        required = rule["required"]
        description = rule["description"]

        # Find matching edge
        found_edge = None
        found_target = None
        target_said = None

        if acdc.edges:
            for edge_name, edge_ref in acdc.edges.items():
                # Skip metadata fields
                if edge_name in ('d', 'n'):
                    continue

                # Check if edge name matches any pattern
                if edge_name.lower() in name_patterns:
                    found_edge = edge_name

                    # Extract target SAID
                    if isinstance(edge_ref, str):
                        target_said = edge_ref
                    elif isinstance(edge_ref, dict):
                        target_said = edge_ref.get('n') or edge_ref.get('d')

                    if target_said and target_said in dossier_acdcs:
                        found_target = dossier_acdcs[target_said]
                    break

        # Validate edge presence and target type
        if found_edge is None:
            # APE vetting edge is ALWAYS required per §6.3.3, even for root issuers
            skip_for_root = is_root and cred_type != "APE"
            if required and not skip_for_root:
                raise ACDCChainInvalid(
                    f"{cred_type} credential {acdc.said[:20]}... missing required edge: "
                    f"{description}"
                )
            else:
                warnings.append(f"Optional edge not found: {description}")
        elif found_target is None:
            # Edge exists but target is not in dossier (external reference)
            # APE vetting edge is ALWAYS required per §6.3.3, even for root issuers
            skip_for_root = is_root and cred_type != "APE"
            if required and not skip_for_root:
                if is_compact:
                    # Per §2.2: Compact variant with external ref → INDETERMINATE
                    # Cannot verify chain without the referenced credential
                    log.warning(
                        f"Cannot verify edge target {target_said[:20] if target_said else 'unknown'}... "
                        f"- not in dossier (compact variant, §2.2 INDETERMINATE)"
                    )
                    warnings.append(
                        f"Edge '{found_edge}' references external SAID not in dossier "
                        f"- cannot verify target type (compact variant)"
                    )
                    status = ClaimStatus.INDETERMINATE
                else:
                    # Full variant must have all required edges resolvable
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

            # Additional APE vetting target validation per §6.3.5
            if cred_type == "APE" and found_edge.lower() in name_patterns:
                from app.core import config
                validate_ape_vetting_target(found_target, strict_schema=config.SCHEMA_VALIDATION_STRICT)

    return warnings, status


def validate_ape_vetting_target(
    vetting_target: ACDC,
    strict_schema: bool = True
) -> None:
    """Validate APE vetting credential per §6.3.3 and §6.3.5.

    Per VVP §6.3.3, APE credentials MUST reference a vetting LE credential.
    Per VVP §6.3.5, that vetting credential MUST conform to the vLEI LE schema.

    Args:
        vetting_target: The credential referenced by APE vetting edge.
        strict_schema: If True, require known vLEI LE schema SAID.

    Raises:
        ACDCChainInvalid: If vetting credential is invalid.
    """
    # Validate credential type is LE
    if vetting_target.credential_type != "LE":
        raise ACDCChainInvalid(
            f"APE vetting credential must be LE type per §6.3.3, "
            f"got {vetting_target.credential_type}"
        )

    # Validate schema SAID against known vLEI LE schemas (§6.3.5)
    if strict_schema and has_governance_schemas("LE"):
        if not is_known_schema("LE", vetting_target.schema_said):
            raise ACDCChainInvalid(
                f"APE vetting credential schema {vetting_target.schema_said[:20]}... "
                f"not in known vLEI LE schemas per §6.3.5"
            )


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
    pss_signer_aid: Optional[str] = None,
    credential_resolver: Optional["CredentialResolver"] = None,
    witness_urls: Optional[List[str]] = None,
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
        credential_resolver: Optional CredentialResolver for fetching external SAIDs
            from witnesses. If provided and enabled, missing edge targets will be
            fetched from witnesses before marking as INDETERMINATE.
        witness_urls: Base URLs of witnesses to query for external SAIDs.

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
    chain_status = ClaimStatus.VALID  # Track worst status across chain
    has_variants = False  # Track if any ACDCs are compact/partial

    async def walk_chain(
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
        nonlocal chain_status, has_variants
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

        # Track variant limitations (compact/partial)
        current_variant = getattr(current, 'variant', 'full')
        if current_variant in ('compact', 'partial'):
            has_variants = True

        # Validate edge semantics per §6.3.3/§6.3.4/§6.3.6
        # This validates that APE has vetting edge to LE, DE has delegation edge, etc.
        edge_warnings, edge_status = validate_edge_semantics(current, dossier_acdcs, is_root=is_at_root)
        if edge_warnings:
            errors.extend(edge_warnings)
        # Propagate worst status (INVALID > INDETERMINATE > VALID)
        if edge_status == ClaimStatus.INDETERMINATE and chain_status == ClaimStatus.VALID:
            chain_status = ClaimStatus.INDETERMINATE

        # Validate issuee binding per §6.3.5 (non-bearer token check)
        # Root credentials may lack issuee, leaf credentials MUST have it
        issuee_status = validate_issuee_binding(current, is_root_credential=is_at_root)
        # Propagate worst status
        if issuee_status == ClaimStatus.INDETERMINATE and chain_status == ClaimStatus.VALID:
            chain_status = ClaimStatus.INDETERMINATE

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
                # Attempt external resolution if resolver is provided
                resolved = False
                if credential_resolver and witness_urls:
                    result = await credential_resolver.resolve(parent_said, witness_urls)
                    if result:
                        # Successfully resolved external credential
                        dossier_acdcs[parent_said] = result.acdc
                        log.info(
                            f"Resolved external credential {parent_said[:20]}... "
                            f"from {result.source_url}"
                        )
                        resolved = True

                        # Per review: externally resolved credentials MUST have their
                        # signatures cryptographically verified before producing VALID
                        if result.signature:
                            # Verify signature against issuer's key
                            from ..keri import resolve_key_state, ResolutionFailedError
                            from datetime import datetime, timezone
                            try:
                                key_state = await resolve_key_state(
                                    kid=result.acdc.issuer_aid,
                                    reference_time=datetime.now(timezone.utc),
                                    _allow_test_mode=False,
                                )
                                # Try each signing key
                                signature_valid = False
                                for signing_key in key_state.signing_keys:
                                    try:
                                        verify_acdc_signature(
                                            result.acdc, result.signature, signing_key
                                        )
                                        signature_valid = True
                                        log.info(
                                            f"Verified signature for external credential "
                                            f"{parent_said[:20]}..."
                                        )
                                        break
                                    except ACDCSignatureInvalid:
                                        continue

                                if not signature_valid:
                                    raise ACDCSignatureInvalid(
                                        f"No issuer key validates signature for "
                                        f"external credential {parent_said[:20]}..."
                                    )

                            except ResolutionFailedError as e:
                                # Key resolution failed - mark as INDETERMINATE
                                errors.append(
                                    f"Cannot resolve issuer key for external credential "
                                    f"{parent_said[:20]}...: {e}"
                                )
                                if chain_status == ClaimStatus.VALID:
                                    chain_status = ClaimStatus.INDETERMINATE
                                log.warning(
                                    f"Key resolution failed for external credential "
                                    f"{parent_said[:20]}... - chain marked INDETERMINATE"
                                )
                            except ACDCSignatureInvalid as e:
                                # Signature invalid - this is definitive INVALID
                                raise ACDCChainInvalid(
                                    f"External credential signature invalid: {e}"
                                )
                        else:
                            # No signature - cannot verify cryptographically
                            errors.append(
                                f"External credential {parent_said[:20]}... resolved "
                                f"without signature - cannot verify cryptographically"
                            )
                            if chain_status == ClaimStatus.VALID:
                                chain_status = ClaimStatus.INDETERMINATE
                            log.warning(
                                f"Externally resolved credential {parent_said[:20]}... "
                                f"has no signature - chain marked INDETERMINATE"
                            )

                if not resolved:
                    # Resolution failed or not attempted
                    # For compact variants, external edge refs result in INDETERMINATE
                    # per §2.2 ("Uncertainty must be explicit") - cannot verify the chain
                    current_variant = getattr(current, 'variant', 'full')
                    if current_variant == 'compact':
                        errors.append(
                            f"Cannot verify edge target {parent_said[:20]}... - "
                            f"not in dossier (compact variant)"
                        )
                        chain_status = ClaimStatus.INDETERMINATE
                        # Return None to indicate chain cannot be fully verified
                        # but this is not a definite INVALID - it's uncertainty
                        return None
                    # For full variants, missing edge target is a definite error
                    raise ACDCChainInvalid(
                        f"Edge target {parent_said[:20]}... not found in dossier"
                    )

            parent_acdc = dossier_acdcs[parent_said]

            # For TNAlloc, validate TN allocation is subset of parent
            if current.credential_type == "TNAlloc" and parent_acdc.credential_type == "TNAlloc":
                validate_tnalloc_credential(current, parent_acdc)

            # Recursively validate parent
            root_aid = await walk_chain(parent_acdc, depth + 1, pss_signer_aid)
            if root_aid:
                return root_aid

        # No path to trusted root found
        # If chain_status is already INDETERMINATE (compact variant external refs),
        # don't raise - return None to surface that status
        if chain_status == ClaimStatus.INDETERMINATE:
            errors.append(
                f"Cannot verify path to trusted root from {current.said[:20]}... "
                f"(external references in compact variant)"
            )
            return None
        raise ACDCChainInvalid(
            f"No path to trusted root from credential {current.said[:20]}..."
        )

    # Start chain walk
    try:
        root_aid = await walk_chain(acdc, pss_signer_aid=pss_signer_aid)

        # After chain walk, validate schema documents per §5.1.1-2.8.3
        # This fetches schema documents and validates ACDC attributes against them
        if validate_schemas:
            for cred in chain:
                schema_status, schema_errors = await validate_schema_document(cred)
                if schema_errors:
                    errors.extend(schema_errors)
                # Propagate worst status (INVALID already raises, so just INDETERMINATE)
                if schema_status == ClaimStatus.INDETERMINATE and chain_status == ClaimStatus.VALID:
                    chain_status = ClaimStatus.INDETERMINATE

        # Determine final status: validated but may be INDETERMINATE due to variants
        final_status = chain_status.value if chain_status != ClaimStatus.VALID else "VALID"
        # If root_aid is None but chain_status is INDETERMINATE, return INDETERMINATE result
        # This happens when compact variants have external refs that can't be verified
        return ACDCChainResult(
            chain=chain,
            root_aid=root_aid,
            validated=(root_aid is not None and chain_status != ClaimStatus.INVALID),
            errors=errors,
            status=final_status,
            has_variant_limitations=has_variants
        )
    except ACDCChainInvalid:
        raise
    except Exception as e:
        raise ACDCChainInvalid(f"Chain validation failed: {e}")


def validate_issuee_binding(
    acdc: ACDC,
    is_root_credential: bool = False,
    expected_issuee_aid: Optional[str] = None
) -> ClaimStatus:
    """Validate ACDC has issuee binding (not a bearer token).

    Per VVP §6.3.5, credentials MUST NOT be bearer tokens - they must have
    explicit issuee binding. The issuee field identifies the entity to whom
    the credential was issued.

    Root credentials (from GLEIF/QVIs) may lack issuee as they establish
    the trust anchor. Leaf credentials (APE/DE/TNAlloc) MUST have issuee.

    Per §2.2 ("Uncertainty must be explicit"), partial variants with
    placeholder issuees return INDETERMINATE status rather than raising.

    Args:
        acdc: The ACDC to validate.
        is_root_credential: If True, allows missing issuee for trust anchor.
        expected_issuee_aid: If provided, verifies issuee matches this AID.

    Returns:
        ClaimStatus:
        - VALID if issuee verified or root credential
        - INDETERMINATE if partial variant has placeholder issuee
        - Raises ACDCChainInvalid (→INVALID) for definite failures

    Raises:
        ACDCChainInvalid: If issuee binding is missing or mismatched
            (not for partial variants with placeholders - those get INDETERMINATE).
    """
    # Root credentials may lack issuee (they establish the trust anchor)
    if is_root_credential:
        return ClaimStatus.VALID

    is_partial = getattr(acdc, 'variant', 'full') == 'partial'
    is_compact = getattr(acdc, 'variant', 'full') == 'compact'

    # Handle compact variant (attributes may be SAID string, not dict)
    if is_compact and not isinstance(acdc.attributes, dict):
        log.warning(
            f"Cannot verify issuee binding for compact ACDC {acdc.said[:20]}... "
            f"- attributes is SAID reference, not expanded (§2.2 INDETERMINATE)"
        )
        return ClaimStatus.INDETERMINATE

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

    # Check for placeholder in partial variant
    if issuee and _is_placeholder(issuee):
        if is_partial:
            # Per §2.2: Partial variant with placeholder issuee → INDETERMINATE
            log.warning(
                f"Cannot verify issuee binding for partial ACDC {acdc.said[:20]}... "
                f"- issuee field is redacted (§2.2 INDETERMINATE)"
            )
            return ClaimStatus.INDETERMINATE
        else:
            # Non-partial with placeholder is invalid
            raise ACDCChainInvalid(
                f"Credential {acdc.said[:20]}... has placeholder issuee in non-partial variant"
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

    return ClaimStatus.VALID


def _is_placeholder(value: str) -> bool:
    """Check if a value is a partial variant placeholder.

    Per ACDC spec, placeholders are:
    - "_" (simple redaction)
    - "_:SAID" (typed placeholder with SAID reference)

    Args:
        value: The string value to check.

    Returns:
        True if value is a placeholder marker.
    """
    if not isinstance(value, str):
        return False
    return value == "_" or value.startswith("_:")


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
