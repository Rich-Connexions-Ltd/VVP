"""VVP Verification orchestration engine per spec §9.

Wires together all verification phases and builds a claim tree
with status propagation per §3.3A.

Phase 6 (Tier 1): Fixed claim tree structure with passport_verified
and dossier_verified as required children of caller_authorised.

Phase 9 (Tier 2): Revocation checking per §5.1.1-2.9. The revocation_clear
claim is a REQUIRED child of dossier_verified per §3.3B.

Sprint 15 (Tier 3): Authorization validation per §5A Steps 10-11.
The authorization_valid claim has party_authorized and tn_rights_valid
as REQUIRED children. Case A (no delegation) implemented; Case B deferred.
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

log = logging.getLogger(__name__)

from .api_models import (
    VerifyRequest,
    VerifyResponse,
    ClaimNode,
    ClaimStatus,
    ChildLink,
    ErrorDetail,
    ErrorCode,
    ERROR_RECOVERABILITY,
    derive_overall_status,
    DelegationChainResponse,
    DelegationNodeResponse,
    ToIPWarningDetail,
    IssuerIdentityInfo,
)
from .header import parse_vvp_identity, VVPIdentity
from .passport import parse_passport, validate_passport_binding, Passport
from .keri import (
    verify_passport_signature,
    verify_passport_signature_tier2,
    verify_passport_signature_tier2_with_key_state,
    SignatureInvalidError,
    ResolutionFailedError,
    KeyNotYetValidError,
)
from .dossier import (
    fetch_dossier,
    parse_dossier,
    build_dag,
    validate_dag,
    DossierDAG,
    FetchError,
    ParseError,
    GraphError,
    get_dossier_cache,
    CachedDossier,
)
from .exceptions import VVPIdentityError, PassportError
from .authorization import AuthorizationContext, validate_authorization
from .sip_context import verify_sip_context_alignment
from .brand import verify_brand
from .goal import verify_business_logic, GoalPolicyConfig


# =============================================================================
# DID Web to OOBI Conversion
# =============================================================================


def _convert_did_web_to_oobi(kid: str) -> Optional[str]:
    """Convert did:web: URL to OOBI URL format.

    Per DID Web spec, did:web:domain#fragment where fragment is the AID
    should resolve to an OOBI URL. For KERI/VVP, this typically means
    a witness OOBI endpoint.

    Special handling for Provenant demo domain to use staging witnesses.

    Args:
        kid: The kid value, potentially in did:web: format

    Returns:
        OOBI URL if conversion successful, None if not a did:web URL.

    Examples:
        did:web:demo.provenant.net#EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF
        -> http://witness5.stage.provenant.net:5631/oobi/EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF/witness
    """
    if not kid.startswith("did:web:"):
        return None

    # Parse did:web:domain#fragment
    # Remove "did:web:" prefix
    rest = kid[8:]  # len("did:web:") = 8

    # Split on # to get domain and fragment (AID)
    if "#" not in rest:
        return None

    domain, aid = rest.split("#", 1)
    if not domain or not aid:
        return None

    # Special handling for Provenant demo domain - use staging witness
    # The demo.provenant.net domain uses staging witnesses at witnessX.stage.provenant.net:5631
    if "provenant.net" in domain:
        # Use witness5 as default (confirmed working)
        return f"http://witness5.stage.provenant.net:5631/oobi/{aid}/witness"

    # Default: construct standard OOBI URL
    return f"https://{domain}/oobi/{aid}"


# =============================================================================
# Claim Builder
# =============================================================================


@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim.

    Tracks the claim status, reasons for any failures, and evidence
    gathered during verification. Use build() to create the final ClaimNode.
    """

    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE.

        Args:
            status: The failure status (INVALID or INDETERMINATE)
            reason: Human-readable reason for the failure
        """
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string (e.g., AID, SAID, or verification result)."""
        self.evidence.append(ev)

    def build(self, children: Optional[List[ChildLink]] = None) -> ClaimNode:
        """Build the final ClaimNode from accumulated state."""
        return ClaimNode(
            name=self.name,
            status=self.status,
            reasons=self.reasons,
            evidence=self.evidence,
            children=children or [],
        )


# =============================================================================
# Error Conversion
# =============================================================================


def to_error_detail(exc: Exception) -> ErrorDetail:
    """Convert domain exception to ErrorDetail for API response.

    Extracts error code and message from exception attributes,
    and looks up recoverability from ERROR_RECOVERABILITY mapping.
    """
    code = getattr(exc, "code", ErrorCode.INTERNAL_ERROR)
    message = getattr(exc, "message", str(exc))
    recoverable = ERROR_RECOVERABILITY.get(code, True)
    return ErrorDetail(code=code, message=message, recoverable=recoverable)


# =============================================================================
# Model Conversion Helpers (Phase 11)
# =============================================================================


def _convert_dag_to_acdcs(dag: DossierDAG) -> Dict[str, "ACDC"]:
    """Convert DossierDAG nodes to ACDC format for chain validation.

    The dossier module uses ACDCNode while the acdc module uses ACDC.
    This function bridges the two models.

    Args:
        dag: DossierDAG with ACDCNode objects

    Returns:
        Dict mapping SAID to ACDC objects
    """
    from app.vvp.acdc import ACDC

    result = {}
    for said, node in dag.nodes.items():
        result[said] = ACDC(
            version=node.raw.get("v", ""),
            said=said,
            issuer_aid=node.issuer,
            schema_said=node.raw.get("s", ""),
            attributes=node.raw.get("a"),
            edges=node.edges,
            rules=node.raw.get("r"),
            raw=node.raw,
        )
    return result


def _extract_aid_from_kid(kid: str) -> str:
    """Extract AID from kid (which may be bare AID or OOBI URL).

    Per §4.2, kid SHOULD be an OOBI URL. This function extracts the AID
    from either format for use in chain validation.

    Args:
        kid: PASSporT kid field (bare AID or OOBI URL)

    Returns:
        The extracted AID

    Raises:
        ResolutionFailedError: If AID cannot be extracted from OOBI URL
    """
    if kid.startswith(("http://", "https://")):
        # Extract AID from OOBI URL path
        # Pattern: https://witness.example.com/oobi/{AID}[/witness/...]
        from urllib.parse import urlparse

        parsed = urlparse(kid)
        path_parts = parsed.path.strip("/").split("/")

        # Find AID after 'oobi' in path
        for i, part in enumerate(path_parts):
            if part == "oobi" and i + 1 < len(path_parts):
                aid = path_parts[i + 1]
                if aid and aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                    return aid

        # If OOBI URL but no AID found, raise error
        raise ResolutionFailedError(
            f"Could not extract AID from OOBI URL: {kid[:50]}..."
        )

    # Bare AID - return as-is
    # Note: Per §4.2, bare AIDs should trigger INVALID, but we return them
    # here so the caller can decide how to handle (e.g., for chain validation)
    return kid


def _find_leaf_credentials(dag: DossierDAG, dossier_acdcs: Dict[str, "ACDC"]) -> List[str]:
    """Find leaf credentials in the DAG (credentials not referenced by other edges).

    Per §6.3.x, chain validation should start from the credential(s) relevant
    to the authorization being verified, not necessarily the DAG structural root.
    Leaf credentials are those that authorize specific actions (APE/DE/TNAlloc)
    and are not referenced as edges by other credentials.

    Args:
        dag: DossierDAG with credential nodes
        dossier_acdcs: Dict mapping SAID to ACDC objects

    Returns:
        List of SAIDs for leaf credentials. If no leaves found, returns [dag.root_said].
    """
    # Collect all SAIDs referenced as edges by other credentials
    referenced_saids: Set[str] = set()
    for said, node in dag.nodes.items():
        if not node.edges:
            continue
        for edge_name, edge_ref in node.edges.items():
            # Skip metadata fields
            if edge_name in ('d', 'n'):
                continue

            # Extract referenced SAID from edge
            if isinstance(edge_ref, str):
                referenced_saids.add(edge_ref)
            elif isinstance(edge_ref, dict):
                ref_said = edge_ref.get('n') or edge_ref.get('d')
                if ref_said:
                    referenced_saids.add(ref_said)

    # Leaf credentials are those NOT referenced by other credentials
    leaf_saids = [said for said in dag.nodes.keys() if said not in referenced_saids]

    # If no leaves found (cycle or single node), fall back to root
    if not leaf_saids:
        return [dag.root_said] if dag.root_said else []

    return leaf_saids


def _find_de_credential(dossier_acdcs: Dict[str, "ACDC"]) -> Optional["ACDC"]:
    """Find Delegation Edge (DE) credential in dossier.

    Per §6.3.4, DE credentials authorize delegated signers. They're identified
    by having a 'delegate' or 'auth' edge pointing to another credential.

    Args:
        dossier_acdcs: Dict mapping SAID to ACDC objects

    Returns:
        DE ACDC if found, None otherwise
    """
    for said, acdc in dossier_acdcs.items():
        # Look for DE-indicative edges
        edges = getattr(acdc, "edges", None)
        if edges is None:
            raw = getattr(acdc, "raw", {})
            edges = raw.get("e", {})

        if not isinstance(edges, dict):
            continue

        # DE credentials typically have auth/delegate edges
        de_edge_names = {"auth", "delegate", "delegation", "proxy"}
        for edge_name in edges.keys():
            if edge_name.lower() in de_edge_names:
                return acdc

    return None


def _get_acdc_issuee(acdc: "ACDC") -> Optional[str]:
    """Extract issuee AID from ACDC attributes.

    Per §6.3.4, DE credentials have an 'i' (issuee) field in attributes
    that identifies the delegated signer.

    Args:
        acdc: ACDC credential object

    Returns:
        Issuee AID if found, None otherwise
    """
    attrs = getattr(acdc, "attributes", None)
    if attrs is None:
        raw = getattr(acdc, "raw", {})
        attrs = raw.get("a", {})

    if isinstance(attrs, dict):
        return attrs.get("i")
    return None


def _build_delegation_response(
    chain: "DelegationChain",
    authorization_status: str,
) -> DelegationChainResponse:
    """Convert backend DelegationChain to API response model.

    Sprint 25: Maps the internal DelegationChain dataclass to the API
    response model for UI consumption.

    Args:
        chain: Backend DelegationChain from KeyState.
        authorization_status: Result of validate_delegation_authorization():
            - "VALID": Anchor found and signature verified
            - "INVALID": Anchor signature invalid or missing SAID
            - "INDETERMINATE": Delegator KEL unavailable

    Note: Per reviewer finding, status mapping must distinguish definitive
    failures (INVALID) from incomplete resolution (INDETERMINATE).

    Returns:
        DelegationChainResponse ready for API serialization.
    """
    # Determine per-node status: VALID if chain valid AND authorization passed
    if chain.valid and authorization_status == "VALID":
        node_status = "VALID"
    elif authorization_status == "INVALID" or not chain.valid:
        # Definitive failure: bad signature, missing SAID, or chain invalid
        node_status = "INVALID"
    else:
        # Could not complete: delegator unavailable, KEL incomplete
        node_status = "INDETERMINATE"

    nodes = []
    for aid in chain.delegates:
        nodes.append(DelegationNodeResponse(
            aid=aid,
            aid_short=f"{aid[:16]}...",
            is_root=(aid == chain.root_aid),
            authorization_status=node_status,
        ))

    return DelegationChainResponse(
        chain=nodes,
        depth=len(chain.delegates) - 1 if chain.delegates else 0,
        root_aid=chain.root_aid,
        is_valid=(chain.valid and authorization_status == "VALID"),
        errors=chain.errors,
    )


def _find_signer_de_credential(
    dossier_acdcs: Dict[str, "ACDC"],
    signer_aid: str
) -> Optional["ACDC"]:
    """Find DE credential where issuee matches the PASSporT signer AID.

    Sprint 18 fix A3: The original _find_de_credential() returns the first DE
    in the dossier, which causes false positives/negatives when multiple DEs
    exist. This function filters DEs by the signer's delegation chain.

    Per §6.3.4, DE credentials authorize delegated signers. The issuee ('i')
    field in the DE attributes identifies who is authorized to sign.

    Args:
        dossier_acdcs: Dict mapping SAID to ACDC objects
        signer_aid: AID of the PASSporT signer (from kid)

    Returns:
        DE ACDC where issuee matches signer_aid, or None if not found
    """
    for said, acdc in dossier_acdcs.items():
        # Check if this is a DE credential by looking for DE-indicative edges
        is_de = False
        edges = getattr(acdc, "edges", None)
        if edges is None:
            raw = getattr(acdc, "raw", {})
            edges = raw.get("e", {})

        if isinstance(edges, dict):
            de_edge_names = {"auth", "delegate", "delegation", "proxy"}
            for edge_name in edges.keys():
                if edge_name.lower() in de_edge_names:
                    is_de = True
                    break

        if not is_de:
            continue

        # Check if issuee matches signer AID
        issuee = _get_acdc_issuee(acdc)
        if issuee == signer_aid:
            return acdc

    return None


# =============================================================================
# Revocation Checking (§5.1.1-2.9)
# =============================================================================


async def _query_registry_tel(
    client,
    credential_said: str,
    registry_said: Optional[str],
    base_oobi_url: Optional[str]
):
    """Query TEL via registry OOBI resolution.

    Strategy:
    1. If registry_said available, construct registry OOBI URL from base OOBI pattern
    2. Resolve registry OOBI to get registry controller's witnesses
    3. Query those witnesses for TEL events
    4. If no registry_said, fall back to default witness queries

    Args:
        client: TEL client instance
        credential_said: Credential SAID to check
        registry_said: Registry SAID (from ACDC 'ri' field)
        base_oobi_url: Base OOBI URL to derive registry OOBI pattern

    Returns:
        RevocationResult from registry witnesses
    """
    from .keri.tel_client import CredentialStatus, RevocationResult

    if not registry_said:
        log.info(f"    no registry SAID for {credential_said[:20]}..., using default witnesses")
        # Fall back to default witness queries without registry OOBI
        return await client.check_revocation(
            credential_said=credential_said,
            registry_said=None,
            oobi_url=None
        )

    # Derive registry OOBI URL from base OOBI pattern
    # Pattern: replace AID in OOBI path with registry SAID
    registry_oobi_url = None
    if base_oobi_url:
        parsed = urlparse(base_oobi_url)
        # Construct registry OOBI: {scheme}://{netloc}/oobi/{registry_said}
        registry_oobi_url = f"{parsed.scheme}://{parsed.netloc}/oobi/{registry_said}"
        log.info(f"    constructed registry OOBI: {registry_oobi_url}")

    # Query via registry OOBI
    if registry_oobi_url:
        result = await client.check_revocation(
            credential_said=credential_said,
            registry_said=registry_said,
            oobi_url=registry_oobi_url
        )
        if result.status != CredentialStatus.ERROR:
            return result
        log.info(f"    registry OOBI query failed: {result.error}")

    # Fallback: try direct witness queries (existing behavior)
    log.info(f"    falling back to default witness queries")
    return await client.check_revocation(
        credential_said=credential_said,
        registry_said=registry_said,
        oobi_url=None  # Use default witnesses
    )


async def check_dossier_revocations(
    dag: DossierDAG,
    raw_dossier: Optional[bytes] = None,
    oobi_url: Optional[str] = None
) -> Tuple[ClaimBuilder, List[str]]:
    """Check revocation status for all credentials in a dossier DAG.

    Per spec §5.1.1-2.9: Revocation Status Check
    - Query TEL for each credential in dossier
    - If ANY credential is revoked → INVALID
    - If ANY credential status unknown/error → INDETERMINATE
    - If ALL credentials active → VALID

    Strategy (Phase 9.4):
    1. First check if TEL events are included inline in raw_dossier
    2. If found, use inline TEL to determine status (no network required)
    3. If not found, resolve registry OOBI to discover TEL-serving witnesses
    4. Query registry witnesses for TEL events

    The PASSporT signer's OOBI (oobi_url) is NOT used directly for TEL queries
    because it points to the signer's agent, not the credential registry controller.
    Instead, it's used to derive the registry OOBI pattern.

    Args:
        dag: Parsed and validated DossierDAG
        raw_dossier: Raw dossier bytes for inline TEL parsing
        oobi_url: Base OOBI URL for registry OOBI derivation

    Returns:
        Tuple of (ClaimBuilder for `revocation_clear` claim, list of revoked SAIDs)
    """
    from .keri.tel_client import get_tel_client, CredentialStatus

    claim = ClaimBuilder("revocation_clear")
    client = get_tel_client()
    revoked_saids: List[str] = []

    log.info(f"check_dossier_revocations: checking {len(dag.nodes)} credential(s)")

    # Step 1: Try to extract TEL events from inline dossier (binary-safe)
    inline_tel_results: Dict[str, any] = {}
    if raw_dossier:
        log.info("  Step 1: checking for inline TEL events")
        # Use latin-1 for byte-transparent decoding (preserves all bytes)
        # CESR JSON portions are ASCII-safe, binary attachments are Base64 (also ASCII-safe)
        dossier_text = raw_dossier.decode("latin-1")
        for said, node in dag.nodes.items():
            registry_said = node.raw.get("ri")
            result = client.parse_dossier_tel(
                dossier_text,
                credential_said=said,
                registry_said=registry_said
            )
            if result.status != CredentialStatus.UNKNOWN:
                inline_tel_results[said] = result
                log.info(f"    found inline TEL for {said[:20]}...: {result.status.value}")

    if not inline_tel_results:
        log.info("  Step 1: no inline TEL events found")

    # Step 2: Check each credential
    revoked_count = 0
    unknown_count = 0
    active_count = 0
    inline_count = len(inline_tel_results)

    for said, node in dag.nodes.items():
        registry_said = node.raw.get("ri")

        # Use inline result if available
        if said in inline_tel_results:
            result = inline_tel_results[said]
            log.info(f"  using inline TEL for {said[:20]}...: {result.status.value}")
        else:
            # Step 3: Resolve registry OOBI and query its witnesses
            log.info(f"  no inline TEL for {said[:20]}..., resolving registry OOBI")
            result = await _query_registry_tel(
                client,
                credential_said=said,
                registry_said=registry_said,
                base_oobi_url=oobi_url
            )

        # Process result with consistent evidence format
        if result.status == CredentialStatus.REVOKED:
            revoked_count += 1
            revoked_saids.append(said)
            claim.fail(
                ClaimStatus.INVALID,
                f"Credential {said[:20]}... is revoked"
            )
            claim.add_evidence(f"revocation_source:{result.source}")
            log.info(f"  credential REVOKED: {said[:20]}...")

            # Invalidate dossier cache entries containing this revoked credential
            # Per §5.1.1-2.7: Cache invalidation on revocation
            dossier_cache = get_dossier_cache()
            invalidated = await dossier_cache.invalidate_by_said(said)
            if invalidated > 0:
                log.info(f"  cache invalidated: {invalidated} dossier(s)")

        elif result.status in (CredentialStatus.UNKNOWN, CredentialStatus.ERROR):
            unknown_count += 1
            # Only mark INDETERMINATE if we haven't already found revoked creds
            if claim.status != ClaimStatus.INVALID:
                claim.fail(
                    ClaimStatus.INDETERMINATE,
                    f"Could not determine revocation status for {said[:20]}...: {result.error or 'unknown'}"
                )
            claim.add_evidence(f"unknown:{said[:16]}...|revocation_source:{result.source}")
            log.info(f"  credential status UNKNOWN: {said[:20]}... error={result.error}")

        else:
            # ACTIVE - credential is valid
            active_count += 1
            claim.add_evidence(f"active:{said[:16]}...|revocation_source:{result.source}")
            log.info(f"  credential ACTIVE: {said[:20]}...")

    # Summary evidence
    total = len(dag.nodes)
    queried_count = total - inline_count
    claim.add_evidence(f"checked:{total},inline:{inline_count},queried:{queried_count}")

    return claim, revoked_saids


# =============================================================================
# Status Propagation (§3.3A)
# =============================================================================


def _worse_status(a: ClaimStatus, b: ClaimStatus) -> ClaimStatus:
    """Return the worse of two statuses per precedence rules.

    Precedence: INVALID > INDETERMINATE > VALID
    """
    if a == ClaimStatus.INVALID or b == ClaimStatus.INVALID:
        return ClaimStatus.INVALID
    if a == ClaimStatus.INDETERMINATE or b == ClaimStatus.INDETERMINATE:
        return ClaimStatus.INDETERMINATE
    return ClaimStatus.VALID


def propagate_status(node: ClaimNode) -> ClaimStatus:
    """Compute effective status considering REQUIRED children per §3.3A.

    Rules:
    - REQUIRED children: parent status is worst of own + all required children
    - OPTIONAL children: do not affect parent status

    This function recursively processes the tree, computing child status
    before parent status (post-order traversal).

    Args:
        node: ClaimNode to compute status for

    Returns:
        Effective status considering required children
    """
    worst = node.status
    for link in node.children:
        if link.required:
            child_status = propagate_status(link.node)
            worst = _worse_status(worst, child_status)
    return worst


# =============================================================================
# Main Orchestrator
# =============================================================================


async def verify_vvp(
    req: VerifyRequest,
    vvp_identity_header: Optional[str] = None,
    reference_time: Optional[int] = None,
) -> Tuple[str, VerifyResponse]:
    """Orchestrate VVP verification per spec §9.

    Flow:
    1. Parse VVP-Identity header (Phase 2)
    2. Parse + bind PASSporT (Phase 3)
    3. Verify signature (Phase 4)
    4. Fetch + validate dossier (Phase 5)
    5. Build claim tree (Phase 6)
    6. Propagate status + derive overall

    Error handling:
    - VVP-Identity errors: Early exit with INVALID (non-recoverable)
    - PASSporT errors: Mark passport_verified INVALID, skip signature verification
    - Signature errors: INVALID (crypto fail) or INDETERMINATE (resolution fail)
    - Dossier errors: INVALID (parse/graph) or INDETERMINATE (fetch fail)

    Reviewer feedback applied:
    - Skip dossier fetch when passport has non-recoverable failure
    - Use propagate_status uniformly for status computation

    Args:
        req: VerifyRequest with passport_jwt and context
        vvp_identity_header: Raw VVP-Identity header value from HTTP request
        reference_time: Optional reference timestamp for expiry checks (testing only).
            If provided, used instead of current time for PASSporT expiry validation.

    Returns:
        Tuple of (request_id, VerifyResponse)
    """
    request_id = str(uuid.uuid4())
    errors: List[ErrorDetail] = []

    passport_claim = ClaimBuilder("passport_verified")
    dossier_claim = ClaimBuilder("dossier_verified")

    # -------------------------------------------------------------------------
    # Phase 2: VVP-Identity Header
    # -------------------------------------------------------------------------
    vvp_identity: Optional[VVPIdentity] = None
    try:
        vvp_identity = parse_vvp_identity(vvp_identity_header)
    except VVPIdentityError as e:
        errors.append(to_error_detail(e))
        # Non-recoverable - return early with INVALID, no claims
        return request_id, VerifyResponse(
            request_id=request_id,
            overall_status=ClaimStatus.INVALID,
            claims=None,
            errors=errors,
        )

    # -------------------------------------------------------------------------
    # Phase 3: PASSporT Parse + Binding
    # -------------------------------------------------------------------------
    passport: Optional[Passport] = None
    passport_fatal = False  # Track if passport has non-recoverable failure

    try:
        passport = parse_passport(req.passport_jwt)
        passport_claim.add_evidence(f"kid={passport.header.kid[:20]}...")
    except PassportError as e:
        errors.append(to_error_detail(e))
        passport_claim.fail(ClaimStatus.INVALID, e.message)
        passport_fatal = True

    if passport and vvp_identity and not passport_fatal:
        try:
            validate_passport_binding(passport, vvp_identity, now=reference_time)
            passport_claim.add_evidence("binding_valid")
        except PassportError as e:
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True

    # -------------------------------------------------------------------------
    # Phase 4: KERI Signature Verification (§4.2, §5.1)
    # -------------------------------------------------------------------------
    # Per §4.2, kid MUST be an OOBI URL. Bare AIDs are non-compliant and
    # result in INVALID status. When kid is an OOBI URL, we use Tier 2
    # verification with historical key state resolution.
    #
    # Sprint 25: Track delegation chain data for UI visualization
    delegation_chain_data: Optional[DelegationChainResponse] = None
    signer_aid: Optional[str] = None

    if passport and not passport_fatal:
        kid = passport.header.kid

        # Try to convert did:web: to OOBI URL (DID Web spec support)
        oobi_url = None
        if kid.startswith(("http://", "https://")):
            oobi_url = kid
        elif kid.startswith("did:web:"):
            oobi_url = _convert_did_web_to_oobi(kid)
            if oobi_url:
                passport_claim.add_evidence(f"did_web_converted:{kid[:30]}...")

        try:
            if oobi_url:
                # Tier 2: Use historical key state resolution via OOBI
                # Sprint 25: Use _with_key_state variant to capture delegation chain
                key_state, auth_status = await verify_passport_signature_tier2_with_key_state(
                    passport,
                    oobi_url=oobi_url,
                    _allow_test_mode=False
                )
                passport_claim.add_evidence("signature_valid,tier2")

                # Sprint 25: Capture signer AID for credential mapping
                signer_aid = key_state.aid

                # Sprint 25: Build delegation chain response if present
                if key_state.delegation_chain and key_state.delegation_chain.delegates:
                    delegation_chain_data = _build_delegation_response(
                        key_state.delegation_chain,
                        auth_status,
                    )
                    passport_claim.add_evidence(f"delegation_depth={delegation_chain_data.depth}")
            else:
                # §4.2: kid MUST be an OOBI URL - bare AIDs are non-compliant
                # Mark as INVALID rather than silently falling back to Tier 1
                raise ResolutionFailedError(
                    f"kid must be an OOBI URL per §4.2, got bare AID: {kid[:20]}..."
                )
        except SignatureInvalidError as e:
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True
        except KeyNotYetValidError as e:
            # §4.2A: Reference time before inception → KERI_STATE_INVALID
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True
        except ResolutionFailedError as e:
            errors.append(to_error_detail(e))
            # Distinguish between spec violation (bare AID) and network issues
            if "must be an OOBI" in str(e):
                passport_claim.fail(ClaimStatus.INVALID, e.message)
                passport_fatal = True
            else:
                passport_claim.fail(ClaimStatus.INDETERMINATE, e.message)
                # Note: INDETERMINATE is recoverable, so not setting passport_fatal

    # -------------------------------------------------------------------------
    # Phase 5: Dossier Fetch and Validation
    # -------------------------------------------------------------------------
    # Per reviewer feedback: skip dossier fetch if passport has fatal failure
    # This reduces load and provides clearer error diagnostics
    # Per §5.1.1-2.7: Check dossier cache before fetching
    import time as _time
    raw_dossier: Optional[bytes] = None
    dag: Optional[DossierDAG] = None
    acdc_signatures: Dict[str, bytes] = {}  # SAID -> signature bytes from CESR
    has_variant_limitations: bool = False  # Track if any ACDC is compact/partial per §1.4
    dossier_cache = get_dossier_cache()
    cache_hit = False

    if vvp_identity and not passport_fatal:
        # §5.1.1-2.7: Check cache first (URL available pre-fetch)
        evd_url = vvp_identity.evd
        cached = await dossier_cache.get(evd_url)
        if cached:
            # Cache hit - use cached data
            cache_hit = True
            dag = cached.dag
            raw_dossier = cached.raw_content
            dossier_claim.add_evidence(f"cache_hit={evd_url[:40]}...")
            dossier_claim.add_evidence(f"dag_valid,root={dag.root_said}")
            if dag.is_aggregate:
                dossier_claim.add_evidence(f"aggregate_roots={len(dag.root_saids)}")
            log.info(f"Dossier cache hit: {evd_url[:50]}...")
        else:
            # Cache miss - fetch from network
            try:
                raw_dossier = await fetch_dossier(evd_url)
                dossier_claim.add_evidence(f"fetched={evd_url[:40]}...")
            except FetchError as e:
                errors.append(to_error_detail(e))
                dossier_claim.fail(ClaimStatus.INDETERMINATE, e.message)

            if raw_dossier is not None:
                try:
                    from app.core.config import ALLOW_AGGREGATE_DOSSIERS
                    nodes, acdc_signatures = parse_dossier(raw_dossier)
                    dag = build_dag(nodes)
                    validate_dag(dag, allow_aggregate=ALLOW_AGGREGATE_DOSSIERS)
                    dossier_claim.add_evidence(f"dag_valid,root={dag.root_said}")
                    if dag.is_aggregate:
                        dossier_claim.add_evidence(f"aggregate_roots={len(dag.root_saids)}")
                    if acdc_signatures:
                        dossier_claim.add_evidence(f"cesr_sigs={len(acdc_signatures)}")

                    # Log ToIP spec warnings (non-blocking)
                    if dag.warnings:
                        for w in dag.warnings:
                            log.info(f"ToIP warning: {w.code.value} - {w.message}")
                        dossier_claim.add_evidence(f"toip_warnings={len(dag.warnings)}")

                    # §5.1.1-2.7: Store in cache on successful parse/validate
                    contained_saids = set(dag.nodes.keys())
                    cached_dossier = CachedDossier(
                        dag=dag,
                        raw_content=raw_dossier,
                        fetch_timestamp=_time.time(),
                        content_type="application/json+cesr",
                        contained_saids=contained_saids,
                    )
                    await dossier_cache.put(evd_url, cached_dossier)
                    log.info(f"Dossier cached: {evd_url[:50]}... (saids={len(contained_saids)})")
                except (ParseError, GraphError) as e:
                    errors.append(to_error_detail(e))
                    dossier_claim.fail(ClaimStatus.INVALID, e.message)
                    dag = None  # Ensure dag is None on validation failure
    elif passport_fatal:
        # Mark dossier as indeterminate since we skipped verification
        dossier_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Skipped due to passport verification failure",
        )

    # -------------------------------------------------------------------------
    # Phase 5.5: ACDC Chain Verification (§6.3.x)
    # -------------------------------------------------------------------------
    # chain_verified is a REQUIRED child of dossier_verified per §3.3B
    # This validates credential type rules (APE/DE/TNAlloc) and chain trust
    # Per §5A Step 8: dossier cryptographic verification MUST be performed
    # even when PASSporT is absent (we just can't validate DE signer binding)
    chain_claim = ClaimBuilder("chain_verified")

    if dag is not None:
        from app.core.config import (
            TRUSTED_ROOT_AIDS,
            SCHEMA_VALIDATION_STRICT,
            EXTERNAL_SAID_RESOLUTION_ENABLED,
            EXTERNAL_SAID_RESOLUTION_TIMEOUT,
            EXTERNAL_SAID_MAX_DEPTH,
            EXTERNAL_SAID_CACHE_TTL_SECONDS,
            EXTERNAL_SAID_CACHE_MAX_ENTRIES,
        )
        from app.vvp.acdc import (
            validate_credential_chain,
            ACDCChainInvalid,
            ACDCSAIDMismatch,
            verify_acdc_signature,
            ACDCSignatureInvalid,
        )
        from app.vvp.keri import resolve_key_state
        from app.vvp.keri.tel_client import TELClient

        # Convert DossierDAG nodes to ACDC format
        dossier_acdcs = _convert_dag_to_acdcs(dag)

        # Get PSS signer AID from passport kid for DE validation (if passport available)
        # Per §6.3.4, PSS signer must match delegate in DE credential
        pss_signer_aid = None
        witness_urls = []
        if passport:
            try:
                pss_signer_aid = _extract_aid_from_kid(passport.header.kid)
            except ResolutionFailedError:
                pass  # Chain validation can proceed without

            # Extract witness URL from passport kid for external SAID resolution
            if passport.header.kid:
                witness_base_url = TELClient.extract_witness_base_url(passport.header.kid)
                if witness_base_url:
                    witness_urls.append(witness_base_url)

        # Set up credential resolver for external SAID resolution if enabled
        credential_resolver = None
        if EXTERNAL_SAID_RESOLUTION_ENABLED and witness_urls:
            from app.vvp.keri.credential_resolver import (
                CredentialResolver,
                CredentialResolverConfig,
            )
            credential_resolver = CredentialResolver(
                config=CredentialResolverConfig(
                    enabled=True,
                    timeout_seconds=EXTERNAL_SAID_RESOLUTION_TIMEOUT,
                    max_recursion_depth=EXTERNAL_SAID_MAX_DEPTH,
                    cache_ttl_seconds=EXTERNAL_SAID_CACHE_TTL_SECONDS,
                    cache_max_entries=EXTERNAL_SAID_CACHE_MAX_ENTRIES,
                )
            )
            log.debug(
                f"External SAID resolution enabled with {len(witness_urls)} witness(es)"
            )

        # Find leaf credentials to validate (not just the DAG root)
        # Per §6.3.x, validate from APE/DE/TNAlloc credentials that are leaves
        leaf_saids = _find_leaf_credentials(dag, dossier_acdcs)
        chain_claim.add_evidence(f"leaves={len(leaf_saids)}")

        # Validate chain from each leaf credential
        # Per §2.2: Track worst status across all leaves (INVALID > INDETERMINATE > VALID)
        # Per §6.1: For aggregate dossiers, ALL leaves must validate
        chain_errors: List[str] = []
        valid_chains = 0
        indeterminate_chains = 0
        invalid_chains = 0
        worst_chain_status = ClaimStatus.VALID

        for leaf_said in leaf_saids:
            leaf_acdc = dossier_acdcs.get(leaf_said)
            if not leaf_acdc:
                chain_errors.append(f"Leaf {leaf_said[:16]}... not in dossier")
                invalid_chains += 1
                continue

            try:
                # §6.3.3-6: Schema validation strictness controlled by config
                result = await validate_credential_chain(
                    acdc=leaf_acdc,
                    trusted_roots=TRUSTED_ROOT_AIDS,
                    dossier_acdcs=dossier_acdcs,
                    pss_signer_aid=pss_signer_aid,
                    validate_schemas=SCHEMA_VALIDATION_STRICT,
                    credential_resolver=credential_resolver,
                    witness_urls=witness_urls if credential_resolver else None,
                )

                # Track variant limitations from chain result (§1.4)
                if result.has_variant_limitations:
                    has_variant_limitations = True
                    chain_claim.add_evidence("variant_limitations=true")

                # Check result status - INDETERMINATE can occur for compact variants
                # with external edge refs (per §2.2 "uncertainty must be explicit")
                result_status_str = result.status or "VALID"
                if result_status_str == "INDETERMINATE":
                    indeterminate_chains += 1
                    chain_claim.add_evidence(f"chain_indeterminate:{leaf_said[:12]}...")
                    if worst_chain_status == ClaimStatus.VALID:
                        worst_chain_status = ClaimStatus.INDETERMINATE
                elif result.validated and result.root_aid:
                    valid_chains += 1
                    chain_claim.add_evidence(f"chain_valid:{leaf_said[:12]}...,root={result.root_aid[:12]}...")
                else:
                    # Chain returned but not validated (shouldn't happen but handle defensively)
                    invalid_chains += 1
                    chain_errors.append(f"{leaf_said[:16]}...: Chain not validated")
            except ACDCSAIDMismatch as e:
                # §4.2A: SAID mismatch is a distinct error code from chain invalid
                error_msg = f"ACDC SAID mismatch: {str(e)}"
                errors.append(ErrorDetail(
                    code=ErrorCode.ACDC_SAID_MISMATCH,
                    message=error_msg,
                    recoverable=False
                ))
                chain_claim.fail(ClaimStatus.INVALID, error_msg)
                break  # Fatal error, no point checking other leaves
            except ACDCChainInvalid as e:
                invalid_chains += 1
                chain_errors.append(f"{leaf_said[:16]}...: {str(e)}")

        # Determine final chain_claim status
        # Per §6.1: For aggregate dossiers, ALL leaves must validate
        # For non-aggregate: at least one valid chain suffices (prior behavior)
        # Per §2.2: INDETERMINATE propagates unless overridden by INVALID
        if chain_claim.status != ClaimStatus.INVALID:  # Don't override SAID mismatch failure
            is_aggregate = dag.is_aggregate if dag else False

            if is_aggregate:
                # Aggregate dossiers: ALL chains must pass
                if invalid_chains > 0:
                    error_msg = f"Aggregate dossier chain validation failed: {'; '.join(chain_errors[:3])}"
                    errors.append(ErrorDetail(
                        code=ErrorCode.DOSSIER_GRAPH_INVALID,
                        message=error_msg,
                        recoverable=False
                    ))
                    chain_claim.fail(ClaimStatus.INVALID, error_msg)
                elif worst_chain_status == ClaimStatus.INDETERMINATE:
                    chain_claim.fail(
                        ClaimStatus.INDETERMINATE,
                        "Aggregate chain verification incomplete due to variant limitations"
                    )
                # else: all chains valid, chain_claim stays VALID
            else:
                # Non-aggregate dossiers: at least one valid chain suffices
                if valid_chains > 0:
                    # At least one chain validated successfully - overall success
                    # Propagate INDETERMINATE if any chains had variant limitations
                    if worst_chain_status == ClaimStatus.INDETERMINATE:
                        chain_claim.fail(
                            ClaimStatus.INDETERMINATE,
                            "Chain verification incomplete due to variant limitations"
                        )
                    # else: at least one chain VALID, chain_claim stays VALID
                elif indeterminate_chains > 0:
                    # No valid chains but some INDETERMINATE - propagate uncertainty
                    chain_claim.fail(
                        ClaimStatus.INDETERMINATE,
                        "Chain verification incomplete - no chain fully validated"
                    )
                else:
                    # No valid or indeterminate chains - all failed
                    error_msg = f"No credential chain reaches trusted root: {'; '.join(chain_errors[:3])}"
                    errors.append(ErrorDetail(
                        code=ErrorCode.DOSSIER_GRAPH_INVALID,
                        message=error_msg,
                        recoverable=False
                    ))
                    chain_claim.fail(ClaimStatus.INVALID, error_msg)

        # Verify ACDC signatures (for CESR format dossiers)
        # Per §5A Step 8: cryptographic verification MUST be performed
        if acdc_signatures and chain_claim.status == ClaimStatus.VALID:
            from datetime import datetime, timezone
            reference_time = datetime.now(timezone.utc)

            for said, signature in acdc_signatures.items():
                acdc = dossier_acdcs.get(said)
                if not acdc:
                    continue

                try:
                    # Resolve issuer key state with strict validation
                    # Per §4.2, OOBI MUST resolve to valid KEL in production
                    key_state = await resolve_key_state(
                        kid=acdc.issuer_aid,
                        reference_time=reference_time,
                        _allow_test_mode=False  # Strict validation in production
                    )

                    # Verify signature against ALL issuer keys (not just index 0)
                    # At least one key must validate the signature
                    signature_valid = False
                    for signing_key in key_state.signing_keys:
                        try:
                            verify_acdc_signature(acdc, signature, signing_key)
                            signature_valid = True
                            break
                        except ACDCSignatureInvalid:
                            continue

                    if not signature_valid:
                        raise ACDCSignatureInvalid(
                            f"No issuer key validates signature for {said[:20]}..."
                        )

                    chain_claim.add_evidence(f"sig_valid:{said[:16]}...")

                except ACDCSignatureInvalid as e:
                    errors.append(ErrorDetail(
                        code=ErrorCode.ACDC_PROOF_MISSING,
                        message=str(e),
                        recoverable=False
                    ))
                    chain_claim.fail(ClaimStatus.INVALID, f"ACDC signature invalid: {e}")
                    break
                except ResolutionFailedError as e:
                    # Key resolution failed - mark as INDETERMINATE
                    log.warning(f"Could not resolve issuer key for {said[:20]}...: {e}")
                    chain_claim.fail(
                        ClaimStatus.INDETERMINATE,
                        f"Could not resolve issuer key: {e}"
                    )
                    break
    else:
        chain_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot validate chain: dossier validation failed"
        )

    # -------------------------------------------------------------------------
    # Phase 9: Revocation Checking (§5.1.1-2.9)
    # -------------------------------------------------------------------------
    # revocation_clear is a REQUIRED child of dossier_verified per §3.3B
    revocation_claim = ClaimBuilder("revocation_clear")
    revoked_saids: List[str] = []

    if dag is not None:
        # Check revocation for all credentials in dossier
        # Pass raw_dossier for inline TEL parsing (Phase 9.4)
        revocation_claim, revoked_saids = await check_dossier_revocations(
            dag,
            raw_dossier=raw_dossier,
            oobi_url=passport.header.kid if passport else None
        )
        # Emit CREDENTIAL_REVOKED errors for each revoked credential
        for revoked_said in revoked_saids:
            errors.append(ErrorDetail(
                code=ErrorCode.CREDENTIAL_REVOKED,
                message=f"Credential {revoked_said[:20]}... is revoked",
                recoverable=ERROR_RECOVERABILITY.get(ErrorCode.CREDENTIAL_REVOKED, False)
            ))
    else:
        # Dossier failed - revocation check is INDETERMINATE
        revocation_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot check revocation: dossier validation failed"
        )

    # -------------------------------------------------------------------------
    # Sprint 15: Authorization Validation (§5A Steps 10-11)
    # -------------------------------------------------------------------------
    # authorization_valid is a REQUIRED child of caller_authorised per §3.3B
    # It has party_authorized and tn_rights_valid as REQUIRED children
    authorization_claim = ClaimBuilder("authorization_valid")
    party_claim = ClaimBuilder("party_authorized")
    tn_rights_claim = ClaimBuilder("tn_rights_valid")

    if dag is not None and passport is not None and not passport_fatal:
        # Extract orig.tn from passport (now an array with single element per §4.2)
        orig_tn = None
        if passport.payload.orig and isinstance(passport.payload.orig, dict):
            tn_array = passport.payload.orig.get("tn")
            if isinstance(tn_array, list) and len(tn_array) == 1:
                orig_tn = tn_array[0]

        if orig_tn:
            # Extract signer AID from kid
            try:
                pss_signer_aid_for_auth = _extract_aid_from_kid(passport.header.kid)

                # Build authorization context
                auth_context = AuthorizationContext(
                    pss_signer_aid=pss_signer_aid_for_auth,
                    orig_tn=orig_tn,
                    dossier_acdcs=dossier_acdcs,
                )

                # Validate authorization
                auth_party_claim, auth_tn_claim = validate_authorization(auth_context)

                # Convert AuthorizationClaimBuilder to verify.py ClaimBuilder
                party_claim.status = auth_party_claim.status
                party_claim.reasons = auth_party_claim.reasons
                party_claim.evidence = auth_party_claim.evidence

                tn_rights_claim.status = auth_tn_claim.status
                tn_rights_claim.reasons = auth_tn_claim.reasons
                tn_rights_claim.evidence = auth_tn_claim.evidence

                # Add errors for authorization failures
                if auth_party_claim.status == ClaimStatus.INVALID:
                    errors.append(ErrorDetail(
                        code=ErrorCode.AUTHORIZATION_FAILED,
                        message=auth_party_claim.reasons[0] if auth_party_claim.reasons else "Party authorization failed",
                        recoverable=ERROR_RECOVERABILITY.get(ErrorCode.AUTHORIZATION_FAILED, False),
                    ))
                if auth_tn_claim.status == ClaimStatus.INVALID:
                    errors.append(ErrorDetail(
                        code=ErrorCode.TN_RIGHTS_INVALID,
                        message=auth_tn_claim.reasons[0] if auth_tn_claim.reasons else "TN rights validation failed",
                        recoverable=ERROR_RECOVERABILITY.get(ErrorCode.TN_RIGHTS_INVALID, False),
                    ))

            except ResolutionFailedError as e:
                party_claim.fail(ClaimStatus.INDETERMINATE, f"Cannot extract signer AID: {e}")
                tn_rights_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: signer AID extraction failed")
        else:
            party_claim.fail(ClaimStatus.INVALID, "PASSporT missing orig.tn")
            tn_rights_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate TN rights without orig.tn")
            errors.append(ErrorDetail(
                code=ErrorCode.AUTHORIZATION_FAILED,
                message="PASSporT missing orig.tn field",
                recoverable=False,
            ))
    else:
        # Dependencies failed
        if dag is None:
            party_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: dossier failed")
            tn_rights_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: dossier failed")
        else:
            party_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: passport failed")
            tn_rights_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: passport failed")

    # -------------------------------------------------------------------------
    # Phase 13: SIP Contextual Alignment (§5A Step 2)
    # -------------------------------------------------------------------------
    # context_aligned is REQUIRED or OPTIONAL per policy (default: OPTIONAL)
    from app.core.config import (
        CONTEXT_ALIGNMENT_REQUIRED,
        SIP_TIMING_TOLERANCE_SECONDS,
        ACCEPTED_GOALS,
        REJECT_UNKNOWN_GOALS,
        GEO_CONSTRAINTS_ENFORCED,
    )

    sip_context = req.context.sip if req.context else None
    # Sprint 18 fix A1/A2: Pass config values for context requirement and timing tolerance
    context_claim = verify_sip_context_alignment(
        passport,
        sip_context,
        timing_tolerance=SIP_TIMING_TOLERANCE_SECONDS,
        context_required=CONTEXT_ALIGNMENT_REQUIRED,
    )

    # Add errors for context alignment failures
    if context_claim.status == ClaimStatus.INVALID:
        errors.append(ErrorDetail(
            code=ErrorCode.CONTEXT_MISMATCH,
            message=context_claim.reasons[0] if context_claim.reasons else "Context alignment failed",
            recoverable=ERROR_RECOVERABILITY.get(ErrorCode.CONTEXT_MISMATCH, False),
        ))

    # -------------------------------------------------------------------------
    # Phase 11: Brand Verification (§5A Step 12)
    # -------------------------------------------------------------------------
    # brand_verified is REQUIRED when card is present (failures propagate)
    brand_claim = None
    if passport and getattr(passport.payload, "card", None):
        # Sprint 18 fix A3: Find DE credential for the signer's delegation chain
        # Using signer AID ensures we get the correct DE when multiple DEs exist
        de_credential = None
        if dag is not None and pss_signer_aid:
            de_credential = _find_signer_de_credential(dossier_acdcs, pss_signer_aid)
            if de_credential is None:
                # Fallback to first DE if signer-specific not found (no delegation case)
                de_credential = _find_de_credential(dossier_acdcs)

        brand_claim = verify_brand(passport, dossier_acdcs if dag else {}, de_credential)

        # Add errors for brand verification failures
        if brand_claim and brand_claim.status == ClaimStatus.INVALID:
            errors.append(ErrorDetail(
                code=ErrorCode.BRAND_CREDENTIAL_INVALID,
                message=brand_claim.reasons[0] if brand_claim.reasons else "Brand verification failed",
                recoverable=ERROR_RECOVERABILITY.get(ErrorCode.BRAND_CREDENTIAL_INVALID, False),
            ))

    # -------------------------------------------------------------------------
    # Phase 11: Business Logic Verification (§5A Step 13)
    # -------------------------------------------------------------------------
    # business_logic_verified is REQUIRED when goal is present (failures propagate)
    business_claim = None
    if passport and getattr(passport.payload, "goal", None):
        from datetime import datetime, timezone
        policy = GoalPolicyConfig(
            accepted_goals=ACCEPTED_GOALS,
            reject_unknown=REJECT_UNKNOWN_GOALS,
            geo_enforced=GEO_CONSTRAINTS_ENFORCED,
        )

        # Sprint 18 fix A3: Find DE credential for the signer's delegation chain
        # Using signer AID ensures we get the correct DE when multiple DEs exist
        de_credential = None
        if dag is not None and pss_signer_aid:
            de_credential = _find_signer_de_credential(dossier_acdcs, pss_signer_aid)
            if de_credential is None:
                # Fallback to first DE if signer-specific not found (no delegation case)
                de_credential = _find_de_credential(dossier_acdcs)

        # No caller_geo available currently - results in INDETERMINATE if geo enforced
        business_claim = verify_business_logic(
            passport,
            dossier_acdcs if dag else {},
            de_credential,
            policy,
            call_time=datetime.now(timezone.utc),
            caller_geo=None,  # GeoIP not yet implemented
        )

        # Add errors for business logic failures
        if business_claim and business_claim.status == ClaimStatus.INVALID:
            errors.append(ErrorDetail(
                code=ErrorCode.GOAL_REJECTED,
                message=business_claim.reasons[0] if business_claim.reasons else "Goal rejected by policy",
                recoverable=ERROR_RECOVERABILITY.get(ErrorCode.GOAL_REJECTED, False),
            ))

    # -------------------------------------------------------------------------
    # Phase 6: Build Claim Tree
    # -------------------------------------------------------------------------
    passport_node = passport_claim.build()
    chain_node = chain_claim.build()
    revocation_node = revocation_claim.build()

    # dossier_verified has chain_verified and revocation_clear as REQUIRED children per §3.3B
    # First build with original dossier status, then propagate child status
    dossier_node_temp = dossier_claim.build(children=[
        ChildLink(required=True, node=chain_node),
        ChildLink(required=True, node=revocation_node),
    ])
    # Propagate status from revocation_clear to dossier_verified per §3.3A
    dossier_effective_status = propagate_status(dossier_node_temp)
    dossier_node = ClaimNode(
        name=dossier_node_temp.name,
        status=dossier_effective_status,
        reasons=dossier_node_temp.reasons,
        evidence=dossier_node_temp.evidence,
        children=dossier_node_temp.children,
    )

    # Build authorization_valid with party_authorized and tn_rights_valid as REQUIRED children
    # Per §3.3B, authorization_valid is a REQUIRED child of caller_authorised
    party_node = party_claim.build()
    tn_rights_node = tn_rights_claim.build()
    authorization_node_temp = authorization_claim.build(children=[
        ChildLink(required=True, node=party_node),
        ChildLink(required=True, node=tn_rights_node),
    ])
    # Propagate status from children to authorization_valid per §3.3A
    authorization_effective_status = propagate_status(authorization_node_temp)
    authorization_node = ClaimNode(
        name=authorization_node_temp.name,
        status=authorization_effective_status,
        reasons=authorization_node_temp.reasons,
        evidence=authorization_node_temp.evidence,
        children=authorization_node_temp.children,
    )

    # Build context_aligned node from SIP context verification
    # context_aligned is REQUIRED or OPTIONAL per CONTEXT_ALIGNMENT_REQUIRED
    context_node = ClaimNode(
        name=context_claim.name,
        status=context_claim.status,
        reasons=context_claim.reasons,
        evidence=context_claim.evidence,
        children=[],
    )

    # Build root claim children list
    root_children = [
        ChildLink(required=True, node=passport_node),
        ChildLink(required=True, node=dossier_node),
        ChildLink(required=True, node=authorization_node),
        ChildLink(required=CONTEXT_ALIGNMENT_REQUIRED, node=context_node),
    ]

    # Add brand_verified node if card was present (REQUIRED when present)
    if brand_claim is not None:
        brand_node = ClaimNode(
            name=brand_claim.name,
            status=brand_claim.status,
            reasons=brand_claim.reasons,
            evidence=brand_claim.evidence,
            children=[],
        )
        root_children.append(ChildLink(required=True, node=brand_node))

    # Add business_logic_verified node if goal was present (REQUIRED when present)
    if business_claim is not None:
        business_node = ClaimNode(
            name=business_claim.name,
            status=business_claim.status,
            reasons=business_claim.reasons,
            evidence=business_claim.evidence,
            children=[],
        )
        root_children.append(ChildLink(required=True, node=business_node))

    # Build root claim with children
    root_claim = ClaimNode(
        name="caller_authorised",
        status=ClaimStatus.VALID,  # Will be updated by propagation
        reasons=[],
        evidence=[],
        children=root_children,
    )

    # Use propagate_status uniformly per reviewer feedback
    # This handles the status computation correctly for any tree structure
    root_status = propagate_status(root_claim)

    # Create final root with computed status
    root_claim = ClaimNode(
        name="caller_authorised",
        status=root_status,
        reasons=[],
        evidence=[],
        children=root_children,
    )

    claims = [root_claim]
    overall_status = derive_overall_status(claims, errors if errors else None)

    # Convert ToIP warnings from dag to API response format
    toip_warnings = None
    if dag and dag.warnings:
        toip_warnings = [
            ToIPWarningDetail(
                code=w.code.value,
                message=w.message,
                said=w.said,
                field_path=w.field_path,
            )
            for w in dag.warnings
        ]

    # Build issuer identity map from dossier credentials
    issuer_identities = None
    if dag is not None and dag.nodes:
        from .identity import build_issuer_identity_map, get_wellknown_identity
        from .acdc.models import ACDC

        # Convert DAG nodes to ACDC list for identity extraction
        acdcs = [
            ACDC(
                version=node.raw.get("v", ""),
                said=said,
                issuer_aid=node.issuer,
                schema_said=node.schema,
                attributes=node.attributes,
                edges=node.edges,
                rules=node.rules,
                raw=node.raw,
            )
            for said, node in dag.nodes.items()
        ]
        identity_map = build_issuer_identity_map(acdcs)

        # Include delegation chain AIDs if available
        if delegation_chain_data and delegation_chain_data.chain:
            for chain_node in delegation_chain_data.chain:
                if chain_node.aid not in identity_map:
                    # Check well-known registry for delegation chain AIDs
                    wk = get_wellknown_identity(chain_node.aid)
                    if wk:
                        identity_map[chain_node.aid] = wk

        if identity_map:
            issuer_identities = {
                aid: IssuerIdentityInfo(
                    aid=aid,
                    legal_name=ident.legal_name,
                    lei=ident.lei,
                    source_said=ident.source_said,
                    identity_source="dossier" if ident.source_said else "wellknown",
                )
                for aid, ident in identity_map.items()
            }

    return request_id, VerifyResponse(
        request_id=request_id,
        overall_status=overall_status,
        claims=claims,
        errors=errors if errors else None,
        has_variant_limitations=has_variant_limitations,
        delegation_chain=delegation_chain_data,
        signer_aid=signer_aid,
        toip_warnings=toip_warnings,
        issuer_identities=issuer_identities,
    )
