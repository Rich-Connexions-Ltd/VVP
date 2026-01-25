"""VVP Verification orchestration engine per spec §9.

Wires together all verification phases and builds a claim tree
with status propagation per §3.3A.

Phase 6 (Tier 1): Fixed claim tree structure with passport_verified
and dossier_verified as required children of caller_authorised.

Phase 9 (Tier 2): Revocation checking per §5.1.1-2.9. The revocation_clear
claim is a REQUIRED child of dossier_verified per §3.3B.
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
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
)
from .header import parse_vvp_identity, VVPIdentity
from .passport import parse_passport, validate_passport_binding, Passport
from .keri import verify_passport_signature, SignatureInvalidError, ResolutionFailedError
from .dossier import (
    fetch_dossier,
    parse_dossier,
    build_dag,
    validate_dag,
    DossierDAG,
    FetchError,
    ParseError,
    GraphError,
)
from .exceptions import VVPIdentityError, PassportError


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
            validate_passport_binding(passport, vvp_identity)
            passport_claim.add_evidence("binding_valid")
        except PassportError as e:
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True

    # -------------------------------------------------------------------------
    # Phase 4: KERI Signature Verification
    # -------------------------------------------------------------------------
    if passport and not passport_fatal:
        try:
            verify_passport_signature(passport)
            passport_claim.add_evidence("signature_valid")
        except SignatureInvalidError as e:
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True
        except ResolutionFailedError as e:
            errors.append(to_error_detail(e))
            passport_claim.fail(ClaimStatus.INDETERMINATE, e.message)
            # Note: INDETERMINATE is recoverable, so not setting passport_fatal

    # -------------------------------------------------------------------------
    # Phase 5: Dossier Fetch and Validation
    # -------------------------------------------------------------------------
    # Per reviewer feedback: skip dossier fetch if passport has fatal failure
    # This reduces load and provides clearer error diagnostics
    raw_dossier: Optional[bytes] = None
    dag: Optional[DossierDAG] = None

    if vvp_identity and not passport_fatal:
        try:
            raw_dossier = await fetch_dossier(vvp_identity.evd)
            dossier_claim.add_evidence(f"fetched={vvp_identity.evd[:40]}...")
        except FetchError as e:
            errors.append(to_error_detail(e))
            dossier_claim.fail(ClaimStatus.INDETERMINATE, e.message)

        if raw_dossier is not None:
            try:
                nodes = parse_dossier(raw_dossier)
                dag = build_dag(nodes)
                validate_dag(dag)
                dossier_claim.add_evidence(f"dag_valid,root={dag.root_said}")
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
    # Phase 6: Build Claim Tree
    # -------------------------------------------------------------------------
    passport_node = passport_claim.build()
    revocation_node = revocation_claim.build()

    # dossier_verified has revocation_clear as a REQUIRED child per §3.3B
    # First build with original dossier status, then propagate child status
    dossier_node_temp = dossier_claim.build(children=[
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

    # Build root claim with children
    root_claim = ClaimNode(
        name="caller_authorised",
        status=ClaimStatus.VALID,  # Will be updated by propagation
        reasons=[],
        evidence=[],
        children=[
            ChildLink(required=True, node=passport_node),
            ChildLink(required=True, node=dossier_node),
        ],
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
        children=[
            ChildLink(required=True, node=passport_node),
            ChildLink(required=True, node=dossier_node),
        ],
    )

    claims = [root_claim]
    overall_status = derive_overall_status(claims, errors if errors else None)

    return request_id, VerifyResponse(
        request_id=request_id,
        overall_status=overall_status,
        claims=claims,
        errors=errors if errors else None,
    )
