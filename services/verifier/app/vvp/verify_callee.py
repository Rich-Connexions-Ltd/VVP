"""VVP Callee Verification per spec §5B.

Sprint 19 - Phase 12: Callee verification validates the called party's identity
and rights. This module implements the 14-step callee verification algorithm
specified in VVP §5B.

Key differences from caller verification (§5A):
- Dialog matching: call-id/cseq validation against SIP INVITE
- Issuer verification: dossier issuer must match PASSporT kid
- TN rights context: validates callee can RECEIVE at the number (not originate)
- Goal overlap: checks goal compatibility between caller and callee (when present)
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .api_models import (
    VerifyCalleeRequest,
    VerifyResponse,
    ClaimNode,
    ClaimStatus,
    ChildLink,
    ErrorDetail,
    ErrorCode,
    ERROR_RECOVERABILITY,
    derive_overall_status,
    CallContext,
)
from .header import parse_vvp_identity, VVPIdentity
from .passport import parse_passport, validate_passport_binding, Passport
from .keri import (
    verify_passport_signature_tier2,
    SignatureInvalidError,
    ResolutionFailedError,
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
from .brand import verify_brand, BrandInfo
from .goal import verify_goal_overlap, GoalPolicyConfig

log = logging.getLogger(__name__)


# =============================================================================
# Claim Builder (shared pattern with verify.py)
# =============================================================================


@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim."""

    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)

    def build(self, children: Optional[List[ChildLink]] = None) -> ClaimNode:
        """Build the final ClaimNode."""
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
    """Convert domain exception to ErrorDetail."""
    code = getattr(exc, "code", ErrorCode.INTERNAL_ERROR)
    message = getattr(exc, "message", str(exc))
    recoverable = ERROR_RECOVERABILITY.get(code, True)
    return ErrorDetail(code=code, message=message, recoverable=recoverable)


# =============================================================================
# Dialog Matching (§5B Step 1)
# =============================================================================


def validate_dialog_match(
    passport: Passport,
    context_call_id: str,
    sip_cseq: int,
) -> ClaimBuilder:
    """Validate call-id and cseq match SIP INVITE per §5B Step 1.

    Per VVP §5.2 (draft-04):
    - "Two new claims are added to the JWT payload: call-id and cseq.
       These MUST contain the values of the Call-ID and CSeq values
       on the preceding SIP INVITE."
    - Missing call-id or cseq in callee passport → INVALID
    - Mismatch with SIP INVITE values → INVALID (DIALOG_MISMATCH)

    Args:
        passport: Parsed callee PASSporT
        context_call_id: call_id from CallContext
        sip_cseq: cseq from SipContext

    Returns:
        ClaimBuilder for dialog_matched claim
    """
    claim = ClaimBuilder("dialog_matched")

    # Extract call-id and cseq from passport payload
    # These are callee-specific claims per VVP §5.2
    passport_call_id = getattr(passport.payload, "call_id", None)
    passport_cseq = getattr(passport.payload, "cseq", None)

    # Check for missing claims in passport
    if passport_call_id is None:
        claim.fail(ClaimStatus.INVALID, "Callee PASSporT missing call-id claim")
        return claim

    if passport_cseq is None:
        claim.fail(ClaimStatus.INVALID, "Callee PASSporT missing cseq claim")
        return claim

    claim.add_evidence(f"passport_call_id:{passport_call_id}")
    claim.add_evidence(f"passport_cseq:{passport_cseq}")

    # Validate call-id match
    if passport_call_id != context_call_id:
        claim.fail(
            ClaimStatus.INVALID,
            f"call-id mismatch: passport '{passport_call_id}' != context '{context_call_id}'",
        )
        return claim

    claim.add_evidence(f"call_id_matched:{context_call_id}")

    # Validate cseq match
    if passport_cseq != sip_cseq:
        claim.fail(
            ClaimStatus.INVALID,
            f"cseq mismatch: passport {passport_cseq} != context {sip_cseq}",
        )
        return claim

    claim.add_evidence(f"cseq_matched:{sip_cseq}")
    return claim


# =============================================================================
# Issuer Verification (§5B Step 9)
# =============================================================================


def validate_issuer_match(
    passport_kid: str,
    dossier_issuer_aid: str,
) -> ClaimBuilder:
    """Validate dossier was signed by AID in passport kid per §5B Step 9.

    Per §5.2-2.9:
    - Dossier issuer AID MUST match AID extracted from passport kid

    Args:
        passport_kid: kid from PASSporT header (OOBI URL or bare AID)
        dossier_issuer_aid: Issuer AID from dossier root credential

    Returns:
        ClaimBuilder for issuer_matched claim
    """
    claim = ClaimBuilder("issuer_matched")

    # Extract AID from kid (which may be OOBI URL or bare AID)
    kid_aid = _extract_aid_from_kid(passport_kid)

    claim.add_evidence(f"kid_aid:{kid_aid[:20]}...")
    claim.add_evidence(f"dossier_issuer:{dossier_issuer_aid[:20]}...")

    if kid_aid != dossier_issuer_aid:
        claim.fail(
            ClaimStatus.INVALID,
            f"Issuer mismatch: kid AID '{kid_aid[:20]}...' != dossier issuer '{dossier_issuer_aid[:20]}...'",
        )
        return claim

    claim.add_evidence("issuer_matched:verified")
    return claim


def _extract_aid_from_kid(kid: str) -> str:
    """Extract AID from kid (OOBI URL or bare AID).

    Per §4.2, kid SHOULD be an OOBI URL. This function extracts the AID
    from either format for issuer verification.

    Args:
        kid: PASSporT kid field (bare AID or OOBI URL)

    Returns:
        The extracted AID
    """
    if kid.startswith(("http://", "https://")):
        # Extract AID from OOBI URL path
        parsed = urlparse(kid)
        path_parts = parsed.path.strip("/").split("/")

        # Find AID after 'oobi' in path
        for i, part in enumerate(path_parts):
            if part == "oobi" and i + 1 < len(path_parts):
                aid = path_parts[i + 1]
                if aid and aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                    return aid

        # If OOBI URL but no AID found, return the URL as-is (will fail match)
        return kid

    # Bare AID - return as-is
    return kid


# =============================================================================
# Model Conversion Helpers
# =============================================================================


def _convert_dag_to_acdcs(dag: DossierDAG) -> Dict[str, "ACDC"]:
    """Convert DossierDAG nodes to ACDC format for chain validation."""
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


def _get_dossier_root_issuer(dag: DossierDAG) -> Optional[str]:
    """Get the issuer AID of the dossier root credential.

    Per §5B Step 9, the dossier issuer must match the passport kid.

    Args:
        dag: Parsed DossierDAG

    Returns:
        Issuer AID of the root credential, or None if not found
    """
    if dag.root_said and dag.root_said in dag.nodes:
        return dag.nodes[dag.root_said].issuer
    return None


# =============================================================================
# Callee TN Rights Validation (§5B Step 12)
# =============================================================================


def validate_callee_tn_rights(
    callee_tn: str,
    dossier_acdcs: Dict[str, "ACDC"],
    accountable_party_aid: Optional[str],
) -> ClaimBuilder:
    """Validate callee has right to RECEIVE calls at this number per §5B Step 12.

    Per VVP §5.2 (draft-04):
    - "A callee's dossier might differ in one minor way that doesn't
       affect the schema: it could prove the right to use a TN that
       has a DNO flag."
    - Callee's TNAlloc proves right to receive, not originate
    - DNO (Do Not Originate) flag may be present

    This is similar to caller TN rights validation but checks the dest.tn
    (To URI) instead of orig.tn (From URI). Rights must be bound to the
    accountable party (APE issuee), not just any signer.

    Args:
        callee_tn: Phone number from SIP To URI (E.164 format)
        dossier_acdcs: Dict mapping SAID to ACDC objects
        accountable_party_aid: AID of the accountable party (APE issuee)

    Returns:
        ClaimBuilder for tn_rights_valid claim
    """
    from .authorization import _find_credentials_by_type, _get_issuee
    from .tn_utils import TNParseError, is_subset, parse_tn_allocation

    claim = ClaimBuilder("tn_rights_valid")
    claim.add_evidence(f"callee_tn:{callee_tn}")

    # If no accountable_party_aid, we cannot bind TN rights
    if not accountable_party_aid:
        claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot validate TN rights without accountable party AID"
        )
        return claim

    if not dossier_acdcs:
        claim.fail(ClaimStatus.INDETERMINATE, "No credentials in dossier to validate TN rights")
        return claim

    # Parse callee TN using proper E.164 validation
    try:
        callee_ranges = parse_tn_allocation(callee_tn)
    except TNParseError as e:
        claim.fail(
            ClaimStatus.INVALID,
            f"Invalid callee TN format: {e}"
        )
        return claim

    # Find TNAlloc credentials in dossier
    tnalloc_credentials = _find_credentials_by_type(dossier_acdcs, "TNAlloc")

    if not tnalloc_credentials:
        claim.fail(
            ClaimStatus.INVALID,
            f"No TNAlloc credential found for callee TN {callee_tn}",
        )
        return claim

    claim.add_evidence(f"tnalloc_count:{len(tnalloc_credentials)}")

    # Filter to TNAlloc credentials bound to the accountable party
    bound_tnallocs = []
    for tnalloc in tnalloc_credentials:
        issuee = _get_issuee(tnalloc)
        if issuee == accountable_party_aid:
            bound_tnallocs.append(tnalloc)

    if not bound_tnallocs:
        claim.fail(
            ClaimStatus.INVALID,
            f"No TNAlloc credential issued to accountable party {accountable_party_aid[:20]}..."
        )
        claim.add_evidence(f"accountable_party:{accountable_party_aid[:16]}...")
        return claim

    claim.add_evidence(f"bound_tnalloc_count:{len(bound_tnallocs)}")

    # Check if any bound TNAlloc covers the callee TN
    for tnalloc in bound_tnallocs:
        # Extract TN allocation from attributes
        tn_data = (
            tnalloc.attributes.get("tn") if tnalloc.attributes else None
        ) or (
            tnalloc.attributes.get("phone") if tnalloc.attributes else None
        ) or (
            tnalloc.attributes.get("allocation") if tnalloc.attributes else None
        )

        if not tn_data:
            continue  # Skip credentials without TN data

        try:
            alloc_ranges = parse_tn_allocation(tn_data)
        except TNParseError:
            continue  # Skip malformed allocations

        # Check if callee_tn is covered by this allocation using proper subset check
        if is_subset(callee_ranges, alloc_ranges):
            claim.add_evidence(f"tnalloc_said:{tnalloc.said[:16]}...")
            claim.add_evidence(f"issuee_match:{accountable_party_aid[:16]}...")
            claim.add_evidence("covered:true")

            # Check for DNO (Do Not Originate) flag - valid for callee receiving
            dno_flag = tnalloc.attributes.get("dno") if tnalloc.attributes else None
            if dno_flag:
                claim.add_evidence("dno_flag:present(valid_for_receive)")

            return claim

    # No bound TNAlloc covers the callee TN
    claim.fail(
        ClaimStatus.INVALID,
        f"No TNAlloc credential for accountable party covers callee TN {callee_tn}"
    )
    claim.add_evidence(f"accountable_party:{accountable_party_aid[:16]}...")

    return claim


# =============================================================================
# Status Propagation
# =============================================================================


def _worse_status(a: ClaimStatus, b: ClaimStatus) -> ClaimStatus:
    """Return the worse of two statuses."""
    if a == ClaimStatus.INVALID or b == ClaimStatus.INVALID:
        return ClaimStatus.INVALID
    if a == ClaimStatus.INDETERMINATE or b == ClaimStatus.INDETERMINATE:
        return ClaimStatus.INDETERMINATE
    return ClaimStatus.VALID


def propagate_status(node: ClaimNode) -> ClaimStatus:
    """Compute effective status considering REQUIRED children per §3.3A."""
    worst = node.status
    for link in node.children:
        if link.required:
            child_status = propagate_status(link.node)
            worst = _worse_status(worst, child_status)
    return worst


# =============================================================================
# Main Callee Verification Orchestrator
# =============================================================================


async def verify_callee_vvp(
    vvp_identity_raw: str,
    passport_jwt: str,
    context: CallContext,
    caller_passport_jwt: Optional[str] = None,
) -> Tuple[str, VerifyResponse]:
    """Orchestrate VVP callee verification per spec §5B.

    This implements the 14-step callee verification algorithm:
    1. Dialog matching (call-id, cseq)
    2. Timing alignment (iat validation)
    3. Expiration analysis
    4. Key identifier extraction (kid)
    5. Signature verification
    6. Dossier fetch and validation
    7. ACDC chain validation
    8. Revocation status check
    9. Issuer verification (dossier issuer == kid)
    10. Phone number rights (callee receiving)
    11. Brand attributes verification (REQUIRED when card present)
    12. Goal overlap verification (REQUIRED when both goals present)

    Args:
        vvp_identity_raw: Raw VVP-Identity header value
        passport_jwt: Callee's PASSporT JWT
        context: Call context with call_id and sip.cseq
        caller_passport_jwt: Optional caller's passport for goal overlap

    Returns:
        Tuple of (request_id, VerifyResponse)
    """
    request_id = str(uuid.uuid4())
    errors: List[ErrorDetail] = []

    passport_claim = ClaimBuilder("passport_verified")
    dossier_claim = ClaimBuilder("dossier_verified")

    # -------------------------------------------------------------------------
    # Parse VVP-Identity Header
    # -------------------------------------------------------------------------
    vvp_identity: Optional[VVPIdentity] = None
    try:
        vvp_identity = parse_vvp_identity(vvp_identity_raw)
    except VVPIdentityError as e:
        errors.append(to_error_detail(e))
        return request_id, VerifyResponse(
            request_id=request_id,
            overall_status=ClaimStatus.INVALID,
            claims=None,
            errors=errors,
        )

    # -------------------------------------------------------------------------
    # Parse Callee PASSporT
    # -------------------------------------------------------------------------
    passport: Optional[Passport] = None
    passport_fatal = False

    try:
        passport = parse_passport(passport_jwt)
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
    # Dialog Matching (§5B Step 1) - CALLEE SPECIFIC
    # -------------------------------------------------------------------------
    dialog_claim = ClaimBuilder("dialog_matched")

    if passport and not passport_fatal:
        dialog_claim = validate_dialog_match(
            passport,
            context.call_id,
            context.sip.cseq if context.sip else 0,
        )

        if dialog_claim.status == ClaimStatus.INVALID:
            errors.append(
                ErrorDetail(
                    code=ErrorCode.DIALOG_MISMATCH,
                    message=dialog_claim.reasons[0] if dialog_claim.reasons else "Dialog mismatch",
                    recoverable=False,
                )
            )
            passport_fatal = True
    else:
        dialog_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: passport failed")

    # -------------------------------------------------------------------------
    # Timing Validation (§5B Step 2-3) - Per approved plan claim tree
    # -------------------------------------------------------------------------
    timing_claim = ClaimBuilder("timing_valid")

    if passport and not passport_fatal:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        iat = getattr(passport.payload, "iat", None)
        exp = getattr(passport.payload, "exp", None)

        if iat:
            timing_claim.add_evidence(f"iat:{iat}")
            # Check iat is not in the future (with 5s tolerance per §5.2A)
            if iat > now.timestamp() + 5:
                timing_claim.fail(ClaimStatus.INVALID, "PASSporT iat is in the future")
            else:
                timing_claim.add_evidence("iat_valid")
        else:
            timing_claim.fail(ClaimStatus.INVALID, "PASSporT missing iat claim")

        if exp:
            timing_claim.add_evidence(f"exp:{exp}")
            if exp < now.timestamp():
                timing_claim.fail(ClaimStatus.INVALID, "PASSporT has expired")
            else:
                timing_claim.add_evidence("not_expired")
        else:
            # exp is optional per spec
            timing_claim.add_evidence("exp:absent(optional)")
    else:
        timing_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: passport failed")

    # -------------------------------------------------------------------------
    # Signature Verification (§5B Step 5-6)
    # -------------------------------------------------------------------------
    signature_claim = ClaimBuilder("signature_valid")

    if passport and not passport_fatal:
        kid = passport.header.kid
        is_oobi_kid = kid.startswith(("http://", "https://"))

        try:
            if is_oobi_kid:
                await verify_passport_signature_tier2(
                    passport,
                    oobi_url=kid,
                    _allow_test_mode=False,
                )
                signature_claim.add_evidence("tier2_verified")
                passport_claim.add_evidence("signature_valid,tier2")
            else:
                raise ResolutionFailedError(
                    f"kid must be an OOBI URL per §4.2, got bare AID: {kid[:20]}..."
                )
        except SignatureInvalidError as e:
            errors.append(to_error_detail(e))
            signature_claim.fail(ClaimStatus.INVALID, e.message)
            passport_claim.fail(ClaimStatus.INVALID, e.message)
            passport_fatal = True
        except ResolutionFailedError as e:
            errors.append(to_error_detail(e))
            if "must be an OOBI" in str(e):
                signature_claim.fail(ClaimStatus.INVALID, e.message)
                passport_claim.fail(ClaimStatus.INVALID, e.message)
                passport_fatal = True
            else:
                signature_claim.fail(ClaimStatus.INDETERMINATE, e.message)
                passport_claim.fail(ClaimStatus.INDETERMINATE, e.message)
    else:
        signature_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: passport failed")

    # -------------------------------------------------------------------------
    # Dossier Fetch and Validation (§5B Steps 7-8)
    # -------------------------------------------------------------------------
    import time as _time
    raw_dossier: Optional[bytes] = None
    dag: Optional[DossierDAG] = None
    acdc_signatures: Dict[str, bytes] = {}
    dossier_acdcs: Dict[str, "ACDC"] = {}
    dossier_cache = get_dossier_cache()
    cache_hit = False

    # Per approved plan: structure_valid and acdc_signatures_valid are REQUIRED children
    structure_claim = ClaimBuilder("structure_valid")
    acdc_sigs_claim = ClaimBuilder("acdc_signatures_valid")

    if vvp_identity and not passport_fatal:
        evd_url = vvp_identity.evd

        # §5.1.1-2.7: Check cache first (URL available pre-fetch)
        cached = await dossier_cache.get(evd_url)
        if cached:
            # Cache hit - use cached data
            cache_hit = True
            dag = cached.dag
            raw_dossier = cached.raw_content
            dossier_claim.add_evidence(f"cache_hit={evd_url[:40]}...")
            dossier_claim.add_evidence(f"dag_valid,root={dag.root_said}")
            dossier_acdcs = _convert_dag_to_acdcs(dag)
            structure_claim.add_evidence(f"nodes:{len(dag.nodes)}")
            structure_claim.add_evidence(f"root_said:{dag.root_said[:16]}...")
            structure_claim.add_evidence("cache_hit")
            acdc_sigs_claim.add_evidence("cache_hit")
            log.info(f"Dossier cache hit: {evd_url[:50]}...")
        else:
            # Cache miss - fetch from network
            try:
                raw_dossier = await fetch_dossier(evd_url)
                dossier_claim.add_evidence(f"fetched={evd_url[:40]}...")
            except FetchError as e:
                errors.append(to_error_detail(e))
                dossier_claim.fail(ClaimStatus.INDETERMINATE, e.message)
                structure_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: dossier fetch failed")
                acdc_sigs_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: dossier fetch failed")

            if raw_dossier is not None:
                try:
                    nodes, acdc_signatures = parse_dossier(raw_dossier)
                    dag = build_dag(nodes)
                    validate_dag(dag)
                    dossier_claim.add_evidence(f"dag_valid,root={dag.root_said}")
                    dossier_acdcs = _convert_dag_to_acdcs(dag)
                    structure_claim.add_evidence(f"nodes:{len(nodes)}")
                    structure_claim.add_evidence(f"root_said:{dag.root_said[:16]}...")

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
                    structure_claim.fail(ClaimStatus.INVALID, e.message)
                    acdc_sigs_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: structure invalid")
                    dag = None

                # Validate ACDC signatures if structure is valid
                if dag is not None and acdc_signatures:
                    acdc_sigs_claim.add_evidence(f"signature_count:{len(acdc_signatures)}")
                    # ACDC signature verification is done as part of chain validation
                    # Mark as valid here; chain_verified will catch any issues
                    acdc_sigs_claim.add_evidence("deferred_to_chain_verification")
                elif dag is not None:
                    acdc_sigs_claim.add_evidence("no_attached_signatures")
    elif passport_fatal:
        dossier_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Skipped due to passport verification failure",
        )
        structure_claim.fail(ClaimStatus.INDETERMINATE, "Skipped due to passport failure")
        acdc_sigs_claim.fail(ClaimStatus.INDETERMINATE, "Skipped due to passport failure")

    # -------------------------------------------------------------------------
    # Chain Verification (reuse from verify.py patterns)
    # -------------------------------------------------------------------------
    chain_claim = ClaimBuilder("chain_verified")

    if dag is not None:
        from app.core.config import TRUSTED_ROOT_AIDS, SCHEMA_VALIDATION_STRICT
        from app.vvp.acdc import validate_credential_chain, ACDCChainInvalid
        from app.vvp.verify import _find_leaf_credentials

        pss_signer_aid = None
        if passport:
            pss_signer_aid = _extract_aid_from_kid(passport.header.kid)

        leaf_saids = _find_leaf_credentials(dag, dossier_acdcs)
        chain_claim.add_evidence(f"leaves={len(leaf_saids)}")

        any_chain_valid = False
        chain_errors: List[str] = []

        for leaf_said in leaf_saids:
            leaf_acdc = dossier_acdcs.get(leaf_said)
            if not leaf_acdc:
                chain_errors.append(f"Leaf {leaf_said[:16]}... not in dossier")
                continue

            try:
                result = await validate_credential_chain(
                    acdc=leaf_acdc,
                    trusted_roots=TRUSTED_ROOT_AIDS,
                    dossier_acdcs=dossier_acdcs,
                    pss_signer_aid=pss_signer_aid,
                    validate_schemas=SCHEMA_VALIDATION_STRICT,
                )
                chain_claim.add_evidence(f"chain_valid:{leaf_said[:12]}...,root={result.root_aid[:12]}...")
                any_chain_valid = True
            except ACDCChainInvalid as e:
                chain_errors.append(f"{leaf_said[:16]}...: {str(e)}")

        if not any_chain_valid:
            error_msg = f"No credential chain reaches trusted root: {'; '.join(chain_errors[:3])}"
            errors.append(
                ErrorDetail(
                    code=ErrorCode.DOSSIER_GRAPH_INVALID,
                    message=error_msg,
                    recoverable=False,
                )
            )
            chain_claim.fail(ClaimStatus.INVALID, error_msg)
    else:
        chain_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot validate chain: dossier validation failed",
        )

    # -------------------------------------------------------------------------
    # Revocation Checking (§5B Step 8 - reuse from verify.py)
    # -------------------------------------------------------------------------
    from .verify import check_dossier_revocations

    revocation_claim = ClaimBuilder("revocation_clear")
    revoked_saids: List[str] = []

    if dag is not None:
        revocation_claim, revoked_saids = await check_dossier_revocations(
            dag,
            raw_dossier=raw_dossier,
            oobi_url=passport.header.kid if passport else None,
        )
        for revoked_said in revoked_saids:
            errors.append(
                ErrorDetail(
                    code=ErrorCode.CREDENTIAL_REVOKED,
                    message=f"Credential {revoked_said[:20]}... is revoked",
                    recoverable=False,
                )
            )
    else:
        revocation_claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot check revocation: dossier validation failed",
        )

    # -------------------------------------------------------------------------
    # Issuer Verification (§5B Step 9) - CALLEE SPECIFIC
    # -------------------------------------------------------------------------
    issuer_claim = ClaimBuilder("issuer_matched")

    if dag is not None and passport is not None:
        dossier_issuer = _get_dossier_root_issuer(dag)
        if dossier_issuer:
            issuer_claim = validate_issuer_match(passport.header.kid, dossier_issuer)
            if issuer_claim.status == ClaimStatus.INVALID:
                errors.append(
                    ErrorDetail(
                        code=ErrorCode.ISSUER_MISMATCH,
                        message=issuer_claim.reasons[0] if issuer_claim.reasons else "Issuer mismatch",
                        recoverable=False,
                    )
                )
        else:
            issuer_claim.fail(ClaimStatus.INDETERMINATE, "Could not extract dossier issuer")
    else:
        issuer_claim.fail(ClaimStatus.INDETERMINATE, "Cannot verify: dossier or passport failed")

    # -------------------------------------------------------------------------
    # Callee TN Rights (§5B Step 12) - CALLEE SPECIFIC
    # -------------------------------------------------------------------------
    tn_rights_claim = ClaimBuilder("tn_rights_valid")

    # Determine accountable party AID from APE credential
    # Per §5A Step 10/11 patterns, accountable party is the APE issuee
    accountable_party_aid = None
    if dag is not None and dossier_acdcs:
        from .authorization import _find_credentials_by_type, _get_issuee

        ape_credentials = _find_credentials_by_type(dossier_acdcs, "APE")
        if ape_credentials:
            # Use first APE's issuee as accountable party
            # In delegation scenarios, chain validation ensures this is correct
            accountable_party_aid = _get_issuee(ape_credentials[0])
            tn_rights_claim.add_evidence(f"accountable_party:{accountable_party_aid[:16]}..." if accountable_party_aid else "accountable_party:none")

    if dag is not None and passport is not None and context.sip is not None:
        # Extract callee TN from SIP To URI
        from .sip_context import extract_tn_from_sip_uri

        callee_tn = extract_tn_from_sip_uri(context.sip.to_uri)

        if callee_tn:
            tn_rights_claim = validate_callee_tn_rights(callee_tn, dossier_acdcs, accountable_party_aid)
            if tn_rights_claim.status == ClaimStatus.INVALID:
                errors.append(
                    ErrorDetail(
                        code=ErrorCode.TN_RIGHTS_INVALID,
                        message=tn_rights_claim.reasons[0] if tn_rights_claim.reasons else "TN rights invalid",
                        recoverable=False,
                    )
                )
        else:
            tn_rights_claim.fail(ClaimStatus.INVALID, "Could not extract callee TN from To URI")
    else:
        tn_rights_claim.fail(ClaimStatus.INDETERMINATE, "Cannot validate: dependencies failed")

    # -------------------------------------------------------------------------
    # Brand Verification (§5B Step 11 - REQUIRED when card present)
    # -------------------------------------------------------------------------
    # Sprint 44: Also extract brand info for SIP header population
    brand_claim = None
    brand_info = None
    if passport and getattr(passport.payload, "card", None):
        from .verify import _find_signer_de_credential

        de_credential = None
        signer_aid = _extract_aid_from_kid(passport.header.kid)
        if dag is not None:
            de_credential = _find_signer_de_credential(dossier_acdcs, signer_aid)

        # Sprint 44: verify_brand now returns (claim, brand_info) tuple
        brand_claim, brand_info = verify_brand(passport, dossier_acdcs if dag else {}, de_credential)

        if brand_claim and brand_claim.status == ClaimStatus.INVALID:
            errors.append(
                ErrorDetail(
                    code=ErrorCode.BRAND_CREDENTIAL_INVALID,
                    message=brand_claim.reasons[0] if brand_claim.reasons else "Brand verification failed",
                    recoverable=False,
                )
            )

    # -------------------------------------------------------------------------
    # Goal Overlap Verification (§5B Step 14 - REQUIRED when both goals present)
    # -------------------------------------------------------------------------
    goal_overlap_claim = None
    caller_passport: Optional[Passport] = None

    if caller_passport_jwt:
        try:
            caller_passport = parse_passport(caller_passport_jwt)
        except PassportError:
            pass  # Caller passport parse failure - goal overlap check skipped

    if passport:
        goal_overlap_claim = verify_goal_overlap(passport, caller_passport)

        if goal_overlap_claim and goal_overlap_claim.status == ClaimStatus.INVALID:
            errors.append(
                ErrorDetail(
                    code=ErrorCode.GOAL_REJECTED,
                    message=goal_overlap_claim.reasons[0] if goal_overlap_claim.reasons else "Goal overlap check failed",
                    recoverable=False,
                )
            )

    # -------------------------------------------------------------------------
    # Build Claim Tree
    # -------------------------------------------------------------------------
    # Build passport_verified with dialog_matched, timing_valid, signature_valid as REQUIRED children
    dialog_node = dialog_claim.build()
    timing_node = timing_claim.build()
    signature_node = signature_claim.build()

    passport_node_temp = passport_claim.build(children=[
        ChildLink(required=True, node=dialog_node),
        ChildLink(required=True, node=timing_node),
        ChildLink(required=True, node=signature_node),
    ])
    passport_effective_status = propagate_status(passport_node_temp)
    passport_node = ClaimNode(
        name=passport_node_temp.name,
        status=passport_effective_status,
        reasons=passport_node_temp.reasons,
        evidence=passport_node_temp.evidence,
        children=passport_node_temp.children,
    )

    # Build dossier_verified with structure_valid, acdc_signatures_valid, chain, revocation, and issuer as REQUIRED children
    structure_node = structure_claim.build()
    acdc_sigs_node = acdc_sigs_claim.build()
    chain_node = chain_claim.build()
    revocation_node = revocation_claim.build()
    issuer_node = issuer_claim.build()

    dossier_node_temp = dossier_claim.build(children=[
        ChildLink(required=True, node=structure_node),
        ChildLink(required=True, node=acdc_sigs_node),
        ChildLink(required=True, node=chain_node),
        ChildLink(required=True, node=revocation_node),
        ChildLink(required=True, node=issuer_node),
    ])
    dossier_effective_status = propagate_status(dossier_node_temp)
    dossier_node = ClaimNode(
        name=dossier_node_temp.name,
        status=dossier_effective_status,
        reasons=dossier_node_temp.reasons,
        evidence=dossier_node_temp.evidence,
        children=dossier_node_temp.children,
    )

    # Build tn_rights_valid node
    tn_rights_node = tn_rights_claim.build()

    # Build root claim children list
    root_children = [
        ChildLink(required=True, node=passport_node),
        ChildLink(required=True, node=dossier_node),
        ChildLink(required=True, node=tn_rights_node),
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

    # Add goal_overlap_verified node if both goals present (REQUIRED when present)
    if goal_overlap_claim is not None:
        goal_overlap_node = ClaimNode(
            name=goal_overlap_claim.name,
            status=goal_overlap_claim.status,
            reasons=goal_overlap_claim.reasons,
            evidence=goal_overlap_claim.evidence,
            children=[],
        )
        root_children.append(ChildLink(required=True, node=goal_overlap_node))

    # Build root claim
    root_claim = ClaimNode(
        name="callee_verified",
        status=ClaimStatus.VALID,
        reasons=[],
        evidence=[],
        children=root_children,
    )

    root_status = propagate_status(root_claim)

    root_claim = ClaimNode(
        name="callee_verified",
        status=root_status,
        reasons=[],
        evidence=[],
        children=root_children,
    )

    claims = [root_claim]
    overall_status = derive_overall_status(claims, errors if errors else None)

    # Sprint 44: Populate brand fields when brand verification succeeded
    response_brand_name = None
    response_brand_logo_url = None
    if brand_info and brand_claim and brand_claim.status == ClaimStatus.VALID:
        response_brand_name = brand_info.brand_name
        response_brand_logo_url = brand_info.brand_logo_url

    return request_id, VerifyResponse(
        request_id=request_id,
        overall_status=overall_status,
        claims=claims,
        errors=errors if errors else None,
        brand_name=response_brand_name,
        brand_logo_url=response_brand_logo_url,
    )
