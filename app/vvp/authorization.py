"""Authorization verification for VVP Verifier.

Per VVP Specification §5A Steps 10-11:
- Step 10: Verify originating party is authorized to sign PASSporT
- Step 11: Verify accountable party has TN rights for orig.tn

Implementation:
- Case A (no delegation): OP == AP, verified via APE issuee match
- Case B (with delegation): DE issuee == OP, DE chain terminates at APE
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from common.vvp.models import ACDC
from common.vvp.utils.tn_utils import TNParseError, is_subset, parse_tn_allocation

from app.vvp.api_models import ClaimStatus


@dataclass
class AuthorizationContext:
    """Context for authorization validation.

    Attributes:
        pss_signer_aid: AID extracted from PASSporT kid header.
        orig_tn: E.164 telephone number from passport.payload.orig["tn"].
        dossier_acdcs: All ACDC credentials parsed from the dossier.
    """
    pss_signer_aid: str
    orig_tn: str
    dossier_acdcs: Dict[str, ACDC]


@dataclass
class AuthorizationClaimBuilder:
    """Builder for accumulating claim evidence and status.

    Note: This is a local copy to avoid circular imports with verify.py.
    The interface matches verify.py ClaimBuilder for compatibility.
    verify.py will convert these to proper ClaimNode objects.
    """
    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = None
    evidence: List[str] = None

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []
        if self.evidence is None:
            self.evidence = []

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure with status and reason."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)


def _get_issuee(acdc: ACDC) -> Optional[str]:
    """Extract issuee AID from ACDC attributes.

    Per ACDC spec, the issuee may be in 'i', 'issuee', or 'holder' field.

    Args:
        acdc: The ACDC credential.

    Returns:
        The issuee AID string, or None if not found.
    """
    if not acdc.attributes:
        return None
    return (
        acdc.attributes.get("i") or
        acdc.attributes.get("issuee") or
        acdc.attributes.get("holder")
    )


def _find_credentials_by_type(
    dossier_acdcs: Dict[str, ACDC],
    cred_type: str
) -> List[ACDC]:
    """Find all credentials of a specific type in the dossier.

    Args:
        dossier_acdcs: All credentials from dossier.
        cred_type: Credential type to find (e.g., "APE", "DE", "TNAlloc").

    Returns:
        List of matching credentials.
    """
    return [acdc for acdc in dossier_acdcs.values() if acdc.credential_type == cred_type]


def _find_delegation_target(
    de: ACDC,
    dossier_acdcs: Dict[str, ACDC]
) -> Optional[ACDC]:
    """Find the credential referenced by a DE's delegation edge.

    Per §6.3.4, DE credentials must have a delegation edge pointing to
    either an APE or another DE credential.

    Args:
        de: The DE credential to inspect.
        dossier_acdcs: All credentials in the dossier for edge resolution.

    Returns:
        The target credential (APE or DE), or None if not found.
    """
    if not de.edges:
        return None

    # Check for delegation edge (various naming conventions)
    # Note: "issuer" edge is used by some delegation credentials (e.g., delsig)
    for edge_name, edge_ref in de.edges.items():
        if edge_name.lower() in ('delegation', 'd', 'delegate', 'delegator', 'issuer'):
            # Extract target SAID from edge reference
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get('n') or edge_ref.get('d')

            if target_said and target_said in dossier_acdcs:
                return dossier_acdcs[target_said]

    return None


def _find_ape_referencing_de(
    de_said: str,
    dossier_acdcs: Dict[str, ACDC]
) -> Optional[ACDC]:
    """Find an APE credential that references a DE credential via any edge.

    This handles terminal DEs that don't have their own delegation edge
    but are referenced by the APE (e.g., via "alloc", "delsig" edges).

    Args:
        de_said: The SAID of the DE credential to look for.
        dossier_acdcs: All credentials in the dossier.

    Returns:
        The APE credential that references this DE, or None if not found.
    """
    ape_credentials = _find_credentials_by_type(dossier_acdcs, "APE")

    for ape in ape_credentials:
        if not ape.edges:
            continue

        # Check all edges of the APE for references to this DE
        for edge_name, edge_ref in ape.edges.items():
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get('n') or edge_ref.get('d')

            if target_said == de_said:
                return ape

    return None


def _walk_de_chain(
    starting_de: ACDC,
    dossier_acdcs: Dict[str, ACDC],
    max_depth: int = 10,
) -> Tuple[bool, Optional[ACDC], Optional[str], List[str]]:
    """Walk a single DE chain to find the terminating APE.

    Args:
        starting_de: The DE credential to start walking from.
        dossier_acdcs: All credentials in the dossier for edge resolution.
        max_depth: Maximum chain depth to prevent infinite loops.

    Returns:
        Tuple of (success, APE credential or None, error reason or None, evidence list).
    """
    visited: set = set()
    current = starting_de
    depth = 0
    evidence: List[str] = []

    while depth < max_depth:
        visited.add(current.said)

        # Find delegation target
        target = _find_delegation_target(current, dossier_acdcs)

        if target is None:
            # DE has no delegation edge - check if it's referenced by an APE
            # This handles terminal DEs that are directly linked from the APE
            # (e.g., TN Allocator referenced via APE's "alloc" edge)
            referencing_ape = _find_ape_referencing_de(current.said, dossier_acdcs)
            if referencing_ape:
                evidence.append(f"terminal_de:{current.said[:16]}...")
                evidence.append(f"ape_said:{referencing_ape.said[:16]}...")
                accountable_aid = _get_issuee(referencing_ape)
                if accountable_aid:
                    evidence.append(f"accountable_party:{accountable_aid[:16]}...")
                return (True, referencing_ape, None, evidence)

            return (
                False, None,
                f"DE {current.said[:20]}... delegation edge target not found in dossier",
                evidence
            )

        # Check for cycle
        if target.said in visited:
            return (
                False, None,
                f"Circular delegation detected at {target.said[:20]}...",
                evidence
            )

        # Check if target is APE (chain terminates)
        if target.credential_type == "APE":
            evidence.append(f"ape_said:{target.said[:16]}...")
            accountable_aid = _get_issuee(target)
            if accountable_aid:
                evidence.append(f"accountable_party:{accountable_aid[:16]}...")
            return (True, target, None, evidence)

        # Target is another DE - continue walking
        if target.credential_type == "DE":
            evidence.append(f"de_chain:{target.said[:16]}...")
            current = target
            depth += 1
            continue

        # Unexpected credential type in chain
        return (
            False, None,
            f"Unexpected credential type {target.credential_type} in delegation chain",
            evidence
        )

    # Exceeded max depth without reaching APE
    return (
        False, None,
        f"Delegation chain exceeds maximum depth of {max_depth}",
        evidence
    )


def _verify_delegation_chain(
    ctx: AuthorizationContext,
    matching_des: List[ACDC],
    claim: AuthorizationClaimBuilder,
    max_depth: int = 10,
) -> Tuple[AuthorizationClaimBuilder, Optional[ACDC]]:
    """Validate delegation chain from DE to APE (Case B).

    Per §5A Step 10 Case B:
    - Originating party (pss_signer_aid) MUST be issuee of DE credential
    - DE delegation edge MUST point to APE (or another DE in nested delegation)
    - Chain terminates when APE is reached (accountable party credential)

    Tries all matching DEs and accepts the first valid chain.

    Args:
        ctx: Authorization context with signer AID and all dossier credentials.
        matching_des: List of DE credentials where issuee == signer.
        claim: AuthorizationClaimBuilder to record status and evidence.
        max_depth: Maximum chain depth to prevent infinite loops (default 10).

    Returns:
        Tuple of (claim, APE credential). APE.issuee = accountable party.
        Returns (claim, None) on failure with appropriate status/reason.
    """
    # Try each matching DE and accept the first valid chain
    last_error = None
    for de in matching_des:
        success, ape, error, evidence = _walk_de_chain(
            de, ctx.dossier_acdcs, max_depth
        )

        if success:
            # Add evidence for successful chain
            claim.add_evidence(f"de_said:{de.said[:16]}...")
            claim.add_evidence(f"de_issuee_match:{ctx.pss_signer_aid[:16]}...")
            for ev in evidence:
                claim.add_evidence(ev)
            return claim, ape

        # Record error for later (in case all chains fail)
        last_error = error

    # All matching DEs failed - report the last error
    claim.fail(
        ClaimStatus.INVALID,
        last_error or "All delegation chains failed"
    )
    claim.add_evidence(f"matching_de_count:{len(matching_des)}")
    claim.add_evidence(f"signer:{ctx.pss_signer_aid[:16]}...")
    return claim, None


def verify_party_authorization(
    ctx: AuthorizationContext,
) -> Tuple[AuthorizationClaimBuilder, Optional[ACDC]]:
    """Verify originating party is authorized to sign PASSporT (Step 10).

    Per §5A Step 10:
    - Case A (no delegation): APE issuee == pss_signer_aid (OP is AP)
    - Case B (with delegation): DE issuee == pss_signer_aid, DE → APE chain valid

    Case B is only used when there exists a DE credential with issuee matching
    the signer. If unrelated DEs are present (issuee != signer), they are ignored
    and Case A is attempted instead.

    In both cases, returns the APE credential. The accountable party is the
    APE issuee (in Case A, this equals the signer; in Case B, it's different).

    Args:
        ctx: Authorization context with signer AID and dossier credentials.

    Returns:
        Tuple of (AuthorizationClaimBuilder for party_authorized, matching APE if found).
        The APE issuee is the accountable party for TN rights binding in Step 11.
    """
    claim = AuthorizationClaimBuilder("party_authorized")

    # Find APE and DE credentials
    ape_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "APE")
    de_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "DE")

    # Find DEs where issuee == signer (matching DEs for Case B)
    matching_des = [
        de for de in de_credentials
        if _get_issuee(de) == ctx.pss_signer_aid
    ]

    # Case B: With delegation - only if there are DEs matching the signer
    if matching_des:
        return _verify_delegation_chain(ctx, matching_des, claim)

    # Case A: No delegation (or no matching DEs) - OP must be issuee of APE
    if not ape_credentials:
        claim.fail(
            ClaimStatus.INVALID,
            "No APE credential found in dossier"
        )
        return claim, None

    # Check if any APE has issuee matching the signer
    for ape in ape_credentials:
        issuee = _get_issuee(ape)
        if issuee == ctx.pss_signer_aid:
            claim.add_evidence(f"ape_said:{ape.said[:16]}...")
            claim.add_evidence(f"issuee_match:{ctx.pss_signer_aid[:16]}...")
            return claim, ape

    # No matching APE found
    claim.fail(
        ClaimStatus.INVALID,
        f"No APE credential with issuee matching signer AID {ctx.pss_signer_aid[:20]}..."
    )
    claim.add_evidence(f"ape_count:{len(ape_credentials)}")
    claim.add_evidence(f"signer:{ctx.pss_signer_aid[:16]}...")

    return claim, None


def verify_tn_rights(
    ctx: AuthorizationContext,
    authorized_aid: Optional[str] = None,
) -> AuthorizationClaimBuilder:
    """Verify accountable party has TN rights for orig.tn (Step 11).

    Per §5A Step 11:
    - Find TNAlloc credential(s) in dossier
    - Verify the TNAlloc is bound to the accountable party (authorized_aid)
    - Verify orig.tn is covered by the TNAlloc allocation

    Args:
        ctx: Authorization context with orig_tn and dossier credentials.
        authorized_aid: The AID of the accountable party from Step 10 (APE issuee).
            If None, TN rights cannot be validated and returns INDETERMINATE.

    Returns:
        AuthorizationClaimBuilder for tn_rights_valid claim.
    """
    claim = AuthorizationClaimBuilder("tn_rights_valid")

    # If no authorized_aid, we cannot bind TN rights to accountable party
    if not authorized_aid:
        claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot validate TN rights without accountable party AID"
        )
        return claim

    # Find TNAlloc credentials
    tnalloc_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "TNAlloc")

    if not tnalloc_credentials:
        claim.fail(
            ClaimStatus.INVALID,
            "No TNAlloc credential found in dossier"
        )
        return claim

    # Parse the orig_tn as a range (single number)
    try:
        orig_ranges = parse_tn_allocation(ctx.orig_tn)
    except TNParseError as e:
        claim.fail(
            ClaimStatus.INVALID,
            f"Invalid orig.tn format: {e}"
        )
        return claim

    # Filter to TNAlloc credentials bound to the accountable party
    bound_tnallocs = []
    for tnalloc in tnalloc_credentials:
        issuee = _get_issuee(tnalloc)
        if issuee == authorized_aid:
            bound_tnallocs.append(tnalloc)

    if not bound_tnallocs:
        claim.fail(
            ClaimStatus.INVALID,
            f"No TNAlloc credential issued to accountable party {authorized_aid[:20]}..."
        )
        claim.add_evidence(f"tnalloc_count:{len(tnalloc_credentials)}")
        claim.add_evidence(f"authorized_aid:{authorized_aid[:16]}...")
        return claim

    # Check if any bound TNAlloc covers the orig_tn
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

        # Check if orig_tn is covered by this allocation
        if is_subset(orig_ranges, alloc_ranges):
            claim.add_evidence(f"tnalloc_said:{tnalloc.said[:16]}...")
            claim.add_evidence(f"issuee_match:{authorized_aid[:16]}...")
            claim.add_evidence(f"orig_tn:{ctx.orig_tn}")
            claim.add_evidence(f"covered:true")
            return claim

    # No bound TNAlloc covers the orig_tn
    claim.fail(
        ClaimStatus.INVALID,
        f"No TNAlloc credential for accountable party covers orig.tn {ctx.orig_tn}"
    )
    claim.add_evidence(f"bound_tnalloc_count:{len(bound_tnallocs)}")
    claim.add_evidence(f"authorized_aid:{authorized_aid[:16]}...")
    claim.add_evidence(f"orig_tn:{ctx.orig_tn}")

    return claim


def validate_authorization(
    ctx: AuthorizationContext,
) -> Tuple[AuthorizationClaimBuilder, AuthorizationClaimBuilder]:
    """Main entry point: validate party authorization and TN rights.

    Orchestrates §5A Steps 10-11:
    1. verify_party_authorization (Step 10) - identifies accountable party
    2. verify_tn_rights (Step 11) - validates TN rights for accountable party

    Per §5A Step 11, TN rights must be validated for the accountable party
    identified in Step 10, not just any party in the dossier.

    Args:
        ctx: Authorization context with all required data.

    Returns:
        Tuple of (party_authorized claim, tn_rights_valid claim).
    """
    party_claim, matching_ape = verify_party_authorization(ctx)

    # Extract authorized AID from matching APE credential for TN rights binding
    # In Case A, the accountable party is the APE issuee (== signer)
    authorized_aid = None
    if matching_ape is not None:
        authorized_aid = _get_issuee(matching_ape)

    tn_rights_claim = verify_tn_rights(ctx, authorized_aid=authorized_aid)

    return party_claim, tn_rights_claim
