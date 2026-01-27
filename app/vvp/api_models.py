"""
VVP Verifier API models.
Per VVP_Verifier_Specification_v1.4_FINAL.md
"""

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# =============================================================================
# §3.2 Claim Status
# =============================================================================

class ClaimStatus(str, Enum):
    """Three-valued claim status per spec §3.2"""
    VALID = "VALID"              # Proven by evidence
    INVALID = "INVALID"          # Contradicted by evidence
    INDETERMINATE = "INDETERMINATE"  # Insufficient or unverifiable evidence


# =============================================================================
# §4.3B Claim Node Schema
# =============================================================================

class ChildLink(BaseModel):
    """Child relationship with explicit required/optional flag per §4.3B"""
    required: bool
    node: "ClaimNode"


class ClaimNode(BaseModel):
    """Claim node schema per spec §4.3B"""
    name: str
    status: ClaimStatus
    reasons: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    children: List["ChildLink"] = Field(default_factory=list)


# Rebuild for forward references
ChildLink.model_rebuild()
ClaimNode.model_rebuild()


# =============================================================================
# §4.1 Request Models
# =============================================================================

class SipContext(BaseModel):
    """SIP context fields per spec §4.4.

    When provided, the verifier MUST perform contextual alignment (§5A Step 2).
    When absent, context_aligned claim is INDETERMINATE (not INVALID).
    """
    from_uri: str  # SIP From URI (originating party)
    to_uri: str  # SIP To URI (destination party)
    invite_time: str  # RFC3339 timestamp of SIP INVITE
    cseq: Optional[int] = None  # CSeq number (for callee verification)


class CallContext(BaseModel):
    """Call context per §4.1"""
    call_id: str
    received_at: str  # RFC3339 timestamp
    sip: Optional[SipContext] = None  # SIP context for contextual alignment (§4.4)


class VerifyRequest(BaseModel):
    """Request body for /verify endpoint per §4.1"""
    passport_jwt: str
    context: CallContext  # Required per spec §4.1


class VerifyCalleeRequest(BaseModel):
    """Request body for /verify-callee endpoint per §5B.

    Sprint 19 - Phase 12: Callee verification requires:
    - passport_jwt: Callee's PASSporT (includes call-id, cseq claims)
    - context: Call context with call_id (REQUIRED) and sip.cseq (REQUIRED)
    - caller_passport_jwt: Optional caller's passport for goal overlap check

    Note: call_id is in CallContext, cseq is in SipContext.cseq
    Both are required for callee verification (enforced at endpoint level).
    """
    passport_jwt: str  # Callee's PASSporT JWT
    context: CallContext  # Call context (call_id required, sip.cseq required for callee)
    caller_passport_jwt: Optional[str] = None  # Caller's passport for goal overlap


# =============================================================================
# §4.2 Error Models
# =============================================================================

class ErrorDetail(BaseModel):
    """Error detail per §4.2"""
    code: str
    message: str
    recoverable: bool


class ErrorCode:
    """Error code registry per spec §4.2A (18 codes) + revocation extension"""
    # Protocol layer
    VVP_IDENTITY_MISSING = "VVP_IDENTITY_MISSING"
    VVP_IDENTITY_INVALID = "VVP_IDENTITY_INVALID"
    VVP_OOBI_FETCH_FAILED = "VVP_OOBI_FETCH_FAILED"
    VVP_OOBI_CONTENT_INVALID = "VVP_OOBI_CONTENT_INVALID"
    PASSPORT_MISSING = "PASSPORT_MISSING"
    PASSPORT_PARSE_FAILED = "PASSPORT_PARSE_FAILED"
    PASSPORT_EXPIRED = "PASSPORT_EXPIRED"

    # Crypto layer
    PASSPORT_SIG_INVALID = "PASSPORT_SIG_INVALID"
    PASSPORT_FORBIDDEN_ALG = "PASSPORT_FORBIDDEN_ALG"
    ACDC_SAID_MISMATCH = "ACDC_SAID_MISMATCH"
    ACDC_PROOF_MISSING = "ACDC_PROOF_MISSING"

    # Evidence layer
    DOSSIER_URL_MISSING = "DOSSIER_URL_MISSING"
    DOSSIER_FETCH_FAILED = "DOSSIER_FETCH_FAILED"
    DOSSIER_PARSE_FAILED = "DOSSIER_PARSE_FAILED"
    DOSSIER_GRAPH_INVALID = "DOSSIER_GRAPH_INVALID"

    # KERI layer
    KERI_RESOLUTION_FAILED = "KERI_RESOLUTION_FAILED"
    KERI_STATE_INVALID = "KERI_STATE_INVALID"

    # Revocation layer (Phase 9 extension)
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"

    # Authorization layer (Sprint 15)
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    TN_RIGHTS_INVALID = "TN_RIGHTS_INVALID"

    # Contextual alignment layer (Sprint 18)
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"

    # Brand/business logic layer (Sprint 18)
    BRAND_CREDENTIAL_INVALID = "BRAND_CREDENTIAL_INVALID"
    GOAL_REJECTED = "GOAL_REJECTED"

    # Callee verification layer (Sprint 19 - Phase 12)
    DIALOG_MISMATCH = "DIALOG_MISMATCH"  # call-id/cseq don't match SIP INVITE
    ISSUER_MISMATCH = "ISSUER_MISMATCH"  # dossier issuer != passport kid

    # Verifier layer
    INTERNAL_ERROR = "INTERNAL_ERROR"


# Recoverability mapping per §4.2A
ERROR_RECOVERABILITY: Dict[str, bool] = {
    ErrorCode.VVP_IDENTITY_MISSING: False,
    ErrorCode.VVP_IDENTITY_INVALID: False,
    ErrorCode.VVP_OOBI_FETCH_FAILED: True,   # Recoverable
    ErrorCode.VVP_OOBI_CONTENT_INVALID: False,
    ErrorCode.PASSPORT_MISSING: False,
    ErrorCode.PASSPORT_PARSE_FAILED: False,
    ErrorCode.PASSPORT_SIG_INVALID: False,
    ErrorCode.PASSPORT_FORBIDDEN_ALG: False,
    ErrorCode.PASSPORT_EXPIRED: False,
    ErrorCode.DOSSIER_URL_MISSING: False,
    ErrorCode.DOSSIER_FETCH_FAILED: True,    # Recoverable
    ErrorCode.DOSSIER_PARSE_FAILED: False,
    ErrorCode.DOSSIER_GRAPH_INVALID: False,
    ErrorCode.ACDC_SAID_MISMATCH: False,
    ErrorCode.ACDC_PROOF_MISSING: False,
    ErrorCode.KERI_RESOLUTION_FAILED: True,  # Recoverable
    ErrorCode.KERI_STATE_INVALID: False,
    ErrorCode.CREDENTIAL_REVOKED: False,     # Non-recoverable
    ErrorCode.AUTHORIZATION_FAILED: False,   # Non-recoverable (Sprint 15)
    ErrorCode.TN_RIGHTS_INVALID: False,      # Non-recoverable (Sprint 15)
    ErrorCode.CONTEXT_MISMATCH: False,       # Non-recoverable (Sprint 18)
    ErrorCode.BRAND_CREDENTIAL_INVALID: False,  # Non-recoverable (Sprint 18)
    ErrorCode.GOAL_REJECTED: False,          # Non-recoverable (Sprint 18)
    ErrorCode.DIALOG_MISMATCH: False,        # Non-recoverable (Sprint 19)
    ErrorCode.ISSUER_MISMATCH: False,        # Non-recoverable (Sprint 19)
    ErrorCode.INTERNAL_ERROR: True,          # Recoverable
}


# =============================================================================
# Sprint 25: Delegation Chain Response Models
# =============================================================================


class DelegationNodeResponse(BaseModel):
    """Single node in delegation chain for API response.

    Represents one identifier in a multi-level delegation chain from
    leaf (delegated) to root (non-delegated).

    Attributes:
        aid: Full AID string.
        aid_short: Truncated AID for display (first 16 chars + "...").
        display_name: Human-readable name if resolved from LE credential.
        is_root: True if this is the non-delegated root of the chain.
        authorization_status: Authorization check result - VALID, INVALID, or INDETERMINATE.
    """

    aid: str
    aid_short: str
    display_name: Optional[str] = None
    is_root: bool = False
    authorization_status: str = "INDETERMINATE"


class DelegationChainResponse(BaseModel):
    """Complete delegation chain for API response.

    Provides visibility into multi-level KERI delegation validation.
    The chain runs from the delegated identifier (leaf) to the
    non-delegated root.

    Attributes:
        chain: List of DelegationNodeResponse from leaf to root.
        depth: Number of delegation levels (0 = non-delegated).
        root_aid: AID of the non-delegated root.
        is_valid: True if entire chain validates (authorization passed).
        errors: List of validation error messages.
    """

    chain: List[DelegationNodeResponse] = Field(default_factory=list)
    depth: int = 0
    root_aid: Optional[str] = None
    is_valid: bool = False
    errors: List[str] = Field(default_factory=list)


# =============================================================================
# §4.3 Response Models
# =============================================================================

class ToIPWarningDetail(BaseModel):
    """ToIP Verifiable Dossiers Specification warning detail.

    These warnings indicate non-compliance with ToIP stricter requirements
    but do NOT fail VVP verification. Per VVP Spec §6.1C-D.
    """

    code: str
    message: str
    said: Optional[str] = None
    field_path: Optional[str] = None


class IssuerIdentityInfo(BaseModel):
    """Resolved identity for an AID.

    This is INFORMATIONAL only and may be incomplete when dossiers are
    partial/compact. The identity_source indicates provenance:
    - "dossier": Identity from LE credential (including vCard-derived values)
    - "wellknown": Identity from built-in registry fallback

    Attributes:
        aid: The AID this identity refers to.
        legal_name: Legal entity name from LE credential or vCard ORG.
        lei: Legal Entity Identifier (ISO 17442) if present.
        source_said: SAID of the LE credential providing this identity.
        identity_source: Provenance of the identity data.
    """

    aid: str
    legal_name: Optional[str] = None
    lei: Optional[str] = None
    source_said: Optional[str] = None
    identity_source: Literal["dossier", "wellknown"] = "dossier"


class VerifyResponse(BaseModel):
    """Response schema for /verify endpoint per §4.2, §4.3

    Attributes:
        request_id: Unique identifier for this verification request.
        overall_status: Final verification status (VALID, INVALID, INDETERMINATE).
        claims: Claim tree with verification results.
        errors: List of errors encountered during verification.
        has_variant_limitations: True if dossier contains compact/partial ACDCs
            that may limit verification completeness (per §1.4). When True,
            some claims may be INDETERMINATE due to unverifiable external refs
            or redacted fields.
        delegation_chain: Delegation chain details when Tier 2 verification
            resolves a delegated identifier (Sprint 25). None for non-delegated.
        signer_aid: AID of the PASSporT signer (extracted from kid). Used for
            credential-to-delegation mapping in UI (Sprint 25).
        toip_warnings: ToIP Verifiable Dossiers Specification compliance warnings.
            These are informational only and do not affect verification status.
        issuer_identities: Resolved identities for AIDs in the dossier and
            delegation chain. INFORMATIONAL only - may be incomplete for
            partial/compact dossiers. None when no dossier is present.
    """

    request_id: str
    overall_status: ClaimStatus
    claims: Optional[List[ClaimNode]] = None
    errors: Optional[List[ErrorDetail]] = None
    has_variant_limitations: bool = False
    delegation_chain: Optional[DelegationChainResponse] = None
    signer_aid: Optional[str] = None
    toip_warnings: Optional[List[ToIPWarningDetail]] = None
    issuer_identities: Optional[Dict[str, IssuerIdentityInfo]] = None


# =============================================================================
# §4.3A Status Derivation
# =============================================================================

def derive_overall_status(
    claims: Optional[List[ClaimNode]],
    errors: Optional[List[ErrorDetail]]
) -> ClaimStatus:
    """
    Derive overall_status per §4.3A precedence rules:
    - INVALID > INDETERMINATE > VALID
    - Non-recoverable errors force INVALID
    - Recoverable errors alone yield INDETERMINATE
    """
    worst = ClaimStatus.VALID

    # Check errors first - non-recoverable errors force INVALID
    if errors:
        for err in errors:
            if not err.recoverable:
                return ClaimStatus.INVALID
        worst = ClaimStatus.INDETERMINATE

    # Check root claims
    if claims:
        for claim in claims:
            if claim.status == ClaimStatus.INVALID:
                return ClaimStatus.INVALID
            if claim.status == ClaimStatus.INDETERMINATE:
                worst = ClaimStatus.INDETERMINATE

    return worst
