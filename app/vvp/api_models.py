"""
VVP Verifier API models.
Per VVP_Verifier_Specification_v1.4_FINAL.md
"""

from enum import Enum
from typing import Dict, List, Optional

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
    ErrorCode.INTERNAL_ERROR: True,          # Recoverable
}


# =============================================================================
# §4.3 Response Models
# =============================================================================

class VerifyResponse(BaseModel):
    """Response schema for /verify endpoint per §4.2, §4.3"""
    request_id: str
    overall_status: ClaimStatus
    claims: Optional[List[ClaimNode]] = None
    errors: Optional[List[ErrorDetail]] = None


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
