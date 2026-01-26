"""Pydantic models for test vector format per spec §10.3."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ExpectedStatus(str, Enum):
    """Expected verification status."""

    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


class VectorInput(BaseModel):
    """Input section per §10.3."""

    vvp_identity_header: str  # Base64url JSON
    passport_jwt: str  # header.payload.signature
    call_context: Dict[str, Any]


class VectorArtifacts(BaseModel):
    """Mock artifacts for OOBI/dossier responses per §6.1B."""

    evd_body: Optional[str] = None  # JSON string (will be encoded to bytes)
    evd_content_type: str = "application/json"
    http_status_evd: int = 200
    should_timeout_evd: bool = False

    # Sprint 20: Mock configuration fields for Tier 2/3 vectors
    mock_key_state_error: Optional[str] = None  # "KEY_NOT_YET_VALID" → raises KeyNotYetValidError
    mock_said_validation_error: bool = False  # True → raises ACDCSAIDMismatch
    mock_revocation: Optional[Dict[str, Any]] = None  # {"credential_said": "...", "status": "REVOKED"}
    mock_tn_mismatch: bool = False  # True → TN rights check fails
    mock_delegation_error: bool = False  # True → delegation chain validation fails


class VerificationContext(BaseModel):
    """Verification context per §10.3."""

    reference_time_t: int
    clock_skew: int = 300
    max_token_age: int = 300


class ExpectedClaimNode(BaseModel):
    """Expected claim node with nested children for tree shape assertion."""

    name: str
    status: ExpectedStatus
    reasons_contain: Optional[List[str]] = None
    evidence_contain: Optional[List[str]] = None
    children: Optional[List["ExpectedChildLink"]] = None


class ExpectedChildLink(BaseModel):
    """Expected child link with required flag for §3.3A propagation."""

    required: bool
    node: ExpectedClaimNode


# Forward reference resolution
ExpectedClaimNode.model_rebuild()
ExpectedChildLink.model_rebuild()


class ExpectedResult(BaseModel):
    """Expected verification result per §10.3."""

    overall_status: ExpectedStatus
    root_claim: Optional[ExpectedClaimNode] = None  # Full tree structure
    errors: Optional[List[Dict[str, Any]]] = None


class VectorCase(BaseModel):
    """Complete test vector per spec §10."""

    id: str
    name: str
    description: str
    tier: int = 1
    skip_reason: Optional[str] = None
    input: VectorInput
    artifacts: VectorArtifacts
    verification_context: VerificationContext
    expected: ExpectedResult


