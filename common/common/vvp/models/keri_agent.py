"""KERI Agent DTO models.

Shared request/response models defining the API contract between
the KERI Agent service and the Issuer API. These are data transfer
objects only — no KERI/LMDB logic.

Sprint 68: KERI Agent Service Extraction.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Identity DTOs
# =============================================================================


class CreateIdentityRequest(BaseModel):
    """Request to create a new KERI identity."""

    name: str = Field(..., description="Human-readable identity alias")
    key_count: int = Field(1, description="Number of signing keys")
    key_threshold: str = Field("1", description="Signing threshold expression")
    next_key_count: int = Field(1, description="Number of pre-rotated next keys")
    next_threshold: str = Field("1", description="Next key threshold expression")
    transferable: bool = Field(True, description="Whether keys can be rotated")


class IdentityResponse(BaseModel):
    """Identity information returned by the KERI Agent."""

    aid: str = Field(..., description="Autonomic Identifier")
    name: str = Field(..., description="Human-readable alias")
    created_at: str = Field(..., description="ISO8601 creation timestamp")
    witness_count: int = Field(..., description="Number of witnesses")
    key_count: int = Field(..., description="Number of signing keys")
    sequence_number: int = Field(..., description="Current key event sequence number")
    transferable: bool = Field(..., description="Whether keys can be rotated")


class RotateKeysRequest(BaseModel):
    """Request to rotate identity keys."""

    new_key_count: int | None = Field(None, description="New key count (None = keep current)")
    new_threshold: str | None = Field(None, description="New threshold (None = keep current)")


class RotationResponse(BaseModel):
    """Result of identity key rotation."""

    aid: str = Field(..., description="Autonomic Identifier")
    name: str = Field(..., description="Human-readable alias")
    previous_sequence_number: int = Field(..., description="Sequence before rotation")
    new_sequence_number: int = Field(..., description="Sequence after rotation")
    new_key_count: int = Field(..., description="Key count after rotation")


# =============================================================================
# Registry DTOs
# =============================================================================


class CreateRegistryRequest(BaseModel):
    """Request to create a credential registry."""

    name: str = Field(..., description="Registry name")
    identity_name: str = Field(..., description="Identity that owns this registry")
    no_backers: bool = Field(True, description="If True, no TEL-specific backers")


class RegistryResponse(BaseModel):
    """Registry information returned by the KERI Agent."""

    registry_key: str = Field(..., description="TEL registry prefix")
    name: str = Field(..., description="Registry name")
    identity_aid: str = Field(..., description="Owning identity AID")
    identity_name: str = Field(..., description="Owning identity name")
    credential_count: int = Field(0, description="Number of credentials in this registry")
    no_backers: bool = Field(True, description="Whether TEL-specific backers are disabled")


# =============================================================================
# Credential DTOs
# =============================================================================


class IssueCredentialRequest(BaseModel):
    """Request to issue an ACDC credential."""

    identity_name: str = Field(..., description="Issuing identity name")
    registry_name: str = Field(..., description="Registry to track the credential")
    schema_said: str = Field(..., description="Schema SAID for the credential type")
    recipient_aid: str | None = Field(None, description="Recipient (issuee) AID")
    attributes: dict = Field(..., description="Credential attributes (the 'a' block)")
    edges: dict | None = Field(None, description="Edge references to other credentials")
    rules: dict | None = Field(None, description="Rules section")
    publish: bool = Field(True, description="Whether to publish to witnesses")


class CredentialResponse(BaseModel):
    """Credential information returned by the KERI Agent."""

    said: str = Field(..., description="Credential SAID")
    issuer_aid: str = Field(..., description="Issuing identity AID")
    recipient_aid: str | None = Field(None, description="Recipient AID")
    registry_key: str = Field(..., description="Registry key tracking this credential")
    schema_said: str = Field(..., description="Schema SAID")
    issuance_dt: str = Field(..., description="ISO8601 issuance timestamp")
    status: str = Field(..., description="Credential status: issued | revoked")
    revocation_dt: str | None = Field(None, description="ISO8601 revocation timestamp")
    attributes: dict = Field(..., description="The 'a' section data")
    edges: dict | None = Field(None, description="Edge references")
    rules: dict | None = Field(None, description="Rules section")


class RevokeCredentialRequest(BaseModel):
    """Request to revoke a credential."""

    publish: bool = Field(True, description="Whether to publish revocation to witnesses")


# =============================================================================
# Dossier DTOs
# =============================================================================


class BuildDossierRequest(BaseModel):
    """Request to build a dossier from a credential chain."""

    root_said: str = Field(..., description="Root credential SAID")
    root_saids: list[str] | None = Field(None, description="Multiple root SAIDs for aggregate dossier")
    include_tel: bool = Field(True, description="Whether to include TEL issuance events")


class DossierResponse(BaseModel):
    """Dossier information returned by the KERI Agent."""

    root_said: str = Field(..., description="Primary root credential SAID")
    root_saids: list[str] = Field(default_factory=list, description="All root SAIDs")
    credential_saids: list[str] = Field(default_factory=list, description="Credentials in topological order")
    is_aggregate: bool = Field(False, description="Whether this is a multi-root aggregate dossier")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal build warnings")


# =============================================================================
# VVP Attestation DTOs
# =============================================================================


class CreateVVPAttestationRequest(BaseModel):
    """Request to create a VVP attestation (PASSporT + VVP-Identity header)."""

    identity_name: str = Field(..., description="Signing identity name")
    dossier_said: str = Field(..., description="Dossier SAID for evidence URL")
    orig_tn: str = Field(..., description="Originating telephone number (E.164)")
    dest_tn: list[str] = Field(..., description="Destination telephone numbers (E.164)")
    exp_seconds: int = Field(300, description="PASSporT validity in seconds (max 300)")
    call_id: str | None = Field(None, description="SIP Call-ID")
    cseq: str | None = Field(None, description="SIP CSeq")

    @field_validator("dest_tn", mode="before")
    @classmethod
    def normalize_dest_tn(cls, v):
        """Accept both scalar string and list for backward compatibility."""
        if isinstance(v, str):
            return [v]
        return v
    # Sprint 68c: Additional fields passed by issuer for attestation construction
    card: list[str] | None = Field(None, description="vCard card claim lines for brand identity")
    dossier_url: str | None = Field(None, description="Pre-computed dossier evidence URL")
    kid_oobi: str | None = Field(None, description="Pre-computed key OOBI URL")


class VVPAttestationResponse(BaseModel):
    """VVP attestation result from the KERI Agent."""

    vvp_identity_header: str = Field(..., description="Base64url-encoded VVP-Identity header")
    passport_jwt: str = Field(..., description="Signed PASSporT JWT")
    identity_header: str = Field(..., description="RFC 8224 Identity header value")
    dossier_url: str = Field(..., description="Dossier evidence URL")
    kid_oobi: str = Field(..., description="Key OOBI URL for verifier")
    iat: int = Field(..., description="Issued-at Unix timestamp")
    exp: int = Field(..., description="Expiry Unix timestamp")


# =============================================================================
# Bootstrap DTOs
# =============================================================================


class BootstrapStatusResponse(BaseModel):
    """Bootstrap state from the KERI Agent's mock vLEI infrastructure."""

    initialized: bool = Field(..., description="Whether mock vLEI is initialized")
    gleif_aid: str | None = Field(None, description="Mock GLEIF identity AID")
    gleif_registry_key: str | None = Field(None, description="Mock GLEIF registry key")
    qvi_aid: str | None = Field(None, description="Mock QVI identity AID")
    qvi_registry_key: str | None = Field(None, description="Mock QVI registry key")
    gsma_aid: str | None = Field(None, description="Mock GSMA identity AID")
    gsma_registry_key: str | None = Field(None, description="Mock GSMA registry key")
    gleif_name: str | None = Field(None, description="Mock GLEIF identity name")
    qvi_name: str | None = Field(None, description="Mock QVI identity name")
    gsma_name: str | None = Field(None, description="Mock GSMA identity name")
    # Sprint 68b: Credential SAIDs needed by issuer for edge construction
    qvi_credential_said: str | None = Field(None, description="QVI credential SAID (needed for LE edge)")
    gsma_governance_said: str | None = Field(None, description="GSMA governance credential SAID")


# =============================================================================
# Operational DTOs
# =============================================================================


class AgentHealthResponse(BaseModel):
    """Health check response from the KERI Agent."""

    status: str = Field(..., description="Agent status: ok | unhealthy")
    identity_count: int = Field(0, description="Number of managed identities")
    registry_count: int = Field(0, description="Number of registries")
    credential_count: int = Field(0, description="Number of issued credentials")
    lmdb_accessible: bool = Field(True, description="Whether LMDB is accessible")


class AgentStatsResponse(BaseModel):
    """Statistics from the KERI Agent."""

    identity_count: int = Field(0, description="Number of managed identities")
    registry_count: int = Field(0, description="Number of registries")
    credential_count: int = Field(0, description="Number of issued credentials")


class AgentErrorResponse(BaseModel):
    """Error response from the KERI Agent."""

    detail: str = Field(..., description="Human-readable error message")
    error_code: str | None = Field(None, description="Machine-readable error code")
