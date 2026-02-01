"""API models for VVP Issuer.

Pydantic models for API requests and responses.
"""
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# Request Models
# =============================================================================


class CreateIdentityRequest(BaseModel):
    """Request to create a new identity."""

    name: str = Field(..., description="Human-readable alias for the identity")
    transferable: bool = Field(True, description="Whether keys can rotate")
    key_count: Optional[int] = Field(None, description="Number of signing keys")
    key_threshold: Optional[str] = Field(None, description="Signing threshold")
    next_key_count: Optional[int] = Field(None, description="Number of next keys")
    next_threshold: Optional[str] = Field(None, description="Next signing threshold")
    publish_to_witnesses: bool = Field(True, description="Publish OOBI to witnesses")


# =============================================================================
# Response Models
# =============================================================================


class IdentityResponse(BaseModel):
    """Response containing identity information."""

    aid: str = Field(..., description="Autonomic Identifier (AID)")
    name: str = Field(..., description="Human-readable alias")
    created_at: Optional[str] = Field(None, description="Creation timestamp (ISO8601)")
    witness_count: int = Field(..., description="Number of witnesses")
    key_count: int = Field(..., description="Number of signing keys")
    sequence_number: int = Field(..., description="Current key event sequence")
    transferable: bool = Field(..., description="Whether keys can rotate")


class OobiResponse(BaseModel):
    """Response containing OOBI URLs."""

    aid: str = Field(..., description="The AID")
    oobi_urls: list[str] = Field(..., description="List of OOBI URLs")


class WitnessPublishResult(BaseModel):
    """Result of publishing to a witness."""

    url: str
    success: bool
    error: Optional[str] = None


class CreateIdentityResponse(BaseModel):
    """Response from identity creation."""

    identity: IdentityResponse
    oobi_urls: list[str] = Field(default_factory=list)
    publish_results: Optional[list[WitnessPublishResult]] = None


class IdentityListResponse(BaseModel):
    """Response listing all identities."""

    identities: list[IdentityResponse]
    count: int


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""

    ok: bool
    service: str = "vvp-issuer"
    identities_loaded: int = 0


# =============================================================================
# Registry Models
# =============================================================================


class CreateRegistryRequest(BaseModel):
    """Request to create a new credential registry."""

    name: str = Field(..., description="Human-readable name for the registry")
    identity_name: Optional[str] = Field(None, description="Issuer identity by name")
    issuer_aid: Optional[str] = Field(None, description="Issuer identity by AID")
    no_backers: bool = Field(True, description="If True, no TEL-specific backers")
    publish_to_witnesses: bool = Field(True, description="Publish TEL to witnesses")

    def model_post_init(self, __context) -> None:
        """Validate that either identity_name or issuer_aid is provided."""
        if not self.identity_name and not self.issuer_aid:
            raise ValueError("Either identity_name or issuer_aid is required")


class RegistryResponse(BaseModel):
    """Response containing registry information."""

    registry_key: str = Field(..., description="Registry prefix (regk)")
    name: str = Field(..., description="Human-readable name")
    issuer_aid: str = Field(..., description="Issuer identity AID")
    created_at: Optional[str] = Field(None, description="Creation timestamp (ISO8601)")
    sequence_number: int = Field(..., description="Current TEL sequence")
    no_backers: bool = Field(..., description="Whether using TEL-specific backers")


class CreateRegistryResponse(BaseModel):
    """Response from registry creation."""

    registry: RegistryResponse
    publish_results: Optional[list[WitnessPublishResult]] = None


class RegistryListResponse(BaseModel):
    """Response listing all registries."""

    registries: list[RegistryResponse]
    count: int


# =============================================================================
# Schema Models
# =============================================================================


class SchemaResponse(BaseModel):
    """Response containing schema information."""

    said: str = Field(..., description="Schema SAID")
    title: str = Field(..., description="Schema title")
    description: Optional[str] = Field(None, description="Schema description")
    source: Optional[str] = Field(None, description="Schema source (embedded, imported, custom)")
    schema_document: Optional[dict] = Field(None, description="Full JSON schema")


class SchemaListResponse(BaseModel):
    """Response listing all schemas."""

    schemas: list[SchemaResponse]
    count: int


class SchemaValidationRequest(BaseModel):
    """Request to validate a schema SAID."""

    said: str = Field(..., description="Schema SAID to validate")
    credential_type: Optional[str] = Field(None, description="Credential type (LE, APE, DE, TNAlloc)")


class SchemaValidationResponse(BaseModel):
    """Response from schema validation."""

    said: str = Field(..., description="Schema SAID that was validated")
    valid: bool = Field(..., description="Whether the SAID is recognized")
    credential_type: Optional[str] = Field(None, description="Credential type if specified")


class SchemaImportRequest(BaseModel):
    """Request to import a schema."""

    source: str = Field(..., description="Import source: 'weboftrust' or 'url'")
    schema_id: Optional[str] = Field(None, description="Schema SAID for weboftrust import")
    url: Optional[str] = Field(None, description="URL for direct URL import")
    verify_said: bool = Field(True, description="Verify SAID matches computed value")


class SchemaImportResponse(BaseModel):
    """Response from schema import."""

    said: str = Field(..., description="Imported schema SAID")
    title: str = Field(..., description="Schema title")
    source: str = Field(..., description="Import source")
    verified: bool = Field(..., description="Whether SAID was verified")


class SchemaCreateRequest(BaseModel):
    """Request to create a new schema."""

    title: str = Field(..., description="Schema title")
    description: Optional[str] = Field(None, description="Schema description")
    credential_type: str = Field("VerifiableCredential", description="Credential type name")
    properties: Optional[dict] = Field(None, description="Additional schema properties")


class SchemaCreateResponse(BaseModel):
    """Response from schema creation."""

    said: str = Field(..., description="Generated schema SAID")
    title: str = Field(..., description="Schema title")
    schema_document: dict = Field(..., description="Full generated schema")


class SchemaVerifyResponse(BaseModel):
    """Response from SAID verification."""

    said: str = Field(..., description="Schema SAID")
    valid: bool = Field(..., description="Whether stored SAID matches computed")
    computed_said: Optional[str] = Field(None, description="Computed SAID if different")


class WebOfTrustRegistryResponse(BaseModel):
    """Response listing WebOfTrust registry schemas."""

    schemas: list[dict] = Field(..., description="Available schemas in registry")
    count: int = Field(..., description="Number of schemas")
    ref: str = Field(..., description="Git ref used (branch/tag/commit)")


# =============================================================================
# Credential Models
# =============================================================================


class IssueCredentialRequest(BaseModel):
    """Request to issue a new credential."""

    registry_name: str = Field(..., description="Registry name to track credential")
    schema_said: str = Field(..., description="Schema SAID for validation")
    attributes: dict = Field(..., description="Credential attributes (a section)")
    recipient_aid: Optional[str] = Field(None, description="Recipient AID if targeted")
    edges: Optional[dict] = Field(None, description="Edge references for chained creds")
    rules: Optional[dict] = Field(None, description="Rules section")
    private: bool = Field(False, description="Add privacy-preserving nonces")
    publish_to_witnesses: bool = Field(True, description="Publish TEL to witnesses")


class CredentialResponse(BaseModel):
    """Response containing credential information."""

    said: str = Field(..., description="Credential SAID")
    issuer_aid: str = Field(..., description="Issuing identity AID")
    recipient_aid: Optional[str] = Field(None, description="Recipient AID")
    registry_key: str = Field(..., description="Registry tracking this credential")
    schema_said: str = Field(..., description="Schema SAID")
    issuance_dt: str = Field(..., description="Issuance datetime")
    status: str = Field(..., description="issued or revoked")
    revocation_dt: Optional[str] = Field(None, description="Revocation datetime")


class CredentialDetailResponse(CredentialResponse):
    """Detailed credential response including attributes."""

    attributes: dict = Field(default_factory=dict, description="Credential attributes")
    edges: Optional[dict] = Field(None, description="Edge references")
    rules: Optional[dict] = Field(None, description="Rules section")


class IssueCredentialResponse(BaseModel):
    """Response from credential issuance."""

    credential: CredentialResponse
    publish_results: Optional[list[WitnessPublishResult]] = None


class RevokeCredentialRequest(BaseModel):
    """Request to revoke a credential."""

    reason: Optional[str] = Field(None, description="Optional revocation reason")
    publish_to_witnesses: bool = Field(True, description="Publish TEL to witnesses")


class RevokeCredentialResponse(BaseModel):
    """Response from credential revocation."""

    credential: CredentialResponse
    publish_results: Optional[list[WitnessPublishResult]] = None


class CredentialListResponse(BaseModel):
    """Response listing credentials."""

    credentials: list[CredentialResponse]
    count: int


# =============================================================================
# Dossier Models
# =============================================================================


class BuildDossierRequest(BaseModel):
    """Request to build a dossier from credential chain."""

    root_said: str = Field(..., description="Root credential SAID")
    root_saids: Optional[list[str]] = Field(None, description="Multiple roots for aggregate")
    format: str = Field("cesr", description="Output format: cesr or json")
    include_tel: bool = Field(True, description="Include TEL events (CESR only)")


class DossierInfoResponse(BaseModel):
    """Information about a built dossier."""

    root_said: str = Field(..., description="Primary root credential SAID")
    root_saids: list[str] = Field(..., description="All root SAIDs")
    credential_count: int = Field(..., description="Number of credentials in dossier")
    is_aggregate: bool = Field(..., description="Whether multiple roots")
    format: str = Field(..., description="Output format used")
    content_type: str = Field(..., description="HTTP Content-Type header")
    size_bytes: int = Field(..., description="Size of serialized dossier")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal issues")


class BuildDossierResponse(BaseModel):
    """Response from dossier build (metadata only, content in body)."""

    dossier: DossierInfoResponse
