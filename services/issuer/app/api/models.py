"""API models for VVP Issuer.

Pydantic models for API requests and responses.
"""
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Request Models
# =============================================================================


class CreateIdentityRequest(BaseModel):
    """Request to create a new identity."""

    name: str = Field(..., description="Human-readable alias for the identity")
    transferable: bool = Field(True, description="Allow key rotation")
    key_count: Optional[int] = Field(None, description="Number of signing keys")
    key_threshold: Optional[str] = Field(None, description="Signing threshold")
    next_key_count: Optional[int] = Field(None, description="Number of next keys")
    next_threshold: Optional[str] = Field(None, description="Next signing threshold")
    publish_to_witnesses: bool = Field(True, description="Publish OOBI to witnesses")
    metadata: Optional[dict] = Field(None, description="Optional metadata (e.g. {\"type\": \"test\"})")


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
    transferable: bool = Field(..., description="Allow key rotation")


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


class RotateIdentityRequest(BaseModel):
    """Request to rotate an identity's keys."""

    next_key_count: Optional[int] = Field(
        None,
        ge=1,
        description="Number of next keys to generate for future rotation",
    )
    next_threshold: Optional[str] = Field(
        None,
        description="Signing threshold for next keys (e.g., '1', '2', '1/2,1/2')",
    )
    publish_to_witnesses: bool = Field(
        True,
        description="Publish rotation event to witnesses",
    )


class WitnessPublishDetail(BaseModel):
    """Per-witness publish result for operator visibility."""

    witness_url: str = Field(..., description="Witness URL that was called")
    success: bool = Field(..., description="Whether publish succeeded")
    error: Optional[str] = Field(None, description="Error message if failed")


class RotateIdentityResponse(BaseModel):
    """Response from identity rotation."""

    identity: IdentityResponse = Field(..., description="Updated identity info")
    previous_sequence_number: int = Field(
        ...,
        description="Sequence number before rotation",
    )
    publish_results: Optional[list[WitnessPublishDetail]] = Field(
        None,
        description="Per-witness publish results",
    )
    publish_threshold_met: bool = Field(
        True,
        description="Whether enough witnesses receipted the rotation",
    )


class IdentityListResponse(BaseModel):
    """Response listing all identities."""

    identities: list[IdentityResponse]
    count: int


class DeleteResponse(BaseModel):
    """Response confirming deletion."""

    deleted: bool = Field(..., description="Whether deletion was successful")
    resource_type: str = Field(..., description="Type of resource deleted")
    resource_id: str = Field(..., description="ID of deleted resource")
    message: Optional[str] = Field(None, description="Additional information")


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

    registry_name: Optional[str] = Field(None, description="Registry name (auto-resolved from org if omitted)")
    schema_said: str = Field(..., description="Schema SAID for validation")
    attributes: dict = Field(..., description="Credential attributes (a section)")
    recipient_aid: Optional[str] = Field(None, description="Recipient AID if targeted")
    edges: Optional[dict] = Field(None, description="Edge references for chained creds")
    rules: Optional[dict] = Field(None, description="Rules section")
    private: bool = Field(False, description="Add privacy-preserving nonces")
    publish_to_witnesses: bool = Field(True, description="Publish TEL to witnesses")
    organization_id: Optional[str] = Field(
        None,
        description="Organization context for cross-org admin operations. "
                    "Required for extended schemas when principal has no org.",
    )


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
    relationship: Optional[str] = Field(None, description="Relationship to requesting org: 'issued' or 'subject'")
    issuer_name: Optional[str] = Field(None, description="Issuer organization name if known")
    recipient_name: Optional[str] = Field(None, description="Recipient organization name if known")


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
    """Response listing credentials.

    Sprint 72: Added ``total``, ``limit``, ``offset`` for server-side pagination.
    ``count`` is the number of credentials in this page (backward compat).
    ``total`` is the unfiltered total before pagination.
    """

    credentials: list[CredentialResponse]
    count: int
    total: Optional[int] = None
    limit: Optional[int] = None
    offset: Optional[int] = None


# =============================================================================
# Dossier Models
# =============================================================================


class CreateDossierRequest(BaseModel):
    """Request to create a new dossier ACDC via the wizard."""

    owner_org_id: str = Field(..., description="Organization that owns the dossier (AP)")
    edges: dict[str, str] = Field(
        ...,
        description="Edge slot name to credential SAID mapping. "
        "Required: vetting, alloc, tnalloc, delsig. Optional: bownr, bproxy.",
    )
    name: Optional[str] = Field(None, description="Optional dossier name")
    osp_org_id: Optional[str] = Field(
        None, description="OSP organization to associate (administrative)"
    )


class CreateDossierResponse(BaseModel):
    """Response from dossier creation."""

    dossier_said: str = Field(..., description="SAID of the created dossier ACDC")
    issuer_aid: str = Field(..., description="AID of the AP that issued the dossier")
    schema_said: str = Field(..., description="Dossier schema SAID")
    edge_count: int = Field(..., description="Number of edges in the dossier")
    name: Optional[str] = Field(None, description="Dossier name if provided")
    osp_org_id: Optional[str] = Field(None, description="Associated OSP org ID")
    dossier_url: str = Field(..., description="Public URL for dossier access")
    publish_results: Optional[list["WitnessPublishResult"]] = Field(
        None, description="Witness publish results (null if not attempted or failed)"
    )


class AssociatedDossierEntry(BaseModel):
    """An individual dossier-OSP association entry."""

    dossier_said: str = Field(..., description="Dossier credential SAID")
    owner_org_id: str = Field(..., description="AP organization that owns the dossier")
    owner_org_name: Optional[str] = Field(None, description="AP organization name")
    osp_org_id: str = Field(..., description="OSP organization ID")
    osp_org_name: Optional[str] = Field(None, description="OSP organization name")
    created_at: str = Field(..., description="Association creation timestamp")


class AssociatedDossierListResponse(BaseModel):
    """Response listing dossier-OSP associations."""

    associations: list[AssociatedDossierEntry] = Field(
        default_factory=list, description="Dossier associations"
    )
    count: int = Field(..., description="Total number of associations")


class DossierSlotStatus(BaseModel):
    """Status of a single dossier edge slot for readiness check."""

    edge: str = Field(..., description="Edge slot name (e.g., 'vetting', 'alloc')")
    label: str = Field(..., description="Human-readable label")
    required: bool = Field(..., description="Whether this edge is required for dossier creation")
    schema_constraint: Optional[str] = Field(None, description="Schema SAID constraint (null if any)")
    available_count: int = Field(..., description="Credentials passing all validation checks")
    total_count: int = Field(..., description="Total credentials matching schema (before validation)")
    status: str = Field(
        ...,
        description=(
            "Slot status: ready (valid candidates found), missing (required, none exist), "
            "invalid (candidates exist but fail validation), optional_missing (optional, none exist), "
            "or optional_unconstrained (optional with no schema constraint — candidates exist but "
            "suitability requires manual assessment)"
        ),
    )


class DossierReadinessResponse(BaseModel):
    """Response from dossier readiness check."""

    org_id: str = Field(..., description="Organization ID checked")
    org_name: str = Field(..., description="Organization name")
    ready: bool = Field(
        ..., description="True when all required edge slots are satisfied"
    )
    slots: list[DossierSlotStatus] = Field(
        default_factory=list, description="Per-edge slot status"
    )
    blocking_reason: Optional[str] = Field(
        None, description="Human-readable reason when not ready (e.g., 'Required edge tnalloc is not satisfied')"
    )


class OrganizationNameResponse(BaseModel):
    """Lightweight org name response (id + name + optional AID)."""

    id: str = Field(..., description="Organization ID")
    name: str = Field(..., description="Organization name")
    aid: Optional[str] = Field(None, description="Organization KERI AID (if provisioned)")


class OrganizationNameListResponse(BaseModel):
    """Response listing organization names."""

    organizations: list[OrganizationNameResponse] = Field(
        default_factory=list, description="Organization names"
    )
    count: int = Field(..., description="Total number of organizations")


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


# =============================================================================
# VVP Header/PASSporT Models
# =============================================================================


class CreateVVPRequest(BaseModel):
    """Request to create VVP-Identity header and PASSporT."""

    identity_name: str = Field(..., description="Issuer identity name for signing")
    dossier_said: str = Field(..., description="Root credential SAID for dossier")
    orig_tn: str = Field(..., description="Originating phone number (E.164 format)")
    dest_tn: list[str] = Field(..., description="Destination phone numbers (E.164 format)")
    exp_seconds: int = Field(300, ge=1, le=300, description="Validity window in seconds (max 300)")
    call_id: Optional[str] = Field(None, description="SIP Call-ID for dialog binding (callee PASSporT §5.2)")
    cseq: Optional[int] = Field(None, description="SIP CSeq number for dialog binding (callee PASSporT §5.2)")
    # Sprint 60: brand_name/brand_logo_url removed — brand derived from dossier only


class CreateVVPResponse(BaseModel):
    """Response containing VVP-Identity header and PASSporT."""

    vvp_identity_header: str = Field(..., description="Base64url-encoded VVP-Identity header")
    passport_jwt: str = Field(..., description="Signed PASSporT JWT with PSS CESR signature")
    dossier_url: str = Field(..., description="Full evd URL for dossier")
    kid_oobi: str = Field(..., description="Full kid OOBI URL for issuer")
    iat: int = Field(..., description="Issued-at timestamp (seconds since epoch)")
    exp: int = Field(..., description="Expiry timestamp (seconds since epoch)")
    identity_header: str = Field(
        ...,
        description=(
            "RFC 8224 Identity header value. "
            "Format: JWT;info=<OOBI-URL>;alg=EdDSA;ppt=vvp"
        ),
    )
    revocation_status: str = Field(
        "TRUSTED",
        description=(
            "Credential revocation check result. "
            "TRUSTED = credentials active or status pending (safe to sign). "
            "UNTRUSTED results in 403 rejection, not returned here."
        ),
    )


# =============================================================================
# TN Mapping Models (Sprint 42)
# =============================================================================


class CreateTNMappingRequest(BaseModel):
    """Request to create a TN mapping for SIP redirect signing."""

    tn: str = Field(
        ...,
        description="E.164 telephone number (e.g., +15551234567)",
        pattern=r"^\+[1-9]\d{1,14}$",
    )
    dossier_said: str = Field(
        ...,
        description="Root credential SAID for the dossier",
        min_length=44,
        max_length=44,
    )
    identity_name: str = Field(
        ...,
        description="KERI identity name for signing",
    )


class UpdateTNMappingRequest(BaseModel):
    """Request to update a TN mapping."""

    dossier_said: Optional[str] = Field(
        None,
        description="Root credential SAID for the dossier",
        min_length=44,
        max_length=44,
    )
    identity_name: Optional[str] = Field(
        None,
        description="KERI identity name for signing",
    )
    brand_name: Optional[str] = Field(
        None,
        description="Brand name to display (overrides auto-extracted value)",
    )
    brand_logo_url: Optional[str] = Field(
        None,
        description="Brand logo URL (overrides auto-extracted value)",
    )
    enabled: Optional[bool] = Field(None, description="Enable/disable mapping")


class TNMappingResponse(BaseModel):
    """Response containing TN mapping information."""

    id: str = Field(..., description="Mapping ID (UUID)")
    tn: str = Field(..., description="E.164 telephone number")
    organization_id: str = Field(..., description="Organization ID")
    dossier_said: str = Field(..., description="Root credential SAID")
    identity_name: str = Field(..., description="KERI identity name")
    brand_name: Optional[str] = Field(None, description="Brand name from dossier")
    brand_logo_url: Optional[str] = Field(None, description="Brand logo URL")
    enabled: bool = Field(..., description="Whether mapping is active")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")


class TNMappingListResponse(BaseModel):
    """Response listing TN mappings."""

    count: int = Field(..., description="Total count")
    mappings: list[TNMappingResponse] = Field(..., description="TN mappings")


class TNLookupRequest(BaseModel):
    """Internal request for TN lookup (from SIP service)."""

    tn: str = Field(..., description="E.164 telephone number to lookup")
    api_key: str = Field(..., description="API key for authentication")


class TNLookupResponse(BaseModel):
    """Response from TN lookup."""

    found: bool = Field(..., description="Whether mapping was found")
    tn: Optional[str] = Field(None, description="Matched TN")
    organization_id: Optional[str] = Field(None, description="Organization ID")
    organization_name: Optional[str] = Field(None, description="Organization name")
    dossier_said: Optional[str] = Field(None, description="Root credential SAID")
    identity_name: Optional[str] = Field(None, description="KERI identity name")
    brand_name: Optional[str] = Field(None, description="Brand name")
    brand_logo_url: Optional[str] = Field(None, description="Brand logo URL")
    error: Optional[str] = Field(None, description="Error message if not found")


# =============================================================================
# Sprint 61: Vetter Certification Models
# =============================================================================


class VetterCertificationCreateRequest(BaseModel):
    """Request to issue a VetterCertification credential."""

    organization_id: str = Field(..., description="Target org UUID")
    ecc_targets: list[str] = Field(..., min_length=1, description="E.164 country codes")
    jurisdiction_targets: list[str] = Field(
        ..., min_length=1, description="ISO 3166-1 alpha-3 codes"
    )
    name: str = Field(..., min_length=1, max_length=255, description="Vetter name")
    certification_expiry: Optional[str] = Field(
        None,
        description="Expiry date (ISO8601 UTC). Stored as 'certificationExpiry' in ACDC.",
        alias="certificationExpiry",
    )

    model_config = {"populate_by_name": True}

    @field_validator("ecc_targets")
    @classmethod
    def validate_ecc_targets(cls, v):
        from app.vetter.constants import VALID_ECC_CODES
        for code in v:
            if code not in VALID_ECC_CODES:
                raise ValueError(
                    f"Invalid ECC target: {code}. Must be a valid E.164 country code."
                )
        return v

    @field_validator("jurisdiction_targets")
    @classmethod
    def validate_jurisdiction_targets(cls, v):
        from app.vetter.constants import VALID_JURISDICTION_CODES
        for code in v:
            if code not in VALID_JURISDICTION_CODES:
                raise ValueError(
                    f"Invalid jurisdiction: {code}. Must be a valid ISO 3166-1 alpha-3 code."
                )
        return v


class VetterCertificationResponse(BaseModel):
    """Response with VetterCertification credential info."""

    said: str
    issuer_aid: str
    vetter_aid: str
    organization_id: str
    organization_name: str
    ecc_targets: list[str]
    jurisdiction_targets: list[str]
    name: str
    certification_expiry: Optional[str] = Field(
        None,
        description="Expiry from ACDC 'certificationExpiry' attribute",
        alias="certificationExpiry",
    )
    status: str
    created_at: str

    model_config = {"populate_by_name": True}


class VetterCertificationListResponse(BaseModel):
    """List response for VetterCertification credentials."""

    certifications: list[VetterCertificationResponse]
    count: int


class OrganizationConstraintsResponse(BaseModel):
    """Constraint visibility response for an organization."""

    organization_id: str
    organization_name: str
    vetter_certification_said: Optional[str] = None
    ecc_targets: Optional[list[str]] = None
    jurisdiction_targets: Optional[list[str]] = None
    certification_status: Optional[str] = None
    certification_expiry: Optional[str] = None


# =============================================================================
# PBX Configuration Models (Sprint 71)
# =============================================================================


class PBXExtension(BaseModel):
    """Configuration for a single PBX extension."""

    ext: int = Field(..., ge=1000, le=1009, description="Extension number (1000-1009)")
    cli: str = Field(
        ...,
        description="E.164 Calling Line Identity",
        pattern=r"^\+[1-9]\d{1,14}$",
    )
    enabled: bool = Field(True, description="Whether extension is active")
    description: str = Field("", max_length=100, description="Human-readable label")


class PBXConfigResponse(BaseModel):
    """Current PBX configuration."""

    api_key_org_id: Optional[str] = None
    api_key_org_name: Optional[str] = None
    api_key_id: Optional[str] = None
    api_key_name: Optional[str] = None
    api_key_preview: Optional[str] = None  # First 8 chars of raw key
    extensions: list[PBXExtension] = Field(default_factory=list)
    default_caller_id: str = "+441923311000"
    last_deployed_at: Optional[str] = None
    last_deployed_by: Optional[str] = None


class UpdatePBXConfigRequest(BaseModel):
    """Request to update PBX configuration."""

    api_key_org_id: Optional[str] = Field(None, description="Organization ID for API key")
    api_key_id: Optional[str] = Field(None, description="API key ID within the org")
    api_key_value: Optional[str] = Field(None, description="Raw API key value (needed for dialplan)")
    extensions: Optional[list[PBXExtension]] = Field(None, description="Extension configs (1000-1009)")
    default_caller_id: Optional[str] = Field(
        None,
        description="Default caller ID for VVP loopback",
        pattern=r"^\+[1-9]\d{1,14}$",
    )

    @field_validator("extensions")
    @classmethod
    def validate_no_duplicate_extensions(cls, v):
        if v is None:
            return v
        ext_nums = [e.ext for e in v]
        if len(ext_nums) != len(set(ext_nums)):
            raise ValueError("Duplicate extension numbers are not allowed")
        return v


class PBXDeployRequest(BaseModel):
    """Request to deploy dialplan to PBX."""

    dry_run: bool = Field(False, description="If true, return generated XML without deploying")


class PBXDeployResponse(BaseModel):
    """Response from PBX deployment."""

    success: bool
    dialplan_xml: Optional[str] = None  # Included in dry_run mode
    dialplan_size_bytes: int = 0
    message: str
    deployed_at: Optional[str] = None
