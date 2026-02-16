# VVP Data Models Reference

## Verifier Models (`services/verifier/app/vvp/`)

### api_models.py - Request/Response Models

#### Enums
```python
class ClaimStatus(str, Enum):
    VALID = "VALID"                # Proven by evidence
    INVALID = "INVALID"            # Contradicted by evidence
    INDETERMINATE = "INDETERMINATE"  # Insufficient evidence
```

#### Request Models
```python
class SipContext(BaseModel):
    from_uri: str                  # SIP From URI
    to_uri: str                    # SIP To URI
    invite_time: str               # RFC3339 timestamp
    cseq: Optional[int] = None    # CSeq number (callee verification)

class CallContext(BaseModel):
    call_id: str                   # Call identifier
    received_at: str               # RFC3339 timestamp
    sip: Optional[SipContext]      # SIP context for alignment

class VerifyRequest(BaseModel):
    passport_jwt: str              # PASSporT JWT string
    context: CallContext           # Call context (required)

class VerifyCalleeRequest(BaseModel):
    passport_jwt: str              # Callee's PASSporT
    context: CallContext           # Must include call_id + sip.cseq
    caller_passport_jwt: Optional[str]  # For goal overlap check
```

#### Response Models
```python
class ChildLink(BaseModel):
    required: bool                 # Is this child required for parent validity?
    node: ClaimNode                # The child claim node

class ClaimNode(BaseModel):
    name: str                      # Claim name (e.g., "passport_verified")
    status: ClaimStatus            # VALID/INVALID/INDETERMINATE
    reasons: List[str]             # Explanation strings
    evidence: List[str]            # SAIDs or references
    children: List[ChildLink]      # Child claims

class ErrorDetail(BaseModel):
    code: str                      # ErrorCode constant
    message: str                   # Human-readable message
    recoverable: bool              # Can be retried?

class VerifyResponse(BaseModel):
    request_id: str                # UUID
    overall_status: ClaimStatus    # Final status
    claims: Optional[List[ClaimNode]]
    errors: Optional[List[ErrorDetail]]
    has_variant_limitations: bool  # Compact/partial ACDCs present?
    delegation_chain: Optional[DelegationChainResponse]
    signer_aid: Optional[str]
    toip_warnings: Optional[List[ToIPWarningDetail]]
    issuer_identities: Optional[Dict[str, IssuerIdentityInfo]]
    vetter_constraints: Optional[Dict[str, VetterConstraintInfo]]
    brand_name: Optional[str]     # From PASSporT card claim
    brand_logo_url: Optional[str] # From PASSporT card claim

class DelegationChainResponse(BaseModel):
    chain: List[DelegationNodeResponse]
    depth: int
    root_aid: Optional[str]
    is_valid: bool
    errors: List[str]

class VetterConstraintInfo(BaseModel):
    credential_said: str
    credential_type: str           # "TN", "Identity", "Brand"
    constraint_type: str           # "ecc" or "jurisdiction"
    target_value: str              # e.g., "44" for ECC
    allowed_values: List[str]
    is_authorized: bool
    reason: str
```

### exceptions.py - Domain Exceptions
```python
class VVPIdentityError(Exception):
    code: str    # ErrorCode constant
    message: str
    # Factory methods: .missing(), .invalid(reason)

class PassportError(Exception):
    code: str
    message: str
    # Factory methods: .missing(), .parse_failed(reason),
    #                  .forbidden_alg(alg), .expired(reason)
```

### acdc/acdc.py - ACDC Model
```python
@dataclass
class ACDC:
    said: str                      # Content-derived identifier
    issuer: str                    # Issuer AID
    issuee: Optional[str]         # Subject AID
    schema_said: str              # Schema reference
    attributes: dict              # Attribute block
    edges: dict                   # Edge block (links to other ACDCs)
    raw: dict                     # Original JSON
    variant: str                  # "full", "compact", "partial"
    registry_said: Optional[str]  # Registry for revocation
    credential_type: str          # Inferred: "LE", "APE", "DE", "TNAlloc", etc.
```

### dossier/models.py - Dossier Models
```python
@dataclass
class ACDCNode:
    acdc: ACDC
    signatures: list              # Attached signatures
    parents: List[str]            # SAIDs of parent credentials
    children: List[str]           # SAIDs of child credentials

class DossierDAG:
    nodes: Dict[str, ACDCNode]    # SAID → node
    root: Optional[ACDCNode]      # Single root node
    edges: List[Tuple[str, str]]  # (from_said, to_said)
```

---

## Issuer Models

### db/models.py - SQLAlchemy Database Models
```python
class OrgType(str, Enum):          # Sprint 67 — organization type hierarchy
    ROOT_AUTHORITY = "root_authority"   # GLEIF (issues QVI credentials)
    QVI = "qvi"                        # Qualified vLEI Issuer (issues LE credentials)
    VETTER_AUTHORITY = "vetter_authority"  # GSMA (issues VetterCert, Governance)
    REGULAR = "regular"                # Standard organization (Brand, TN Alloc)

class Organization(Base):
    id: String(36)                 # UUID, primary key
    name: String(255)              # Organization name, unique
    pseudo_lei: String(20)         # Deterministic pseudo-LEI, unique
    aid: Optional[String(44)]      # KERI Autonomic Identifier
    le_credential_said: Optional[String(44)]  # Auto-issued LE credential
    registry_key: Optional[String(44)]  # TEL registry prefix
    vetter_certification_said: Optional[String(44)]  # Active VetterCert SAID (Sprint 61)
    org_type: String(20)           # OrgType value (Sprint 67, default "regular")
    enabled: bool                  # Tenant enabled flag (default True)
    created_at: datetime
    updated_at: datetime
    # Relationships: users, api_keys, credentials, tn_mappings

class User(Base):
    id: String(36)                 # UUID, primary key
    email: String(255)             # Email, globally unique, lowercased
    name: String(255)
    password_hash: Optional[String(255)]  # bcrypt hash (nullable for OAuth users)
    system_roles: String(255)      # Comma-separated system role list
    organization_id: Optional[String(36)]  # FK to Organization
    enabled: bool                  # Default True
    is_oauth_user: bool            # Default False
    created_at: datetime
    updated_at: datetime
    # Relationships: organization, org_roles
    # Property: system_roles_set (computed set from comma-separated string)

class UserOrgRole(Base):           # Sprint 41 — user org role join table
    __tablename__ = "user_org_roles"
    id: int                        # Auto-increment primary key
    user_id: String(36)            # FK to User (cascade delete)
    org_id: String(36)             # FK to Organization (cascade delete)
    role: String(50)               # 'org:administrator' or 'org:dossier_manager'
    created_at: datetime
    # UniqueConstraint: (user_id, org_id, role)

class OrgAPIKey(Base):
    __tablename__ = "org_api_keys"
    id: String(36)                 # UUID, primary key
    name: String(255)              # Key name
    key_hash: String(255)          # bcrypt hash
    organization_id: String(36)    # FK to Organization (cascade delete)
    revoked: bool                  # Default False
    created_at: datetime
    # Relationships: organization, roles

class OrgAPIKeyRole(Base):         # Roles assigned to an org API key
    __tablename__ = "org_api_key_roles"
    id: int                        # Auto-increment primary key
    key_id: String(36)             # FK to OrgAPIKey (cascade delete)
    role: String(50)               # 'org:administrator' or 'org:dossier_manager'
    # UniqueConstraint: (key_id, role)

class ManagedCredential(Base):     # Tracks credential ownership by organization
    __tablename__ = "managed_credentials"
    said: String(44)               # Credential SAID, primary key
    organization_id: String(36)    # FK to Organization (cascade delete)
    schema_said: String(44)        # Schema SAID
    issuer_aid: String(44)         # Issuing identity AID
    created_at: datetime

class TNMapping(Base):
    __tablename__ = "tn_mappings"
    id: String(36)                 # UUID, primary key
    tn: String(20)                 # E.164 format (e.g., +15551234567)
    organization_id: String(36)    # FK to Organization (cascade delete)
    dossier_said: String(44)       # Root credential SAID
    identity_name: String(255)     # KERI identity name for signing
    brand_name: Optional[String(255)]
    brand_logo_url: Optional[String(1024)]
    enabled: bool                  # Default True
    created_at: datetime
    updated_at: datetime
    # UniqueConstraint: (organization_id, tn), Index: tn

class DossierOspAssociation(Base):   # Sprint 63
    """Administrative record: which OSP org can reference which dossier.
    Visibility only — does NOT gate TN mapping authorization."""
    __tablename__ = "dossier_osp_associations"
    id: int                        # Primary key, autoincrement
    dossier_said: String(44)       # Dossier credential SAID
    owner_org_id: String(36)       # FK to Organization (AP), CASCADE
    osp_org_id: String(36)         # FK to Organization (OSP), CASCADE, indexed
    created_at: datetime
    # Unique constraint: (dossier_said, osp_org_id)

class MockVLEIState(Base):            # Persists mock vLEI infrastructure state
    __tablename__ = "mock_vlei_state"
    id: int                        # Primary key (single row expected)
    gleif_aid: String(44)          # Mock GLEIF root AID
    gleif_registry_key: String(44)
    qvi_aid: String(44)            # Mock QVI AID
    qvi_credential_said: String(44) # QVI credential SAID
    qvi_registry_key: String(44)
    gsma_aid: Optional[String(44)]  # Mock GSMA AID (Sprint 61)
    gsma_registry_key: Optional[String(44)]  # Mock GSMA registry (Sprint 61)
    gsma_governance_said: Optional[String(44)]  # GSMA governance cred (Sprint 62)
    gleif_org_id: Optional[String(36)]  # FK to Organization (Sprint 67)
    qvi_org_id: Optional[String(36)]    # FK to Organization (Sprint 67)
    gsma_org_id: Optional[String(36)]   # FK to Organization (Sprint 67)
```

### api/models.py - Issuer API Models (complete inventory)
All Pydantic request/response models for the issuer API. Source: `services/issuer/app/api/models.py`.

#### Identity Models
```python
class CreateIdentityRequest(BaseModel):
    name: str                      # Human-readable alias
    transferable: bool = True      # Whether keys can rotate
    key_count: Optional[int]       # Number of signing keys
    key_threshold: Optional[str]   # Signing threshold
    next_key_count: Optional[int]  # Number of next keys
    next_threshold: Optional[str]  # Next signing threshold
    publish_to_witnesses: bool = True

class IdentityResponse(BaseModel):
    aid: str                       # Autonomic Identifier
    name: str                      # Alias
    created_at: Optional[str]      # ISO8601
    witness_count: int
    key_count: int
    sequence_number: int
    transferable: bool

class OobiResponse(BaseModel):
    aid: str
    oobi_urls: list[str]

class CreateIdentityResponse(BaseModel):
    identity: IdentityResponse
    oobi_urls: list[str]
    publish_results: Optional[list[WitnessPublishResult]]

class RotateIdentityRequest(BaseModel):
    next_key_count: Optional[int]
    next_threshold: Optional[str]
    publish_to_witnesses: bool = True

class WitnessPublishDetail(BaseModel):
    witness_url: str
    success: bool
    error: Optional[str]

class RotateIdentityResponse(BaseModel):
    identity: IdentityResponse
    previous_sequence_number: int
    publish_results: Optional[list[WitnessPublishDetail]]
    publish_threshold_met: bool = True

class IdentityListResponse(BaseModel):
    identities: list[IdentityResponse]
    count: int
```

#### Common Response Models
```python
class DeleteResponse(BaseModel):
    deleted: bool
    resource_type: str
    resource_id: str
    message: Optional[str]

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str]

class HealthResponse(BaseModel):
    ok: bool
    service: str = "vvp-issuer"
    identities_loaded: int = 0
```

#### Registry Models
```python
class CreateRegistryRequest(BaseModel):
    name: str
    identity_name: Optional[str]   # Issuer identity by name
    issuer_aid: Optional[str]      # Issuer identity by AID
    no_backers: bool = True
    publish_to_witnesses: bool = True

class RegistryResponse(BaseModel):
    registry_key: str              # Registry prefix (regk)
    name: str
    issuer_aid: str
    created_at: Optional[str]
    sequence_number: int
    no_backers: bool

class CreateRegistryResponse(BaseModel):
    registry: RegistryResponse
    publish_results: Optional[list[WitnessPublishResult]]

class RegistryListResponse(BaseModel):
    registries: list[RegistryResponse]
    count: int
```

#### Schema Models
```python
class SchemaResponse(BaseModel):
    said: str
    title: str
    description: Optional[str]
    source: Optional[str]          # embedded, imported, custom
    schema_document: Optional[dict]

class SchemaListResponse(BaseModel):
    schemas: list[SchemaResponse]
    count: int

class SchemaValidationRequest(BaseModel):
    said: str
    credential_type: Optional[str]

class SchemaValidationResponse(BaseModel):
    said: str
    valid: bool
    credential_type: Optional[str]

class SchemaImportRequest(BaseModel):
    source: str                    # 'weboftrust' or 'url'
    schema_id: Optional[str]
    url: Optional[str]
    verify_said: bool = True

class SchemaImportResponse(BaseModel):
    said: str
    title: str
    source: str
    verified: bool

class SchemaCreateRequest(BaseModel):
    title: str
    description: Optional[str]
    credential_type: str = "VerifiableCredential"
    properties: Optional[dict]

class SchemaCreateResponse(BaseModel):
    said: str
    title: str
    schema_document: dict

class SchemaVerifyResponse(BaseModel):
    said: str
    valid: bool
    computed_said: Optional[str]

class WebOfTrustRegistryResponse(BaseModel):
    schemas: list[dict]
    count: int
    ref: str                       # Git ref used
```

#### Credential Models
```python
class IssueCredentialRequest(BaseModel):
    registry_name: str
    schema_said: str
    attributes: dict               # Credential attributes (a section)
    recipient_aid: Optional[str]
    edges: Optional[dict]
    rules: Optional[dict]
    private: bool = False
    publish_to_witnesses: bool = True
    organization_id: Optional[str] # Cross-org issuance (Sprint 61)

class CredentialResponse(BaseModel):
    said: str
    issuer_aid: str
    recipient_aid: Optional[str]
    registry_key: str
    schema_said: str
    issuance_dt: str
    status: str                    # "issued" or "revoked"
    revocation_dt: Optional[str]
    relationship: Optional[str]    # "issued" or "subject"
    issuer_name: Optional[str]
    recipient_name: Optional[str]

class CredentialDetailResponse(CredentialResponse):
    attributes: dict
    edges: Optional[dict]
    rules: Optional[dict]

class IssueCredentialResponse(BaseModel):
    credential: CredentialResponse
    publish_results: Optional[list[WitnessPublishResult]]

class RevokeCredentialRequest(BaseModel):
    reason: Optional[str]
    publish_to_witnesses: bool = True

class RevokeCredentialResponse(BaseModel):
    credential: CredentialResponse
    publish_results: Optional[list[WitnessPublishResult]]

class CredentialListResponse(BaseModel):
    credentials: list[CredentialResponse]
    count: int
```

#### Dossier Models
```python
# Sprint 63 — Dossier Creation Wizard
class CreateDossierRequest(BaseModel):
    owner_org_id: str              # AP organization ID
    edges: dict[str, str]          # {edge_name: credential_SAID}
    name: Optional[str]
    osp_org_id: Optional[str]      # OSP org to associate

class CreateDossierResponse(BaseModel):
    dossier_said: str
    issuer_aid: str
    schema_said: str
    edge_count: int
    name: Optional[str]
    osp_org_id: Optional[str]
    dossier_url: str
    publish_results: Optional[list[WitnessPublishResult]]

class AssociatedDossierEntry(BaseModel):
    dossier_said: str
    owner_org_id: str
    owner_org_name: Optional[str]
    osp_org_id: str
    osp_org_name: Optional[str]
    created_at: str

class AssociatedDossierListResponse(BaseModel):
    associations: list[AssociatedDossierEntry]
    count: int

# Sprint 65 — Dossier Readiness Assessment
class DossierSlotStatus(BaseModel):
    edge: str                      # Edge name (vetting, alloc, tnalloc, etc.)
    label: str                     # Human-readable label
    required: bool
    schema_constraint: Optional[str]  # Required schema SAID (if constrained)
    available_count: int
    total_count: int
    status: str                    # "ready", "missing", "invalid", "optional_missing", "optional_unconstrained"

class DossierReadinessResponse(BaseModel):
    org_id: str
    org_name: str
    ready: bool                    # All required slots ready
    slots: list[DossierSlotStatus]
    blocking_reason: Optional[str]

class OrganizationNameResponse(BaseModel):
    id: str
    name: str
    aid: Optional[str]             # Included when purpose=ap (Sprint 65)

class OrganizationNameListResponse(BaseModel):
    organizations: list[OrganizationNameResponse]
    count: int

class BuildDossierRequest(BaseModel):
    root_said: str
    root_saids: Optional[list[str]]
    format: str = "cesr"
    include_tel: bool = True

class DossierInfoResponse(BaseModel):
    root_said: str
    root_saids: list[str]
    credential_count: int
    is_aggregate: bool
    format: str
    content_type: str
    size_bytes: int
    warnings: list[str]

class BuildDossierResponse(BaseModel):
    dossier: DossierInfoResponse
```

#### Session & Org Context Models (Sprint 67)
```python
@dataclass
class Session:
    session_id: str
    key_id: str
    principal: Principal
    created_at: datetime
    expires_at: datetime
    home_org_id: Optional[str] = None     # Immutable: user's actual org (Sprint 67)
    active_org_id: Optional[str] = None   # Mutable: switched org context (Sprint 67)

class SwitchOrgRequest(BaseModel):
    organization_id: Optional[str] = None  # None reverts to home org

class SwitchOrgResponse(BaseModel):
    active_org_id: Optional[str]
    active_org_name: Optional[str]
    active_org_type: Optional[str]
    home_org_id: Optional[str]
    home_org_name: Optional[str]

class AuthStatusResponse(BaseModel):
    authenticated: bool
    method: Optional[str]
    user_email: Optional[str]
    user_name: Optional[str]
    user_id: Optional[str]
    is_system_admin: bool
    roles: list[str]
    organization_id: Optional[str]         # Effective org (active if switched)
    organization_name: Optional[str]
    home_org_id: Optional[str] = None      # User's actual org (Sprint 67)
    home_org_name: Optional[str] = None
    home_org_type: Optional[str] = None    # Admin's own org type (Sprint 67)
    active_org_id: Optional[str] = None    # Switched org (Sprint 67)
    active_org_name: Optional[str] = None
    active_org_type: Optional[str] = None
```

#### Schema Authorization (Sprint 67)
```python
# app/auth/schema_auth.py — Hard-coded mapping (trust chain is spec-defined)
SCHEMA_AUTHORIZATION: dict[OrgType, set[str]] = {
    OrgType.ROOT_AUTHORITY: {QVI_SAID},
    OrgType.QVI: {LE_SAID, EXT_LE_SAID},
    OrgType.VETTER_AUTHORITY: {VETTER_CERT_SAID, GOVERNANCE_SAID},
    OrgType.REGULAR: {EXT_BRAND_SAID, TN_ALLOC_SAID, EXT_TN_ALLOC_SAID, DE_GCD_SAID},
}

def is_schema_authorized(org_type: str, schema_said: str) -> bool
def get_authorized_schemas(org_type: str) -> set[str]
```

#### VVP Header/PASSporT Models
```python
class CreateVVPRequest(BaseModel):
    identity_name: str
    dossier_said: str
    orig_tn: str                   # E.164 format
    dest_tn: list[str]             # E.164 format
    exp_seconds: int = 300         # Max 300
    call_id: Optional[str]         # SIP Call-ID for dialog binding
    cseq: Optional[int]            # SIP CSeq for dialog binding

class CreateVVPResponse(BaseModel):
    vvp_identity_header: str       # Base64url VVP-Identity
    passport_jwt: str              # Signed PASSporT JWT
    dossier_url: str
    kid_oobi: str
    iat: int
    exp: int
    identity_header: str           # RFC 8224 Identity header
    revocation_status: str = "TRUSTED"
```

#### TN Mapping Models
```python
class CreateTNMappingRequest(BaseModel):
    tn: str                        # E.164 (e.g., +15551234567)
    dossier_said: str              # Root credential SAID (44 chars)
    identity_name: str             # KERI identity name

class UpdateTNMappingRequest(BaseModel):
    dossier_said: Optional[str]
    identity_name: Optional[str]
    brand_name: Optional[str]
    brand_logo_url: Optional[str]
    enabled: Optional[bool]

class TNMappingResponse(BaseModel):
    id: str                        # UUID
    tn: str
    organization_id: str
    dossier_said: str
    identity_name: str
    brand_name: Optional[str]
    brand_logo_url: Optional[str]
    enabled: bool
    created_at: str
    updated_at: str

class TNMappingListResponse(BaseModel):
    count: int
    mappings: list[TNMappingResponse]

class TNLookupRequest(BaseModel):
    tn: str                        # E.164 format
    api_key: str

class TNLookupResponse(BaseModel):
    found: bool
    tn: Optional[str]
    organization_id: Optional[str]
    organization_name: Optional[str]
    dossier_said: Optional[str]
    identity_name: Optional[str]
    brand_name: Optional[str]
    brand_logo_url: Optional[str]
    error: Optional[str]
```

#### Vetter Certification Models (Sprint 61)
```python
class VetterCertificationCreateRequest(BaseModel):
    organization_id: str           # Target org UUID
    ecc_targets: list[str]         # E.164 country codes (validated against VALID_ECC_CODES)
    jurisdiction_targets: list[str]  # ISO 3166-1 alpha-3 codes (validated against VALID_JURISDICTION_CODES)
    name: str                      # Vetter name (1-255 chars)
    certification_expiry: Optional[str]  # ISO8601 UTC, alias "certificationExpiry"

class VetterCertificationResponse(BaseModel):
    said: str
    issuer_aid: str                # Mock GSMA AID
    vetter_aid: str                # Org AID
    organization_id: str
    organization_name: str
    ecc_targets: list[str]
    jurisdiction_targets: list[str]
    name: str
    certification_expiry: Optional[str]  # Alias "certificationExpiry"
    status: str                    # "issued" or "revoked"
    created_at: str

class VetterCertificationListResponse(BaseModel):
    certifications: list[VetterCertificationResponse]
    count: int

class OrganizationConstraintsResponse(BaseModel):
    organization_id: str
    organization_name: str
    vetter_certification_said: Optional[str]
    ecc_targets: Optional[list[str]]
    jurisdiction_targets: Optional[list[str]]
    certification_status: Optional[str]
    certification_expiry: Optional[str]
```

---

## Common Models (`common/`)

### vvp/sip/models.py - Shared SIP Models
```python
@dataclass
class SIPRequest:
    method: str                    # INVITE, BYE, etc.
    request_uri: str               # Target URI
    sip_version: str = "SIP/2.0"
    via: list[str]                 # All Via headers (RFC 3261)
    from_header: str               # From header value
    to_header: str                 # To header value
    call_id: str                   # Call-ID header
    cseq: str                      # CSeq header
    from_tn: Optional[str]         # Extracted caller TN (E.164)
    to_tn: Optional[str]           # Extracted callee TN (E.164)
    vvp_api_key: Optional[str]     # X-VVP-API-Key (signing)
    identity_header: Optional[str] # RFC 8224 Identity header
    p_vvp_identity: Optional[str]  # P-VVP-Identity (base64url JSON)
    p_vvp_passport: Optional[str]  # P-VVP-Passport (JWT)
    contact: Optional[str]
    headers: dict                  # All headers dict (for monitoring)
    source_addr: Optional[str]     # Source address (for monitoring)
    raw: bytes                     # Raw message for debugging
    # Properties: is_invite, has_verification_headers, has_signing_headers

@dataclass
class SIPResponse:
    status_code: int               # 302, 400, 401, 403, 404, 500
    reason_phrase: str
    sip_version: str = "SIP/2.0"
    via: list[str]                 # Copied from request (RFC 3261)
    from_header: str               # Copied from request
    to_header: str                 # Copied from request (with tag)
    call_id: str                   # Copied from request
    cseq: str                      # Copied from request
    contact: Optional[str]         # Redirect destination
    identity: Optional[str]        # RFC 8224 Identity header
    vvp_identity: Optional[str]    # P-VVP-Identity header
    vvp_passport: Optional[str]    # P-VVP-Passport header
    vvp_status: str = "INDETERMINATE"  # VALID | INVALID | INDETERMINATE
    brand_name: Optional[str]      # X-VVP-Brand-Name
    brand_logo_url: Optional[str]  # X-VVP-Brand-Logo
    caller_id: Optional[str]       # X-VVP-Caller-ID
    vetter_status: Optional[str]   # X-VVP-Vetter-Status (Sprint 62)
    error_reason: Optional[str]    # Error info for non-2xx
    error_code: Optional[str]      # X-VVP-Error code
    # Method: to_bytes() -> bytes
```

### vvp/sip/builder.py - SIP Response Builder
Factory functions for SIP responses (all copy transaction headers per RFC 3261):
- `build_302_redirect(request, contact_uri, identity, vvp_identity, vvp_passport, vvp_status, brand_name, brand_logo_url, caller_id, error_code, vetter_status)` — VVP redirect with all headers
- `build_400_bad_request(request, reason)` — Malformed request
- `build_401_unauthorized(request, reason, vvp_status="INVALID")` — Auth failure
- `build_403_forbidden(request, reason, vvp_status="INVALID")` — Authorization denied
- `build_404_not_found(request, reason, vvp_status="INVALID")` — TN not mapped
- `build_500_error(request, reason, vvp_status="INDETERMINATE")` — Internal error

### vvp/canonical/ - Serialization
- `said.py`: SAID computation (Blake3-256)
- `cesr.py`: CESR encoding/decoding
- `parser.py`: CESR stream parsing
- `keri_canonical.py`: KERI canonical JSON serialization

### vvp/schema/ - Schema Infrastructure
- `registry.py`: Schema SAID → credential type mapping
- `store.py`: Schema storage and retrieval
- `validator.py`: JSON Schema validation of ACDC attributes

### vvp/models/keri_agent.py - KERI Agent Client DTOs (Sprint 68b)
Shared request/response models defining the API contract between the KERI Agent service and the Issuer API. Data transfer objects only — no KERI/LMDB logic.

```python
# Identity DTOs
class CreateIdentityRequest(BaseModel):
    name: str                      # Human-readable identity alias
    key_count: int = 1             # Number of signing keys
    key_threshold: str = "1"       # Signing threshold expression
    next_key_count: int = 1        # Number of pre-rotated next keys
    next_threshold: str = "1"      # Next key threshold expression
    transferable: bool = True      # Whether keys can be rotated

class IdentityResponse(BaseModel):
    aid: str                       # Autonomic Identifier
    name: str                      # Human-readable alias
    created_at: str                # ISO8601 creation timestamp
    witness_count: int
    key_count: int
    sequence_number: int
    transferable: bool

class RotateKeysRequest(BaseModel):
    new_key_count: int | None      # None = keep current
    new_threshold: str | None      # None = keep current

class RotationResponse(BaseModel):
    aid: str
    name: str
    previous_sequence_number: int
    new_sequence_number: int
    new_key_count: int

# Registry DTOs
class CreateRegistryRequest(BaseModel):
    name: str
    identity_name: str
    no_backers: bool = True

class RegistryResponse(BaseModel):
    registry_key: str              # TEL registry prefix
    name: str
    identity_aid: str
    identity_name: str
    credential_count: int = 0
    no_backers: bool = True

# Credential DTOs
class IssueCredentialRequest(BaseModel):
    identity_name: str
    registry_name: str
    schema_said: str
    recipient_aid: str | None
    attributes: dict               # The 'a' block
    edges: dict | None
    rules: dict | None
    publish: bool = True

class CredentialResponse(BaseModel):
    said: str
    issuer_aid: str
    recipient_aid: str | None
    registry_key: str
    schema_said: str
    issuance_dt: str
    status: str                    # "issued" | "revoked"
    revocation_dt: str | None
    attributes: dict
    edges: dict | None
    rules: dict | None

class RevokeCredentialRequest(BaseModel):
    publish: bool = True

# Dossier DTOs
class BuildDossierRequest(BaseModel):
    root_said: str
    root_saids: list[str] | None
    include_tel: bool = True

class DossierResponse(BaseModel):
    root_said: str
    root_saids: list[str]
    credential_saids: list[str]    # Topological order
    is_aggregate: bool = False
    warnings: list[str]

# Bootstrap DTOs
class BootstrapStatusResponse(BaseModel):
    initialized: bool
    gleif_aid: str | None
    gleif_registry_key: str | None
    qvi_aid: str | None
    qvi_registry_key: str | None
    gsma_aid: str | None
    gsma_registry_key: str | None
    gleif_name: str | None
    qvi_name: str | None
    gsma_name: str | None
    qvi_credential_said: str | None    # For LE edge construction
    gsma_governance_said: str | None   # For vetter cert edges

# Operational DTOs
class AgentHealthResponse(BaseModel):
    status: str                    # "ok" | "unhealthy"
    identity_count: int = 0
    registry_count: int = 0
    credential_count: int = 0
    lmdb_accessible: bool = True

class AgentStatsResponse(BaseModel):
    identity_count: int = 0
    registry_count: int = 0
    credential_count: int = 0

class AgentErrorResponse(BaseModel):
    detail: str
    error_code: str | None
```

---

## Error Code Registry

See `services/verifier/app/vvp/api_models.py:ErrorCode` for the complete registry.

Key error codes by layer:
- **Protocol**: VVP_IDENTITY_*, PASSPORT_*, CONTEXT_MISMATCH, DIALOG_MISMATCH
- **Crypto**: PASSPORT_SIG_INVALID, PASSPORT_FORBIDDEN_ALG, ACDC_SAID_MISMATCH
- **Evidence**: DOSSIER_*, CREDENTIAL_REVOKED, BRAND_CREDENTIAL_INVALID
- **KERI**: KERI_RESOLUTION_FAILED, KERI_STATE_INVALID
- **Authorization**: AUTHORIZATION_FAILED, TN_RIGHTS_INVALID
- **Vetter**: VETTER_ECC_UNAUTHORIZED, VETTER_JURISDICTION_UNAUTHORIZED
- **Internal**: INTERNAL_ERROR
