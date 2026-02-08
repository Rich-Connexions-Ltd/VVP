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
class Organization(Base):
    id: UUID                       # Primary key
    name: str                      # Organization name
    lei: Optional[str]             # Legal Entity Identifier
    aid: Optional[str]             # KERI AID
    le_credential_said: Optional[str]  # Auto-issued LE credential
    status: str                    # "active", "suspended"
    created_at: datetime
    updated_at: datetime

class OrgAPIKey(Base):
    id: UUID
    organization_id: UUID          # FK to Organization
    key_hash: str                  # Hashed API key
    key_prefix: str                # First 8 chars for identification
    name: str                      # Human-readable name
    roles: str                     # JSON list of roles
    is_active: bool
    created_at: datetime

class Credential(Base):
    said: str                      # Primary key (SAID)
    organization_id: UUID          # FK to Organization
    schema_said: str
    credential_type: str
    issuer_aid: str
    issuee_aid: Optional[str]
    registry_key: str
    status: str                    # "issued", "revoked"
    raw_json: str                  # Full credential JSON

class Dossier(Base):
    id: UUID
    organization_id: UUID
    root_credential_said: str
    format: str                    # "cesr" or "json"
    content: bytes                 # Serialized dossier
    credential_count: int

class TNMapping(Base):
    id: UUID
    organization_id: UUID
    telephone_number: str          # E.164 format
    dossier_id: UUID               # FK to Dossier
    signing_identity_aid: str      # AID for signing
    enabled: bool
    brand_name: Optional[str]
    brand_logo_url: Optional[str]

class User(Base):
    id: UUID
    email: str
    password_hash: str
    name: str
    roles: str                     # JSON list
    organization_id: Optional[UUID]
    is_active: bool
```

### api/models.py - Issuer API Models
Request/response Pydantic models for all issuer endpoints. Key models:

```python
class CreateIdentityRequest(BaseModel):
    name: str
    witness_urls: Optional[List[str]]

class IssueCredentialRequest(BaseModel):
    schema_said: str
    issuer_aid: str
    issuee_aid: Optional[str]
    registry_key: str
    attributes: dict
    edges: Optional[dict]

class CreateTNMappingRequest(BaseModel):
    telephone_number: str          # E.164
    dossier_id: str
    signing_identity_aid: str
    brand_name: Optional[str]
    brand_logo_url: Optional[str]

class TNLookupRequest(BaseModel):
    telephone_number: str          # E.164 format

class CreateOrganizationRequest(BaseModel):
    name: str
    lei: Optional[str]
```

---

## Common Models (`common/`)

### vvp/sip/models.py - Shared SIP Models
```python
class SIPRequest(BaseModel):
    method: str                    # INVITE, BYE, etc.
    request_uri: str               # Target URI
    sip_version: str               # SIP/2.0
    headers: Dict[str, str]        # All headers
    body: Optional[str]            # SDP body
    raw: bytes                     # Original bytes
    from_tn: Optional[str]         # Extracted caller TN
    to_tn: Optional[str]           # Extracted callee TN
    call_id: Optional[str]
    cseq: Optional[str]
    via: Optional[str]
    api_key: Optional[str]         # X-VVP-API-Key
    identity_header: Optional[str] # Identity (PASSporT)
    vvp_identity_header: Optional[str]  # VVP-Identity
```

### vvp/canonical/ - Serialization
- `said.py`: SAID computation (Blake3-256)
- `cesr.py`: CESR encoding/decoding
- `parser.py`: CESR stream parsing
- `keri_canonical.py`: KERI canonical JSON serialization

### vvp/schema/ - Schema Infrastructure
- `registry.py`: Schema SAID → credential type mapping
- `store.py`: Schema storage and retrieval
- `validator.py`: JSON Schema validation of ACDC attributes

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
