"""Credential card view-model adapter.

This module provides dataclasses and an adapter function to normalize
raw ACDC credentials into a template-friendly view-model. This decouples
templates from ACDC field naming variations across schemas.

Per Sprint 21 plan (PLAN_Credential_Card_UI.md):
- Normalizes schema-specific attribute fields (tn, phone, legalName, etc.)
- Separates ClaimStatus (VALID/INVALID/INDETERMINATE) from revocation state
- Handles edges as strings, dicts with 'n', or dicts with 'd'
- Surfaces compact/partial variant limitations for UI banners
- Checks issuer against TRUSTED_ROOT_AIDS for trust anchor display
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import TRUSTED_ROOT_AIDS
from common.vvp.models import ACDC, ACDCChainResult
from app.vvp.gleif import lookup_lei


# =============================================================================
# Sprint 24: Evidence Status Enum
# =============================================================================


class EvidenceStatus(str, Enum):
    """Evidence fetch status values.

    Used consistently across EvidenceFetchRecord, timeline rendering, and CSS badges.
    Per Sprint 24 plan: normalized status enum for evidence retrieval operations.
    """

    SUCCESS = "SUCCESS"  # Fetch succeeded
    FAILED = "FAILED"  # Fetch failed with error
    CACHED = "CACHED"  # Served from cache
    INDETERMINATE = "INDETERMINATE"  # Could not determine (e.g., schema unavailable)


# =============================================================================
# View-Model Dataclasses
# =============================================================================


@dataclass
class RevocationStatus:
    """Revocation state (independent of ClaimStatus).

    ClaimStatus values are VALID/INVALID/INDETERMINATE based on chain validation.
    RevocationStatus tracks the TEL/registry state separately.

    Attributes:
        state: ACTIVE, REVOKED, or UNKNOWN.
        checked_at: RFC3339 timestamp of last check, or None if not checked.
        source: Where the revocation data came from (witness, oobi, inline, unknown).
        error: Error message if the revocation check failed.
    """

    state: str = "UNKNOWN"
    checked_at: Optional[str] = None
    source: str = "unknown"
    error: Optional[str] = None


@dataclass
class KeyStateInfo:
    """Key state information for a resolved AID.

    Populated when an AID is resolved via OOBI/KEL lookup. Provides
    visibility into the cryptographic key state at verification time.

    Attributes:
        sequence: Current key event sequence number (0 = inception).
        establishment_type: Type of current establishment event (icp, rot, dip, drt).
        rotated: True if key has been rotated (sequence > 0).
        witness_count: Number of witnesses backing this AID.
        witness_threshold: TOAD (threshold of accountable duplicity).
        is_delegated: True if this AID is delegated.
        delegator_aid: Delegator AID if delegated (truncated for display).
        resolution_source: Source of key state (oobi, witness, cache).
        resolved_at: RFC3339 timestamp when key state was resolved.
        signature_verified: True if signature was verified against this key state.
        valid_from: RFC3339 timestamp when current key state became valid.
        signing_key_count: Number of current signing keys.
        first_key_fingerprint: Truncated first signing key (base64, first 12 chars).
        establishment_said: SAID of the establishment event.
        witness_aids: List of witness AIDs (truncated for display).
        delegation_chain: List of delegator AIDs from leaf to root (truncated).
        delegation_root_aid: The non-delegated root AID (truncated).
        delegation_chain_valid: Whether the delegation chain was validated.
        delegation_depth: Number of delegation levels (0 if not delegated).
    """

    sequence: int = 0
    establishment_type: str = "icp"
    rotated: bool = False
    witness_count: int = 0
    witness_threshold: int = 0
    is_delegated: bool = False
    delegator_aid: Optional[str] = None
    resolution_source: str = "unknown"
    resolved_at: Optional[str] = None
    signature_verified: bool = False
    valid_from: Optional[str] = None
    # New fields for additional key state visibility
    signing_key_count: int = 0
    first_key_fingerprint: Optional[str] = None
    establishment_said: Optional[str] = None
    witness_aids: Optional[List[str]] = None
    # Delegation chain fields
    delegation_chain: Optional[List[str]] = None
    delegation_root_aid: Optional[str] = None
    delegation_chain_valid: bool = False
    delegation_depth: int = 0


@dataclass
class IssuerInfo:
    """Issuer identity information.

    Attributes:
        aid: Full issuer AID string.
        aid_short: Truncated AID for display (first 16 chars + "...").
        is_trusted_root: True if this AID is in TRUSTED_ROOT_AIDS.
        display_name: Human-readable name from LE credential (if available).
        lei: Legal Entity Identifier from LE credential (if available).
        gleif_legal_name: Legal name from GLEIF API lookup (if LEI available).
        key_state: Resolved key state info (if AID was resolved via OOBI).
    """

    aid: str
    aid_short: str
    is_trusted_root: bool
    display_name: Optional[str] = None
    lei: Optional[str] = None
    gleif_legal_name: Optional[str] = None
    key_state: Optional[KeyStateInfo] = None


@dataclass
class AttributeDisplay:
    """Normalized attribute for display.

    Attributes:
        label: Human-readable label (e.g., "Phone Number", "Legal Name").
        value: Display value, or special markers like "—" or "(redacted)".
        css_class: Optional CSS class for styling (e.g., "attr-bool-true", "attr-date").
        tooltip: Normative description for mouseover, from FIELD_DESCRIPTIONS.
        raw_key: Original field key (for Raw Contents display).
    """

    label: str
    value: str
    css_class: str = ""
    tooltip: str = ""
    raw_key: str = ""


@dataclass
class AttributeSection:
    """Group of related attributes for collapsible display.

    Attributes:
        name: Section header (e.g., "Dates & Times", "Identity").
        css_class: CSS class for styling (e.g., "section-dates").
        attributes: List of attributes in this section.
        initially_open: Whether section should be expanded by default.
    """

    name: str
    css_class: str
    attributes: List[AttributeDisplay]
    initially_open: bool = True


@dataclass
class EdgeLink:
    """Normalized edge link for chain expansion.

    Attributes:
        said: Target credential SAID, or None if edge is malformed.
        label: Human-readable label (e.g., "Vetted By", "Legal Entity").
        available: True if the target credential exists in the current dossier.
    """

    said: Optional[str]
    label: str
    available: bool


@dataclass
class VariantLimitations:
    """Surfaces data limitations for compact/partial variants.

    Templates use this to display banners and disable features when
    credential data is incomplete.

    Attributes:
        has_variant_limitations: True if any limitation applies.
        missing_edge_targets: SAIDs of edges not found in dossier.
        redacted_fields: Field names that have placeholder values.
        is_compact: True if attributes is a SAID reference (not expanded).
        is_partial: True if some fields have placeholder values.
        verification_impact: Impact description (e.g., "Status INDETERMINATE per §2.2").
        remediation_hints: List of suggested actions to resolve limitations.
    """

    has_variant_limitations: bool = False
    missing_edge_targets: List[str] = field(default_factory=list)
    redacted_fields: List[str] = field(default_factory=list)
    is_compact: bool = False
    is_partial: bool = False
    verification_impact: Optional[str] = None
    remediation_hints: List[str] = field(default_factory=list)


@dataclass
class RawACDCData:
    """Raw ACDC data for debug/details panel.

    Attributes:
        attributes: Original attributes dict or SAID string.
        edges: Original edges dict.
        source_format: Format the credential was parsed from (json, cesr).
    """

    attributes: Any = None
    edges: Optional[Dict[str, Any]] = None
    source_format: str = "json"


@dataclass
class VCardInfo:
    """Parsed vCard data from credential attributes.

    vCard fields are stored as a list of RFC 6350 lines in the
    credential's `vcard` attribute. This dataclass holds the
    parsed, display-ready values.

    Attributes:
        logo_url: URL extracted from LOGO;VALUE=URI:... line.
        logo_hash: SHA-256 hash from LOGO;HASH=... (for integrity check).
        org: Organization name from ORG: line.
        lei: LEI from NOTE;LEI:... line.
        gleif_legal_name: Legal name from GLEIF API lookup (if LEI available).
        categories: Categories from CATEGORIES: line.
        fn: Full name from FN: line.
        adr: Address from ADR: line.
        tel: Telephone from TEL: line.
        email: Email from EMAIL: line.
        url: Website URL from URL: line.
        raw_lines: Original vCard lines for debugging.
    """

    logo_url: Optional[str] = None
    logo_hash: Optional[str] = None
    org: Optional[str] = None
    lei: Optional[str] = None
    gleif_legal_name: Optional[str] = None
    categories: Optional[str] = None
    fn: Optional[str] = None
    adr: Optional[str] = None
    tel: Optional[str] = None
    email: Optional[str] = None
    url: Optional[str] = None
    raw_lines: List[str] = field(default_factory=list)


# =============================================================================
# Sprint 24: Validation & Evidence View-Model Dataclasses
# =============================================================================


@dataclass
class ValidationCheckResult:
    """Single validation check result for dashboard strip.

    Represents one category of validation (Signature, Schema, Chain, etc.)
    with its outcome and display metadata.

    Attributes:
        name: Check category name (e.g., "Signature", "Schema", "Delegation").
        status: VALID, INVALID, or INDETERMINATE.
        short_reason: Brief reason for the status.
        spec_ref: VVP spec section reference (e.g., "§5.0").
        severity: CSS class key: "success", "error", or "warning".
    """

    name: str
    status: str
    short_reason: str
    spec_ref: Optional[str] = None
    severity: str = "success"


@dataclass
class ValidationSummary:
    """Top-level validation dashboard aggregating all checks.

    Provides an at-a-glance summary of validation outcomes across
    all categories (chain, schema, revocation, delegation, etc.).

    Attributes:
        checks: List of individual ValidationCheckResult items.
        overall_status: Worst status across all checks (INVALID > INDETERMINATE > VALID).
        failure_count: Number of INVALID checks.
        warning_count: Number of INDETERMINATE checks.
    """

    checks: List[ValidationCheckResult] = field(default_factory=list)
    overall_status: str = "VALID"
    failure_count: int = 0
    warning_count: int = 0


@dataclass
class ErrorBucketItem:
    """Single error or warning with optional remediation hint.

    Used to display actionable error information in the UI.

    Attributes:
        message: Error or warning message.
        spec_ref: VVP spec section reference (e.g., "§2.2").
        remedy_hint: Suggested action to resolve the issue.
    """

    message: str
    spec_ref: Optional[str] = None
    remedy_hint: Optional[str] = None


@dataclass
class ErrorBucket:
    """Grouped errors (INVALID) or warnings (INDETERMINATE).

    Per §2.2, INDETERMINATE is semantically different from INVALID.
    This dataclass separates them for clear UI display.

    Attributes:
        title: Bucket header ("Failures" or "Uncertainties").
        bucket_type: CSS class key: "error" or "warning".
        items: List of ErrorBucketItem in this bucket.
    """

    title: str
    bucket_type: str
    items: List[ErrorBucketItem] = field(default_factory=list)


@dataclass
class SchemaPropertyInfo:
    """Single property definition from JSON Schema.

    Represents one field in a schema's properties for display.

    Attributes:
        name: Property name/key.
        type_name: JSON Schema type (string, integer, array, object, etc.).
        description: Property description from schema (if available).
        required: True if this property is in the schema's required array.
        format: JSON Schema format hint (date-time, email, uri, etc.).
        enum_values: Allowed values if property has enum constraint.
    """

    name: str
    type_name: str
    description: str = ""
    required: bool = False
    format: Optional[str] = None
    enum_values: List[str] = field(default_factory=list)


@dataclass
class SchemaValidationInfo:
    """Schema validation details for a credential.

    Provides visibility into schema validation status, registry source,
    and any field-level validation errors.

    Attributes:
        schema_said: Schema SAID (self-addressing identifier).
        registry_source: Source of schema ("GLEIF", "Pending", "Fetched").
        validation_status: VALID, INVALID, or INDETERMINATE.
        has_governance: True if schema is in governance registry.
        field_errors: List of field-level validation errors.
        validated_count: Number of fields that passed validation.
        total_required: Total required fields in schema.
        schema_title: Human-readable title from schema document.
        schema_description: Description from schema document.
        properties: List of schema property definitions for display.
        has_document: True if the actual schema document is available.
    """

    schema_said: str
    registry_source: str
    validation_status: str
    has_governance: bool = False
    field_errors: List[str] = field(default_factory=list)
    validated_count: int = 0
    total_required: int = 0
    schema_title: str = ""
    schema_description: str = ""
    properties: List[SchemaPropertyInfo] = field(default_factory=list)
    has_document: bool = False


@dataclass
class EvidenceFetchRecord:
    """Single evidence fetch operation for timeline display.

    Records details of each evidence retrieval operation for
    debugging and transparency.

    Attributes:
        source_type: Type of evidence (OOBI, SCHEMA, TEL, DOSSIER, KEY_STATE).
        url: Fetch URL or identifier.
        status: Fetch outcome (uses EvidenceStatus enum).
        latency_ms: Fetch latency in milliseconds.
        cache_hit: True if served from cache.
        cache_ttl_remaining: Seconds until cache expiry (if cached).
        error: Error message if fetch failed.
    """

    source_type: str
    url: str
    status: EvidenceStatus
    latency_ms: Optional[int] = None
    cache_hit: bool = False
    cache_ttl_remaining: Optional[int] = None
    error: Optional[str] = None


@dataclass
class EvidenceTimeline:
    """Timeline of all evidence fetch operations.

    Aggregates fetch records for display in the UI evidence panel.

    Attributes:
        records: List of EvidenceFetchRecord in chronological order.
        total_fetch_time_ms: Sum of all fetch latencies.
        cache_hit_rate: Percentage of cache hits (0.0 to 1.0).
        failed_count: Number of failed fetches.
    """

    records: List[EvidenceFetchRecord] = field(default_factory=list)
    total_fetch_time_ms: int = 0
    cache_hit_rate: float = 0.0
    failed_count: int = 0


@dataclass
class DelegationNode:
    """Node in a delegation chain visualization.

    Represents one identifier in a multi-level delegation chain
    from leaf (delegated) to root (non-delegated).

    Attributes:
        aid: Full AID string.
        aid_short: Truncated AID for display.
        display_name: Human-readable name if resolved.
        is_root: True if this is the non-delegated root.
        authorization_status: VALID, INVALID, or INDETERMINATE.
    """

    aid: str
    aid_short: str
    display_name: Optional[str] = None
    is_root: bool = False
    authorization_status: str = "INDETERMINATE"


@dataclass
class DelegationChainInfo:
    """Complete delegation chain from leaf to root.

    Provides visibility into multi-level delegation validation
    for the UI delegation panel.

    Attributes:
        chain: List of DelegationNode from leaf to root.
        depth: Number of delegation levels.
        root_aid: AID of the non-delegated root.
        is_valid: True if entire chain validates.
        errors: List of validation errors.
    """

    chain: List[DelegationNode] = field(default_factory=list)
    depth: int = 0
    root_aid: Optional[str] = None
    is_valid: bool = False
    errors: List[str] = field(default_factory=list)


@dataclass
class DossierViewModel:
    """Top-level view model for dossier display.

    Aggregates all credentials with dossier-wide validation summary,
    evidence timeline, and error buckets.

    Attributes:
        evd_url: Evidence URL where dossier was fetched from.
        credentials: List of CredentialCardViewModel for each credential.
        validation_summary: Dossier-wide validation summary.
        evidence_timeline: Fetch timeline for all evidence retrieval.
        error_buckets: Separated failures and uncertainties.
        total_time_ms: Total processing time in milliseconds.
    """

    evd_url: str
    credentials: List["CredentialCardViewModel"] = field(default_factory=list)
    validation_summary: Optional[ValidationSummary] = None
    evidence_timeline: Optional[EvidenceTimeline] = None
    error_buckets: List[ErrorBucket] = field(default_factory=list)
    total_time_ms: int = 0


@dataclass
class CredentialCardViewModel:
    """Normalized view model for credential card rendering.

    This is the main output of build_credential_card_vm(). Templates
    should use this rather than accessing raw ACDC fields directly.

    Attributes:
        said: Credential SAID (from acdc.d / acdc.said).
        schema_said: Schema SAID (from acdc.s / acdc.schema_said).
        credential_type: Inferred type (APE, DE, TNAlloc, vLEI, LE, unknown).
        variant: ACDC variant (full, compact, partial).
        status: ClaimStatus from chain validation (VALID, INVALID, INDETERMINATE).
        revocation: Revocation state (separate from status).
        issuer: Issuer identity info.
        primary: Primary attribute for prominent display.
        secondary: Up to 3 secondary attributes (for backwards compatibility).
        sections: Categorized attribute sections for collapsible display.
        edges: Normalized edge links for chain expansion.
        limitations: Variant limitations for UI banners.
        raw: Original data for debug panel.
        raw_contents: All fields with tooltips for Raw Contents section.
        vcard: Parsed vCard data (if credential has vcard attribute).
        chain_status: Explicit chain validation result (from ACDCChainResult.status).
        schema_info: Schema validation details (Sprint 24).
        delegation_info: Delegation chain info (Sprint 24).
        validation_checks: Per-credential validation checks (Sprint 24).
    """

    said: str
    schema_said: str
    credential_type: str
    variant: str
    status: str
    revocation: RevocationStatus
    issuer: IssuerInfo
    primary: AttributeDisplay
    secondary: List[AttributeDisplay]
    sections: List[AttributeSection]
    edges: Dict[str, EdgeLink]
    limitations: VariantLimitations
    raw: RawACDCData
    raw_contents: List[AttributeDisplay] = field(default_factory=list)
    vcard: Optional[VCardInfo] = None
    # Sprint 24 additions
    chain_status: str = "INDETERMINATE"
    schema_info: Optional[SchemaValidationInfo] = None
    delegation_info: Optional[DelegationChainInfo] = None
    validation_checks: List[ValidationCheckResult] = field(default_factory=list)


# =============================================================================
# Mapping Constants
# =============================================================================

# Primary attribute source fields by credential type (checked in order)
PRIMARY_ATTRIBUTE_SOURCES: Dict[str, List[tuple[str, str]]] = {
    "APE": [("tn", "Phone Number"), ("phone", "Phone Number"), ("number", "Phone Number")],
    "DE": [("name", "Delegate Name"), ("delegateName", "Delegate Name")],
    "TNAlloc": [("tn", "Number Block"), ("block", "Number Block"), ("range", "Number Range")],
    "vLEI": [("legalName", "Legal Name"), ("LEI", "LEI")],
    "LE": [("legalName", "Legal Name"), ("LEI", "LEI")],
}

# Edge key to display label mapping
EDGE_LABELS: Dict[str, str] = {
    "vetting": "Vetted By",
    "le": "Legal Entity",
    "delegation": "Delegated By",
    "jl": "Jurisdiction",
    "jurisdiction": "Jurisdiction",
    "parent": "Parent",
    "auth": "Authorized By",
}

# Fields to exclude from secondary attributes
EXCLUDED_SECONDARY_FIELDS: Set[str] = {"d", "dt", "i", "s", "v", "n"}

# Attribute category mappings for collapsible sections
# Maps category key to (display name, list of field names)
ATTRIBUTE_CATEGORIES: Dict[str, Tuple[str, List[str]]] = {
    "identity": ("Identity", ["LEI", "legalName", "lids", "issuee", "role", "subject"]),
    "dates": ("Dates & Times", ["dt", "startDate", "endDate", "issuanceDate", "expirationDate"]),
    "permissions": ("Permissions", ["c_goal", "channel", "doNotOriginate", "authorized"]),
    "numbers": ("Numbers & Ranges", ["tn", "phone", "numbers", "rangeStart", "rangeEnd"]),
}

# Normative field descriptions from ToIP ACDC Specification
# See: https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md
FIELD_DESCRIPTIONS: Dict[str, str] = {
    # Top-level ACDC fields (normative from ToIP spec)
    "v": "Version String: Encodes protocol type, version, and serialization kind.",
    "t": "Message Type: Identifies the ACDC type or purpose.",
    "d": "SAID (Self-Addressing Identifier): Self-referential cryptographic digest that uniquely identifies this ACDC.",
    "u": "UUID: Salty nonce for privacy protection, enables compact disclosure.",
    "i": "Issuer AID: Autonomic Identifier of the issuer, established via KERI Key State.",
    "rd": "Registry Digest: SAID of the credential registry for revocation status.",
    "s": "Schema: SAID reference or embedded JSON Schema defining credential structure.",
    "a": "Attributes: Nested field map containing the credential's payload data.",
    "A": "Attribute Aggregate: Blinded aggregate of selectively disclosable attributes.",
    "e": "Edges: References to other ACDCs via SAIDs, establishing the credential chain.",
    "r": "Rules: Ricardian contract clauses defining legal terms and conditions.",
    "n": "Node: Target SAID of an edge reference to another ACDC.",
    "o": "Operator: Edge operator defining relationship semantics (AND, OR, etc.).",
    "w": "Weight: Edge weight for weighted threshold operators.",
    "l": "Legal/Liability: Terms, warranties, and conditions for credential use.",
    # Common attribute fields (descriptive, not normatively defined in ACDC spec)
    "dt": "Datetime: ISO 8601 / RFC-3339 formatted timestamp.",
    "LEI": "Legal Entity Identifier: 20-character ISO 17442 identifier for legal entities.",
    "legalName": "Legal Name: Official registered name of the legal entity.",
    "lids": "LEI Data Source: Source identifier for LEI data verification.",
    "issuee": "Issuee: AID or identifier of the credential subject/holder.",
    "role": "Role: Assigned role or function within the credential context.",
    "subject": "Subject: The entity or topic this credential describes.",
    "startDate": "Start Date: Effective start date/time for credential validity.",
    "endDate": "End Date: Expiration date/time for credential validity.",
    "issuanceDate": "Issuance Date: Date/time when this credential was issued.",
    "expirationDate": "Expiration Date: Date/time when this credential expires.",
    "c_goal": "Credential Goals: Authorized purposes or use cases for this credential.",
    "channel": "Channel: Communication channel type (voice, data, etc.).",
    "doNotOriginate": "Do Not Originate: Flag indicating call origination restrictions.",
    "authorized": "Authorized: Boolean flag for authorization status.",
    "tn": "Telephone Number: E.164 formatted telephone number or number block.",
    "phone": "Phone: Telephone number in E.164 or national format.",
    "numbers": "Numbers: Range or set of telephone numbers.",
    "rangeStart": "Range Start: First number in an allocated telephone number range.",
    "rangeEnd": "Range End: Last number in an allocated telephone number range.",
    "vcard": "vCard: Contact information in vCard format (RFC 6350).",
}


# =============================================================================
# Helper Functions
# =============================================================================


def normalize_edge(edge_value: Any) -> Optional[str]:
    """Extract target SAID from edge value.

    Edges can be:
    - A string (direct SAID reference)
    - A dict with 'n' (node) key
    - A dict with 'd' (digest) key
    - A list of the above (returns first valid)

    Args:
        edge_value: Raw edge value from ACDC.

    Returns:
        Target SAID string, or None if edge is malformed/empty.
    """
    if edge_value is None:
        return None

    if isinstance(edge_value, str):
        return edge_value if edge_value else None

    if isinstance(edge_value, dict):
        return edge_value.get("n") or edge_value.get("d")

    if isinstance(edge_value, list):
        # Return first valid SAID from list
        for item in edge_value:
            result = normalize_edge(item)
            if result:
                return result
        return None

    return None


def _truncate_aid(aid: str, length: int = 16) -> str:
    """Truncate AID for display."""
    if len(aid) <= length:
        return aid
    return f"{aid[:length]}..."


def _is_iso_date(value: str) -> bool:
    """Check if string looks like ISO 8601 date.

    Args:
        value: String to check.

    Returns:
        True if value matches YYYY-MM-DD pattern at start.
    """
    if len(value) < 10:
        return False
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", value))


def _format_date(iso_string: str) -> str:
    """Format ISO date to human-readable.

    Args:
        iso_string: ISO 8601 date string.

    Returns:
        Formatted date like "Nov 25, 2024 08:20 PM", or original if parse fails.
    """
    try:
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %I:%M %p")
    except (ValueError, AttributeError):
        return iso_string


def _is_redacted_value(value: Any) -> bool:
    """Check if a value is a redaction placeholder.

    ACDC partial disclosure uses specific placeholder values:
    - "_" : Full redaction placeholder
    - "_:type" : Typed placeholder (e.g., "_:string", "_:date")
    - "" : Empty string
    - "#" : Hash marker
    - "[REDACTED]" : Explicit redaction marker

    Args:
        value: The value to check.

    Returns:
        True if the value appears to be a redaction placeholder.
    """
    if value is None:
        return False
    if not isinstance(value, str):
        return False
    # ACDC partial disclosure placeholders
    if value == "_":
        return True
    if value.startswith("_:"):
        return True
    # Common redaction patterns
    if value in ("", "#", "[REDACTED]"):
        return True
    return False


def _format_value(value: Any, key: str = "") -> Tuple[str, str]:
    """Format a single attribute value for display.

    Args:
        value: The raw attribute value.
        key: The attribute key (unused, for future extension).

    Returns:
        Tuple of (formatted_value, css_class).
    """
    if value is None:
        return "—", "attr-null"

    # Check for redaction placeholders BEFORE other formatting
    if _is_redacted_value(value):
        return "(redacted)", "attr-redacted"

    if isinstance(value, bool):
        return ("Yes" if value else "No"), ("attr-bool-true" if value else "attr-bool-false")

    if isinstance(value, str):
        if _is_iso_date(value):
            return _format_date(value), "attr-date"
        return value, ""

    if isinstance(value, list):
        return ", ".join(str(v) for v in value), "attr-array"

    return str(value), ""


def _get_field_tooltip(key: str) -> str:
    """Get normative description for a field key.

    Looks up the field in FIELD_DESCRIPTIONS, trying both the full key
    and the base key (for nested fields like "numbers.rangeStart").

    Args:
        key: Field key, possibly with dot notation for nested fields.

    Returns:
        Description string, or empty string if not found.
    """
    # Try exact match first
    if key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[key]

    # Try base key (before first dot)
    base_key = key.split(".")[0]
    if base_key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[base_key]

    # Try last segment (for nested keys like "numbers.rangeStart")
    last_key = key.split(".")[-1]
    if last_key in FIELD_DESCRIPTIONS:
        return FIELD_DESCRIPTIONS[last_key]

    return ""


def _flatten_nested(
    attributes: Dict[str, Any],
    parent_key: str = "",
) -> List[Tuple[str, Any]]:
    """Flatten nested dicts to list of (dotted_key, value) pairs.

    Args:
        attributes: Dictionary of attributes, possibly nested.
        parent_key: Prefix for nested keys (used in recursion).

    Returns:
        List of (key, value) tuples with nested keys using dot notation.
    """
    items: List[Tuple[str, Any]] = []
    for key, value in attributes.items():
        if key.startswith("_") or key in EXCLUDED_SECONDARY_FIELDS:
            continue
        full_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(_flatten_nested(value, full_key))
        else:
            items.append((full_key, value))
    return items


def _build_attribute_sections(
    attributes: Any,
    primary_field: Optional[str] = None,
) -> List[AttributeSection]:
    """Build categorized attribute sections for collapsible display.

    Groups attributes into predefined categories (Identity, Dates, etc.)
    and formats values appropriately.

    Args:
        attributes: ACDC attributes dict.
        primary_field: Field used for primary display (excluded from sections).

    Returns:
        List of AttributeSection with categorized attributes.
    """
    if not isinstance(attributes, dict):
        return []

    # Flatten all attributes including nested
    flat = _flatten_nested(attributes)

    # Categorize each attribute
    categorized: Dict[str, List[AttributeDisplay]] = {
        "identity": [],
        "dates": [],
        "permissions": [],
        "numbers": [],
        "other": [],
    }

    for key, value in flat:
        if key == primary_field:
            continue

        # Skip empty values
        if value is None or value == "":
            continue

        formatted, css_class = _format_value(value, key)
        attr = AttributeDisplay(
            label=key.replace("_", " ").replace(".", " › ").title(),
            value=formatted,
            css_class=css_class,
            tooltip=_get_field_tooltip(key),
            raw_key=key,
        )

        # Find category based on base key (before any dots)
        category_found = "other"
        base_key = key.split(".")[0]
        for cat_key, (_, fields) in ATTRIBUTE_CATEGORIES.items():
            if base_key in fields or key in fields:
                category_found = cat_key
                break

        categorized[category_found].append(attr)

    # Build sections (only non-empty)
    sections: List[AttributeSection] = []
    for cat_key, (cat_name, _) in ATTRIBUTE_CATEGORIES.items():
        if categorized[cat_key]:
            sections.append(
                AttributeSection(
                    name=cat_name,
                    css_class=f"section-{cat_key}",
                    attributes=categorized[cat_key],
                )
            )

    if categorized["other"]:
        sections.append(
            AttributeSection(
                name="Other Attributes",
                css_class="section-other",
                attributes=categorized["other"],
            )
        )

    return sections


def _build_raw_contents(acdc_dict: Dict[str, Any]) -> List[AttributeDisplay]:
    """Build raw contents list with tooltips for all ACDC fields.

    This provides a complete view of all fields in the credential,
    with normative descriptions from the ToIP ACDC specification.

    Args:
        acdc_dict: Full ACDC dictionary including top-level fields.

    Returns:
        List of AttributeDisplay for all fields with tooltips.
    """
    result: List[AttributeDisplay] = []

    def add_field(key: str, value: Any, prefix: str = "") -> None:
        """Recursively add fields, flattening nested dicts."""
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            # Add the dict itself as a container
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value="{...}",
                    css_class="attr-object",
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )
            # Recursively add nested fields
            for nested_key, nested_value in value.items():
                add_field(nested_key, nested_value, full_key)
        elif isinstance(value, list):
            # Format list as JSON-like representation
            if len(value) <= 3:
                display_val = "[" + ", ".join(repr(v) for v in value) + "]"
            else:
                display_val = "[" + ", ".join(repr(v) for v in value[:3]) + ", ...]"
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value=display_val,
                    css_class="attr-array",
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )
        else:
            # Format scalar value
            formatted, css_class = _format_value(value, key)
            result.append(
                AttributeDisplay(
                    label=full_key,
                    value=formatted,
                    css_class=css_class,
                    tooltip=_get_field_tooltip(key),
                    raw_key=full_key,
                )
            )

    # Add all top-level fields in order
    for key, value in acdc_dict.items():
        add_field(key, value)

    return result


def _get_primary_attribute(
    credential_type: str,
    attributes: Any,
    said: str,
) -> AttributeDisplay:
    """Extract primary attribute based on credential type.

    Args:
        credential_type: Inferred credential type.
        attributes: ACDC attributes (dict or SAID string for compact).
        said: Credential SAID (fallback for unknown types).

    Returns:
        AttributeDisplay with label and value.
    """
    # Compact variant: attributes is a SAID string
    if isinstance(attributes, str):
        return AttributeDisplay(
            label="Credential",
            value=f"{_truncate_aid(said, 16)}",
        )

    # Not a dict: can't extract attributes
    if not isinstance(attributes, dict):
        return AttributeDisplay(
            label="Credential",
            value=f"{_truncate_aid(said, 16)}",
        )

    # Try to find primary attribute for this type
    sources = PRIMARY_ATTRIBUTE_SOURCES.get(credential_type, [])
    for field_name, label in sources:
        value = attributes.get(field_name)
        if value:
            # Handle list values (e.g., multiple phone numbers)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:3])
                if len(attributes.get(field_name, [])) > 3:
                    value += "..."
            return AttributeDisplay(label=label, value=str(value))

    # Fallback: truncated SAID
    return AttributeDisplay(
        label=credential_type.upper() if credential_type != "unknown" else "Credential",
        value=f"{_truncate_aid(said, 16)}",
    )


def _get_secondary_attributes(
    attributes: Any,
    primary_field: Optional[str] = None,
    max_count: int = 3,
) -> List[AttributeDisplay]:
    """Extract secondary attributes for display.

    Args:
        attributes: ACDC attributes dict.
        primary_field: Field used for primary (exclude from secondary).
        max_count: Maximum number of secondary attributes.

    Returns:
        List of AttributeDisplay for secondary attributes.
    """
    if not isinstance(attributes, dict):
        return []

    result = []
    for key, value in attributes.items():
        # Skip excluded fields
        if key in EXCLUDED_SECONDARY_FIELDS:
            continue
        # Skip primary field
        if key == primary_field:
            continue
        # Skip internal fields
        if key.startswith("_"):
            continue
        # Skip empty values
        if value is None or value == "":
            continue

        # Format the value
        if isinstance(value, list):
            display_value = ", ".join(str(v) for v in value[:2])
            if len(value) > 2:
                display_value += "..."
        elif isinstance(value, dict):
            display_value = "(complex)"
        else:
            display_value = str(value)
            if len(display_value) > 50:
                display_value = display_value[:47] + "..."

        # Human-readable label
        label = key.replace("_", " ").title()

        result.append(AttributeDisplay(label=label, value=display_value))

        if len(result) >= max_count:
            break

    return result


def _detect_redacted_fields(attributes: Any) -> List[str]:
    """Detect fields with placeholder/redacted values.

    Partial variants may have placeholder values per ACDC spec:
    - "_" : Full redaction placeholder
    - "_:type" : Typed placeholder (e.g., "_:string", "_:date")
    - "" : Empty string
    - "#" : Hash marker
    - "[REDACTED]" : Explicit redaction marker

    Args:
        attributes: ACDC attributes dict.

    Returns:
        List of field names that appear redacted.
    """
    if not isinstance(attributes, dict):
        return []

    redacted = []
    for key, value in attributes.items():
        if key.startswith("_"):
            continue

        # ACDC partial disclosure placeholders
        if value == "_":
            redacted.append(key)
        elif isinstance(value, str) and value.startswith("_:"):
            # Typed placeholder like "_:string", "_:date", "_:datetime"
            redacted.append(key)
        # Common redaction patterns
        elif value == "" or value == "#" or value == "[REDACTED]":
            redacted.append(key)
        elif isinstance(value, str) and value.startswith("E") and len(value) == 44:
            # Might be a SAID placeholder for unexpanded nested data
            # This is a heuristic; real detection would need schema info
            pass

    return redacted


def _build_edges(
    edges: Optional[Dict[str, Any]],
    available_saids: Optional[Set[str]],
) -> tuple[Dict[str, EdgeLink], List[str]]:
    """Build normalized edge links.

    Args:
        edges: Raw ACDC edges dict.
        available_saids: Set of SAIDs available in dossier for expansion.

    Returns:
        Tuple of (edges dict, list of missing SAIDs).
    """
    if not edges or not isinstance(edges, dict):
        return {}, []

    result = {}
    missing = []
    available = available_saids or set()

    for key, value in edges.items():
        # Skip metadata fields
        if key in ("d", "n"):
            continue

        said = normalize_edge(value)
        label = EDGE_LABELS.get(key, key.replace("_", " ").title())

        is_available = said in available if said else False
        if said and not is_available:
            missing.append(said)

        result[key] = EdgeLink(
            said=said,
            label=label,
            available=is_available,
        )

    return result, missing


def _parse_vcard_lines(vcard_lines: List[str]) -> VCardInfo:
    """Parse vCard lines from credential attributes.

    vCard data is stored as a list of RFC 6350 formatted lines:
    - "LOGO;HASH=sha256-...;VALUE=URI:https://..."
    - "ORG:Organization Name"
    - "NOTE;LEI:123456789012345678"
    - "CATEGORIES:..."
    - "FN:Full Name"
    - "ADR:;;Street;City;Region;PostCode;Country"
    - "TEL:+1-555-123-4567"
    - "EMAIL:contact@example.com"
    - "URL:https://example.com"

    Args:
        vcard_lines: List of vCard line strings.

    Returns:
        VCardInfo with extracted fields.
    """
    info = VCardInfo(raw_lines=vcard_lines)

    for line in vcard_lines:
        line = line.strip()
        line_upper = line.upper()

        # Parse LOGO line: LOGO;HASH=...;VALUE=URI:https://...
        if line_upper.startswith("LOGO"):
            # Extract VALUE=URI:... part
            if "VALUE=URI:" in line_upper:
                uri_start = line_upper.find("VALUE=URI:")
                if uri_start != -1:
                    info.logo_url = line[uri_start + len("VALUE=URI:"):]

            # Extract HASH=... part
            if "HASH=" in line_upper:
                hash_start = line_upper.find("HASH=")
                if hash_start != -1:
                    # Find end of hash (before ; or end of line)
                    hash_part = line[hash_start + len("HASH="):]
                    if ";" in hash_part:
                        hash_part = hash_part.split(";")[0]
                    info.logo_hash = hash_part

        # Parse ORG line: ORG:Organization Name
        elif line_upper.startswith("ORG:"):
            info.org = line[4:].strip()

        # Parse NOTE;LEI line: NOTE;LEI:123456789012345678
        elif line_upper.startswith("NOTE;LEI:"):
            info.lei = line[9:].strip()

        # Parse CATEGORIES line: CATEGORIES:...
        elif line_upper.startswith("CATEGORIES:"):
            info.categories = line[11:].strip()

        # Parse FN line: FN:Full Name
        elif line_upper.startswith("FN:"):
            info.fn = line[3:].strip()

        # Parse ADR line: ADR:;;Street;City;Region;PostCode;Country
        # Also handles ADR;TYPE=... variants
        elif line_upper.startswith("ADR"):
            colon_idx = line.find(":")
            if colon_idx != -1:
                info.adr = line[colon_idx + 1:].strip()

        # Parse TEL line: TEL:+1-555-123-4567
        # Also handles TEL;TYPE=... variants
        elif line_upper.startswith("TEL"):
            colon_idx = line.find(":")
            if colon_idx != -1:
                info.tel = line[colon_idx + 1:].strip()

        # Parse EMAIL line: EMAIL:contact@example.com
        # Also handles EMAIL;TYPE=... variants
        elif line_upper.startswith("EMAIL"):
            colon_idx = line.find(":")
            if colon_idx != -1:
                info.email = line[colon_idx + 1:].strip()

        # Parse URL line: URL:https://example.com
        elif line_upper.startswith("URL:"):
            info.url = line[4:].strip()

    # Look up GLEIF legal name if LEI is available
    if info.lei:
        lei_record = lookup_lei(info.lei)
        if lei_record:
            info.gleif_legal_name = lei_record.legal_name

    return info


# =============================================================================
# Issuer Identity Resolution
# =============================================================================

# Import identity resolution from core module to avoid duplication
# The identity module handles well-known AIDs (configurable) and extraction logic
from ..identity import (
    IssuerIdentity,
    WELLKNOWN_AIDS,
    build_issuer_identity_map,
    get_wellknown_identity,
)


async def build_issuer_identity_map_async(
    acdcs: List[ACDC],
    oobi_url: Optional[str] = None,
    discover_missing: bool = True,
) -> Dict[str, IssuerIdentity]:
    """Build AID-to-identity mapping with OOBI discovery fallback.

    Two-tier resolution:
    1. Tier 1: Extract identities from LE credentials in acdcs (synchronous)
    2. Tier 2: If discover_missing=True, query OOBI for AIDs without identity

    Note: OOBI discovery is disabled by default because current KERI witnesses
    serve KEL data only, not ACDC credentials. Enable via VVP_IDENTITY_DISCOVERY_ENABLED
    when witness implementations support credential queries.

    Args:
        acdcs: Parsed ACDC credentials from dossier.
        oobi_url: OOBI URL for witness discovery (e.g., kid_url from PASSporT).
        discover_missing: If True, query OOBI for missing identities.

    Returns:
        Dict mapping AID strings to IssuerIdentity objects.
    """
    from app.core.config import IDENTITY_DISCOVERY_ENABLED, IDENTITY_DISCOVERY_TIMEOUT_SECONDS

    # Tier 1: Dossier-based resolution (existing sync logic)
    identity_map = build_issuer_identity_map(acdcs)

    if not discover_missing or not IDENTITY_DISCOVERY_ENABLED:
        return identity_map

    # Collect all issuer AIDs not yet resolved
    all_issuer_aids = {acdc.issuer_aid for acdc in acdcs}
    missing_aids = all_issuer_aids - set(identity_map.keys())

    if not missing_aids:
        return identity_map

    # Tier 2: OOBI-based discovery for missing AIDs (parallel queries)
    from app.vvp.keri.identity_resolver import discover_identities_parallel

    discovered = await discover_identities_parallel(
        list(missing_aids),
        oobi_url=oobi_url,
        timeout=IDENTITY_DISCOVERY_TIMEOUT_SECONDS,
    )

    # Merge discovered identities into the map
    for aid, disc_identity in discovered.items():
        if disc_identity.legal_name or disc_identity.lei:
            identity_map[aid] = IssuerIdentity(
                aid=aid,
                legal_name=disc_identity.legal_name,
                lei=disc_identity.lei,
                source_said=disc_identity.source_said,
            )

    return identity_map


# =============================================================================
# Key State Conversion
# =============================================================================


def build_key_state_info(
    key_state: Any,
    resolution_source: str = "oobi",
    resolved_at: Optional[str] = None,
    signature_verified: bool = False,
) -> KeyStateInfo:
    """Convert a KeyState from KEL resolution to a KeyStateInfo view model.

    Args:
        key_state: KeyState dataclass from kel_resolver.py.
        resolution_source: Source of resolution (oobi, witness, cache).
        resolved_at: RFC3339 timestamp when resolved.
        signature_verified: Whether signature was verified against this state.

    Returns:
        KeyStateInfo for template display.
    """
    import base64
    from datetime import datetime, timezone

    # Determine establishment type from sequence and delegation status
    if key_state.is_delegated:
        establishment_type = "drt" if key_state.sequence > 0 else "dip"
    else:
        establishment_type = "rot" if key_state.sequence > 0 else "icp"

    # Format valid_from as RFC3339 string
    valid_from_str = None
    if key_state.valid_from:
        if isinstance(key_state.valid_from, datetime):
            valid_from_str = key_state.valid_from.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            valid_from_str = str(key_state.valid_from)

    # Truncate delegator AID for display
    delegator_short = None
    if key_state.delegator_aid:
        delegator_short = _truncate_aid(key_state.delegator_aid)

    # Extract signing key information
    signing_key_count = len(key_state.signing_keys) if key_state.signing_keys else 0
    first_key_fingerprint = None
    if key_state.signing_keys and len(key_state.signing_keys) > 0:
        # Convert first key to base64 and truncate for display
        first_key_b64 = base64.urlsafe_b64encode(key_state.signing_keys[0]).decode()
        first_key_fingerprint = first_key_b64[:12] + "..."

    # Get establishment event SAID
    establishment_said = None
    if hasattr(key_state, "establishment_digest") and key_state.establishment_digest:
        establishment_said = key_state.establishment_digest

    # Truncate witness AIDs for display
    witness_aids_short = None
    if key_state.witnesses:
        witness_aids_short = [_truncate_aid(w) for w in key_state.witnesses]

    # Extract delegation chain information
    delegation_chain_short = None
    delegation_root_short = None
    delegation_chain_valid = False
    delegation_depth = 0

    if hasattr(key_state, "delegation_chain") and key_state.delegation_chain:
        chain = key_state.delegation_chain
        if chain.delegates:
            delegation_chain_short = [_truncate_aid(aid) for aid in chain.delegates]
            delegation_depth = len(chain.delegates)
        if chain.root_aid:
            delegation_root_short = _truncate_aid(chain.root_aid)
        delegation_chain_valid = chain.valid

    return KeyStateInfo(
        sequence=key_state.sequence,
        establishment_type=establishment_type,
        rotated=key_state.sequence > 0,
        witness_count=len(key_state.witnesses) if key_state.witnesses else 0,
        witness_threshold=key_state.toad,
        is_delegated=key_state.is_delegated,
        delegator_aid=delegator_short,
        resolution_source=resolution_source,
        resolved_at=resolved_at,
        signature_verified=signature_verified,
        valid_from=valid_from_str,
        signing_key_count=signing_key_count,
        first_key_fingerprint=first_key_fingerprint,
        establishment_said=establishment_said,
        witness_aids=witness_aids_short,
        delegation_chain=delegation_chain_short,
        delegation_root_aid=delegation_root_short,
        delegation_chain_valid=delegation_chain_valid,
        delegation_depth=delegation_depth,
    )


# =============================================================================
# Main Adapter Function
# =============================================================================


def build_credential_card_vm(
    acdc: ACDC,
    chain_result: Optional[ACDCChainResult] = None,
    revocation_result: Optional[dict] = None,
    available_saids: Optional[Set[str]] = None,
    issuer_identities: Optional[Dict[str, IssuerIdentity]] = None,
    key_states: Optional[Dict[str, Any]] = None,
) -> CredentialCardViewModel:
    """Build view model from raw ACDC and validation results.

    This is the main entry point for converting ACDC data to a
    template-friendly view model.

    Args:
        acdc: Parsed ACDC credential.
        chain_result: Optional chain validation result for status.
        revocation_result: Optional revocation check result dict with keys:
            - status: "ACTIVE", "REVOKED", or "UNKNOWN"
            - checked_at: RFC3339 timestamp
            - source: "witness", "oobi", "inline", "unknown"
            - error: Optional error message
        available_saids: Set of credential SAIDs available in dossier
            (for determining which edge links can be expanded).
        issuer_identities: Optional mapping of AID→IssuerIdentity from
            build_issuer_identity_map(). Used to display issuer names
            instead of truncated AIDs.
        key_states: Optional mapping of AID→KeyState from KEL resolution.
            Used to display key state info on credential cards.

    Returns:
        CredentialCardViewModel ready for template rendering.
    """
    # Extract basic info
    said = acdc.said
    schema_said = acdc.schema_said
    credential_type = acdc.credential_type
    variant = acdc.variant

    # Determine status from chain result
    if chain_result and chain_result.status:
        status = chain_result.status
    else:
        status = "INDETERMINATE"

    # Build revocation status
    if revocation_result:
        revocation = RevocationStatus(
            state=revocation_result.get("status", "UNKNOWN"),
            checked_at=revocation_result.get("checked_at"),
            source=revocation_result.get("source", "unknown"),
            error=revocation_result.get("error"),
        )
    else:
        revocation = RevocationStatus()

    # Build issuer info with resolved identity if available
    issuer_aid = acdc.issuer_aid
    issuer_identity = (issuer_identities or {}).get(issuer_aid)
    lei = issuer_identity.lei if issuer_identity else None

    # Look up GLEIF legal name if LEI is available
    gleif_legal_name = None
    if lei:
        lei_record = lookup_lei(lei)
        if lei_record:
            gleif_legal_name = lei_record.legal_name

    # Build key state info if available for this issuer
    key_state_info: Optional[KeyStateInfo] = None
    if key_states and issuer_aid in key_states:
        key_state = key_states[issuer_aid]
        # Check if it's a KeyStateInfo (already converted) or KeyState (needs conversion)
        if isinstance(key_state, KeyStateInfo):
            key_state_info = key_state
        elif hasattr(key_state, "signing_keys"):
            # It's a KeyState from kel_resolver - convert it
            from datetime import datetime, timezone
            key_state_info = build_key_state_info(
                key_state,
                resolution_source="oobi",
                resolved_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                signature_verified=True,  # Assume verified if we have it
            )

    issuer = IssuerInfo(
        aid=issuer_aid,
        aid_short=_truncate_aid(issuer_aid),
        is_trusted_root=issuer_aid in TRUSTED_ROOT_AIDS,
        display_name=issuer_identity.legal_name if issuer_identity else None,
        lei=lei,
        gleif_legal_name=gleif_legal_name,
        key_state=key_state_info,
    )

    # Build primary attribute
    primary = _get_primary_attribute(credential_type, acdc.attributes, said)

    # Determine which field was used for primary (if any)
    primary_field = None
    if isinstance(acdc.attributes, dict):
        sources = PRIMARY_ATTRIBUTE_SOURCES.get(credential_type, [])
        for field_name, _ in sources:
            if acdc.attributes.get(field_name):
                primary_field = field_name
                break

    # Build secondary attributes (for backwards compatibility)
    secondary = _get_secondary_attributes(acdc.attributes, primary_field)

    # Build attribute sections (new categorized display)
    sections = _build_attribute_sections(acdc.attributes, primary_field)

    # Build edges
    edges, missing_edges = _build_edges(acdc.edges, available_saids)

    # Detect limitations
    is_compact = variant == "compact" or not isinstance(acdc.attributes, dict)
    redacted_fields = _detect_redacted_fields(acdc.attributes)
    is_partial = variant == "partial" or len(redacted_fields) > 0

    limitations = VariantLimitations(
        has_variant_limitations=is_compact or is_partial or len(missing_edges) > 0,
        missing_edge_targets=missing_edges,
        redacted_fields=redacted_fields,
        is_compact=is_compact,
        is_partial=is_partial,
    )

    # Mark redacted fields in secondary attributes
    if redacted_fields:
        for attr in secondary:
            # Check if this attribute's source field is redacted
            field_key = attr.label.lower().replace(" ", "_")
            if field_key in redacted_fields or attr.value in ("", "#", "[REDACTED]"):
                attr.value = "(redacted)"

    # Build raw data for debug
    raw = RawACDCData(
        attributes=acdc.attributes,
        edges=acdc.edges,
        source_format="cesr" if acdc.signature else "json",
    )

    # Build raw contents for "Raw Contents" collapsible section with tooltips
    # Include all top-level ACDC fields
    acdc_full_dict: Dict[str, Any] = {
        "d": acdc.said,
        "i": acdc.issuer_aid,
        "s": acdc.schema_said,
    }
    if isinstance(acdc.attributes, dict):
        acdc_full_dict["a"] = acdc.attributes
    elif acdc.attributes:
        acdc_full_dict["a"] = acdc.attributes  # SAID string for compact
    if acdc.edges:
        acdc_full_dict["e"] = acdc.edges
    # Include any additional fields from the raw ACDC
    if hasattr(acdc, "raw") and isinstance(acdc.raw, dict):
        for key in ("v", "t", "u", "rd", "r"):
            if key in acdc.raw:
                acdc_full_dict[key] = acdc.raw[key]

    raw_contents = _build_raw_contents(acdc_full_dict)

    # Parse vCard data if present
    vcard_info: Optional[VCardInfo] = None
    if isinstance(acdc.attributes, dict) and "vcard" in acdc.attributes:
        vcard_data = acdc.attributes["vcard"]
        if isinstance(vcard_data, list):
            vcard_info = _parse_vcard_lines(vcard_data)

    return CredentialCardViewModel(
        said=said,
        schema_said=schema_said,
        credential_type=credential_type,
        variant=variant,
        status=status,
        revocation=revocation,
        issuer=issuer,
        primary=primary,
        secondary=secondary,
        sections=sections,
        edges=edges,
        limitations=limitations,
        raw=raw,
        raw_contents=raw_contents,
        vcard=vcard_info,
        # Sprint 24: Explicit chain validation result for validation summary
        chain_status=status,
    )


# =============================================================================
# Sprint 24: Validation Summary & Error Bucket Builders
# =============================================================================


def _extract_schema_properties(
    schema_doc: Dict[str, Any],
) -> List[SchemaPropertyInfo]:
    """Extract property definitions from JSON Schema document.

    Parses the schema's properties object and required array to build
    a list of SchemaPropertyInfo for UI display.

    Args:
        schema_doc: JSON Schema document.

    Returns:
        List of SchemaPropertyInfo sorted by required status then name.
    """
    properties: List[SchemaPropertyInfo] = []
    required_fields = set(schema_doc.get("required", []))

    # Get properties from schema (may be at top level or under definitions)
    schema_props = schema_doc.get("properties", {})

    # Also check for nested attribute schema (common in ACDC schemas)
    if "properties" in schema_props.get("a", {}):
        schema_props = schema_props["a"]["properties"]
    elif "$id" in schema_props:
        # Schema has $id in properties - likely a reference, use top-level
        pass

    for prop_name, prop_def in schema_props.items():
        if not isinstance(prop_def, dict):
            continue

        # Skip internal ACDC fields in display
        if prop_name in ("d", "i", "dt", "u"):
            continue

        # Get type (may be string or array)
        type_val = prop_def.get("type", "any")
        if isinstance(type_val, list):
            type_name = " | ".join(type_val)
        else:
            type_name = type_val

        # Get format hint
        format_hint = prop_def.get("format")

        # Get enum values
        enum_values = prop_def.get("enum", [])
        if enum_values and not isinstance(enum_values, list):
            enum_values = []

        properties.append(
            SchemaPropertyInfo(
                name=prop_name,
                type_name=type_name,
                description=prop_def.get("description", ""),
                required=prop_name in required_fields,
                format=format_hint,
                enum_values=enum_values[:5],  # Limit to first 5 for display
            )
        )

    # Sort: required fields first, then alphabetically
    properties.sort(key=lambda p: (not p.required, p.name))
    return properties


def build_schema_info(
    acdc: ACDC,
    schema_doc: Optional[Dict[str, Any]],
    errors: List[str],
) -> SchemaValidationInfo:
    """Build schema validation info from validation results.

    Args:
        acdc: Parsed ACDC credential.
        schema_doc: Fetched schema document, or None if unavailable.
        errors: List of schema validation error messages.

    Returns:
        SchemaValidationInfo with registry source and validation status.
    """
    from common.vvp.schema.registry import has_governance_schemas, is_known_schema

    cred_type = acdc.credential_type
    schema_said = acdc.schema_said

    # Determine registry source
    if has_governance_schemas(cred_type) and is_known_schema(cred_type, schema_said):
        registry_source = "GLEIF"
    elif schema_doc:
        registry_source = "Fetched"
    else:
        registry_source = "Pending"

    # Determine validation status
    if errors:
        validation_status = "INVALID"
    elif schema_doc:
        validation_status = "VALID"
    else:
        validation_status = "INDETERMINATE"

    # Extract schema document details for display
    schema_title = ""
    schema_description = ""
    properties: List[SchemaPropertyInfo] = []
    has_document = False

    if schema_doc:
        has_document = True
        schema_title = schema_doc.get("title", "")
        schema_description = schema_doc.get("description", "")
        properties = _extract_schema_properties(schema_doc)

    return SchemaValidationInfo(
        schema_said=schema_said,
        registry_source=registry_source,
        validation_status=validation_status,
        has_governance=has_governance_schemas(cred_type),
        field_errors=errors,
        schema_title=schema_title,
        schema_description=schema_description,
        properties=properties,
        has_document=has_document,
    )


async def build_schema_info_with_fetch(
    acdc: ACDC,
    errors: Optional[List[str]] = None,
) -> SchemaValidationInfo:
    """Build schema info by fetching the schema document via SchemaResolver.

    This async helper fetches the schema document using the configured
    SchemaResolver, enabling the UI to display schema properties.

    Args:
        acdc: Parsed ACDC credential.
        errors: Optional list of validation errors (defaults to empty).

    Returns:
        SchemaValidationInfo with schema document details if available.
    """
    from app.vvp.acdc.schema_resolver import get_schema_resolver
    from app.core import config as app_config

    errors = errors or []
    schema_doc = None

    # Try to fetch the schema document if resolver is enabled
    if app_config.SCHEMA_RESOLVER_ENABLED and acdc.schema_said:
        try:
            resolver = get_schema_resolver()
            result = await resolver.resolve(acdc.schema_said)
            if result:
                schema_doc = result.schema_doc
        except Exception:
            # Schema fetch failed - continue without document
            pass

    return build_schema_info(acdc, schema_doc, errors)


def build_validation_summary(
    credential_vms: List[CredentialCardViewModel],
) -> ValidationSummary:
    """Aggregate validation checks across all credentials.

    Creates a dossier-level summary by examining each credential's
    chain_status, schema_info, and revocation state.

    Args:
        credential_vms: List of credential view models.

    Returns:
        ValidationSummary with aggregated checks and overall status.
    """
    checks: List[ValidationCheckResult] = []

    # Chain validation - use explicit chain_status field (per reviewer feedback)
    chain_statuses = [vm.chain_status for vm in credential_vms]
    if "INVALID" in chain_statuses:
        chain_result, severity = "INVALID", "error"
    elif "INDETERMINATE" in chain_statuses:
        chain_result, severity = "INDETERMINATE", "warning"
    else:
        chain_result, severity = "VALID", "success"

    checks.append(
        ValidationCheckResult(
            name="Chain",
            status=chain_result,
            short_reason=f"{len(credential_vms)} credentials",
            spec_ref="§5.1.1",
            severity=severity,
        )
    )

    # Schema validation - use schema_info.validation_status
    schema_statuses = [
        vm.schema_info.validation_status
        for vm in credential_vms
        if vm.schema_info
    ]
    if "INVALID" in schema_statuses:
        schema_result, severity = "INVALID", "error"
    elif "INDETERMINATE" in schema_statuses:
        schema_result, severity = "INDETERMINATE", "warning"
    elif schema_statuses:
        schema_result, severity = "VALID", "success"
    else:
        schema_result, severity = "INDETERMINATE", "warning"

    checks.append(
        ValidationCheckResult(
            name="Schema",
            status=schema_result,
            short_reason=f"{len(schema_statuses)} schemas",
            spec_ref="§6.3",
            severity=severity,
        )
    )

    # Revocation
    rev_states = [vm.revocation.state for vm in credential_vms]
    if "REVOKED" in rev_states:
        rev_status, severity = "INVALID", "error"
    elif "UNKNOWN" in rev_states:
        rev_status, severity = "INDETERMINATE", "warning"
    else:
        rev_status, severity = "VALID", "success"

    checks.append(
        ValidationCheckResult(
            name="Revocation",
            status=rev_status,
            short_reason="TEL checked",
            spec_ref="§5.1.1-2.9",
            severity=severity,
        )
    )

    # Calculate totals
    failures = sum(1 for c in checks if c.severity == "error")
    warnings = sum(1 for c in checks if c.severity == "warning")
    overall = "INVALID" if failures else ("INDETERMINATE" if warnings else "VALID")

    return ValidationSummary(
        checks=checks,
        overall_status=overall,
        failure_count=failures,
        warning_count=warnings,
    )


def build_delegation_chain_info(
    delegation_response: Optional["DelegationChainResponse"],
    issuer_identities: Optional[Dict[str, IssuerIdentity]] = None,
) -> Optional[DelegationChainInfo]:
    """Convert API DelegationChainResponse to UI DelegationChainInfo.

    Sprint 25: Maps the API response model to the UI view model,
    enriching nodes with resolved identity information from LE credentials.

    Args:
        delegation_response: API response from verify_vvp(), or None.
        issuer_identities: Optional AID→IssuerIdentity mapping from
            build_issuer_identity_map() for resolving display names.

    Returns:
        DelegationChainInfo for template rendering, or None if no delegation.
    """
    # Import here to avoid circular dependency
    from app.vvp.api_models import DelegationChainResponse

    if not delegation_response or not delegation_response.chain:
        return None

    nodes: List[DelegationNode] = []
    for node in delegation_response.chain:
        # Resolve display name from identity map
        display_name = None
        if issuer_identities and node.aid in issuer_identities:
            display_name = issuer_identities[node.aid].legal_name

        nodes.append(DelegationNode(
            aid=node.aid,
            aid_short=node.aid_short,
            display_name=display_name,
            is_root=node.is_root,
            authorization_status=node.authorization_status,
        ))

    return DelegationChainInfo(
        chain=nodes,
        depth=delegation_response.depth,
        root_aid=delegation_response.root_aid,
        is_valid=delegation_response.is_valid,
        errors=delegation_response.errors,
    )


def build_error_buckets(
    credential_vms: List[CredentialCardViewModel],
) -> List[ErrorBucket]:
    """Separate errors and warnings into buckets with remediation hints.

    Per §2.2:
    - INVALID = definitively failed (error bucket)
    - INDETERMINATE = could not complete (warning bucket)

    Args:
        credential_vms: List of credential view models.

    Returns:
        List of ErrorBucket (failures and uncertainties).
    """
    failures: List[ErrorBucketItem] = []
    uncertainties: List[ErrorBucketItem] = []

    for vm in credential_vms:
        # Use chain_status for accurate chain-specific reporting
        if vm.chain_status == "INVALID":
            failures.append(
                ErrorBucketItem(
                    message=f"Credential {vm.said[:16]}... chain INVALID",
                    spec_ref="§2.2",
                )
            )
        elif vm.chain_status == "INDETERMINATE":
            remedy = None
            if vm.limitations.is_compact:
                remedy = "Fetch expanded credential from issuer"
            elif vm.limitations.missing_edge_targets:
                remedy = f"Fetch missing: {vm.limitations.missing_edge_targets[0][:16]}..."
            uncertainties.append(
                ErrorBucketItem(
                    message=f"Credential {vm.said[:16]}... chain INDETERMINATE",
                    spec_ref="§2.2",
                    remedy_hint=remedy,
                )
            )

        # Schema validation errors
        if vm.schema_info and vm.schema_info.validation_status == "INVALID":
            for err in vm.schema_info.field_errors:
                failures.append(
                    ErrorBucketItem(
                        message=f"Schema error in {vm.said[:16]}...: {err}",
                        spec_ref="§6.3",
                    )
                )

        # Revocation errors
        if vm.revocation.state == "REVOKED":
            failures.append(
                ErrorBucketItem(
                    message=f"Credential {vm.said[:16]}... has been REVOKED",
                    spec_ref="§5.1.1-2.9",
                )
            )

    buckets: List[ErrorBucket] = []
    if failures:
        buckets.append(
            ErrorBucket(title="Failures", bucket_type="error", items=failures)
        )
    if uncertainties:
        buckets.append(
            ErrorBucket(title="Uncertainties", bucket_type="warning", items=uncertainties)
        )
    return buckets
