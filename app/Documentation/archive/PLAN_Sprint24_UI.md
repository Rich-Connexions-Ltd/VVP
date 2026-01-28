# Sprint 24 UI Enhancement Plan: Evidence, Validation & Schema Visibility

## Summary

Enhance the VVP Verifier UI to surface new backend capabilities from Sprint 24:
- Schema registry and validation status
- Multi-level delegation chain visualization
- Evidence fetch timeline with cache metrics
- Clear separation of INVALID vs INDETERMINATE outcomes (per spec §2.2)
- Enhanced variant limitation details with remediation hints

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-01-27 | Addressed reviewer feedback: normalized EvidenceStatus enum, added chain_status field, fixed spec notation |

---

## Implementation Phases

### Phase 1: View Model Extensions
**Files:** `app/vvp/ui/credential_viewmodel.py`

Add new dataclasses following existing patterns (type hints, docstrings, default_factory):

```python
# Shared enum for evidence fetch status (addresses reviewer finding)
class EvidenceStatus(str, Enum):
    """Evidence fetch status values.

    Used consistently across EvidenceFetchRecord, timeline rendering, and CSS badges.
    """
    SUCCESS = "SUCCESS"              # Fetch succeeded
    FAILED = "FAILED"                # Fetch failed with error
    CACHED = "CACHED"                # Served from cache
    INDETERMINATE = "INDETERMINATE"  # Could not determine (e.g., schema unavailable)

@dataclass
class ValidationCheckResult:
    """Single validation check result for dashboard strip."""
    name: str                          # "Signature", "Schema", "Delegation", etc.
    status: str                        # VALID, INVALID, INDETERMINATE
    short_reason: str                  # Brief reason
    spec_ref: Optional[str] = None     # e.g., "§5.0"
    severity: str = "success"          # error, warning, success

@dataclass
class ValidationSummary:
    """Top-level validation dashboard."""
    checks: List[ValidationCheckResult] = field(default_factory=list)
    overall_status: str = "VALID"
    failure_count: int = 0
    warning_count: int = 0

@dataclass
class ErrorBucketItem:
    """Single error/warning with remediation."""
    message: str
    spec_ref: Optional[str] = None
    remedy_hint: Optional[str] = None

@dataclass
class ErrorBucket:
    """Grouped errors (INVALID) or warnings (INDETERMINATE)."""
    title: str                         # "Failures" or "Uncertainties"
    bucket_type: str                   # "error" or "warning"
    items: List[ErrorBucketItem] = field(default_factory=list)

@dataclass
class SchemaValidationInfo:
    """Schema validation details for a credential."""
    schema_said: str
    registry_source: str               # "GLEIF", "Pending", "Fetched"
    validation_status: str             # VALID, INVALID, INDETERMINATE
    has_governance: bool = False       # True if in governance registry
    field_errors: List[str] = field(default_factory=list)
    validated_count: int = 0
    total_required: int = 0

@dataclass
class EvidenceFetchRecord:
    """Single evidence fetch operation."""
    source_type: str                   # OOBI, SCHEMA, TEL, DOSSIER, KEY_STATE
    url: str
    status: EvidenceStatus             # SUCCESS, FAILED, CACHED, INDETERMINATE (uses shared enum)
    latency_ms: Optional[int] = None
    cache_hit: bool = False
    cache_ttl_remaining: Optional[int] = None
    error: Optional[str] = None

@dataclass
class EvidenceTimeline:
    """Timeline of all evidence fetches."""
    records: List[EvidenceFetchRecord] = field(default_factory=list)
    total_fetch_time_ms: int = 0
    cache_hit_rate: float = 0.0
    failed_count: int = 0

@dataclass
class DelegationNode:
    """Node in delegation chain."""
    aid: str
    aid_short: str
    display_name: Optional[str] = None
    is_root: bool = False
    authorization_status: str = "INDETERMINATE"

@dataclass
class DelegationChainInfo:
    """Complete delegation chain from leaf to root."""
    chain: List[DelegationNode] = field(default_factory=list)
    depth: int = 0
    root_aid: Optional[str] = None
    is_valid: bool = False
    errors: List[str] = field(default_factory=list)
```

**Extend existing VariantLimitations:**
```python
@dataclass
class VariantLimitations:
    # ... existing fields ...
    verification_impact: Optional[str] = None      # "Status INDETERMINATE per §2.2"
    remediation_hints: List[str] = field(default_factory=list)
```

**Extend CredentialCardViewModel:**
```python
@dataclass
class CredentialCardViewModel:
    # ... existing fields ...
    chain_status: str = "INDETERMINATE"  # Explicit chain validation result (from ACDCChainResult.status)
    schema_info: Optional[SchemaValidationInfo] = None
    delegation_info: Optional[DelegationChainInfo] = None
    validation_checks: List[ValidationCheckResult] = field(default_factory=list)
```

**Note:** `chain_status` is sourced directly from `ACDCChainResult.status` during view model construction, separate from the overall `status` field. This allows validation summary to accurately report chain-specific outcomes.

**Add DossierViewModel:**
```python
@dataclass
class DossierViewModel:
    """Top-level view model for dossier display."""
    evd_url: str
    credentials: List[CredentialCardViewModel] = field(default_factory=list)
    validation_summary: Optional[ValidationSummary] = None
    evidence_timeline: Optional[EvidenceTimeline] = None
    error_buckets: List[ErrorBucket] = field(default_factory=list)
    total_time_ms: int = 0
```

---

## Approval

**Reviewer Verdict:** APPROVED (2026-01-27)

> The required changes are addressed: EvidenceStatus is normalized and used consistently across timeline/metrics, chain reporting now uses `chain_status` sourced from `ACDCChainResult.status`, and spec references are corrected to §. The evidence timeline template and legend now accommodate the full status set without conflating INDETERMINATE.
