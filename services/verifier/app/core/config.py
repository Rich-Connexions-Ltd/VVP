"""
VVP Verifier configuration constants.
All values derive from VVP_Verifier_Specification_v1.4_FINAL.md

Constants are organized into:
- NORMATIVE: Fixed by spec, cannot be changed without spec revision
- CONFIGURABLE: Defaults per spec, may be overridden by deployment policy
- POLICY: Implementation choices where spec requires enforcement but doesn't specify values
- OPERATIONAL: Deployment-specific settings (env vars)
"""

import os

# =============================================================================
# NORMATIVE CONSTANTS (fixed by spec)
# =============================================================================

# Maximum iat drift between VVP-Identity and PASSporT
# §5.2A: "The absolute difference... MUST be ≤ 5 seconds"
# This is NORMATIVE - changing this value violates the spec
MAX_IAT_DRIFT_SECONDS: int = 5

# Allowed algorithms
# §5.1: "EdDSA (Ed25519) as the baseline algorithm"
# §5.0: "VVP mandates alg = EdDSA and explicitly forbids ES256/HMAC/RSA"
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"EdDSA"})

# Forbidden algorithms
# §5.0, §5.1: "reject ES256, HMAC, and RSA algorithms... reject none"
FORBIDDEN_ALGORITHMS: frozenset[str] = frozenset({
    "ES256", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none"
})

# =============================================================================
# CONFIGURABLE DEFAULTS (per spec, may be overridden)
# =============================================================================

# Clock skew for iat validation
# §4.1A: "default policy for this project is ±300 seconds"
# Configurable per deployment
CLOCK_SKEW_SECONDS: int = 300

# Maximum token age when exp is absent
# §4.1A, §5.2B: "300 seconds... unless explicitly configured otherwise"
MAX_TOKEN_AGE_SECONDS: int = 300

# Maximum PASSporT validity window
# §5.2B: "Default maximum validity window: 300 seconds"
# §5.2B: "unless explicitly configured otherwise"
MAX_PASSPORT_VALIDITY_SECONDS: int = 300

# Allow PASSporT exp omission when VVP-Identity has explicit exp
# §5.2A: "unless explicitly configured to allow exp omission (default: reject)"
# Default is False (reject) per spec
ALLOW_PASSPORT_EXP_OMISSION: bool = False

# =============================================================================
# POLICY CONSTANTS (spec requires enforcement, values are implementation choice)
# =============================================================================

# Dossier fetch constraints
# §6.1B: "timeouts... size limits" - spec requires enforcement but doesn't specify values
DOSSIER_FETCH_TIMEOUT_SECONDS: int = 5
DOSSIER_MAX_SIZE_BYTES: int = 1_048_576  # 1 MB
DOSSIER_MAX_REDIRECTS: int = 3

# Schema SAID validation strictness (§6.3.3-6)
# Per spec, schema rules are MUSTs and should reject unknown schema SAIDs.
# True (default): Reject unknown schema SAIDs per spec compliance
# False: Log warnings but allow (documented policy deviation)
#
# Setting to False is a POLICY DEVIATION that should be documented.
# Use only for testing with non-production credentials.
SCHEMA_VALIDATION_STRICT: bool = os.getenv("SCHEMA_VALIDATION_STRICT", "true").lower() == "true"

# =============================================================================
# TIER 2 KERI FEATURES
# =============================================================================
# KERI-based key state resolution for cryptographic signature verification.

# Tier 2 KERI key state resolution via KEL parsing
#
# Implementation includes:
# - CESR binary format supported (application/json+cesr)
# - KERI-compliant canonicalization with proper field ordering
# - SAID validation using Blake3-256 with CESR encoding
# - Witness receipt signature validation against AIDs
#
# This enables verification of VVP-Identity JWTs signed with KERI-managed keys.
#
# Set to "true" to enable Tier 2 key state resolution (default).
# Set to "false" to disable (falls back to Tier 1 verification only).
TIER2_KEL_RESOLUTION_ENABLED: bool = os.getenv(
    "TIER2_KEL_RESOLUTION_ENABLED", "true"
).lower() == "true"

# =============================================================================
# OPERATIONAL SETTINGS (deployment-specific, via environment variables)
# =============================================================================

# Admin endpoint visibility
# Default: True for dev, set to False in production deployments
# Controls whether /admin endpoint returns configuration data
ADMIN_ENDPOINT_ENABLED: bool = os.getenv("ADMIN_ENDPOINT_ENABLED", "true").lower() == "true"


def _parse_trusted_roots() -> frozenset[str]:
    """Parse comma-separated trusted root AIDs from environment.

    Per VVP §5.1-7, the verifier MUST accept a configured root of trust.
    This determines which AIDs anchor the ACDC credential chain.

    Supports multiple roots for different governance frameworks:
    - GLEIF Root (production vLEI ecosystem)
    - GLEIF External (legacy/alternate identifier)
    - QVI roots (Qualified vLEI Issuers)
    - GSMA Governance AID (Sprint 62: vetter constraint trust chain)
    - Test roots (development/staging)

    Environment variable format:
        VVP_TRUSTED_ROOT_AIDS=EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2,EBfdlu8R27Fbx...

    Returns:
        frozenset of trusted root AID strings.
    """
    env_value = os.getenv("VVP_TRUSTED_ROOT_AIDS", "")
    if env_value:
        # Parse comma-separated AIDs, strip whitespace, filter empty
        return frozenset(aid.strip() for aid in env_value.split(",") if aid.strip())
    # Default: GLEIF Root AID for production vLEI ecosystem
    # - EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2: GLEIF Root (from gleif.org OOBI)
    #
    # NOTE: EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao is the QVI SCHEMA SAID,
    # not an issuer AID. It was incorrectly included here in earlier versions.
    # Schema SAIDs and issuer AIDs are different identifier types:
    # - Schema SAIDs identify credential schemas (content-addressed)
    # - Issuer AIDs identify entities that sign credentials (key-derived)
    #
    # The actual GLEIF GEDA (GLEIF External Delegated AID) used for issuing QVI
    # credentials should be obtained from GLEIF. Use VVP_TRUSTED_ROOT_AIDS env
    # var to configure additional trusted root AIDs.
    #
    # Sprint 62: GSMA Governance AID is required for vetter constraint validation.
    # The GSMA AID is generated by scripts/bootstrap-issuer.py and stored in the
    # issuer's MockVLEIState.gsma_aid. After bootstrap, add the GSMA AID to
    # VVP_TRUSTED_ROOT_AIDS alongside the GLEIF root. Example:
    #   VVP_TRUSTED_ROOT_AIDS=EDP1vHcw...,<gsma-aid-from-bootstrap>
    # The issuer's GET /admin/config endpoint reports the GSMA AID.
    return frozenset({
        "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2",  # GLEIF Root (production)
    })


# Trusted root AIDs for ACDC chain validation
# Per VVP §5.1-7: verifier MUST accept root of trust
# ACDC credentials must chain back to one of these AIDs
TRUSTED_ROOT_AIDS: frozenset[str] = _parse_trusted_roots()


# =============================================================================
# SPRINT 18: SIP CONTEXT AND BUSINESS LOGIC (Phase 11 & 13)
# =============================================================================

# SIP contextual alignment timing tolerance (§5A Step 2)
# Default 30 seconds allows for normal SIP processing delays
SIP_TIMING_TOLERANCE_SECONDS: int = int(os.getenv("VVP_SIP_TIMING_TOLERANCE", "30"))

# Whether context alignment is required (§4.4 - default False)
# When False: missing SIP context results in INDETERMINATE (not INVALID)
# When True: missing SIP context results in INVALID
CONTEXT_ALIGNMENT_REQUIRED: bool = os.getenv("VVP_CONTEXT_REQUIRED", "false").lower() == "true"

# Whether callee TN rights validation is a required claim (default True)
# When True: TN rights failure propagates to overall status
# When False: TN rights is evaluated but does not affect overall status
# Set to False when dossiers lack APE/TNAlloc credentials (e.g., dev/demo)
CALLEE_TN_RIGHTS_REQUIRED: bool = os.getenv(
    "VVP_CALLEE_TN_RIGHTS_REQUIRED", "true"
).lower() == "true"


def _parse_accepted_goals() -> frozenset[str]:
    """Parse comma-separated accepted goals from environment.

    Per §5.1.1-2.13, verifier may accept only specific goals.
    Empty set means accept all goals.

    Environment variable format:
        VVP_ACCEPTED_GOALS=sales,support,callback

    Returns:
        frozenset of accepted goal strings.
    """
    env_value = os.getenv("VVP_ACCEPTED_GOALS", "")
    if env_value:
        return frozenset(g.strip() for g in env_value.split(",") if g.strip())
    return frozenset()  # Empty = accept all


# Goal acceptance policy (§5.1.1-2.13)
# Empty = accept all goals
ACCEPTED_GOALS: frozenset[str] = _parse_accepted_goals()

# Whether to reject unknown goals (default: False = accept unknown)
# When True: goals not in ACCEPTED_GOALS result in INVALID
# When False: unknown goals accepted with warning
REJECT_UNKNOWN_GOALS: bool = os.getenv("VVP_REJECT_UNKNOWN_GOALS", "false").lower() == "true"

# Geographic constraint enforcement (§5.1.1-2.13)
# When True (default): geo constraints trigger INDETERMINATE if GeoIP unavailable
# When False: geo constraints are skipped (documented policy deviation)
GEO_CONSTRAINTS_ENFORCED: bool = os.getenv("VVP_GEO_CONSTRAINTS_ENFORCED", "true").lower() == "true"


# =============================================================================
# SPRINT 21: ACDC VARIANT SUPPORT (Phase 8.9 / §1.4)
# =============================================================================

# Aggregate dossier support (§1.4 / §6.1)
# Per §6.1: "unless local policy explicitly supports multiple roots"
#
# When True: Accept dossiers with multiple root nodes (aggregate disclosure)
# When False (default): Require exactly one root per spec default behavior
#
# Aggregate dossiers are used for composite credentials from multiple
# independent trust hierarchies. Each sub-graph is validated independently.
ALLOW_AGGREGATE_DOSSIERS: bool = os.getenv(
    "VVP_ALLOW_AGGREGATE_DOSSIERS", "false"
).lower() == "true"


# =============================================================================
# SPRINT 23: OOBI-BASED ISSUER IDENTITY RESOLUTION
# =============================================================================

# Enable OOBI-based identity discovery for unknown issuers
# When True: Query witness endpoints for LE credentials
# When False (default): Only use identities from dossier LE credentials
#
# NOTE: Currently disabled by default because KERI witnesses serve KEL data
# only, not ACDC credentials. Enable when witness implementations support
# credential queries at /credentials?issuer={aid} endpoints.
IDENTITY_DISCOVERY_ENABLED: bool = os.getenv(
    "VVP_IDENTITY_DISCOVERY_ENABLED", "false"
).lower() == "true"

# Timeout for identity discovery queries (per-request)
# Lower than dossier timeout since this is enhancement, not requirement
IDENTITY_DISCOVERY_TIMEOUT_SECONDS: float = float(
    os.getenv("VVP_IDENTITY_DISCOVERY_TIMEOUT", "3.0")
)

# Cache TTL for discovered identities (positive and negative results)
IDENTITY_CACHE_TTL_SECONDS: float = float(
    os.getenv("VVP_IDENTITY_CACHE_TTL", "300.0")
)


# =============================================================================
# SPRINT 23: DOSSIER CACHING (Phase 14.2 / §5.1.1-2.7)
# =============================================================================

# Dossier cache TTL (§5C.2 freshness policy)
# Default 300s aligns with key state cache freshness per §5C.2
# Can be increased for stable production dossiers, but should not exceed
# MAX_TOKEN_AGE_SECONDS to ensure verification freshness
DOSSIER_CACHE_TTL_SECONDS: float = float(
    os.getenv("VVP_DOSSIER_CACHE_TTL", "300.0")
)

# Maximum dossier cache entries before LRU eviction
DOSSIER_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_DOSSIER_CACHE_MAX_ENTRIES", "100")
)


# =============================================================================
# SPRINT 24: SCHEMA VALIDATION (Phase 8.6 / §5.1.1-2.8.3)
# =============================================================================

# Schema cache TTL (§5C.2 freshness policy)
# Default 300s aligns with key state cache freshness per §5C.2
# Schemas change rarely, so this can be longer than dossier cache
SCHEMA_CACHE_TTL_SECONDS: int = int(
    os.getenv("VVP_SCHEMA_CACHE_TTL", "300")
)


# =============================================================================
# SAID-FIRST SCHEMA RESOLUTION (ACDC Spec / KERI Content-Addressed Model)
# =============================================================================
# Multi-source schema resolution with mandatory SAID verification.
# Per ACDC spec, schemas are content-addressed via SAID - verification is mandatory.

import logging as _config_logging

_config_log = _config_logging.getLogger(__name__)

# Enable SchemaResolver for multi-source resolution
# When True (default): Use SchemaResolver with cache, registries, optional OOBI
# When False: Use legacy schema_fetcher.py directly
SCHEMA_RESOLVER_ENABLED: bool = os.getenv(
    "VVP_SCHEMA_RESOLVER_ENABLED", "true"
).lower() == "true"

# Schema resolver cache TTL (longer than credentials - schemas are immutable)
# Default 1 hour is safe because schema content is verified via SAID
SCHEMA_RESOLVER_CACHE_TTL_SECONDS: int = int(
    os.getenv("VVP_SCHEMA_RESOLVER_CACHE_TTL", "3600")
)

# Maximum schema cache entries before LRU eviction
SCHEMA_RESOLVER_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_SCHEMA_RESOLVER_CACHE_MAX_ENTRIES", "200")
)


def _parse_schema_registry_urls() -> list[str]:
    """Parse comma-separated schema registry URLs from environment.

    Format: "https://schema.gleif.org/,https://schema.provenant.net/"
    - Splits on comma
    - Strips whitespace from each URL
    - Filters empty strings
    - Falls back to GitHub raw URLs if not set
    - Logs warning if result is empty list

    Note: The embedded schema store is checked BEFORE these URLs.
    These registries are fallback for schemas not in the embedded store.

    Returns:
        List of registry URL strings.
    """
    # Default includes both official registries and GitHub raw URLs as fallback
    # GitHub URLs serve the same schemas but may be more reliable
    default = (
        "https://schema.gleif.org/,"
        "https://schema.provenant.net/,"
        "https://raw.githubusercontent.com/GLEIF-IT/vLEI-schema/main/"
    )
    raw = os.getenv("VVP_SCHEMA_REGISTRY_URLS", default)
    urls = [url.strip() for url in raw.split(",") if url.strip()]
    if not urls:
        _config_log.warning(
            "VVP_SCHEMA_REGISTRY_URLS parsed to empty list; "
            "schema resolution will rely on embedded store and OOBI only"
        )
    return urls


# Schema registry URLs (ordered list - tried in sequence)
SCHEMA_REGISTRY_URLS: list[str] = _parse_schema_registry_urls()

# Enable OOBI-based schema resolution (experimental)
# When True: Attempt to fetch schemas from KERI witnesses
# When False (default): Only use HTTP registries
# NOTE: Current KERI witnesses typically serve KEL data, not schemas
SCHEMA_OOBI_RESOLUTION_ENABLED: bool = os.getenv(
    "VVP_SCHEMA_OOBI_RESOLUTION", "false"
).lower() == "true"

# Timeout for schema fetch operations (per source)
SCHEMA_RESOLVER_TIMEOUT_SECONDS: float = float(
    os.getenv("VVP_SCHEMA_RESOLVER_TIMEOUT", "5.0")
)


# =============================================================================
# SPRINT 25: EXTERNAL SAID RESOLUTION (§2.2 / §1.4)
# =============================================================================
# Attempt to resolve external credential SAIDs from KERI witnesses when
# compact ACDCs have edge references to credentials not in the dossier.

# Enable external SAID resolution from witnesses
# When True (default): Attempt to fetch missing edge credentials from witnesses before INDETERMINATE
# When False: Immediately return INDETERMINATE for missing edges per §2.2
EXTERNAL_SAID_RESOLUTION_ENABLED: bool = os.getenv(
    "VVP_EXTERNAL_SAID_RESOLUTION", "true"
).lower() == "true"

# Timeout for external credential fetch (per-request)
# Lower than dossier timeout since this is enhancement, not requirement
EXTERNAL_SAID_RESOLUTION_TIMEOUT: float = float(
    os.getenv("VVP_EXTERNAL_SAID_TIMEOUT", "5.0")
)

# Maximum recursion depth for resolving chained external credentials
# Prevents infinite loops when fetched credentials have their own external refs
EXTERNAL_SAID_MAX_DEPTH: int = int(
    os.getenv("VVP_EXTERNAL_SAID_MAX_DEPTH", "3")
)

# Cache TTL for resolved external credentials
# Aligns with dossier cache TTL per §5C.2 freshness policy
EXTERNAL_SAID_CACHE_TTL_SECONDS: int = int(
    os.getenv("VVP_EXTERNAL_SAID_CACHE_TTL", "300")
)

# Maximum external credential cache entries before LRU eviction
EXTERNAL_SAID_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_EXTERNAL_SAID_CACHE_MAX_ENTRIES", "500")
)


# =============================================================================
# WITNESS POOL CONFIGURATION
# =============================================================================
# Unified witness pool for AID resolution, aggregating witnesses from:
# 1. Configured witnesses (Provenant staging) - always available
# 2. GLEIF witnesses - discovered from well-known OOBI
# 3. Per-request witnesses - from PASSporT kid OOBI URLs
# 4. KEL-extracted witnesses - from 'b' field in establishment events

# Provenant staging witnesses (default fallback)
# These are loaded at WitnessPool initialization and always available
# Override with VVP_LOCAL_WITNESS_URLS for local development (Sprint 27)


def _parse_witness_urls() -> list[str]:
    """Parse witness URLs from environment or use defaults.

    Supports local development override via VVP_LOCAL_WITNESS_URLS env var.
    Format: comma-separated list of URLs
    Example: "http://127.0.0.1:5642,http://127.0.0.1:5643,http://127.0.0.1:5644"

    When running in Docker with docker-compose, use service names:
    Example: "http://witnesses:5642,http://witnesses:5643,http://witnesses:5644"
    """
    local_urls = os.getenv("VVP_LOCAL_WITNESS_URLS", "")
    if local_urls:
        urls = [url.strip() for url in local_urls.split(",") if url.strip()]
        if urls:
            _config_log.info(f"Using local witness URLs from VVP_LOCAL_WITNESS_URLS: {urls}")
            return urls

    # Default to Provenant staging
    return [
        "http://witness4.stage.provenant.net:5631",
        "http://witness5.stage.provenant.net:5631",
        "http://witness6.stage.provenant.net:5631",
    ]


PROVENANT_WITNESS_URLS: list[str] = _parse_witness_urls()

# GLEIF well-known OOBI for witness discovery
# The GLEIF Root AID OOBI endpoint returns reply messages with witness URLs
GLEIF_WITNESS_OOBI_URL: str = os.getenv(
    "VVP_GLEIF_WITNESS_OOBI",
    "https://www.gleif.org/.well-known/keri/oobi/EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2"
)

# GLEIF Root AID (for reference/logging)
GLEIF_ROOT_AID: str = "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2"

# TEL Client timeout for revocation status queries
# This is the HTTP timeout for individual witness queries
TEL_CLIENT_TIMEOUT_SECONDS: float = float(
    os.getenv("VVP_TEL_CLIENT_TIMEOUT", "10.0")
)

# Enable GLEIF witness discovery
# When True (default): Attempt to discover GLEIF witnesses on first use
# When False: Only use configured Provenant witnesses
GLEIF_WITNESS_DISCOVERY_ENABLED: bool = os.getenv(
    "VVP_GLEIF_WITNESS_DISCOVERY", "true"
).lower() == "true"

# Cache TTL for discovered GLEIF witnesses (seconds)
# After this time, discovery will be re-attempted
GLEIF_WITNESS_CACHE_TTL: int = int(
    os.getenv("VVP_GLEIF_WITNESS_CACHE_TTL", "300")
)


# =============================================================================
# SPRINT 40: VETTER CERTIFICATION CONSTRAINTS
# =============================================================================
# Per VVP Multichannel Vetters spec, verify geographic/jurisdictional constraints
# on credential issuers (vetters) via their Vetter Certification credentials.
#
# Results are status bits - clients decide whether to treat as errors or warnings.

# Enforce vetter constraints as verification failures
# When False (default): Violations are reported in vetter_constraints response
#   field but do NOT affect overall verification status (soft-fail mode).
#   Per spec: "The client of the verification API gets to decide whether it
#   considers these bits to be errors (don't route the call), warnings
#   (route but suppress brand), etc."
# When True: Violations propagate to overall_status as INVALID (hard-fail mode)
ENFORCE_VETTER_CONSTRAINTS: bool = os.getenv(
    "VVP_ENFORCE_VETTER_CONSTRAINTS", "false"
).lower() == "true"

# NOTE: External resolution of vetter certifications (fetching from witnesses
# when not in dossier) was considered but not implemented. Per spec, credentials
# must include certification edges pointing to certifications IN the dossier.


# =============================================================================
# EDGE OPERATOR VALIDATION (ACDC spec I2I/DI2I/NI2I constraints)
# =============================================================================
# Per ACDC spec, edge operators control how authority flows through credential
# chains. Operator violations can be treated as soft warnings (INDETERMINATE)
# or hard failures (INVALID) based on deployment policy.

# Operator violation severity
# "INDETERMINATE" (default): Soft warnings - verification continues, violations logged
# "INVALID": Hard failures - operator violations result in INVALID verification status
#
# Use "INVALID" for strict deployments requiring full ACDC compliance.
# Use "INDETERMINATE" for backward compatibility and graceful handling.
VVP_OPERATOR_VIOLATION_SEVERITY: str = os.getenv(
    "VVP_OPERATOR_VIOLATION_SEVERITY", "INDETERMINATE"
)


# =============================================================================
# VLEI CHAIN RESOLUTION (Deep chain traversal to GLEIF root)
# =============================================================================
# When enabled, the verifier follows e.qvi edges from LE credentials to fetch
# QVI credentials from witnesses, verifying the chain reaches GLEIF root.

# Enable deep vLEI chain resolution
# When True (default): Attempt to resolve e.qvi edges to GLEIF root
# When False: Stop at terminal issuer (Brand assure, Rich Connexions, etc.)
VLEI_CHAIN_RESOLUTION_ENABLED: bool = os.getenv(
    "VVP_VLEI_CHAIN_RESOLUTION", "true"
).lower() == "true"

# Maximum depth for vLEI chain resolution
# 3 is sufficient for: LE → QVI → (GLEIF check)
VLEI_CHAIN_MAX_DEPTH: int = int(os.getenv("VVP_VLEI_CHAIN_MAX_DEPTH", "3"))

# Maximum concurrent fetch operations during chain resolution
VLEI_CHAIN_MAX_CONCURRENT: int = int(os.getenv("VVP_VLEI_CHAIN_MAX_CONCURRENT", "5"))

# Maximum total external fetches during chain resolution (budget limit)
VLEI_CHAIN_MAX_TOTAL_FETCHES: int = int(os.getenv("VVP_VLEI_CHAIN_MAX_TOTAL_FETCHES", "10"))

# Timeout for entire chain resolution phase (seconds)
VLEI_CHAIN_TIMEOUT_SECONDS: float = float(os.getenv("VVP_VLEI_CHAIN_TIMEOUT", "10.0"))


# =============================================================================
# DOSSIER SAID RESOLUTION (UI convenience feature)
# =============================================================================
# Default EVD URL pattern for resolving dossiers by SAID.
# This allows users to paste a dossier SAID in the UI and have it automatically
# construct the full evd URL.
#
# The pattern must contain {SAID} placeholder which will be replaced with the actual SAID.
# Example: https://origin.demo.provenant.net/v1/agent/public/{SAID}/dossier.cesr

DEFAULT_EVD_URL_PATTERN: str = os.getenv(
    "VVP_DEFAULT_EVD_URL_PATTERN",
    "https://origin.demo.provenant.net/v1/agent/public/{SAID}/dossier.cesr"
)

# =============================================================================
# VERIFICATION RESULT CACHING (Sprint 51)
# =============================================================================
# Caches dossier-derived verification artifacts (chain validation, ACDC
# signatures, revocation status) to avoid re-running expensive phases on
# repeated requests for the same dossier.

# Feature flag to enable/disable verification result caching
VVP_VERIFICATION_CACHE_ENABLED: bool = os.getenv(
    "VVP_VERIFICATION_CACHE_ENABLED", "true"
).lower() == "true"

# Max cached dossier verification artifacts
VVP_VERIFICATION_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_VERIFICATION_CACHE_MAX_ENTRIES", "200")
)

# TTL for cached artifacts in seconds (handles URL content changes)
VVP_VERIFICATION_CACHE_TTL: float = float(
    os.getenv("VVP_VERIFICATION_CACHE_TTL", "3600")
)

# Seconds between background revocation re-checks; stale data → INDETERMINATE
VVP_REVOCATION_RECHECK_INTERVAL: float = float(
    os.getenv("VVP_REVOCATION_RECHECK_INTERVAL", "300")
)

# Max concurrent background revocation check tasks
VVP_REVOCATION_CHECK_CONCURRENCY: int = int(
    os.getenv("VVP_REVOCATION_CHECK_CONCURRENCY", "1")
)
