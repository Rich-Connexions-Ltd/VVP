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
# EXPERIMENTAL / TEST-ONLY FEATURES
# =============================================================================
# These features are incomplete and NOT spec-compliant. They exist for
# development and testing purposes only. Do NOT enable in production.

# Tier 2 KERI key state resolution via KEL parsing
#
# Phase 7b Implementation (CESR Support):
# - CESR binary format supported (application/json+cesr)
# - KERI-compliant canonicalization with proper field ordering
# - SAID validation using Blake3-256 with CESR encoding
# - Witness receipt signature validation against AIDs
#
# This enables production use with real KERI events from witnesses.
#
# Set to True to enable Tier 2 key state resolution.
TIER2_KEL_RESOLUTION_ENABLED: bool = True

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
    - GLEIF External (production vLEI ecosystem)
    - QVI roots (Qualified vLEI Issuers)
    - Test roots (development/staging)

    Environment variable format:
        VVP_TRUSTED_ROOT_AIDS=EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao,EQq7xL2...

    Returns:
        frozenset of trusted root AID strings.
    """
    env_value = os.getenv("VVP_TRUSTED_ROOT_AIDS", "")
    if env_value:
        # Parse comma-separated AIDs, strip whitespace, filter empty
        return frozenset(aid.strip() for aid in env_value.split(",") if aid.strip())
    # Default: GLEIF External AID for production vLEI ecosystem
    return frozenset({"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"})


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
