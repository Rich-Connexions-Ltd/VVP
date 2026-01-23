"""
VVP Verifier configuration constants.
All values derive from VVP_Verifier_Specification_v1.4_FINAL.md

Constants are organized into:
- NORMATIVE: Fixed by spec, cannot be changed without spec revision
- CONFIGURABLE: Defaults per spec, may be overridden by deployment policy
- POLICY: Implementation choices where spec requires enforcement but doesn't specify values
"""

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

# =============================================================================
# POLICY CONSTANTS (spec requires enforcement, values are implementation choice)
# =============================================================================

# Dossier fetch constraints
# §6.1B: "timeouts... size limits" - spec requires enforcement but doesn't specify values
DOSSIER_FETCH_TIMEOUT_SECONDS: int = 5
DOSSIER_MAX_SIZE_BYTES: int = 1_048_576  # 1 MB
DOSSIER_MAX_REDIRECTS: int = 3
