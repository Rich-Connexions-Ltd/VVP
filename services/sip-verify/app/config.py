"""Configuration for VVP SIP Verify Service.

Sprint 44: Environment-based configuration for SIP verification service.
"""

import os

# =============================================================================
# Network Configuration
# =============================================================================

# SIP listening address
VVP_SIP_VERIFY_HOST = os.getenv("VVP_SIP_VERIFY_HOST", "0.0.0.0")
VVP_SIP_VERIFY_PORT = int(os.getenv("VVP_SIP_VERIFY_PORT", "5071"))

# Transport type: "udp", "tcp", "both"
VVP_SIP_VERIFY_TRANSPORT = os.getenv("VVP_SIP_VERIFY_TRANSPORT", "udp")

# =============================================================================
# Verifier API Configuration
# =============================================================================

# URL of the VVP Verifier service
VVP_VERIFIER_URL = os.getenv("VVP_VERIFIER_URL", "https://vvp-verifier.rcnx.io")

# Timeout for verifier API calls (seconds)
VVP_VERIFIER_TIMEOUT = float(os.getenv("VVP_VERIFIER_TIMEOUT", "5.0"))

# API key for verifier (optional, for authenticated endpoints)
VVP_VERIFIER_API_KEY = os.getenv("VVP_VERIFIER_API_KEY", "")

# =============================================================================
# Redirect Configuration
# =============================================================================

# Default target for SIP 302 redirect (PBX address)
VVP_REDIRECT_TARGET = os.getenv("VVP_REDIRECT_TARGET", "")

# Fallback status when verification cannot complete
VVP_FALLBACK_STATUS = os.getenv("VVP_FALLBACK_STATUS", "INDETERMINATE")

# =============================================================================
# Status Server Configuration
# =============================================================================

# Enable HTTP status server
VVP_STATUS_ENABLED = os.getenv("VVP_STATUS_ENABLED", "true").lower() == "true"
VVP_STATUS_HTTP_PORT = int(os.getenv("VVP_STATUS_HTTP_PORT", "8080"))
VVP_STATUS_ADMIN_KEY = os.getenv("VVP_STATUS_ADMIN_KEY", "")

# =============================================================================
# Monitor Integration (Sprint 48)
# =============================================================================

# URL of the SIP Monitor dashboard's event ingestion endpoint
VVP_MONITOR_URL = os.getenv("VVP_MONITOR_URL", "http://127.0.0.1:8090")

# Enable/disable monitor event capture
VVP_MONITOR_ENABLED = os.getenv("VVP_MONITOR_ENABLED", "true").lower() == "true"

# Timeout for monitor API calls (seconds) - short to avoid blocking SIP
VVP_MONITOR_TIMEOUT = float(os.getenv("VVP_MONITOR_TIMEOUT", "1.0"))

# =============================================================================
# Logo Cache Configuration (Sprint 79)
# =============================================================================

# Cache directory for verified logos
VVP_LOGO_CACHE_DIR = os.getenv("VVP_LOGO_CACHE_DIR", "/tmp/vvp-logo-cache")

# Max cache size in MB
VVP_LOGO_CACHE_MAX_MB = int(os.getenv("VVP_LOGO_CACHE_MAX_MB", "100"))

# Cache TTL in hours
VVP_LOGO_CACHE_TTL_HOURS = int(os.getenv("VVP_LOGO_CACHE_TTL_HOURS", "24"))

# Public base URL for serving cached logos to handsets.
# MUST be the externally-reachable address of this service's HTTP port.
# Default uses pbx.rcnx.io (the PBX's public DNS) since sip-verify runs on the PBX.
# Override via env var for other deployments.
VVP_LOGO_BASE_URL = os.getenv(
    "VVP_LOGO_BASE_URL",
    "https://pbx.rcnx.io",
)

# =============================================================================
# Logging Configuration
# =============================================================================

# Log level
VVP_LOG_LEVEL = os.getenv("VVP_LOG_LEVEL", "INFO")

# Audit log buffer size
VVP_AUDIT_BUFFER_SIZE = int(os.getenv("VVP_AUDIT_BUFFER_SIZE", "1000"))
