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
# Logging Configuration
# =============================================================================

# Log level
VVP_LOG_LEVEL = os.getenv("VVP_LOG_LEVEL", "INFO")

# Audit log buffer size
VVP_AUDIT_BUFFER_SIZE = int(os.getenv("VVP_AUDIT_BUFFER_SIZE", "1000"))
