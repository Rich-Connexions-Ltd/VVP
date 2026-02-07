"""Configuration for VVP SIP Redirect Service.

Sprint 42: Environment-based configuration with sensible defaults.
"""

import os
from pathlib import Path

# SIP Server Configuration
SIP_LISTEN_HOST = os.getenv("VVP_SIP_LISTEN_HOST", "0.0.0.0")
SIP_LISTEN_PORT = int(os.getenv("VVP_SIP_LISTEN_PORT", "5060"))
SIP_TRANSPORT = os.getenv("VVP_SIP_TRANSPORT", "udp")  # udp, tcp, both, all

# SIPS/TLS Configuration
SIPS_ENABLED = os.getenv("VVP_SIPS_ENABLED", "false").lower() == "true"
SIPS_LISTEN_PORT = int(os.getenv("VVP_SIPS_LISTEN_PORT", "5061"))
SIPS_CERT_FILE = os.getenv("VVP_SIPS_CERT_FILE", "")
SIPS_KEY_FILE = os.getenv("VVP_SIPS_KEY_FILE", "")

# Issuer API Configuration
ISSUER_URL = os.getenv("VVP_ISSUER_URL", "http://localhost:8001")
ISSUER_TIMEOUT = float(os.getenv("VVP_ISSUER_TIMEOUT", "10.0"))

# Note: /vvp/create now accepts org API keys with dossier_manager role
# The API key is passed in via SIP X-VVP-API-Key header from PBX dialplan

# Rate Limiting
RATE_LIMIT_RPS = float(os.getenv("VVP_RATE_LIMIT_RPS", "10.0"))
RATE_LIMIT_BURST = int(os.getenv("VVP_RATE_LIMIT_BURST", "50"))

# API Key Cache
API_KEY_CACHE_TTL = int(os.getenv("VVP_API_KEY_CACHE_TTL", "60"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Audit log directory
AUDIT_LOG_DIR = Path(os.getenv("VVP_AUDIT_LOG_DIR", "/var/log/vvp-sip"))

# Status endpoint configuration
STATUS_HTTP_PORT = int(os.getenv("VVP_STATUS_HTTP_PORT", "8080"))
STATUS_ADMIN_KEY = os.getenv("VVP_STATUS_ADMIN_KEY", "")


def validate_config() -> list[str]:
    """Validate configuration and return list of issues."""
    issues = []

    if SIPS_ENABLED:
        if not SIPS_CERT_FILE:
            issues.append("VVP_SIPS_CERT_FILE required when SIPS is enabled")
        elif not Path(SIPS_CERT_FILE).exists():
            issues.append(f"SIPS certificate file not found: {SIPS_CERT_FILE}")

        if not SIPS_KEY_FILE:
            issues.append("VVP_SIPS_KEY_FILE required when SIPS is enabled")
        elif not Path(SIPS_KEY_FILE).exists():
            issues.append(f"SIPS key file not found: {SIPS_KEY_FILE}")

    if SIP_TRANSPORT not in ("udp", "tcp", "both", "all"):
        issues.append(f"Invalid SIP_TRANSPORT: {SIP_TRANSPORT}")

    return issues
