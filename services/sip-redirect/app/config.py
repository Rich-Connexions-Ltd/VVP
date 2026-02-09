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

# TN Lookup Cache - caches TN→dossier mappings to avoid repeated issuer API calls
TN_CACHE_TTL = int(os.getenv("VVP_TN_CACHE_TTL", "300"))  # 5 minutes
TN_CACHE_MAX_ENTRIES = int(os.getenv("VVP_TN_CACHE_MAX_ENTRIES", "1000"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Audit log directory
AUDIT_LOG_DIR = Path(os.getenv("VVP_AUDIT_LOG_DIR", "/var/log/vvp-sip"))

# Status endpoint configuration (PBX uses port 8085 via env override)
STATUS_HTTP_PORT = int(os.getenv("VVP_STATUS_HTTP_PORT", "8080"))
STATUS_ADMIN_KEY = os.getenv("VVP_STATUS_ADMIN_KEY", "")

# Monitoring Dashboard Configuration (Sprint 47)
MONITOR_ENABLED = os.getenv("VVP_MONITOR_ENABLED", "false").lower() == "true"
MONITOR_PORT = int(os.getenv("VVP_MONITOR_PORT", "8090"))
MONITOR_BUFFER_SIZE = int(os.getenv("VVP_MONITOR_BUFFER_SIZE", "100"))
MONITOR_USERS_FILE = os.getenv("VVP_MONITOR_USERS_FILE", "/opt/vvp/sip-redirect/users.json")
MONITOR_SESSION_TTL = int(os.getenv("VVP_MONITOR_SESSION_TTL", "3600"))  # 1 hour
MONITOR_RATE_LIMIT_MAX = int(os.getenv("VVP_MONITOR_RATE_LIMIT_MAX", "5"))
MONITOR_RATE_LIMIT_WINDOW = int(os.getenv("VVP_MONITOR_RATE_LIMIT_WINDOW", "900"))  # 15 min

# Cookie path (Sprint 49) - "/" for local dev, "/sip-monitor/" behind nginx
MONITOR_COOKIE_PATH = os.getenv("VVP_MONITOR_COOKIE_PATH", "/")

# WebSocket Configuration (Sprint 48)
MONITOR_WS_HEARTBEAT = int(os.getenv("VVP_MONITOR_WS_HEARTBEAT", "15"))  # seconds
MONITOR_WS_IDLE_TIMEOUT = int(os.getenv("VVP_MONITOR_WS_IDLE_TIMEOUT", "30"))  # seconds
MONITOR_WS_MAX_PER_IP = int(os.getenv("VVP_MONITOR_WS_MAX_PER_IP", "10"))
MONITOR_WS_MAX_GLOBAL = int(os.getenv("VVP_MONITOR_WS_MAX_GLOBAL", "50"))

# Monitor OAuth M365 Configuration
MONITOR_OAUTH_ENABLED = os.getenv("VVP_MONITOR_OAUTH_ENABLED", "true").lower() == "true"
MONITOR_OAUTH_TENANT_ID = os.getenv("VVP_MONITOR_OAUTH_TENANT_ID")
MONITOR_OAUTH_CLIENT_ID = os.getenv("VVP_MONITOR_OAUTH_CLIENT_ID")
MONITOR_OAUTH_CLIENT_SECRET = os.getenv("VVP_MONITOR_OAUTH_CLIENT_SECRET")
MONITOR_OAUTH_REDIRECT_URI = os.getenv(
    "VVP_MONITOR_OAUTH_REDIRECT_URI",
    "https://pbx.rcnx.io/sip-monitor/auth/oauth/m365/callback",
)
MONITOR_OAUTH_AUTO_PROVISION = (
    os.getenv("VVP_MONITOR_OAUTH_AUTO_PROVISION", "true").lower() == "true"
)
MONITOR_OAUTH_ALLOWED_DOMAINS = [
    d.strip().lower()
    for d in os.getenv("VVP_MONITOR_OAUTH_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
]
MONITOR_OAUTH_STATE_TTL = int(os.getenv("VVP_MONITOR_OAUTH_STATE_TTL", "600"))

# Monitor API Key Store
MONITOR_API_KEYS_FILE = os.getenv(
    "VVP_MONITOR_API_KEYS_FILE", "/opt/vvp/sip-redirect/api_keys.json"
)

# Version tracking (injected by CI/CD)
GIT_SHA = os.getenv("GIT_SHA", "unknown")


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
