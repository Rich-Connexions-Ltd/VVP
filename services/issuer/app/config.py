"""VVP Issuer configuration constants.

Environment-based configuration following the verifier's three-tier pattern:
- NORMATIVE: Fixed by spec (none for issuer yet)
- CONFIGURABLE: Spec defaults that can be overridden
- POLICY: Implementation choices
"""
import json
import os
from pathlib import Path
from typing import Any


# =============================================================================
# PERSISTENCE CONFIGURATION
# =============================================================================

def _get_data_dir() -> Path:
    """Determine data directory based on environment.

    Priority:
    1. VVP_ISSUER_DATA_DIR env var (explicit override)
    2. /data/vvp-issuer if it exists (Docker volume mount)
    3. ~/.vvp-issuer (local development fallback)
    """
    env_path = os.getenv("VVP_ISSUER_DATA_DIR")
    if env_path:
        return Path(env_path)

    docker_path = Path("/data/vvp-issuer")
    if docker_path.exists():
        return docker_path

    return Path.home() / ".vvp-issuer"


DATA_DIR: Path = _get_data_dir()
KEYSTORE_DIR: Path = DATA_DIR / "keystores"
DATABASE_DIR: Path = DATA_DIR / "databases"


# =============================================================================
# WITNESS CONFIGURATION
# =============================================================================

def _get_witness_config_path() -> str:
    """Get path to witness configuration file."""
    return os.getenv(
        "VVP_WITNESS_CONFIG",
        str(Path(__file__).parent.parent / "config" / "witnesses.json")
    )


def _load_witness_config() -> dict[str, Any]:
    """Load witness configuration from JSON file."""
    config_path = Path(_get_witness_config_path())
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"iurls": [], "witness_aids": {}, "ports": {}}


WITNESS_CONFIG_PATH: str = _get_witness_config_path()
WITNESS_CONFIG: dict[str, Any] = _load_witness_config()
WITNESS_IURLS: list[str] = WITNESS_CONFIG.get("iurls", [])
WITNESS_AIDS: dict[str, str] = WITNESS_CONFIG.get("witness_aids", {})
WITNESS_PORTS: dict[str, dict[str, int]] = WITNESS_CONFIG.get("ports", {})

# Witness interaction settings
WITNESS_TIMEOUT_SECONDS: float = float(os.getenv("VVP_WITNESS_TIMEOUT", "10.0"))
WITNESS_RECEIPT_THRESHOLD: int = int(os.getenv("VVP_WITNESS_THRESHOLD", "2"))


# =============================================================================
# IDENTITY DEFAULTS
# =============================================================================

# Default key configuration for new identities
DEFAULT_KEY_COUNT: int = int(os.getenv("VVP_DEFAULT_KEY_COUNT", "1"))
DEFAULT_KEY_THRESHOLD: str = os.getenv("VVP_DEFAULT_KEY_THRESHOLD", "1")
DEFAULT_NEXT_KEY_COUNT: int = int(os.getenv("VVP_DEFAULT_NEXT_KEY_COUNT", "1"))
DEFAULT_NEXT_THRESHOLD: str = os.getenv("VVP_DEFAULT_NEXT_THRESHOLD", "1")


# =============================================================================
# OPERATIONAL
# =============================================================================

ADMIN_ENDPOINT_ENABLED: bool = os.getenv("ADMIN_ENDPOINT_ENABLED", "true").lower() == "true"
SERVICE_PORT: int = int(os.getenv("VVP_ISSUER_PORT", "8001"))


# =============================================================================
# AZURE CONFIGURATION
# =============================================================================

# Azure settings for Container App scaling management (admin feature)
# These are only required if using the /admin/scaling endpoint
AZURE_SUBSCRIPTION_ID: str | None = os.getenv("AZURE_SUBSCRIPTION_ID")
AZURE_RESOURCE_GROUP: str = os.getenv("AZURE_RESOURCE_GROUP", "VVP")


# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

def _get_api_keys_file() -> str:
    """Get path to API keys configuration file."""
    return os.getenv(
        "VVP_API_KEYS_FILE",
        str(Path(__file__).parent.parent / "config" / "api_keys.json")
    )


# API key authentication
API_KEYS_FILE: str = _get_api_keys_file()
API_KEYS_JSON: str | None = os.getenv("VVP_API_KEYS")  # Inline JSON override

# Authentication settings
AUTH_ENABLED: bool = os.getenv("VVP_AUTH_ENABLED", "true").lower() == "true"
AUTH_EXEMPT_PATHS: set[str] = {"/healthz", "/version"}  # Always exempt

# Docs/OpenAPI protection
# Default: protected (require auth). Set to "true" to exempt from auth.
DOCS_AUTH_EXEMPT: bool = os.getenv("VVP_DOCS_AUTH_EXEMPT", "false").lower() == "true"

# UI authentication
# Default: UI does not require auth. Set to "true" to require auth.
UI_AUTH_ENABLED: bool = os.getenv("VVP_UI_AUTH_ENABLED", "false").lower() == "true"

# Key reload settings
AUTH_RELOAD_INTERVAL: int = int(os.getenv("VVP_AUTH_RELOAD_INTERVAL", "60"))  # seconds
AUTH_RELOAD_ENABLED: bool = os.getenv("VVP_AUTH_RELOAD_ENABLED", "true").lower() == "true"


# =============================================================================
# SESSION CONFIGURATION
# =============================================================================

# Session cookie settings
SESSION_TTL_SECONDS: int = int(os.getenv("VVP_SESSION_TTL", "3600"))  # 1 hour default
SESSION_COOKIE_SECURE: bool = os.getenv("VVP_SESSION_SECURE", "true").lower() == "true"
SESSION_CLEANUP_INTERVAL: int = int(os.getenv("VVP_SESSION_CLEANUP_INTERVAL", "300"))  # 5 min

# Login rate limiting
LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = int(os.getenv("VVP_LOGIN_RATE_LIMIT_MAX", "5"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("VVP_LOGIN_RATE_LIMIT_WINDOW", "900"))  # 15 min


# =============================================================================
# USER AUTHENTICATION
# =============================================================================

def _get_users_file() -> str:
    """Get path to users configuration file."""
    return os.getenv(
        "VVP_USERS_FILE",
        str(Path(__file__).parent.parent / "config" / "users.json")
    )


# User authentication (alongside API keys)
USERS_FILE: str = _get_users_file()
USERS_JSON: str | None = os.getenv("VVP_USERS")  # Inline JSON override


# =============================================================================
# OAUTH M365 CONFIGURATION
# =============================================================================

# Enable Microsoft OAuth login (default: disabled)
OAUTH_M365_ENABLED: bool = os.getenv("VVP_OAUTH_M365_ENABLED", "false").lower() == "true"

# Microsoft Entra (Azure AD) application registration
OAUTH_M365_TENANT_ID: str | None = os.getenv("VVP_OAUTH_M365_TENANT_ID")
OAUTH_M365_CLIENT_ID: str | None = os.getenv("VVP_OAUTH_M365_CLIENT_ID")
OAUTH_M365_CLIENT_SECRET: str | None = os.getenv("VVP_OAUTH_M365_CLIENT_SECRET")
OAUTH_M365_REDIRECT_URI: str | None = os.getenv("VVP_OAUTH_M365_REDIRECT_URI")

# Auto-provision users on first OAuth login (default: disabled)
OAUTH_M365_AUTO_PROVISION: bool = os.getenv("VVP_OAUTH_M365_AUTO_PROVISION", "false").lower() == "true"

# Allowed email domains (comma-separated, empty = all domains allowed)
# Example: "example.com,company.org"
OAUTH_M365_ALLOWED_DOMAINS: list[str] = [
    d.strip().lower()
    for d in os.getenv("VVP_OAUTH_M365_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
]

# Default roles for auto-provisioned OAuth users
OAUTH_M365_DEFAULT_ROLES: list[str] = [
    r.strip()
    for r in os.getenv("VVP_OAUTH_M365_DEFAULT_ROLES", "issuer:readonly").split(",")
    if r.strip()
]

# OAuth state TTL (seconds) - how long OAuth state is valid
OAUTH_STATE_TTL_SECONDS: int = int(os.getenv("VVP_OAUTH_STATE_TTL", "600"))  # 10 minutes


def validate_oauth_m365_config() -> tuple[bool, str | None]:
    """Validate OAuth M365 configuration.

    Returns:
        Tuple of (is_valid, error_message). If is_valid is False,
        error_message contains the reason.
    """
    if not OAUTH_M365_ENABLED:
        return True, None

    missing = []
    if not OAUTH_M365_TENANT_ID:
        missing.append("VVP_OAUTH_M365_TENANT_ID")
    if not OAUTH_M365_CLIENT_ID:
        missing.append("VVP_OAUTH_M365_CLIENT_ID")
    if not OAUTH_M365_CLIENT_SECRET:
        missing.append("VVP_OAUTH_M365_CLIENT_SECRET")
    if not OAUTH_M365_REDIRECT_URI:
        missing.append("VVP_OAUTH_M365_REDIRECT_URI")

    if missing:
        return False, f"OAuth M365 enabled but missing config: {', '.join(missing)}"

    return True, None


def get_auth_exempt_paths() -> set[str]:
    """Get the full set of auth-exempt paths based on configuration."""
    exempt = set(AUTH_EXEMPT_PATHS)

    # Auth endpoints must be exempt (login/logout don't require existing auth)
    exempt.add("/auth/login")
    exempt.add("/auth/logout")
    exempt.add("/auth/status")

    # OAuth endpoints must be exempt (user not yet authenticated)
    exempt.add("/auth/oauth/m365/start")
    exempt.add("/auth/oauth/m365/callback")
    exempt.add("/auth/oauth/status")

    if DOCS_AUTH_EXEMPT:
        exempt.add("/docs")
        exempt.add("/openapi.json")
        exempt.add("/redoc")

    if not UI_AUTH_ENABLED:
        exempt.add("/create")
        exempt.add("/registry/ui")
        exempt.add("/schemas/ui")
        exempt.add("/credentials/ui")
        exempt.add("/dossier/ui")
        # New /ui/* routes
        exempt.add("/ui/")
        exempt.add("/ui/identity")
        exempt.add("/ui/registry")
        exempt.add("/ui/schemas")
        exempt.add("/ui/credentials")
        exempt.add("/ui/dossier")
        exempt.add("/ui/admin")

    return exempt
