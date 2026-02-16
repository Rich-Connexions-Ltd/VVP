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
    3. ~/.vvp-issuer (local development)
    4. /tmp/vvp-issuer (container fallback when home unavailable)
    """
    env_path = os.getenv("VVP_ISSUER_DATA_DIR")
    if env_path:
        return Path(env_path)

    docker_path = Path("/data/vvp-issuer")
    if docker_path.exists():
        return docker_path

    # Try home directory for local development
    try:
        home_path = Path.home() / ".vvp-issuer"
        # Test if we can create this directory
        home_path.mkdir(parents=True, exist_ok=True)
        return home_path
    except (OSError, PermissionError):
        # Fall back to /tmp for container environments
        return Path("/tmp/vvp-issuer")


DATA_DIR: Path = _get_data_dir()
KEYSTORE_DIR: Path = DATA_DIR / "keystores"
DATABASE_DIR: Path = DATA_DIR / "databases"


# =============================================================================
# DATABASE CONFIGURATION (Sprint 41: Multi-tenancy, Sprint 46: PostgreSQL)
# =============================================================================


def _get_database_url() -> str:
    """Get database URL from environment.

    Priority:
    1. VVP_DATABASE_URL - explicit full connection string
    2. VVP_POSTGRES_* - construct PostgreSQL URL from components
    3. SQLite fallback for local development

    Sprint 46: PostgreSQL migration with SSL enforcement.
    """
    # Explicit URL takes precedence
    if url := os.getenv("VVP_DATABASE_URL"):
        return url

    # Construct PostgreSQL URL from components (Azure deployment)
    host = os.getenv("VVP_POSTGRES_HOST")
    if host:
        user = os.getenv("VVP_POSTGRES_USER", "vvpadmin")
        password = os.getenv("VVP_POSTGRES_PASSWORD", "")
        db = os.getenv("VVP_POSTGRES_DB", "vvpissuer")
        # sslmode=require enforces encrypted connection to Azure PostgreSQL
        return f"postgresql+psycopg://{user}:{password}@{host}/{db}?sslmode=require"

    # Fallback to SQLite for local development
    return f"sqlite:///{DATA_DIR}/vvp_issuer.db"


DATABASE_URL: str = _get_database_url()


# =============================================================================
# MOCK vLEI CONFIGURATION (Sprint 41: Mock GLEIF/QVI Infrastructure)
# =============================================================================

MOCK_VLEI_ENABLED: bool = os.getenv("VVP_MOCK_VLEI_ENABLED", "true").lower() == "true"
MOCK_GLEIF_NAME: str = os.getenv("VVP_MOCK_GLEIF_NAME", "mock-gleif")
MOCK_QVI_NAME: str = os.getenv("VVP_MOCK_QVI_NAME", "mock-qvi")
MOCK_GSMA_NAME: str = os.getenv("VVP_MOCK_GSMA_NAME", "mock-gsma")


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
WITNESS_OOBI_BASE_URLS: list[str] = WITNESS_CONFIG.get("oobi_base_urls", [])

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
# DASHBOARD CONFIGURATION (Sprint 52: Central Service Dashboard)
# =============================================================================


def _parse_dashboard_services(env_var: str, default: str) -> list[dict[str, str]]:
    """Parse dashboard services JSON from environment variable."""
    raw = os.getenv(env_var, default)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []


DASHBOARD_SERVICES: list[dict[str, str]] = _parse_dashboard_services(
    "VVP_DASHBOARD_SERVICES",
    json.dumps([
        {"name": "Verifier", "url": "http://localhost:8000", "health_path": "/healthz", "category": "core"},
        {"name": "Issuer", "url": "http://localhost:8001", "health_path": "/healthz", "category": "core"},
        {"name": "Witness wan", "url": "http://localhost:5642", "health_path": "/health", "category": "witness"},
        {"name": "Witness wil", "url": "http://localhost:5643", "health_path": "/health", "category": "witness"},
        {"name": "Witness wes", "url": "http://localhost:5644", "health_path": "/health", "category": "witness"},
    ]),
)

# SIP services (separate config — may have custom health paths)
DASHBOARD_SIP_REDIRECT_URL: str = os.getenv("VVP_DASHBOARD_SIP_REDIRECT_URL", "")
DASHBOARD_SIP_REDIRECT_HEALTH: str = os.getenv("VVP_DASHBOARD_SIP_REDIRECT_HEALTH", "/healthz")
DASHBOARD_SIP_VERIFY_URL: str = os.getenv("VVP_DASHBOARD_SIP_VERIFY_URL", "")
DASHBOARD_SIP_VERIFY_HEALTH: str = os.getenv("VVP_DASHBOARD_SIP_VERIFY_HEALTH", "/healthz")
DASHBOARD_SIP_MONITOR_URL: str = os.getenv("VVP_DASHBOARD_SIP_MONITOR_URL", "")

# Timeout for each health check (seconds)
DASHBOARD_REQUEST_TIMEOUT: float = float(os.getenv("VVP_DASHBOARD_REQUEST_TIMEOUT", "5.0"))


# =============================================================================
# KERI AGENT CLIENT CONFIGURATION (Sprint 68: Service Extraction)
# =============================================================================

KERI_AGENT_URL: str = os.getenv("VVP_KERI_AGENT_URL", "http://localhost:8002")
KERI_AGENT_AUTH_TOKEN: str = os.getenv("VVP_KERI_AGENT_AUTH_TOKEN", "")
KERI_AGENT_TIMEOUT: float = float(os.getenv("VVP_KERI_AGENT_TIMEOUT", "30"))
KERI_AGENT_WRITE_TIMEOUT: float = float(os.getenv("VVP_KERI_AGENT_WRITE_TIMEOUT", "120"))


# =============================================================================
# OPERATIONAL
# =============================================================================

ADMIN_ENDPOINT_ENABLED: bool = os.getenv("ADMIN_ENDPOINT_ENABLED", "true").lower() == "true"
SERVICE_PORT: int = int(os.getenv("VVP_ISSUER_PORT", "8001"))

# Sprint 62: Vetter constraint enforcement (issuer-side toggle)
# When false (default): log warnings for constraint violations, proceed normally
#   → allows admin to deliberately create mis-vetted credential chains for testing
# When true: reject requests with 403 for constraint violations
# The verifier always evaluates constraints regardless of this setting.
# Toggleable at runtime via PUT /admin/settings/vetter-enforcement
ENFORCE_VETTER_CONSTRAINTS: bool = os.getenv(
    "VVP_ENFORCE_VETTER_CONSTRAINTS", "false"
).lower() == "true"


def set_enforce_vetter_constraints(value: bool) -> None:
    """Toggle vetter constraint enforcement at runtime.

    Called by the admin API endpoint PUT /admin/settings/vetter-enforcement.
    """
    global ENFORCE_VETTER_CONSTRAINTS
    ENFORCE_VETTER_CONSTRAINTS = value

# VVP Header creation settings
# Base URL for this issuer service (used to construct dossier URLs)
VVP_ISSUER_BASE_URL: str = os.getenv("VVP_ISSUER_BASE_URL", "http://localhost:8001")


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
        # Sprint 41: User management routes (always accessible, auth checked in page)
        exempt.add("/login")
        exempt.add("/profile")
        exempt.add("/users/ui")
        exempt.add("/organizations/ui")
        # Sprint 52: Dashboard
        exempt.add("/ui/dashboard")
        exempt.add("/api/dashboard/status")
        # Sprint 66: Walkthrough
        exempt.add("/ui/walkthrough")
        # Sprint 67: Organization detail
        exempt.add("/ui/organization-detail")

    return exempt
