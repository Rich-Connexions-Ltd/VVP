"""API key authentication backend for VVP Issuer.

Uses bcrypt for secure key hashing with constant-time verification.
Supports key rotation via file mtime polling or admin reload endpoint.

Bcrypt cost factor: 10 (2^10 = 1024 iterations). Lowered from 12 for
API keys (long random strings — cost-10 is still very secure) to reduce
per-request latency on constrained containers. Existing keys hashed at
cost-12 remain valid; they are transparently verified at their embedded cost.

Sprint 77: Short-lived API key result cache (5 min TTL) eliminates repeated
bcrypt verification for the same key within a session. The authenticate()
middleware is also offloaded to asyncio.to_thread() to avoid blocking the
event loop during bcrypt.
"""

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

import bcrypt as bcrypt_lib
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    BaseUser,
)
from starlette.requests import HTTPConnection

log = logging.getLogger(__name__)

# Default bcrypt cost factor (2^10 = 1024 iterations)
# Lowered from 12: API keys are long random strings; cost-10 is sufficient.
# Existing cost-12 hashes are transparently verified at their embedded cost.
BCRYPT_COST_FACTOR = 10

# Short-lived API key verification cache — acceptable for non-production use.
# Eliminates repeated bcrypt for the same key within a 5-minute window.
_API_KEY_CACHE_TTL = 300.0   # 5 minutes
_API_KEY_CACHE_MAX = 256      # max entries (LRU eviction above this)
_api_key_cache: OrderedDict[str, tuple] = OrderedDict()  # key → (principal, error, ts)
_api_key_cache_lock = Lock()

# Session cookie name (must match api/auth.py)
SESSION_COOKIE_NAME = "vvp_session"

# CSRF protection headers
CSRF_HEADER = "X-Requested-With"
CSRF_HEADER_VALUE = "XMLHttpRequest"
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


@dataclass
class Principal(BaseUser):
    """Authenticated principal with roles.

    Implements Starlette's BaseUser interface for middleware integration.

    Attributes:
        key_id: Unique identifier (e.g., "user:email", "api_key:id", "org_key:id")
        name: Display name for the principal
        roles: Set of role strings (system and/or org roles)
        organization_id: Organization UUID for org-scoped principals (None for system-only)
    """

    key_id: str
    name: str
    roles: set[str] = field(default_factory=set)
    organization_id: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def identity(self) -> str:
        return self.key_id

    @property
    def is_system_admin(self) -> bool:
        """Check if principal has system admin role."""
        return "issuer:admin" in self.roles


@dataclass
class KeyConfig:
    """Configuration for a single API key."""

    id: str
    name: str
    hash: str
    roles: set[str]
    revoked: bool = False


class APIKeyStore:
    """Manages API key configuration with reload support.

    Keys are loaded from a JSON config file. The store supports:
    - Automatic reload when file mtime changes (polling)
    - Manual reload via reload() method
    - Revocation via 'revoked' flag in config
    """

    def __init__(self, config_path: str | None = None, config_json: str | None = None):
        """Initialize the key store.

        Args:
            config_path: Path to JSON config file
            config_json: Inline JSON config (takes precedence over file)
        """
        self._config_path = config_path
        self._config_json = config_json
        self._keys: dict[str, KeyConfig] = {}
        self._last_mtime: float = 0
        self._last_check: float = 0
        self._check_interval: float = 60.0  # seconds
        self._version: int = 0

    def load(self) -> None:
        """Load keys from config file or inline JSON."""
        config_data: dict[str, Any] = {"keys": [], "version": 0}

        # Inline JSON takes precedence
        if self._config_json:
            try:
                config_data = json.loads(self._config_json)
                log.info("Loaded API keys from inline JSON")
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse inline API keys JSON: {e}")
                return
        elif self._config_path:
            path = Path(self._config_path)
            if path.exists():
                try:
                    config_data = json.loads(path.read_text())
                    self._last_mtime = path.stat().st_mtime
                    log.info(f"Loaded API keys from {self._config_path}")
                except (json.JSONDecodeError, OSError) as e:
                    log.error(f"Failed to load API keys from {self._config_path}: {e}")
                    return
            else:
                log.warning(f"API keys file not found: {self._config_path}")
                return

        # Parse keys
        self._keys = {}
        self._version = config_data.get("version", 0)

        for key_data in config_data.get("keys", []):
            try:
                key_config = KeyConfig(
                    id=key_data["id"],
                    name=key_data["name"],
                    hash=key_data["hash"],
                    roles=set(key_data.get("roles", [])),
                    revoked=key_data.get("revoked", False),
                )
                self._keys[key_config.id] = key_config

                if key_config.revoked:
                    log.info(f"Loaded revoked key: {key_config.id}")
                else:
                    log.debug(f"Loaded key: {key_config.id} with roles {key_config.roles}")

            except KeyError as e:
                log.error(f"Invalid key config, missing field: {e}")

        log.info(f"Loaded {len(self._keys)} API keys (version {self._version})")

    def reload(self) -> bool:
        """Force reload of keys from config.

        Returns:
            True if reload successful, False otherwise
        """
        try:
            old_count = len(self._keys)
            self.load()
            log.info(f"Reloaded API keys: {old_count} -> {len(self._keys)}")
            return True
        except Exception as e:
            log.error(f"Failed to reload API keys: {e}")
            return False

    def reload_if_stale(self) -> bool:
        """Reload if config file mtime has changed.

        Called periodically (e.g., from middleware). Only checks file
        mtime every check_interval seconds to avoid I/O overhead.

        Returns:
            True if reloaded, False if not needed or failed
        """
        if not self._config_path:
            return False

        now = time.time()
        if now - self._last_check < self._check_interval:
            return False

        self._last_check = now
        path = Path(self._config_path)

        if not path.exists():
            return False

        try:
            current_mtime = path.stat().st_mtime
            if current_mtime > self._last_mtime:
                log.info("API keys file changed, reloading...")
                return self.reload()
        except OSError:
            pass

        return False

    def verify(self, raw_key: str) -> tuple[Principal | None, str | None]:
        """Verify an API key and return the principal.

        Uses bcrypt.checkpw() for constant-time comparison.

        Args:
            raw_key: The raw API key from the request header

        Returns:
            Tuple of (Principal if valid, error_reason if invalid)
            - (Principal, None) for valid key
            - (None, "revoked") for revoked key
            - (None, "invalid") for invalid/unknown key
        """
        for key_config in self._keys.values():
            try:
                if bcrypt_lib.checkpw(raw_key.encode(), key_config.hash.encode()):
                    if key_config.revoked:
                        log.warning(f"Revoked key attempted: {key_config.id}")
                        return None, "revoked"

                    return Principal(
                        key_id=key_config.id,
                        name=key_config.name,
                        roles=key_config.roles,
                    ), None
            except Exception:
                # bcrypt.checkpw can raise on malformed hash
                continue

        return None, "invalid"

    def set_check_interval(self, seconds: float) -> None:
        """Set the interval for file mtime checking."""
        self._check_interval = seconds

    @property
    def key_count(self) -> int:
        """Number of loaded keys."""
        return len(self._keys)

    @property
    def version(self) -> int:
        """Config version number."""
        return self._version


# Global store instance
_api_key_store: APIKeyStore | None = None


def verify_org_api_key(raw_key: str) -> tuple[Principal | None, str | None]:
    """Verify an organization API key from the database.

    Sprint 41: Org API keys are stored in the database with bcrypt hashes.
    This function checks the key against all org API keys.

    Args:
        raw_key: The raw API key from the request header

    Returns:
        Tuple of (Principal if valid, error_reason if invalid)
        - (Principal, None) for valid key
        - (None, "revoked") for revoked key
        - (None, "org_disabled") for disabled org
        - (None, "invalid") for invalid/unknown key
    """
    # Import here to avoid circular dependency
    from app.db.session import get_db_session
    from app.db.models import OrgAPIKey, OrgAPIKeyRole, Organization

    try:
        with get_db_session() as db:
            # Get all non-revoked org API keys
            keys = db.query(OrgAPIKey).all()

            for key in keys:
                try:
                    if bcrypt_lib.checkpw(raw_key.encode(), key.key_hash.encode()):
                        if key.revoked:
                            log.warning(f"Revoked org API key attempted: {key.id}")
                            return None, "revoked"

                        # Check if org is enabled
                        org = db.query(Organization).filter(Organization.id == key.organization_id).first()
                        if org and not org.enabled:
                            log.warning(f"Org API key for disabled org: {key.id}")
                            return None, "org_disabled"

                        # Build roles from join table
                        roles = {r.role for r in key.roles}

                        return Principal(
                            key_id=f"org_key:{key.id}",
                            name=key.name,
                            roles=roles,
                            organization_id=key.organization_id,
                        ), None
                except Exception:
                    # bcrypt.checkpw can raise on malformed hash
                    continue

            return None, "invalid"

    except Exception as e:
        log.error(f"Error verifying org API key: {e}")
        return None, "invalid"


def verify_org_key_still_valid(key_id: str) -> bool:
    """Check if an org API key is still valid (not revoked, org not disabled).

    Used by session validation to verify org API key sessions are still valid
    without needing the raw key material.

    Args:
        key_id: The key_id in "org_key:{db_id}" format

    Returns:
        True if key is still valid, False if revoked/removed/org disabled
    """
    from app.db.session import get_db_session
    from app.db.models import OrgAPIKey, Organization

    try:
        db_id = key_id.split(":", 1)[1]
        with get_db_session() as db:
            key = db.query(OrgAPIKey).filter(OrgAPIKey.id == db_id).first()
            if key is None or key.revoked:
                return False
            org = db.query(Organization).filter(Organization.id == key.organization_id).first()
            if org and not org.enabled:
                return False
            return True
    except Exception as e:
        log.error(f"Error checking org API key validity: {e}")
        return False


def verify_api_key_with_cache(
    raw_key: str,
    store: "APIKeyStore | None" = None,
) -> tuple["Principal | None", "str | None"]:
    """Verify an API key with a short-lived result cache.

    Checks the in-memory cache first (TTL=5min). On a miss, runs the full
    bcrypt verification via the file-based store then the DB org key store,
    and caches the result.

    Thread-safe: safe to call from asyncio.to_thread().

    Args:
        raw_key: Raw API key from the request
        store: Optional pre-fetched APIKeyStore (uses global if not provided)

    Returns:
        (Principal, None) on success, (None, error_str) on failure
    """
    now = time.monotonic()

    # Cache lookup (fast path)
    with _api_key_cache_lock:
        if raw_key in _api_key_cache:
            principal, error, ts = _api_key_cache[raw_key]
            if now - ts < _API_KEY_CACHE_TTL:
                _api_key_cache.move_to_end(raw_key)  # LRU promotion
                log.debug("API key cache hit")
                return principal, error
            else:
                del _api_key_cache[raw_key]  # expired

    # Cache miss — full bcrypt verification
    if store is None:
        store = get_api_key_store()

    principal, error = store.verify(raw_key)
    if principal is None and error == "invalid":
        principal, error = verify_org_api_key(raw_key)

    # Cache the result (including failures, to resist brute-force enumeration)
    with _api_key_cache_lock:
        _api_key_cache[raw_key] = (principal, error, time.monotonic())
        while len(_api_key_cache) > _API_KEY_CACHE_MAX:
            _api_key_cache.popitem(last=False)  # evict LRU

    return principal, error


def reset_api_key_verification_cache() -> None:
    """Clear the API key verification cache (for testing / key rotation)."""
    with _api_key_cache_lock:
        _api_key_cache.clear()
    log.info("API key verification cache cleared")


def get_api_key_store() -> APIKeyStore:
    """Get the global API key store instance.

    Lazily initializes from config on first access.
    """
    global _api_key_store

    if _api_key_store is None:
        # Import here to avoid circular dependency
        from app.config import API_KEYS_FILE, API_KEYS_JSON, AUTH_RELOAD_INTERVAL

        _api_key_store = APIKeyStore(
            config_path=API_KEYS_FILE,
            config_json=API_KEYS_JSON,
        )
        _api_key_store.set_check_interval(AUTH_RELOAD_INTERVAL)
        _api_key_store.load()

    return _api_key_store


def reset_api_key_store() -> None:
    """Reset the global store (for testing)."""
    global _api_key_store
    _api_key_store = None


class APIKeyBackend(AuthenticationBackend):
    """Dual-mode authentication backend: session cookie OR API key.

    Checks for authentication in this order:
    1. Session cookie (vvp_session) - for browser-based UI access
    2. X-API-Key header - for programmatic API access

    CSRF protection is enforced for cookie-authenticated state-changing requests.
    """

    def __init__(self, exempt_paths: set[str] | None = None):
        """Initialize the backend.

        Args:
            exempt_paths: Paths that don't require authentication
        """
        self.exempt_paths = exempt_paths or set()

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, Principal] | None:
        """Authenticate a request.

        Checks session cookie first, then falls back to API key header.
        For cookie-based auth, enforces CSRF header on state-changing methods.

        Args:
            conn: The HTTP connection

        Returns:
            Tuple of (credentials, user) if authenticated, None otherwise
        """
        # Check if path is exempt
        path = conn.url.path
        if path in self.exempt_paths:
            return None

        # Check for exact prefix matches (for paths like /healthz that might have query params)
        for exempt in self.exempt_paths:
            if path.startswith(exempt):
                return None

        # === Check session cookie first ===
        session_id = conn.cookies.get(SESSION_COOKIE_NAME)
        if session_id:
            # Import here to avoid circular dependency
            from app.auth.session import get_session_store

            session_store = get_session_store()
            session = await session_store.get(session_id)

            if session is not None:
                # Valid session found - enforce CSRF for state-changing methods
                method = conn.scope.get("method", "GET")
                if method in STATE_CHANGING_METHODS:
                    csrf_header = conn.headers.get(CSRF_HEADER)
                    if csrf_header != CSRF_HEADER_VALUE:
                        raise AuthenticationError(
                            "CSRF header required for cookie-authenticated requests"
                        )

                return AuthCredentials(list(session.principal.roles)), session.principal

            # Session invalid/expired - fall through to check API key

        # === Check API key header ===
        api_key = conn.headers.get("X-API-Key")

        if not api_key:
            # No auth provided - let the route handler decide if auth is required
            return None

        # Check for stale config
        store = get_api_key_store()
        store.reload_if_stale()

        # Sprint 77: Offload to thread pool — bcrypt blocks the event loop.
        # verify_api_key_with_cache() checks the 5-min cache first, only
        # runs bcrypt on a cache miss.
        principal, error = await asyncio.to_thread(
            verify_api_key_with_cache, api_key, store
        )

        if principal is None:
            # Key is invalid or revoked - raise error
            # Note: We use the same error message for security (no info leak)
            raise AuthenticationError("Invalid API key")

        # Create credentials from roles (no CSRF check for API key auth)
        return AuthCredentials(list(principal.roles)), principal


def hash_api_key(raw_key: str, cost_factor: int = BCRYPT_COST_FACTOR) -> str:
    """Hash an API key using bcrypt.

    Args:
        raw_key: The raw API key to hash
        cost_factor: bcrypt cost factor (default: 12)

    Returns:
        The bcrypt hash string
    """
    salt = bcrypt_lib.gensalt(rounds=cost_factor)
    return bcrypt_lib.hashpw(raw_key.encode(), salt).decode()
