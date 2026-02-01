"""API key authentication backend for VVP Issuer.

Uses bcrypt for secure key hashing with constant-time verification.
Supports key rotation via file mtime polling or admin reload endpoint.

Bcrypt cost factor: 12 (default). To change cost factor for new keys,
update the generator script. Existing keys remain valid until re-hashed.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
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

# Default bcrypt cost factor (2^12 = 4096 iterations)
BCRYPT_COST_FACTOR = 12

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
    """

    key_id: str
    name: str
    roles: set[str] = field(default_factory=set)

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def identity(self) -> str:
        return self.key_id


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

        # Verify the key
        principal, error = store.verify(api_key)

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
