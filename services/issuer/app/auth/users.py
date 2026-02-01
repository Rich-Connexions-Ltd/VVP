"""User authentication for VVP Issuer.

Provides username/password authentication alongside API key auth.
Users are stored in a JSON config file with bcrypt-hashed passwords.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import bcrypt as bcrypt_lib

from app.auth.api_key import Principal

log = logging.getLogger(__name__)

# Default bcrypt cost factor (2^12 = 4096 iterations)
BCRYPT_COST_FACTOR = 12


@dataclass
class UserConfig:
    """Configuration for a single user."""

    email: str
    name: str
    password_hash: str
    roles: set[str]
    enabled: bool = True


class UserStore:
    """Manages user configuration with reload support.

    Users are loaded from a JSON config file. The store supports:
    - Automatic reload when file mtime changes (polling)
    - Manual reload via reload() method
    - User enable/disable via 'enabled' flag
    """

    def __init__(self, config_path: str | None = None, config_json: str | None = None):
        """Initialize the user store.

        Args:
            config_path: Path to JSON config file
            config_json: Inline JSON config (takes precedence over file)
        """
        self._config_path = config_path
        self._config_json = config_json
        self._users: dict[str, UserConfig] = {}
        self._last_mtime: float = 0
        self._last_check: float = 0
        self._check_interval: float = 60.0  # seconds

    def load(self) -> None:
        """Load users from config file or inline JSON."""
        config_data: dict[str, Any] = {"users": []}

        # Inline JSON takes precedence
        if self._config_json:
            try:
                config_data = json.loads(self._config_json)
                log.info("Loaded users from inline JSON")
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse inline users JSON: {e}")
                return
        elif self._config_path:
            path = Path(self._config_path)
            if path.exists():
                try:
                    config_data = json.loads(path.read_text())
                    self._last_mtime = path.stat().st_mtime
                    log.info(f"Loaded users from {self._config_path}")
                except (json.JSONDecodeError, OSError) as e:
                    log.error(f"Failed to load users from {self._config_path}: {e}")
                    return
            else:
                log.warning(f"Users file not found: {self._config_path}")
                return

        # Parse users
        self._users = {}

        for user_data in config_data.get("users", []):
            try:
                user_config = UserConfig(
                    email=user_data["email"].lower(),  # Normalize to lowercase
                    name=user_data["name"],
                    password_hash=user_data["password_hash"],
                    roles=set(user_data.get("roles", ["issuer:readonly"])),
                    enabled=user_data.get("enabled", True),
                )
                self._users[user_config.email] = user_config

                if not user_config.enabled:
                    log.info(f"Loaded disabled user: {user_config.email}")
                else:
                    log.debug(f"Loaded user: {user_config.email} with roles {user_config.roles}")

            except KeyError as e:
                log.error(f"Invalid user config, missing field: {e}")

        log.info(f"Loaded {len(self._users)} users")

    def reload(self) -> bool:
        """Force reload of users from config.

        Returns:
            True if reload successful, False otherwise
        """
        try:
            old_count = len(self._users)
            self.load()
            log.info(f"Reloaded users: {old_count} -> {len(self._users)}")
            return True
        except Exception as e:
            log.error(f"Failed to reload users: {e}")
            return False

    def reload_if_stale(self) -> bool:
        """Reload if config file mtime has changed.

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
                log.info("Users file changed, reloading...")
                return self.reload()
        except OSError:
            pass

        return False

    def verify(self, email: str, password: str) -> tuple[Principal | None, str | None]:
        """Verify a user's credentials and return the principal.

        Uses bcrypt.checkpw() for constant-time comparison.

        Args:
            email: User's email address (case-insensitive)
            password: Raw password

        Returns:
            Tuple of (Principal if valid, error_reason if invalid)
            - (Principal, None) for valid credentials
            - (None, "disabled") for disabled user
            - (None, "invalid") for invalid email/password
        """
        email = email.lower()
        user = self._users.get(email)

        if user is None:
            return None, "invalid"

        try:
            if bcrypt_lib.checkpw(password.encode(), user.password_hash.encode()):
                if not user.enabled:
                    log.warning(f"Disabled user attempted login: {email}")
                    return None, "disabled"

                return Principal(
                    key_id=f"user:{email}",  # Prefix with 'user:' to distinguish from API keys
                    name=user.name,
                    roles=user.roles,
                ), None
        except Exception:
            # bcrypt.checkpw can raise on malformed hash
            pass

        return None, "invalid"

    def get_user(self, email: str) -> UserConfig | None:
        """Get user configuration by email.

        Args:
            email: User's email address (case-insensitive)

        Returns:
            UserConfig if found, None otherwise
        """
        return self._users.get(email.lower())

    def list_users(self) -> list[dict[str, Any]]:
        """List all users (without password hashes).

        Returns:
            List of user info dicts
        """
        return [
            {
                "email": u.email,
                "name": u.name,
                "roles": list(u.roles),
                "enabled": u.enabled,
            }
            for u in self._users.values()
        ]

    def set_check_interval(self, seconds: float) -> None:
        """Set the interval for file mtime checking."""
        self._check_interval = seconds

    @property
    def user_count(self) -> int:
        """Number of loaded users."""
        return len(self._users)


# Global store instance
_user_store: UserStore | None = None


def get_user_store() -> UserStore:
    """Get the global user store instance.

    Lazily initializes from config on first access.
    """
    global _user_store

    if _user_store is None:
        # Import here to avoid circular dependency
        from app.config import USERS_FILE, USERS_JSON, AUTH_RELOAD_INTERVAL

        _user_store = UserStore(
            config_path=USERS_FILE,
            config_json=USERS_JSON,
        )
        _user_store.set_check_interval(AUTH_RELOAD_INTERVAL)
        _user_store.load()

    return _user_store


def reset_user_store() -> None:
    """Reset the global store (for testing)."""
    global _user_store
    _user_store = None


def hash_password(password: str, cost_factor: int = BCRYPT_COST_FACTOR) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The raw password to hash
        cost_factor: bcrypt cost factor (default: 12)

    Returns:
        The bcrypt hash string
    """
    salt = bcrypt_lib.gensalt(rounds=cost_factor)
    return bcrypt_lib.hashpw(password.encode(), salt).decode()
