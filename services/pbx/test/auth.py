"""Session authentication for SIP Monitor Dashboard.

Sprint 47: Provides session-based authentication for the monitoring dashboard.

Features:
- Username/password authentication with bcrypt hashing
- HttpOnly, Secure, SameSite=Strict session cookies
- Login rate limiting (5 attempts per 15 minutes per IP)
- CSRF protection via X-Requested-With header requirement
- In-memory session store with 1-hour expiry
"""

import asyncio
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import bcrypt
except ImportError:
    bcrypt = None  # Will fail gracefully if bcrypt not installed

log = logging.getLogger("sip-monitor-auth")

# Configuration from environment
SESSION_TTL_SECONDS = int(os.getenv("SIP_MONITOR_SESSION_TTL", "3600"))  # 1 hour
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("SIP_MONITOR_RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("SIP_MONITOR_RATE_LIMIT_WINDOW", "900"))  # 15 min
USERS_FILE = Path(os.getenv("SIP_MONITOR_USERS_FILE", "/opt/vvp/monitor/users.json"))
COOKIE_NAME = "vvp_sip_session"


# =============================================================================
# USER STORE
# =============================================================================


@dataclass
class User:
    """User record for authentication."""

    username: str
    password_hash: str  # bcrypt hash
    force_password_change: bool = False
    created_at: str = ""


class UserStore:
    """File-backed user store with bcrypt password hashing."""

    def __init__(self, users_file: Path):
        self._users_file = users_file
        self._users: dict[str, User] = {}
        self._load()

    def _load(self) -> None:
        """Load users from JSON file."""
        if not self._users_file.exists():
            log.warning(f"Users file not found: {self._users_file}")
            return

        try:
            with open(self._users_file) as f:
                data = json.load(f)

            self._users = {}
            for username, info in data.get("users", {}).items():
                self._users[username] = User(
                    username=username,
                    password_hash=info.get("password_hash", ""),
                    force_password_change=info.get("force_password_change", False),
                    created_at=info.get("created_at", ""),
                )

            log.info(f"Loaded {len(self._users)} users from {self._users_file}")

        except Exception as e:
            log.error(f"Failed to load users file: {e}")

    def _save(self) -> None:
        """Save users to JSON file."""
        try:
            self._users_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "users": {
                    u.username: {
                        "password_hash": u.password_hash,
                        "force_password_change": u.force_password_change,
                        "created_at": u.created_at,
                    }
                    for u in self._users.values()
                }
            }

            with open(self._users_file, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            log.error(f"Failed to save users file: {e}")

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password.

        Args:
            username: Username to authenticate
            password: Plain text password

        Returns:
            User object if authenticated, None otherwise
        """
        if bcrypt is None:
            log.error("bcrypt not installed - authentication disabled")
            return None

        user = self._users.get(username)
        if user is None:
            return None

        try:
            if bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
                return user
        except Exception as e:
            log.error(f"Password check failed: {e}")

        return None

    def create_user(self, username: str, password: str, force_password_change: bool = True) -> User:
        """Create a new user with hashed password.

        Args:
            username: Username for new user
            password: Plain text password (will be hashed)
            force_password_change: Require password change on first login

        Returns:
            Created User object
        """
        if bcrypt is None:
            raise RuntimeError("bcrypt not installed")

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        user = User(
            username=username,
            password_hash=password_hash,
            force_password_change=force_password_change,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self._users[username] = user
        self._save()
        log.info(f"Created user: {username}")

        return user

    def change_password(self, username: str, new_password: str) -> bool:
        """Change user's password.

        Args:
            username: Username
            new_password: New plain text password

        Returns:
            True if password changed
        """
        if bcrypt is None:
            return False

        user = self._users.get(username)
        if user is None:
            return False

        user.password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")
        user.force_password_change = False

        self._save()
        log.info(f"Changed password for user: {username}")

        return True

    def get_user(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self._users.get(username)

    @property
    def user_count(self) -> int:
        """Number of users."""
        return len(self._users)


# =============================================================================
# SESSION STORE
# =============================================================================


@dataclass
class Session:
    """Server-side session data."""

    session_id: str
    username: str
    created_at: datetime
    expires_at: datetime
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(timezone.utc) > self.expires_at


class SessionStore:
    """Thread-safe in-memory session store."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def create(self, username: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> Session:
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        session = Session(
            session_id=session_id,
            username=username,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            last_accessed=now,
        )

        async with self._lock:
            self._sessions[session_id] = session

        log.debug(f"Created session {session_id[:8]}... for {username}")
        return session

    async def get(self, session_id: str) -> Optional[Session]:
        """Get session by ID, checking expiry."""
        async with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return None

            if session.is_expired:
                del self._sessions[session_id]
                log.debug(f"Session {session_id[:8]}... expired")
                return None

            session.last_accessed = datetime.now(timezone.utc)
            return session

    async def delete(self, session_id: str) -> bool:
        """Delete a session."""
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                log.debug(f"Deleted session {session_id[:8]}...")
                return True
            return False

    async def cleanup_expired(self) -> int:
        """Remove all expired sessions."""
        now = datetime.now(timezone.utc)
        count = 0

        async with self._lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if session.expires_at < now
            ]
            for sid in expired:
                del self._sessions[sid]
                count += 1

        if count > 0:
            log.info(f"Cleaned up {count} expired sessions")

        return count

    @property
    def session_count(self) -> int:
        """Number of active sessions."""
        return len(self._sessions)


# =============================================================================
# LOGIN RATE LIMITER
# =============================================================================


@dataclass
class RateLimitEntry:
    """Track login attempts for a single IP."""

    attempts: int = 0
    window_start: float = field(default_factory=time.time)
    locked_until: float = 0.0


class LoginRateLimiter:
    """Rate limiter for login attempts."""

    def __init__(
        self,
        max_attempts: int = RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
    ):
        self._entries: dict[str, RateLimitEntry] = {}
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, ip: str) -> bool:
        """Check if IP is allowed to attempt login.

        Returns:
            True if allowed, False if rate limited
        """
        async with self._lock:
            entry = self._entries.get(ip)
            now = time.time()

            if entry is None:
                return True

            if entry.locked_until > now:
                return False

            if now - entry.window_start > self._window_seconds:
                del self._entries[ip]
                return True

            return entry.attempts < self._max_attempts

    async def record_attempt(self, ip: str, success: bool) -> None:
        """Record a login attempt."""
        async with self._lock:
            now = time.time()

            if success:
                if ip in self._entries:
                    del self._entries[ip]
                return

            entry = self._entries.get(ip)

            if entry is None:
                entry = RateLimitEntry(attempts=1, window_start=now)
                self._entries[ip] = entry
            else:
                if now - entry.window_start > self._window_seconds:
                    entry.attempts = 1
                    entry.window_start = now
                    entry.locked_until = 0.0
                else:
                    entry.attempts += 1

            if entry.attempts >= self._max_attempts:
                entry.locked_until = now + self._window_seconds
                log.warning(
                    f"Rate limit exceeded for {ip}: "
                    f"{entry.attempts} failed attempts, locked for {self._window_seconds}s"
                )

    async def get_lockout_remaining(self, ip: str) -> int:
        """Get remaining lockout time in seconds."""
        async with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return 0
            remaining = entry.locked_until - time.time()
            return max(0, int(remaining))


# =============================================================================
# GLOBAL SINGLETONS
# =============================================================================

_user_store: Optional[UserStore] = None
_session_store: Optional[SessionStore] = None
_rate_limiter: Optional[LoginRateLimiter] = None


def get_user_store() -> UserStore:
    """Get global user store instance."""
    global _user_store
    if _user_store is None:
        _user_store = UserStore(USERS_FILE)
    return _user_store


def get_session_store() -> SessionStore:
    """Get global session store instance."""
    global _session_store
    if _session_store is None:
        _session_store = SessionStore()
        log.info("Initialized in-memory session store")
    return _session_store


def get_rate_limiter() -> LoginRateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = LoginRateLimiter()
        log.info(
            f"Initialized login rate limiter: "
            f"max {RATE_LIMIT_MAX_ATTEMPTS} attempts per {RATE_LIMIT_WINDOW_SECONDS}s"
        )
    return _rate_limiter


# =============================================================================
# ADMIN USER SETUP
# =============================================================================


def setup_initial_admin(username: str = "admin") -> str:
    """Create initial admin user with random password.

    Used during first deployment to create an admin account.

    Args:
        username: Username for admin account

    Returns:
        Generated password (display once to user)
    """
    store = get_user_store()

    if store.get_user(username) is not None:
        raise ValueError(f"User '{username}' already exists")

    # Generate random password
    password = secrets.token_urlsafe(16)

    store.create_user(
        username=username,
        password=password,
        force_password_change=True,
    )

    return password


if __name__ == "__main__":
    # CLI for creating initial admin user
    import argparse

    parser = argparse.ArgumentParser(description="Setup SIP Monitor admin user")
    parser.add_argument("--username", default="admin", help="Admin username")
    args = parser.parse_args()

    try:
        password = setup_initial_admin(args.username)
        print(f"\n{'='*50}")
        print("SIP Monitor Admin User Created")
        print(f"{'='*50}")
        print(f"Username: {args.username}")
        print(f"Password: {password}")
        print("\nIMPORTANT: Save this password securely!")
        print("You will be required to change it on first login.")
        print(f"{'='*50}\n")
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    except Exception as e:
        print(f"Setup failed: {e}")
        exit(1)
