"""Session management for VVP Issuer.

Provides session-based authentication alongside API key auth.
Sessions are stored server-side; the client receives an opaque session ID cookie.

Note: The default InMemorySessionStore is per-instance and sessions are lost
on restart. For production multi-instance deployments, implement a Redis-backed
store or use sticky sessions.
"""

import asyncio
import logging
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.auth.api_key import Principal

log = logging.getLogger(__name__)


# =============================================================================
# SESSION DATACLASS
# =============================================================================


@dataclass
class Session:
    """Server-side session data.

    Attributes:
        session_id: Cryptographically random session identifier
        key_id: The API key ID that created this session (for revocation tracking)
        principal: The authenticated principal with roles
        created_at: When the session was created
        expires_at: When the session expires
        last_accessed: Last request timestamp (for activity tracking)
    """

    session_id: str
    key_id: str
    principal: "Principal"
    created_at: datetime
    expires_at: datetime
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    home_org_id: str | None = None     # Sprint 67: Immutable — set on session creation
    active_org_id: str | None = None   # Sprint 67: Mutable — set by POST /session/switch-org

    @property
    def is_expired(self) -> bool:
        """Check if this session has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def ttl_seconds(self) -> int:
        """Remaining time-to-live in seconds."""
        remaining = (self.expires_at - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))


# =============================================================================
# SESSION STORE INTERFACE
# =============================================================================


class SessionStore(ABC):
    """Abstract interface for session storage.

    Implementations must be thread-safe for async operations.
    """

    @abstractmethod
    async def create(self, principal: "Principal", ttl_seconds: int) -> Session:
        """Create a new session for the given principal.

        Args:
            principal: The authenticated principal
            ttl_seconds: Session time-to-live in seconds

        Returns:
            The created Session object
        """
        ...

    @abstractmethod
    async def get(self, session_id: str) -> Session | None:
        """Retrieve a session by ID.

        Returns None if session doesn't exist, is expired, or the underlying
        API key has been revoked.

        Args:
            session_id: The session identifier

        Returns:
            Session if valid, None otherwise
        """
        ...

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Delete a session.

        Args:
            session_id: The session identifier

        Returns:
            True if session was found and deleted
        """
        ...

    @abstractmethod
    async def delete_by_key_id(self, key_id: str) -> int:
        """Delete all sessions for a given API key.

        Used when an API key is revoked to invalidate all its sessions.

        Args:
            key_id: The API key identifier

        Returns:
            Number of sessions deleted
        """
        ...

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove all expired sessions.

        Returns:
            Number of sessions removed
        """
        ...


# =============================================================================
# IN-MEMORY SESSION STORE
# =============================================================================


class InMemorySessionStore(SessionStore):
    """Thread-safe in-memory session store.

    Suitable for single-instance deployments. Sessions are lost on restart.
    For multi-instance deployments, use a Redis-backed implementation.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def create(self, principal: "Principal", ttl_seconds: int) -> Session:
        """Create a new session."""
        # Generate cryptographically secure session ID (32 bytes = 256 bits)
        session_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        session = Session(
            session_id=session_id,
            key_id=principal.key_id,
            principal=principal,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            last_accessed=now,
            home_org_id=principal.organization_id,  # Sprint 67: immutable
        )

        async with self._lock:
            self._sessions[session_id] = session

        log.debug(f"Created session {session_id[:8]}... for {principal.key_id}")
        return session

    async def get(self, session_id: str) -> Session | None:
        """Get session, checking expiry and key/user revocation."""
        async with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return None

            # Check expiry
            if session.is_expired:
                del self._sessions[session_id]
                log.debug(f"Session {session_id[:8]}... expired")
                return None

            # Check if underlying principal is still valid
            if session.key_id.startswith("user:"):
                # User session - check if user is disabled
                # Check file-based store first, then DB-backed store
                from app.auth.users import get_user_store

                user_store = get_user_store()
                user_store.reload_if_stale()
                email = session.key_id[5:]  # Strip "user:" prefix
                user = user_store.get_user(email)

                user_valid = False
                if user is not None:
                    # Found in file-based store — check enabled flag
                    user_valid = not (hasattr(user, 'enabled') and not user.enabled)
                else:
                    # Not in file-based store — check DB-backed user store
                    # Note: We must check enabled INSIDE the db session to avoid
                    # DetachedInstanceError after session.commit() expires attrs.
                    try:
                        from app.auth.db_users import get_db_user_store
                        from app.db.session import get_db_session

                        with get_db_session() as db:
                            db_store = get_db_user_store()
                            db_user = db_store.get_user_by_email(db, email)
                            if db_user is not None and db_user.enabled:
                                user_valid = True
                    except Exception as e:
                        log.debug(f"DB user check failed: {e}")

                if not user_valid:
                    del self._sessions[session_id]
                    log.warning(
                        f"Session {session_id[:8]}... invalidated: "
                        f"user {email} disabled or removed"
                    )
                    return None
            elif session.key_id.startswith("org_key:"):
                # Org API key session - check if key is revoked in database
                from app.auth.api_key import verify_org_key_still_valid

                if not verify_org_key_still_valid(session.key_id):
                    del self._sessions[session_id]
                    log.warning(
                        f"Session {session_id[:8]}... invalidated: "
                        f"org API key {session.key_id} revoked or removed"
                    )
                    return None
            else:
                # File-based API key session - check if key is revoked
                from app.auth.api_key import get_api_key_store

                store = get_api_key_store()
                # Ensure we have fresh key state before checking revocation
                store.reload_if_stale()
                key_config = store._keys.get(session.key_id)

                if key_config is None or key_config.revoked:
                    del self._sessions[session_id]
                    log.warning(
                        f"Session {session_id[:8]}... invalidated: "
                        f"API key {session.key_id} revoked or removed"
                    )
                    return None

            # Update last accessed time
            session.last_accessed = datetime.now(timezone.utc)

            # Sprint 67: If active_org_id is set, return a cloned session
            # with overridden principal.organization_id. The stored session
            # is NOT mutated — the original principal is preserved.
            if session.active_org_id:
                effective_principal = replace(
                    session.principal,
                    organization_id=session.active_org_id,
                )
                return replace(session, principal=effective_principal)

            return session

    async def set_active_org(self, session_id: str, org_id: str | None) -> bool:
        """Set the active_org_id on the stored session (not a clone).

        Sprint 67: Used by switch-org to update the stored session directly,
        since get() returns a clone when active_org_id is set.
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.active_org_id = org_id
            return True

    async def delete(self, session_id: str) -> bool:
        """Delete a session."""
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                log.debug(f"Deleted session {session_id[:8]}...")
                return True
            return False

    async def delete_by_key_id(self, key_id: str) -> int:
        """Delete all sessions for a given API key."""
        async with self._lock:
            to_delete = [
                sid for sid, session in self._sessions.items()
                if session.key_id == key_id
            ]
            for sid in to_delete:
                del self._sessions[sid]

            if to_delete:
                log.info(f"Deleted {len(to_delete)} sessions for key {key_id}")

            return len(to_delete)

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
        """Number of active sessions (for monitoring)."""
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
    """In-memory rate limiter for login attempts.

    Tracks failed login attempts per IP address and blocks further attempts
    after exceeding the threshold.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900) -> None:
        """Initialize the rate limiter.

        Args:
            max_attempts: Maximum failed attempts before lockout
            window_seconds: Time window for counting attempts (default 15 minutes)
        """
        self._entries: dict[str, RateLimitEntry] = {}
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, ip: str) -> bool:
        """Check if an IP is allowed to attempt login.

        Args:
            ip: Client IP address

        Returns:
            True if allowed, False if rate limited
        """
        async with self._lock:
            entry = self._entries.get(ip)
            now = time.time()

            if entry is None:
                return True

            # Check if locked out
            if entry.locked_until > now:
                return False

            # Check if window has expired (reset counter)
            if now - entry.window_start > self._window_seconds:
                del self._entries[ip]
                return True

            # Allow if under threshold
            return entry.attempts < self._max_attempts

    async def record_attempt(self, ip: str, success: bool) -> None:
        """Record a login attempt.

        Args:
            ip: Client IP address
            success: Whether the login was successful
        """
        async with self._lock:
            now = time.time()

            if success:
                # Successful login clears the counter
                if ip in self._entries:
                    del self._entries[ip]
                return

            # Failed attempt
            entry = self._entries.get(ip)

            if entry is None:
                entry = RateLimitEntry(attempts=1, window_start=now)
                self._entries[ip] = entry
            else:
                # Check if window expired
                if now - entry.window_start > self._window_seconds:
                    entry.attempts = 1
                    entry.window_start = now
                    entry.locked_until = 0.0
                else:
                    entry.attempts += 1

            # Lock out if threshold exceeded
            if entry.attempts >= self._max_attempts:
                entry.locked_until = now + self._window_seconds
                log.warning(
                    f"Rate limit exceeded for {ip}: "
                    f"{entry.attempts} failed attempts, locked for {self._window_seconds}s"
                )

    async def is_locked_out(self, ip: str) -> bool:
        """Check if an IP is currently locked out.

        Args:
            ip: Client IP address

        Returns:
            True if locked out
        """
        async with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return False
            return entry.locked_until > time.time()

    async def get_lockout_remaining(self, ip: str) -> int:
        """Get remaining lockout time in seconds.

        Args:
            ip: Client IP address

        Returns:
            Seconds until lockout expires, 0 if not locked
        """
        async with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return 0
            remaining = entry.locked_until - time.time()
            return max(0, int(remaining))

    async def cleanup(self) -> int:
        """Remove expired entries."""
        now = time.time()
        count = 0

        async with self._lock:
            expired = [
                ip for ip, entry in self._entries.items()
                if (now - entry.window_start > self._window_seconds
                    and entry.locked_until < now)
            ]
            for ip in expired:
                del self._entries[ip]
                count += 1

        return count


# =============================================================================
# GLOBAL SINGLETONS
# =============================================================================

_session_store: SessionStore | None = None
_rate_limiter: LoginRateLimiter | None = None


def get_session_store() -> SessionStore:
    """Get the global session store instance."""
    global _session_store

    if _session_store is None:
        _session_store = InMemorySessionStore()
        log.info("Initialized in-memory session store")

    return _session_store


def get_rate_limiter() -> LoginRateLimiter:
    """Get the global login rate limiter instance."""
    global _rate_limiter

    if _rate_limiter is None:
        # Import here to avoid circular dependency
        from app.config import LOGIN_RATE_LIMIT_MAX_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS

        _rate_limiter = LoginRateLimiter(
            max_attempts=LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            window_seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
        log.info(
            f"Initialized login rate limiter: "
            f"max {LOGIN_RATE_LIMIT_MAX_ATTEMPTS} attempts per {LOGIN_RATE_LIMIT_WINDOW_SECONDS}s"
        )

    return _rate_limiter


def reset_session_store() -> None:
    """Reset the global session store (for testing)."""
    global _session_store
    _session_store = None


def reset_rate_limiter() -> None:
    """Reset the global rate limiter (for testing)."""
    global _rate_limiter
    _rate_limiter = None
