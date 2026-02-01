"""Authentication and authorization module for VVP Issuer."""

from app.auth.api_key import APIKeyBackend, APIKeyStore, Principal, get_api_key_store
from app.auth.roles import Role, require_role, require_admin, require_operator, require_readonly
from app.auth.session import (
    Session,
    SessionStore,
    InMemorySessionStore,
    LoginRateLimiter,
    get_session_store,
    get_rate_limiter,
    reset_session_store,
    reset_rate_limiter,
)

__all__ = [
    # API key auth
    "APIKeyBackend",
    "APIKeyStore",
    "Principal",
    "get_api_key_store",
    # Roles
    "Role",
    "require_role",
    "require_admin",
    "require_operator",
    "require_readonly",
    # Session auth
    "Session",
    "SessionStore",
    "InMemorySessionStore",
    "LoginRateLimiter",
    "get_session_store",
    "get_rate_limiter",
    "reset_session_store",
    "reset_rate_limiter",
]
