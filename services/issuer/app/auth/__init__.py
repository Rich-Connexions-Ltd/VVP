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
from app.auth.oauth import (
    OAuthState,
    OAuthStateStore,
    OAuthTokenResponse,
    OAuthUserInfo,
    OAuthError,
    get_oauth_state_store,
    reset_oauth_state_store,
    generate_pkce_pair,
    generate_state,
    generate_nonce,
    build_authorization_url,
    exchange_code_for_tokens,
    validate_id_token,
    is_email_domain_allowed,
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
    # OAuth
    "OAuthState",
    "OAuthStateStore",
    "OAuthTokenResponse",
    "OAuthUserInfo",
    "OAuthError",
    "get_oauth_state_store",
    "reset_oauth_state_store",
    "generate_pkce_pair",
    "generate_state",
    "generate_nonce",
    "build_authorization_url",
    "exchange_code_for_tokens",
    "validate_id_token",
    "is_email_domain_allowed",
]
