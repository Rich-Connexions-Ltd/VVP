"""Microsoft Entra ID (Azure AD) OAuth integration for VVP Issuer.

Provides OAuth 2.0 Authorization Code flow with PKCE for secure
authentication via Microsoft identity platform.

Flow:
1. /auth/oauth/m365/start - Initiates OAuth flow with state + PKCE
2. User authenticates with Microsoft
3. /auth/oauth/m365/callback - Validates code, exchanges for tokens
4. Maps email to VVP user (or auto-provisions)
5. Creates VVP session

Security measures:
- Server-side state storage (OAuthStateStore)
- PKCE (code_verifier/code_challenge) prevents authorization code interception
- State parameter prevents CSRF attacks
- Nonce parameter prevents ID token replay attacks
- ID token signature validation against Microsoft's JWKS
- Tenant (tid) claim validation
"""

import asyncio
import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx

log = logging.getLogger(__name__)


# =============================================================================
# OAUTH DATA CLASSES
# =============================================================================


@dataclass
class OAuthState:
    """State stored during OAuth flow (server-side).

    Attributes:
        state: Random state for CSRF protection (sent to Microsoft)
        nonce: Random nonce for ID token validation
        code_verifier: PKCE code verifier (used in token exchange)
        created_at: Timestamp for expiry check
        redirect_after: Where to redirect after login
    """

    state: str
    nonce: str
    code_verifier: str
    created_at: datetime
    redirect_after: str = "/ui/"


@dataclass
class OAuthTokenResponse:
    """Response from Microsoft token endpoint."""

    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    scope: str


@dataclass
class OAuthUserInfo:
    """User information extracted from validated ID token."""

    email: str
    name: str
    oid: str  # Microsoft object ID (unique per user per tenant)
    tid: str  # Tenant ID


class OAuthError(Exception):
    """OAuth-specific error."""

    pass


# =============================================================================
# OAUTH STATE STORE
# =============================================================================


class OAuthStateStore:
    """Server-side store for OAuth state (CSRF/PKCE protection).

    Mirrors the SessionStore pattern for consistency.
    State is stored server-side with only the state_id in the client cookie.

    Note: In-memory implementation. For multi-instance deployments,
    implement a Redis-backed store.
    """

    def __init__(self, default_ttl: int = 600) -> None:
        """Initialize the store.

        Args:
            default_ttl: Default state TTL in seconds (10 minutes)
        """
        self._states: dict[str, tuple[OAuthState, datetime]] = {}
        self._lock = asyncio.Lock()
        self._default_ttl = default_ttl

    async def create(self, oauth_state: OAuthState, ttl: int | None = None) -> str:
        """Store OAuth state and return a state_id for the cookie.

        Args:
            oauth_state: The OAuth state to store
            ttl: Time-to-live in seconds (uses default if not specified)

        Returns:
            A cryptographically random state_id for the client cookie
        """
        state_id = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=ttl or self._default_ttl
        )

        async with self._lock:
            self._states[state_id] = (oauth_state, expires_at)

        log.debug(f"Created OAuth state {state_id[:8]}...")
        return state_id

    async def get(self, state_id: str) -> OAuthState | None:
        """Retrieve OAuth state by state_id.

        Does NOT delete the state; use get_and_delete() for one-time use.

        Args:
            state_id: The state identifier from the cookie

        Returns:
            OAuthState if found and not expired, None otherwise
        """
        async with self._lock:
            entry = self._states.get(state_id)

            if entry is None:
                return None

            oauth_state, expires_at = entry

            # Check expiry
            if datetime.now(timezone.utc) > expires_at:
                del self._states[state_id]
                log.debug(f"OAuth state {state_id[:8]}... expired")
                return None

            return oauth_state

    async def get_and_delete(self, state_id: str) -> OAuthState | None:
        """Retrieve and delete OAuth state (one-time use).

        Args:
            state_id: The state identifier from the cookie

        Returns:
            OAuthState if found and not expired, None otherwise
        """
        async with self._lock:
            entry = self._states.get(state_id)

            if entry is None:
                return None

            oauth_state, expires_at = entry

            # Always delete (one-time use)
            del self._states[state_id]

            # Check expiry
            if datetime.now(timezone.utc) > expires_at:
                log.debug(f"OAuth state {state_id[:8]}... expired")
                return None

            log.debug(f"Retrieved and deleted OAuth state {state_id[:8]}...")
            return oauth_state

    async def delete(self, state_id: str) -> bool:
        """Delete OAuth state.

        Args:
            state_id: The state identifier

        Returns:
            True if state was found and deleted
        """
        async with self._lock:
            if state_id in self._states:
                del self._states[state_id]
                log.debug(f"Deleted OAuth state {state_id[:8]}...")
                return True
            return False

    async def cleanup_expired(self) -> int:
        """Remove all expired states.

        Returns:
            Number of states removed
        """
        now = datetime.now(timezone.utc)
        count = 0

        async with self._lock:
            expired = [
                state_id
                for state_id, (_, expires_at) in self._states.items()
                if expires_at < now
            ]
            for state_id in expired:
                del self._states[state_id]
                count += 1

        if count > 0:
            log.info(f"Cleaned up {count} expired OAuth states")

        return count

    @property
    def state_count(self) -> int:
        """Number of active states (for monitoring)."""
        return len(self._states)


# =============================================================================
# PKCE HELPERS
# =============================================================================


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge.

    Uses SHA-256 (S256) method as required by Microsoft.

    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate 32 bytes (256 bits) of randomness
    code_verifier = secrets.token_urlsafe(32)

    # SHA-256 hash, base64url encode (no padding)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    return code_verifier, code_challenge


def generate_state() -> str:
    """Generate random state parameter for CSRF protection."""
    return secrets.token_urlsafe(16)


def generate_nonce() -> str:
    """Generate random nonce for ID token replay protection."""
    return secrets.token_urlsafe(16)


# =============================================================================
# MICROSOFT ENDPOINTS
# =============================================================================


def get_authorize_url(tenant_id: str) -> str:
    """Get Microsoft authorization endpoint URL."""
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"


def get_token_url(tenant_id: str) -> str:
    """Get Microsoft token endpoint URL."""
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def get_jwks_url(tenant_id: str) -> str:
    """Get Microsoft JWKS (public keys) endpoint URL."""
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


def build_authorization_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Build the Microsoft authorization URL.

    Args:
        tenant_id: Azure tenant ID
        client_id: App registration client ID
        redirect_uri: OAuth callback URL
        state: CSRF state parameter
        nonce: ID token nonce
        code_challenge: PKCE challenge

    Returns:
        Full authorization URL to redirect user to
    """
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
    }

    base_url = get_authorize_url(tenant_id)
    return f"{base_url}?{urlencode(params)}"


# =============================================================================
# TOKEN EXCHANGE AND VALIDATION
# =============================================================================


async def exchange_code_for_tokens(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
) -> OAuthTokenResponse:
    """Exchange authorization code for tokens.

    Args:
        tenant_id: Azure tenant ID
        client_id: App registration client ID
        client_secret: App registration client secret
        redirect_uri: OAuth callback URL (must match)
        code: Authorization code from callback
        code_verifier: PKCE code verifier

    Returns:
        OAuthTokenResponse with access_token and id_token

    Raises:
        OAuthError: If token exchange fails
    """
    token_url = get_token_url(tenant_id)

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )

            if response.status_code != 200:
                error_detail = response.text
                log.error(f"Token exchange failed: {response.status_code} - {error_detail}")
                raise OAuthError(f"Token exchange failed: {response.status_code}")

            result = response.json()
            return OAuthTokenResponse(
                access_token=result["access_token"],
                id_token=result["id_token"],
                token_type=result["token_type"],
                expires_in=result["expires_in"],
                scope=result["scope"],
            )
    except httpx.RequestError as e:
        log.error(f"Token exchange request failed: {e}")
        raise OAuthError(f"Token exchange request failed: {e}")


async def validate_id_token(
    id_token: str,
    tenant_id: str,
    client_id: str,
    nonce: str,
) -> OAuthUserInfo:
    """Validate ID token and extract user information.

    Validates:
    - Token signature against Microsoft's JWKS
    - Algorithm is RS256
    - Issuer matches tenant
    - Audience matches client ID
    - Tenant ID (tid) matches expected
    - Token not expired (exp)
    - Token issued in past (iat)
    - Not before time (nbf) if present
    - Nonce matches (prevents replay)

    Args:
        id_token: JWT ID token from token response
        tenant_id: Expected Azure tenant ID
        client_id: Expected audience (app client ID)
        nonce: Expected nonce from OAuth state

    Returns:
        OAuthUserInfo with user's email, name, and identifiers

    Raises:
        OAuthError: If validation fails
    """
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError:
        raise OAuthError("PyJWT library not installed")

    # Fetch Microsoft's public keys
    jwks_url = get_jwks_url(tenant_id)

    try:
        jwks_client = PyJWKClient(jwks_url)

        # Get the signing key for this token
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        # Expected issuer for this tenant
        expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

        # Decode and validate the token
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=expected_issuer,
            options={
                "require": ["exp", "iat", "nonce", "aud", "iss"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
            },
        )

        # Validate nonce
        if payload.get("nonce") != nonce:
            raise OAuthError("ID token nonce mismatch")

        # Validate tenant ID
        token_tid = payload.get("tid")
        if token_tid != tenant_id:
            log.warning(f"ID token tid mismatch: expected {tenant_id}, got {token_tid}")
            raise OAuthError("ID token tenant mismatch")

        # Extract user info
        # Microsoft uses 'email' or 'preferred_username' for email
        email = payload.get("email") or payload.get("preferred_username")
        if not email:
            raise OAuthError("ID token missing email claim")

        return OAuthUserInfo(
            email=email.lower(),
            name=payload.get("name", email.split("@")[0]),
            oid=payload.get("oid", ""),
            tid=payload.get("tid", ""),
        )

    except jwt.ExpiredSignatureError:
        raise OAuthError("ID token expired")
    except jwt.InvalidAudienceError:
        raise OAuthError("ID token audience mismatch")
    except jwt.InvalidIssuerError:
        raise OAuthError("ID token issuer mismatch")
    except jwt.InvalidAlgorithmError:
        raise OAuthError("ID token invalid algorithm")
    except jwt.InvalidTokenError as e:
        log.error(f"ID token validation failed: {e}")
        raise OAuthError(f"ID token validation failed")
    except Exception as e:
        log.error(f"Unexpected error validating ID token: {e}")
        raise OAuthError("ID token validation failed")


# =============================================================================
# DOMAIN VALIDATION
# =============================================================================


def is_email_domain_allowed(email: str, allowed_domains: list[str]) -> bool:
    """Check if email domain is in allowed list.

    Args:
        email: User's email address
        allowed_domains: List of allowed domains (empty = all allowed)

    Returns:
        True if allowed, False otherwise
    """
    if not allowed_domains:
        return True

    domain = email.lower().split("@")[-1]
    return domain in [d.lower() for d in allowed_domains]


# =============================================================================
# GLOBAL SINGLETON
# =============================================================================

_oauth_state_store: OAuthStateStore | None = None


def get_oauth_state_store() -> OAuthStateStore:
    """Get the global OAuth state store instance."""
    global _oauth_state_store

    if _oauth_state_store is None:
        from app.config import OAUTH_STATE_TTL_SECONDS

        _oauth_state_store = OAuthStateStore(default_ttl=OAUTH_STATE_TTL_SECONDS)
        log.info(f"Initialized OAuth state store (TTL: {OAUTH_STATE_TTL_SECONDS}s)")

    return _oauth_state_store


def reset_oauth_state_store() -> None:
    """Reset the global OAuth state store (for testing)."""
    global _oauth_state_store
    _oauth_state_store = None
