"""Session authentication API endpoints for VVP Issuer.

Provides login/logout endpoints for session-based authentication.
Sessions are stored server-side; clients receive an HttpOnly cookie.

Supports two authentication methods:
1. API key - for programmatic access
2. Email/password - for user authentication
"""

import logging
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.api_key import get_api_key_store
from app.auth.session import (
    get_rate_limiter,
    get_session_store,
)
from app.auth.users import get_user_store
from app.audit.logger import get_audit_logger
from app.config import SESSION_COOKIE_SECURE, SESSION_TTL_SECONDS

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Cookie configuration
SESSION_COOKIE_NAME = "vvp_session"


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================


class LoginRequest(BaseModel):
    """Login request with API key or email/password.

    Supports two authentication methods:
    1. api_key only - for programmatic access
    2. email + password - for user authentication
    """

    api_key: Optional[str] = Field(None, description="API key to authenticate with")
    email: Optional[str] = Field(None, description="User email address")
    password: Optional[str] = Field(None, description="User password")


class LoginResponse(BaseModel):
    """Successful login response."""

    success: bool = Field(..., description="Whether login succeeded")
    key_id: Optional[str] = Field(None, description="API key identifier")
    name: Optional[str] = Field(None, description="Human-readable name")
    roles: list[str] = Field(default_factory=list, description="Assigned roles")
    expires_at: Optional[str] = Field(None, description="Session expiry (ISO8601)")


class AuthStatusResponse(BaseModel):
    """Current authentication status."""

    authenticated: bool = Field(..., description="Whether currently authenticated")
    method: Optional[str] = Field(
        None, description="Auth method: 'session', 'api_key', or None"
    )
    key_id: Optional[str] = Field(None, description="API key identifier")
    name: Optional[str] = Field(None, description="Human-readable name")
    roles: list[str] = Field(default_factory=list, description="Assigned roles")
    expires_at: Optional[str] = Field(
        None, description="Session expiry (ISO8601), null for API key auth"
    )


class LogoutResponse(BaseModel):
    """Logout response."""

    success: bool = Field(..., description="Whether logout succeeded")
    message: str = Field(..., description="Status message")


class RateLimitResponse(BaseModel):
    """Rate limit exceeded response."""

    error: str = Field(..., description="Error message")
    retry_after: int = Field(..., description="Seconds until retry is allowed")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, considering proxy headers."""
    # Check for forwarded header (common in proxy setups)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain (original client)
        return forwarded.split(",")[0].strip()

    # Fall back to direct client
    if request.client:
        return request.client.host

    return "unknown"


# =============================================================================
# ENDPOINTS
# =============================================================================


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_req: LoginRequest,
    response: Response,
) -> LoginResponse | JSONResponse:
    """Exchange API key or email/password for session cookie.

    Supports two authentication methods:
    1. api_key - validates API key and creates session
    2. email + password - validates user credentials and creates session

    Sets HttpOnly session cookie on success.
    Rate limited to prevent brute-force attacks.
    """
    audit = get_audit_logger()
    rate_limiter = get_rate_limiter()
    client_ip = _get_client_ip(request)

    # Check rate limit
    if not await rate_limiter.check_rate_limit(client_ip):
        remaining = await rate_limiter.get_lockout_remaining(client_ip)
        audit.log_access(
            action="session.login",
            principal_id="anonymous",
            status="denied",
            details={"reason": "rate_limited", "ip": client_ip},
            request=request,
        )
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too many failed login attempts. Please try again later.",
                "retry_after": remaining,
            },
            headers={"Retry-After": str(remaining)},
        )

    # Determine authentication method and verify credentials
    principal = None
    error = None
    auth_method = None

    if login_req.api_key:
        # API key authentication
        auth_method = "api_key"
        store = get_api_key_store()
        principal, error = store.verify(login_req.api_key)
    elif login_req.email and login_req.password:
        # User authentication
        auth_method = "user"
        user_store = get_user_store()
        principal, error = user_store.verify(login_req.email, login_req.password)
    else:
        # Neither api_key nor email/password provided
        error = "invalid"
        audit.log_access(
            action="session.login",
            principal_id="anonymous",
            status="denied",
            details={"reason": "missing_credentials", "ip": client_ip},
            request=request,
        )
        response.status_code = 400
        return LoginResponse(
            success=False,
            key_id=None,
            name=None,
            roles=[],
            expires_at=None,
        )

    if principal is None:
        # Record failed attempt
        await rate_limiter.record_attempt(client_ip, success=False)

        audit.log_access(
            action="session.login",
            principal_id="anonymous",
            status="denied",
            details={"reason": error or "invalid", "ip": client_ip, "method": auth_method},
            request=request,
        )

        # Return 401 without distinguishing invalid vs revoked/disabled
        response.status_code = 401
        return LoginResponse(
            success=False,
            key_id=None,
            name=None,
            roles=[],
            expires_at=None,
        )

    # Record successful attempt (clears rate limit counter)
    await rate_limiter.record_attempt(client_ip, success=True)

    # Create session
    session_store = get_session_store()
    session = await session_store.create(principal, SESSION_TTL_SECONDS)

    # Set cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.session_id,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        path="/",
        max_age=SESSION_TTL_SECONDS,
    )

    audit.log_access(
        action="session.login",
        principal_id=principal.key_id,
        status="success",
        details={"ip": client_ip, "session_ttl": SESSION_TTL_SECONDS, "method": auth_method},
        request=request,
    )

    log.info(f"Login successful for {principal.key_id} from {client_ip}")

    return LoginResponse(
        success=True,
        key_id=principal.key_id,
        name=principal.name,
        roles=list(principal.roles),
        expires_at=session.expires_at.isoformat(),
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
) -> LogoutResponse:
    """Invalidate current session.

    Deletes the session from the store and clears the cookie.
    """
    audit = get_audit_logger()
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    principal_id = "anonymous"

    if session_id:
        session_store = get_session_store()

        # Get session info for audit before deleting
        session = await session_store.get(session_id)
        if session:
            principal_id = session.principal.key_id

        await session_store.delete(session_id)

    # Clear cookie (always, even if no session found)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )

    audit.log_access(
        action="session.logout",
        principal_id=principal_id,
        status="success",
        request=request,
    )

    return LogoutResponse(
        success=True,
        message="Logged out successfully",
    )


@router.get("/status", response_model=AuthStatusResponse)
async def auth_status(request: Request) -> AuthStatusResponse:
    """Get current authentication status.

    Returns info about the current session or API key authentication.
    Does not require authentication (exempt path).
    """
    # Check session cookie first
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        session_store = get_session_store()
        session = await session_store.get(session_id)
        if session:
            return AuthStatusResponse(
                authenticated=True,
                method="session",
                key_id=session.principal.key_id,
                name=session.principal.name,
                roles=list(session.principal.roles),
                expires_at=session.expires_at.isoformat(),
            )

    # Check API key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        store = get_api_key_store()
        principal, error = store.verify(api_key)
        if principal:
            return AuthStatusResponse(
                authenticated=True,
                method="api_key",
                key_id=principal.key_id,
                name=principal.name,
                roles=list(principal.roles),
                expires_at=None,  # API keys don't expire per-request
            )

    # Not authenticated
    return AuthStatusResponse(
        authenticated=False,
        method=None,
        key_id=None,
        name=None,
        roles=[],
        expires_at=None,
    )
