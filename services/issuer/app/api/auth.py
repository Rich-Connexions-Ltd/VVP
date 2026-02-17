"""Session authentication API endpoints for VVP Issuer.

Provides login/logout endpoints for session-based authentication.
Sessions are stored server-side; clients receive an HttpOnly cookie.

Supports three authentication methods:
1. API key - for programmatic access
2. Email/password - for user authentication
3. Microsoft OAuth - for SSO via Microsoft Entra ID
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.auth.api_key import Principal, get_api_key_store, verify_org_api_key
from app.auth.db_users import get_db_user_store
from app.auth.oauth import (
    OAuthError,
    OAuthState,
    build_authorization_url,
    exchange_code_for_tokens,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    get_oauth_state_store,
    is_email_domain_allowed,
    validate_id_token,
)
from app.auth.session import (
    get_rate_limiter,
    get_session_store,
)
from app.auth.users import get_user_store
from app.audit.logger import get_audit_logger
from app.config import (
    OAUTH_M365_ALLOWED_DOMAINS,
    OAUTH_M365_AUTO_PROVISION,
    OAUTH_M365_CLIENT_ID,
    OAUTH_M365_CLIENT_SECRET,
    OAUTH_M365_DEFAULT_ROLES,
    OAUTH_M365_ENABLED,
    OAUTH_M365_REDIRECT_URI,
    OAUTH_M365_TENANT_ID,
    OAUTH_STATE_TTL_SECONDS,
    SESSION_COOKIE_SECURE,
    SESSION_TTL_SECONDS,
)
from app.db.session import get_db_session
from app.db.models import Organization

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Cookie configuration
SESSION_COOKIE_NAME = "vvp_session"
OAUTH_STATE_COOKIE_NAME = "vvp_oauth_state_id"


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
    """Successful login response.

    Sprint 41: Added organization_id and organization_name for multi-tenancy.
    """

    success: bool = Field(..., description="Whether login succeeded")
    key_id: Optional[str] = Field(None, description="API key identifier")
    name: Optional[str] = Field(None, description="Human-readable name")
    roles: list[str] = Field(default_factory=list, description="Assigned roles")
    expires_at: Optional[str] = Field(None, description="Session expiry (ISO8601)")
    organization_id: Optional[str] = Field(None, description="Organization UUID")
    organization_name: Optional[str] = Field(None, description="Organization name")


class AuthStatusResponse(BaseModel):
    """Current authentication status.

    Sprint 41: Added organization_id and organization_name for multi-tenancy.
    Sprint 67: Added home/active org fields for org context switching.
    """

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
    organization_id: Optional[str] = Field(None, description="Effective org UUID (active if switched, home otherwise)")
    organization_name: Optional[str] = Field(None, description="Effective org name")
    # Sprint 67: Org context switching fields
    home_org_id: Optional[str] = Field(None, description="Admin's own org (immutable)")
    home_org_name: Optional[str] = Field(None, description="Admin's own org name")
    home_org_type: Optional[str] = Field(None, description="Admin's own org type")
    active_org_id: Optional[str] = Field(None, description="Switched org (null = home)")
    active_org_name: Optional[str] = Field(None, description="Switched org name")
    active_org_type: Optional[str] = Field(None, description="Switched org type")


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


def _is_safe_redirect_url(url: str | None) -> bool:
    """Check if a redirect URL is safe (same-origin relative path).

    Prevents open redirect vulnerabilities by only allowing relative paths
    that start with '/' and don't contain protocol or host components.

    Args:
        url: The URL to validate (None returns False)

    Returns:
        True if the URL is a safe relative path, False otherwise
    """
    if not url:
        return False

    # Must start with single forward slash (relative path)
    if not url.startswith("/"):
        return False

    # Reject protocol-relative URLs (//evil.com)
    if url.startswith("//"):
        return False

    # Reject URLs with protocol (http://, https://, javascript:, etc.)
    if "://" in url or url.lower().startswith("javascript:"):
        return False

    # Reject URLs with encoded characters that could bypass checks
    # (e.g., %2f%2f for //)
    url_lower = url.lower()
    if "%2f%2f" in url_lower or "%252f" in url_lower:
        return False

    return True


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


def _get_organization_name(organization_id: str | None) -> str | None:
    """Get organization name from database.

    Sprint 41: Helper to enrich auth responses with org name.

    Args:
        organization_id: Organization UUID or None

    Returns:
        Organization name or None if not found
    """
    if not organization_id:
        return None

    try:
        with get_db_session() as db:
            org = db.query(Organization).filter(Organization.id == organization_id).first()
            return org.name if org else None
    except Exception as e:
        log.warning(f"Failed to get organization name: {e}")
        return None


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
        # API key authentication - try file-based first, then org API keys
        auth_method = "api_key"
        store = get_api_key_store()
        principal, error = store.verify(login_req.api_key)

        # Sprint 41: If not found in file-based store, try org API keys
        if principal is None and error == "invalid":
            principal, error = verify_org_api_key(login_req.api_key)
            if principal:
                auth_method = "org_api_key"

    elif login_req.email and login_req.password:
        # User authentication - try file-based first, then database users
        auth_method = "user"
        user_store = get_user_store()
        principal, error = user_store.verify(login_req.email, login_req.password)

        # Sprint 41: If not found in file-based store, try database users
        if principal is None and error == "invalid":
            try:
                with get_db_session() as db:
                    db_user_store = get_db_user_store()
                    principal, error = db_user_store.verify(db, login_req.email, login_req.password)
                    if principal:
                        auth_method = "db_user"
            except Exception as e:
                # DB not available (e.g., during testing), keep original error
                log.debug(f"DB user fallback failed: {e}")
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

    # Sprint 41: Get organization name for response
    org_name = _get_organization_name(principal.organization_id)

    return LoginResponse(
        success=True,
        key_id=principal.key_id,
        name=principal.name,
        roles=list(principal.roles),
        expires_at=session.expires_at.isoformat(),
        organization_id=principal.organization_id,
        organization_name=org_name,
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
            # Sprint 67: Populate home/active org fields for org switching
            home_org_id = session.home_org_id
            home_org_name = _get_organization_name(home_org_id)
            home_org_type = None
            active_org_id = session.active_org_id
            active_org_name = None
            active_org_type = None

            # Look up home org type
            if home_org_id:
                try:
                    with get_db_session() as db:
                        home_org = db.query(Organization).filter(
                            Organization.id == home_org_id
                        ).first()
                        if home_org:
                            home_org_type = home_org.org_type
                except Exception:
                    pass

            if active_org_id:
                active_org_name = _get_organization_name(active_org_id)
                # Get active org type
                try:
                    with get_db_session() as db:
                        active_org = db.query(Organization).filter(
                            Organization.id == active_org_id
                        ).first()
                        if active_org:
                            active_org_type = active_org.org_type
                except Exception:
                    pass

            # Effective org: active if switched, home otherwise
            effective_org_id = active_org_id or home_org_id
            effective_org_name = active_org_name if active_org_id else home_org_name

            return AuthStatusResponse(
                authenticated=True,
                method="session",
                key_id=session.principal.key_id,
                name=session.principal.name,
                roles=list(session.principal.roles),
                expires_at=session.expires_at.isoformat(),
                organization_id=effective_org_id,
                organization_name=effective_org_name,
                home_org_id=home_org_id,
                home_org_name=home_org_name,
                home_org_type=home_org_type,
                active_org_id=active_org_id,
                active_org_name=active_org_name,
                active_org_type=active_org_type,
            )

    # Check API key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        store = get_api_key_store()
        principal, error = store.verify(api_key)

        # Sprint 41: If not found in file-based store, try org API keys
        if principal is None and error == "invalid":
            principal, error = verify_org_api_key(api_key)

        if principal:
            # Sprint 41: Get organization name
            org_name = _get_organization_name(principal.organization_id)
            return AuthStatusResponse(
                authenticated=True,
                method="api_key",
                key_id=principal.key_id,
                name=principal.name,
                roles=list(principal.roles),
                expires_at=None,  # API keys don't expire per-request
                organization_id=principal.organization_id,
                organization_name=org_name,
            )

    # Not authenticated
    return AuthStatusResponse(
        authenticated=False,
        method=None,
        key_id=None,
        name=None,
        roles=[],
        expires_at=None,
        organization_id=None,
        organization_name=None,
    )


# =============================================================================
# OAUTH M365 ENDPOINTS
# =============================================================================


class OAuthStatusResponse(BaseModel):
    """OAuth configuration status response."""

    class M365Status(BaseModel):
        """Microsoft M365 OAuth status."""

        enabled: bool = Field(..., description="Whether M365 OAuth is enabled")
        tenant_id: Optional[str] = Field(None, description="Tenant ID (truncated)")
        client_id: Optional[str] = Field(None, description="Client ID (truncated)")
        redirect_uri: Optional[str] = Field(None, description="Redirect URI")
        auto_provision: bool = Field(..., description="Whether auto-provisioning is enabled")
        allowed_domains: list[str] = Field(..., description="Allowed email domains")

    m365: M365Status = Field(..., description="Microsoft M365 OAuth status")


@router.get("/oauth/status", response_model=OAuthStatusResponse)
async def oauth_status() -> OAuthStatusResponse:
    """Get OAuth configuration status.

    Returns information about enabled OAuth providers (without secrets).
    """
    return OAuthStatusResponse(
        m365=OAuthStatusResponse.M365Status(
            enabled=OAUTH_M365_ENABLED,
            tenant_id=f"{OAUTH_M365_TENANT_ID[:8]}..." if OAUTH_M365_TENANT_ID else None,
            client_id=f"{OAUTH_M365_CLIENT_ID[:8]}..." if OAUTH_M365_CLIENT_ID else None,
            redirect_uri=OAUTH_M365_REDIRECT_URI,
            auto_provision=OAUTH_M365_AUTO_PROVISION,
            allowed_domains=OAUTH_M365_ALLOWED_DOMAINS or ["*"],
        )
    )


@router.get("/oauth/m365/start", response_model=None)
async def oauth_m365_start(
    request: Request,
    redirect_after: str = Query(default="/ui/", description="URL to redirect to after login"),
) -> RedirectResponse | JSONResponse:
    """Initiate Microsoft OAuth login flow.

    Generates PKCE challenge, state, and nonce, stores them server-side,
    then redirects to Microsoft authorization endpoint.

    Query Parameters:
        redirect_after: Where to redirect after successful login (default: /ui/)

    Returns:
        302 redirect to Microsoft login page
    """
    audit = get_audit_logger()

    if not OAUTH_M365_ENABLED:
        audit.log_access(
            action="oauth.m365.start",
            principal_id="anonymous",
            status="denied",
            details={"reason": "oauth_disabled"},
            request=request,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "Microsoft OAuth is not enabled"},
        )

    # Verify configuration
    if not all([OAUTH_M365_TENANT_ID, OAUTH_M365_CLIENT_ID, OAUTH_M365_REDIRECT_URI]):
        log.error("OAuth M365 enabled but missing configuration")
        return JSONResponse(
            status_code=500,
            content={"error": "OAuth configuration incomplete"},
        )

    # Validate redirect_after to prevent open redirects
    if not _is_safe_redirect_url(redirect_after):
        audit.log_access(
            action="oauth.m365.start",
            principal_id="anonymous",
            status="denied",
            details={"reason": "invalid_redirect", "redirect_after": redirect_after},
            request=request,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid redirect URL"},
        )

    # Generate PKCE, state, nonce
    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_state()
    nonce = generate_nonce()

    # Build OAuth state to store server-side
    oauth_state = OAuthState(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        created_at=datetime.now(timezone.utc),
        redirect_after=redirect_after,
    )

    # Store state server-side and get state_id for cookie
    oauth_state_store = get_oauth_state_store()
    state_id = await oauth_state_store.create(oauth_state)

    # Build authorization URL
    auth_url = build_authorization_url(
        tenant_id=OAUTH_M365_TENANT_ID,
        client_id=OAUTH_M365_CLIENT_ID,
        redirect_uri=OAUTH_M365_REDIRECT_URI,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
    )

    # Create response with state_id cookie
    response = RedirectResponse(url=auth_url, status_code=302)

    response.set_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        value=state_id,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        path="/",
        max_age=OAUTH_STATE_TTL_SECONDS,
    )

    audit.log_access(
        action="oauth.m365.start",
        principal_id="anonymous",
        status="initiated",
        details={"redirect_after": redirect_after},
        request=request,
    )

    return response


@router.get("/oauth/m365/callback", response_model=None)
async def oauth_m365_callback(
    request: Request,
    code: Optional[str] = Query(None, description="Authorization code from Microsoft"),
    state: Optional[str] = Query(None, description="State parameter"),
    error: Optional[str] = Query(None, description="Error from Microsoft"),
    error_description: Optional[str] = Query(None, description="Error description"),
) -> RedirectResponse | JSONResponse:
    """Handle Microsoft OAuth callback.

    Validates state, exchanges code for tokens, validates ID token,
    maps email to VVP user, creates session, and redirects to UI.

    Query Parameters:
        code: Authorization code from Microsoft
        state: State parameter (must match server-side state)
        error: Error code if authentication failed
        error_description: Human-readable error description

    Returns:
        302 redirect to UI on success, redirect with error on failure
    """
    audit = get_audit_logger()

    if not OAUTH_M365_ENABLED:
        return JSONResponse(
            status_code=400,
            content={"error": "Microsoft OAuth is not enabled"},
        )

    # Helper to redirect with error
    def error_redirect(message: str, redirect_to: str = "/ui/") -> RedirectResponse:
        encoded_message = quote(message)
        response = RedirectResponse(
            url=f"{redirect_to}?error=oauth_failed&message={encoded_message}",
            status_code=302,
        )
        # Clear OAuth state cookie
        response.delete_cookie(key=OAUTH_STATE_COOKIE_NAME, path="/")
        return response

    # Check for error from Microsoft
    if error:
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"error": error, "description": error_description},
            request=request,
        )
        return error_redirect(error_description or error)

    # Get state_id from cookie
    state_id = request.cookies.get(OAUTH_STATE_COOKIE_NAME)
    if not state_id:
        log.warning("OAuth callback: state cookie missing from request")
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"reason": "missing_state_cookie"},
            request=request,
        )
        return error_redirect("Session expired")

    # Retrieve and delete state from server-side store (one-time use)
    oauth_state_store = get_oauth_state_store()
    log.info(f"OAuth callback: looking up state_id={state_id[:8]}... (store has {oauth_state_store.state_count} entries)")
    oauth_state = await oauth_state_store.get_and_delete(state_id)

    if oauth_state is None:
        log.warning(f"OAuth callback: state not found for state_id={state_id[:8]}... (store has {oauth_state_store.state_count} entries remaining)")
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"reason": "state_not_found"},
            request=request,
        )
        return error_redirect("Session expired")

    # Validate state parameter (CSRF protection)
    if state != oauth_state.state:
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"reason": "state_mismatch"},
            request=request,
        )
        return error_redirect("Invalid session", oauth_state.redirect_after)

    # Check if code is present
    if not code:
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"reason": "missing_code"},
            request=request,
        )
        return error_redirect("Authorization code missing", oauth_state.redirect_after)

    try:
        # Exchange code for tokens
        tokens = await exchange_code_for_tokens(
            tenant_id=OAUTH_M365_TENANT_ID,
            client_id=OAUTH_M365_CLIENT_ID,
            client_secret=OAUTH_M365_CLIENT_SECRET,
            redirect_uri=OAUTH_M365_REDIRECT_URI,
            code=code,
            code_verifier=oauth_state.code_verifier,
        )

        # Validate ID token and extract user info
        user_info = await validate_id_token(
            id_token=tokens.id_token,
            tenant_id=OAUTH_M365_TENANT_ID,
            client_id=OAUTH_M365_CLIENT_ID,
            nonce=oauth_state.nonce,
        )

        # Check domain restriction
        if not is_email_domain_allowed(user_info.email, OAUTH_M365_ALLOWED_DOMAINS):
            audit.log_access(
                action="oauth.m365.callback",
                principal_id=f"oauth:{user_info.email}",
                status="denied",
                details={"reason": "domain_not_allowed"},
                request=request,
            )
            return error_redirect("Email domain not allowed", oauth_state.redirect_after)

        # Map email to VVP user - try file-based first, then database
        user_store = get_user_store()
        user = user_store.get_user(user_info.email)
        is_db_user = False
        db_user_record = None

        # Sprint 41: If not found in file-based store, try database
        if user is None:
            with get_db_session() as db:
                db_user_store = get_db_user_store()
                db_user_record = db_user_store.get_user_by_email(db, user_info.email)
                if db_user_record:
                    is_db_user = True

        if user is None and db_user_record is None:
            if OAUTH_M365_AUTO_PROVISION:
                # Auto-provision new user to file-based store
                user = user_store.create_user(
                    email=user_info.email,
                    name=user_info.name,
                    password_hash="",  # OAuth users don't have passwords
                    roles=set(OAUTH_M365_DEFAULT_ROLES),
                    enabled=True,
                    is_oauth_user=True,
                )
                log.info(f"Auto-provisioned OAuth user: {user_info.email}")
            else:
                audit.log_access(
                    action="oauth.m365.callback",
                    principal_id=f"oauth:{user_info.email}",
                    status="denied",
                    details={"reason": "user_not_found"},
                    request=request,
                )
                return error_redirect("User not registered", oauth_state.redirect_after)

        # Check enabled status
        if is_db_user:
            if not db_user_record.enabled:
                audit.log_access(
                    action="oauth.m365.callback",
                    principal_id=f"user:{user_info.email}",
                    status="denied",
                    details={"reason": "user_disabled"},
                    request=request,
                )
                return error_redirect("Account disabled", oauth_state.redirect_after)
        elif user and not user.enabled:
            audit.log_access(
                action="oauth.m365.callback",
                principal_id=f"user:{user_info.email}",
                status="denied",
                details={"reason": "user_disabled"},
                request=request,
            )
            return error_redirect("Account disabled", oauth_state.redirect_after)

        # Create principal and session
        if is_db_user:
            with get_db_session() as db:
                db_user_store = get_db_user_store()
                principal = db_user_store.get_principal_for_user(db, db_user_record)
        else:
            principal = Principal(
                key_id=f"user:{user.email}",
                name=user.name,
                roles=user.roles,
            )

        session_store = get_session_store()
        session = await session_store.create(principal, SESSION_TTL_SECONDS)

        # Build redirect response with session cookie
        redirect_url = oauth_state.redirect_after
        redirect_response = RedirectResponse(url=redirect_url, status_code=302)

        # Set session cookie
        redirect_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session.session_id,
            httponly=True,
            samesite="lax",
            secure=SESSION_COOKIE_SECURE,
            path="/",
            max_age=SESSION_TTL_SECONDS,
        )

        # Clear OAuth state cookie
        redirect_response.delete_cookie(key=OAUTH_STATE_COOKIE_NAME, path="/")

        audit.log_access(
            action="oauth.m365.callback",
            principal_id=principal.key_id,
            status="success",
            details={"method": "oauth_m365", "session_ttl": SESSION_TTL_SECONDS},
            request=request,
        )

        log.info(f"OAuth login successful for {user_info.email}")
        return redirect_response

    except OAuthError as e:
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="denied",
            details={"reason": "oauth_error", "error": str(e)},
            request=request,
        )
        return error_redirect("Authentication failed", oauth_state.redirect_after)
    except Exception as e:
        log.error(f"OAuth callback error: {e}")
        audit.log_access(
            action="oauth.m365.callback",
            principal_id="anonymous",
            status="error",
            details={"error": str(e)},
            request=request,
        )
        return error_redirect("Authentication failed", oauth_state.redirect_after)
