#!/usr/bin/env python3
"""Mock VVP SIP Redirect Services with Monitoring Dashboard.

Sprint 43: Provides mock signing and verification services for PBX testing.
Sprint 47: Adds circular buffer event capture and web monitoring dashboard.

Signing Service (port 5070):
- Receives SIP INVITE
- Adds X-VVP-* headers (Brand-Name, Brand-Logo, Status)
- Returns 302 redirect to original destination

Verification Service (port 5071):
- Receives SIP INVITE with VVP headers
- Validates/extracts headers
- Returns 302 redirect with verified status

Web Dashboard (port 8090):
- Session-authenticated web UI
- Real-time SIP event visualization
- VVP header and PASSporT parsing

Usage:
    python mock_sip_redirect.py

The server listens on:
- UDP 5070: Mock signing service
- UDP 5071: Mock verification service
- HTTP 8090: Monitoring dashboard (localhost only)
"""

import asyncio
import json
import logging
import os
import re
import sys
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

# Optional aiohttp import for web dashboard
try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("mock-sip-redirect")

# Environment configuration
SIP_MONITOR_ENABLED = os.getenv("SIP_MONITOR_ENABLED", "true").lower() == "true"
SIP_MONITOR_BUFFER_SIZE = int(os.getenv("SIP_MONITOR_BUFFER_SIZE", "100"))


# =============================================================================
# SIP EVENT CAPTURE (Sprint 47)
# =============================================================================


@dataclass
class SIPEvent:
    """Captured SIP request/response event for monitoring.

    Stores all relevant data from a SIP INVITE transaction for
    visualization in the monitoring dashboard.
    """

    id: int  # Auto-incrementing event ID
    timestamp: str  # ISO 8601 timestamp
    service: str  # "SIGNING" or "VERIFY"
    source_addr: str  # IP:port of sender
    method: str  # SIP method (INVITE, etc.)
    request_uri: str  # SIP Request-URI
    call_id: str  # SIP Call-ID
    from_tn: Optional[str]  # Originating telephone number
    to_tn: Optional[str]  # Destination telephone number
    headers: dict  # All SIP headers
    vvp_headers: dict  # VVP-specific headers (X-VVP-*, P-VVP-*, Identity)
    raw_request: str  # Full raw SIP message
    response_code: str  # Response sent (e.g., "302", "500")
    redirect_uri: Optional[str]  # Contact URI from 302 response


class SIPEventBuffer:
    """Thread-safe circular buffer for SIP events.

    Uses asyncio.Lock for thread safety. Events are stored with
    auto-incrementing IDs for efficient polling.
    """

    def __init__(self, max_size: int = 100):
        self._buffer: deque = deque(maxlen=max_size)
        self._lock = asyncio.Lock()
        self._next_id: int = 1

    async def add(self, event_data: dict) -> int:
        """Add an event to the buffer.

        Args:
            event_data: Dict with event fields (id will be auto-assigned)

        Returns:
            The assigned event ID
        """
        async with self._lock:
            event_id = self._next_id
            self._next_id += 1

            event = SIPEvent(
                id=event_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                **event_data,
            )
            self._buffer.append(event)
            return event_id

    async def get_all(self) -> list[dict]:
        """Get all events in buffer (newest first).

        Returns:
            List of event dicts
        """
        async with self._lock:
            return [asdict(e) for e in reversed(self._buffer)]

    async def get_since(self, last_id: int) -> list[dict]:
        """Get events newer than the given ID.

        Args:
            last_id: Only return events with ID > last_id

        Returns:
            List of event dicts (oldest first for append order)
        """
        async with self._lock:
            return [asdict(e) for e in self._buffer if e.id > last_id]

    async def clear(self) -> int:
        """Clear all events from buffer.

        Returns:
            Number of events cleared
        """
        async with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            return count

    @property
    def count(self) -> int:
        """Number of events in buffer."""
        return len(self._buffer)

    @property
    def max_size(self) -> int:
        """Maximum buffer size."""
        return self._buffer.maxlen or 0


# Global event buffer instance
sip_event_buffer = SIPEventBuffer(max_size=SIP_MONITOR_BUFFER_SIZE)


def parse_all_headers(raw: str) -> dict:
    """Parse all headers from raw SIP message.

    Args:
        raw: Raw SIP message text

    Returns:
        Dict of header name -> value (preserves case)
    """
    headers = {}
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")

    for line in lines[1:]:  # Skip request line
        if not line or line.startswith(" "):
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    return headers


def extract_vvp_headers(raw: str) -> dict:
    """Extract VVP-specific headers from raw SIP message.

    Extracts:
    - X-VVP-* headers (Brand-Name, Brand-Logo, Status, etc.)
    - P-VVP-* headers (Identity, Passport)
    - Identity header (RFC 8224 STIR)

    Args:
        raw: Raw SIP message text

    Returns:
        Dict of VVP header name -> value
    """
    vvp_headers = {}
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")

    for line in lines:
        if not line:
            continue
        line_lower = line.lower()
        if line_lower.startswith("x-vvp-"):
            name, value = line.split(":", 1)
            vvp_headers[name.strip()] = value.strip()
        elif line_lower.startswith("p-vvp-"):
            name, value = line.split(":", 1)
            vvp_headers[name.strip()] = value.strip()
        elif line_lower.startswith("identity:"):
            vvp_headers["Identity"] = line.split(":", 1)[1].strip()

    return vvp_headers


# =============================================================================
# SIP REQUEST PARSING
# =============================================================================


@dataclass
class SIPRequest:
    """Parsed SIP request."""

    method: str
    request_uri: str
    via: str
    from_header: str
    to_header: str
    call_id: str
    cseq: str
    contact: Optional[str] = None
    from_tn: Optional[str] = None
    to_tn: Optional[str] = None
    raw: str = ""


def parse_sip_request(data: bytes) -> Optional[SIPRequest]:
    """Parse SIP request from raw bytes."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if not lines:
            return None

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        method = parts[0]
        request_uri = parts[1]

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if not line or line.startswith(" "):
                continue
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        # Extract TNs from URI
        from_tn = None
        to_tn = None

        from_match = re.search(r"sip:(\+?\d+)@", headers.get("from", ""))
        if from_match:
            from_tn = from_match.group(1)

        to_match = re.search(r"sip:(\+?\d+)@", request_uri)
        if to_match:
            to_tn = to_match.group(1)

        return SIPRequest(
            method=method,
            request_uri=request_uri,
            via=headers.get("via", ""),
            from_header=headers.get("from", ""),
            to_header=headers.get("to", ""),
            call_id=headers.get("call-id", ""),
            cseq=headers.get("cseq", ""),
            contact=headers.get("contact"),
            from_tn=from_tn,
            to_tn=to_tn,
            raw=text,
        )
    except Exception as e:
        log.error(f"Failed to parse SIP request: {e}")
        return None


def build_302_response(
    request: SIPRequest,
    contact_uri: str,
    vvp_status: str = "VALID",
    brand_name: str = "Test Corporation Ltd",
    brand_logo: str = "https://example.com/logo.png",
) -> bytes:
    """Build SIP 302 Moved Temporarily response with VVP headers."""
    # URL-encode values for SIP headers
    encoded_brand = quote(brand_name)
    encoded_logo = quote(brand_logo)

    response = f"""SIP/2.0 302 Moved Temporarily
Via: {request.via}
From: {request.from_header}
To: {request.to_header};tag=vvp-mock
Call-ID: {request.call_id}
CSeq: {request.cseq}
Contact: <{contact_uri}>
X-VVP-Brand-Name: {encoded_brand}
X-VVP-Brand-Logo: {encoded_logo}
X-VVP-Status: {vvp_status}
Content-Length: 0

"""
    return response.replace("\n", "\r\n").encode("utf-8")


def build_error_response(request: SIPRequest, code: int, reason: str) -> bytes:
    """Build SIP error response."""
    response = f"""SIP/2.0 {code} {reason}
Via: {request.via}
From: {request.from_header}
To: {request.to_header};tag=vvp-mock-err
Call-ID: {request.call_id}
CSeq: {request.cseq}
Content-Length: 0

"""
    return response.replace("\n", "\r\n").encode("utf-8")


class MockSigningService:
    """Mock VVP Signing Service.

    Receives INVITE, adds VVP attestation headers, returns 302 to loopback.
    """

    def __init__(self, port: int = 5070, loopback_host: str = "127.0.0.1", loopback_port: int = 5080):
        self.port = port
        self.loopback_host = loopback_host
        self.loopback_port = loopback_port
        self.brand_name = "VVP Mock Brand"
        self.brand_logo = "https://vvp.example.com/logo.png"

    async def handle_invite(self, request: SIPRequest, addr: tuple) -> bytes:
        """Handle incoming INVITE by adding VVP headers and redirecting."""
        log.info(f"[SIGNING] INVITE from {addr}: {request.from_tn} -> {request.to_tn}")

        # Extract destination from original request URI
        # Route to loopback (verification) service
        dest_tn = request.to_tn or "unknown"
        contact_uri = f"sip:{dest_tn}@{self.loopback_host}:{self.loopback_port}"

        log.info(f"[SIGNING] Redirecting to {contact_uri} with VVP headers")

        response = build_302_response(
            request=request,
            contact_uri=contact_uri,
            vvp_status="VALID",
            brand_name=self.brand_name,
            brand_logo=self.brand_logo,
        )

        # Capture event for monitoring (Sprint 47)
        await sip_event_buffer.add({
            "service": "SIGNING",
            "source_addr": f"{addr[0]}:{addr[1]}",
            "method": request.method,
            "request_uri": request.request_uri,
            "call_id": request.call_id,
            "from_tn": request.from_tn,
            "to_tn": request.to_tn,
            "headers": parse_all_headers(request.raw),
            "vvp_headers": extract_vvp_headers(request.raw),
            "raw_request": request.raw,
            "response_code": "302",
            "redirect_uri": contact_uri,
        })

        return response


class MockVerificationService:
    """Mock VVP Verification Service.

    Receives INVITE with VVP headers, validates, returns 302 to final destination.
    """

    def __init__(self, port: int = 5071, pbx_host: str = "127.0.0.1", pbx_port: int = 5060):
        self.port = port
        self.pbx_host = pbx_host
        self.pbx_port = pbx_port

    async def handle_invite(self, request: SIPRequest, addr: tuple) -> bytes:
        """Handle incoming INVITE by validating VVP headers and redirecting."""
        log.info(f"[VERIFY] INVITE from {addr}: {request.from_tn} -> {request.to_tn}")

        # In a real service, we'd validate the VVP headers here
        # For mock, just pass through with the same headers

        # Extract VVP headers from raw request
        vvp_status = "VALID"
        brand_name = "VVP Mock Brand"
        brand_logo = "https://vvp.example.com/logo.png"

        for line in request.raw.split("\r\n"):
            if line.lower().startswith("x-vvp-status:"):
                vvp_status = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-vvp-brand-name:"):
                brand_name = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-vvp-brand-logo:"):
                brand_logo = line.split(":", 1)[1].strip()

        log.info(f"[VERIFY] VVP Status: {vvp_status}, Brand: {brand_name}")

        # Route to PBX internal profile
        dest_tn = request.to_tn or "unknown"
        contact_uri = f"sip:{dest_tn}@{self.pbx_host}:{self.pbx_port}"

        log.info(f"[VERIFY] Redirecting to {contact_uri}")

        response = build_302_response(
            request=request,
            contact_uri=contact_uri,
            vvp_status=vvp_status,
            brand_name=brand_name,
            brand_logo=brand_logo,
        )

        # Capture event for monitoring (Sprint 47)
        await sip_event_buffer.add({
            "service": "VERIFY",
            "source_addr": f"{addr[0]}:{addr[1]}",
            "method": request.method,
            "request_uri": request.request_uri,
            "call_id": request.call_id,
            "from_tn": request.from_tn,
            "to_tn": request.to_tn,
            "headers": parse_all_headers(request.raw),
            "vvp_headers": extract_vvp_headers(request.raw),
            "raw_request": request.raw,
            "response_code": "302",
            "redirect_uri": contact_uri,
        })

        return response


class SIPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for SIP messages."""

    def __init__(self, handler, service_name: str):
        self.handler = handler
        self.service_name = service_name
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"[{self.service_name}] UDP listener ready")

    def datagram_received(self, data: bytes, addr: tuple):
        log.debug(f"[{self.service_name}] Received {len(data)} bytes from {addr}")

        request = parse_sip_request(data)
        if not request:
            log.warning(f"[{self.service_name}] Failed to parse SIP message")
            return

        if request.method != "INVITE":
            log.info(f"[{self.service_name}] Ignoring {request.method}")
            # Send 200 OK for non-INVITE methods (like ACK)
            return

        # Handle asynchronously
        asyncio.create_task(self._handle_and_respond(request, addr))

    async def _handle_and_respond(self, request: SIPRequest, addr: tuple):
        try:
            response = await self.handler.handle_invite(request, addr)
            self.transport.sendto(response, addr)
            log.info(f"[{self.service_name}] Sent 302 response to {addr}")
        except Exception as e:
            log.error(f"[{self.service_name}] Error handling INVITE: {e}")
            error_response = build_error_response(request, 500, "Server Error")
            self.transport.sendto(error_response, addr)


# =============================================================================
# WEB DASHBOARD SERVER (Sprint 47)
# =============================================================================

# Directory containing static files for dashboard
MONITOR_WEB_DIR = Path(__file__).parent / "monitor_web"


def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (set by nginx)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    # Fallback to peername
    peername = request.transport.get_extra_info("peername")
    return peername[0] if peername else "unknown"


async def require_session(request) -> Optional["Session"]:
    """Validate session from cookie.

    Returns:
        Session if valid, None otherwise
    """
    from auth import get_session_store, COOKIE_NAME

    session_id = request.cookies.get(COOKIE_NAME)
    if not session_id:
        return None

    session_store = get_session_store()
    return await session_store.get(session_id)


async def require_csrf(request) -> bool:
    """Check CSRF protection for state-changing requests.

    Returns:
        True if valid, False otherwise
    """
    # Require X-Requested-With header for POST/DELETE
    if request.method in ("POST", "DELETE", "PUT", "PATCH"):
        return request.headers.get("X-Requested-With") == "XMLHttpRequest"
    return True


# Web request handlers
async def handle_login_page(request):
    """GET /login - Serve login page."""
    login_file = MONITOR_WEB_DIR / "login.html"
    if not login_file.exists():
        return web.Response(text="Login page not found", status=404)
    return web.FileResponse(login_file)


async def handle_login(request):
    """POST /api/login - Authenticate and create session."""
    from auth import (
        get_user_store, get_session_store, get_rate_limiter,
        COOKIE_NAME, SESSION_TTL_SECONDS
    )

    client_ip = get_client_ip(request)
    rate_limiter = get_rate_limiter()

    # Check rate limit
    if not await rate_limiter.check_rate_limit(client_ip):
        remaining = await rate_limiter.get_lockout_remaining(client_ip)
        return web.json_response(
            {"error": f"Too many attempts. Try again in {remaining} seconds."},
            status=429,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        await rate_limiter.record_attempt(client_ip, success=False)
        return web.json_response({"error": "Username and password required"}, status=400)

    user_store = get_user_store()
    user = user_store.authenticate(username, password)

    if user is None:
        await rate_limiter.record_attempt(client_ip, success=False)
        return web.json_response({"error": "Invalid credentials"}, status=401)

    # Successful login
    await rate_limiter.record_attempt(client_ip, success=True)

    session_store = get_session_store()
    session = await session_store.create(username, SESSION_TTL_SECONDS)

    response = web.json_response({
        "success": True,
        "username": username,
        "force_password_change": user.force_password_change,
    })

    # Set session cookie - HttpOnly, Secure, SameSite=Strict
    response.set_cookie(
        COOKIE_NAME,
        session.session_id,
        httponly=True,
        secure=True,  # Requires HTTPS (via nginx)
        samesite="Strict",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )

    log.info(f"User '{username}' logged in from {client_ip}")
    return response


async def handle_logout(request):
    """POST /api/logout - Destroy session."""
    from auth import get_session_store, COOKIE_NAME

    session_id = request.cookies.get(COOKIE_NAME)
    if session_id:
        session_store = get_session_store()
        await session_store.delete(session_id)

    response = web.json_response({"success": True})
    response.del_cookie(COOKIE_NAME, path="/")

    return response


async def handle_events(request):
    """GET /api/events - Return all buffered events."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    events = await sip_event_buffer.get_all()
    return web.json_response({
        "events": events,
        "buffer_size": sip_event_buffer.count,
        "buffer_max": sip_event_buffer.max_size,
    })


async def handle_events_since(request):
    """GET /api/events/since/{id} - Return events since ID."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    try:
        last_id = int(request.match_info["id"])
    except ValueError:
        return web.json_response({"error": "Invalid ID"}, status=400)

    events = await sip_event_buffer.get_since(last_id)
    return web.json_response({"events": events})


async def handle_clear(request):
    """POST /api/clear - Clear event buffer."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    if not await require_csrf(request):
        return web.json_response({"error": "CSRF validation failed"}, status=403)

    count = await sip_event_buffer.clear()
    log.info(f"User '{session.username}' cleared event buffer ({count} events)")

    return web.json_response({"success": True, "cleared": count})


async def handle_status(request):
    """GET /api/status - Get service status (no auth required)."""
    from auth import get_session_store

    return web.json_response({
        "ok": True,
        "buffer_count": sip_event_buffer.count,
        "buffer_max": sip_event_buffer.max_size,
        "session_count": get_session_store().session_count,
        "signing_port": 5070,
        "verify_port": 5071,
    })


async def handle_auth_status(request):
    """GET /api/auth/status - Check if authenticated."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"authenticated": False})

    return web.json_response({
        "authenticated": True,
        "username": session.username,
        "expires_at": session.expires_at.isoformat(),
    })


async def handle_index(request):
    """GET / - Serve dashboard or redirect to login."""
    session = await require_session(request)

    if session is None:
        # Redirect to login
        raise web.HTTPFound("/login")

    index_file = MONITOR_WEB_DIR / "index.html"
    if not index_file.exists():
        return web.Response(text="Dashboard not found", status=404)

    return web.FileResponse(index_file)


def create_web_app() -> "web.Application":
    """Create aiohttp web application for monitoring dashboard."""
    app = web.Application()

    # API routes
    app.router.add_get("/api/status", handle_status)
    app.router.add_get("/api/auth/status", handle_auth_status)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/logout", handle_logout)
    app.router.add_get("/api/events", handle_events)
    app.router.add_get("/api/events/since/{id}", handle_events_since)
    app.router.add_post("/api/clear", handle_clear)

    # Page routes
    app.router.add_get("/", handle_index)
    app.router.add_get("/login", handle_login_page)

    # Static files
    if MONITOR_WEB_DIR.exists():
        app.router.add_static("/static/", MONITOR_WEB_DIR, name="static")

    return app


async def start_web_server(host: str = "127.0.0.1", port: int = 8090):
    """Start the monitoring dashboard web server.

    Args:
        host: Bind address (default localhost only for security)
        port: HTTP port (default 8090)

    Returns:
        Running web server site
    """
    if not AIOHTTP_AVAILABLE:
        log.warning("aiohttp not installed - web dashboard disabled")
        return None

    app = create_web_app()
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()

    log.info(f"Monitoring Dashboard listening on http://{host}:{port}")
    return site


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


async def main():
    """Start both mock services and optional web dashboard."""
    log.info("Starting VVP Mock SIP Redirect Services")

    loop = asyncio.get_running_loop()

    # Create services
    # Signing service redirects directly to PBX external profile
    signing_service = MockSigningService(
        port=5070,
        loopback_host="127.0.0.1",  # Redirect to PBX external profile
        loopback_port=5080,
    )
    # Verification service (not currently used in this flow, but available for testing)
    verification_service = MockVerificationService(
        port=5071,
        pbx_host="127.0.0.1",
        pbx_port=5080,
    )

    # Start UDP listeners
    signing_transport, _ = await loop.create_datagram_endpoint(
        lambda: SIPProtocol(signing_service, "SIGNING"),
        local_addr=("0.0.0.0", 5070),
    )
    verification_transport, _ = await loop.create_datagram_endpoint(
        lambda: SIPProtocol(verification_service, "VERIFY"),
        local_addr=("0.0.0.0", 5071),
    )

    log.info("Mock Signing Service listening on UDP 5070")
    log.info("Mock Verification Service listening on UDP 5071")

    # Start web dashboard if enabled (Sprint 47)
    web_site = None
    if SIP_MONITOR_ENABLED:
        try:
            web_site = await start_web_server(host="127.0.0.1", port=8090)
        except Exception as e:
            log.error(f"Failed to start web dashboard: {e}")
            log.warning("Continuing without web dashboard")
    else:
        log.info("Web dashboard disabled (SIP_MONITOR_ENABLED=false)")

    log.info("Press Ctrl+C to stop")

    try:
        await asyncio.Event().wait()  # Run forever
    finally:
        signing_transport.close()
        verification_transport.close()
        if web_site:
            await web_site.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down")
        sys.exit(0)
