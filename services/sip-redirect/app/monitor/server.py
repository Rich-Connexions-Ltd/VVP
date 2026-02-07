"""aiohttp Web Server for SIP Monitor Dashboard.

Sprint 47: Provides web-based monitoring dashboard with session authentication
and real-time SIP event visualization.

Sprint 48: Added WebSocket endpoint for real-time event streaming.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from app.config import (
    MONITOR_COOKIE_PATH,
    MONITOR_PORT,
    MONITOR_SESSION_TTL,
    MONITOR_WS_HEARTBEAT,
    MONITOR_WS_IDLE_TIMEOUT,
    MONITOR_WS_MAX_GLOBAL,
    MONITOR_WS_MAX_PER_IP,
)
from app.monitor.auth import (
    COOKIE_NAME,
    Session,
    get_rate_limiter,
    get_session_store,
    get_user_store,
)
from app.monitor.buffer import get_event_buffer

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

log = logging.getLogger(__name__)

# Directory containing static files for dashboard
MONITOR_WEB_DIR = Path(__file__).parent.parent / "monitor_web"


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


async def require_session(request) -> Optional[Session]:
    """Validate session from cookie.

    Returns:
        Session if valid, None otherwise
    """
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


# =============================================================================
# WEB REQUEST HANDLERS
# =============================================================================


async def handle_login_page(request):
    """GET /login - Serve login page."""
    login_file = MONITOR_WEB_DIR / "login.html"
    if not login_file.exists():
        return web.Response(text="Login page not found", status=404)
    return web.FileResponse(login_file)


async def handle_login(request):
    """POST /api/login - Authenticate and create session."""
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
    session = await session_store.create(username, MONITOR_SESSION_TTL)

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
        max_age=MONITOR_SESSION_TTL,
        path=MONITOR_COOKIE_PATH,
    )

    log.info(f"User '{username}' logged in from {client_ip}")
    return response


async def handle_logout(request):
    """POST /api/logout - Destroy session."""
    session_id = request.cookies.get(COOKIE_NAME)
    if session_id:
        session_store = get_session_store()
        await session_store.delete(session_id)

    response = web.json_response({"success": True})
    response.del_cookie(COOKIE_NAME, path=MONITOR_COOKIE_PATH)

    return response


async def handle_events(request):
    """GET /api/events - Return all buffered events."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    buffer = get_event_buffer()
    events = await buffer.get_all()
    return web.json_response({
        "events": events,
        "buffer_size": buffer.count,
        "buffer_max": buffer.max_size,
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

    buffer = get_event_buffer()
    events = await buffer.get_since(last_id)
    return web.json_response({"events": events})


async def handle_clear(request):
    """POST /api/clear - Clear event buffer."""
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    if not await require_csrf(request):
        return web.json_response({"error": "CSRF validation failed"}, status=403)

    buffer = get_event_buffer()
    count = await buffer.clear()
    log.info(f"User '{session.username}' cleared event buffer ({count} events)")

    return web.json_response({"success": True, "cleared": count})


async def handle_status(request):
    """GET /api/status - Get service status (no auth required)."""
    buffer = get_event_buffer()
    ws_manager = get_ws_manager()

    return web.json_response({
        "ok": True,
        "buffer_count": buffer.count,
        "buffer_max": buffer.max_size,
        "session_count": get_session_store().session_count,
        "websocket_connections": ws_manager.total,
        "buffer_subscribers": buffer.subscriber_count,
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
        raise web.HTTPFound("login")

    index_file = MONITOR_WEB_DIR / "index.html"
    if not index_file.exists():
        return web.Response(text="Dashboard not found", status=404)

    return web.FileResponse(index_file)


# =============================================================================
# WEBSOCKET (Sprint 48)
# =============================================================================


class WebSocketManager:
    """Track and limit WebSocket connections per IP and globally."""

    def __init__(
        self,
        max_per_ip: int = MONITOR_WS_MAX_PER_IP,
        max_global: int = MONITOR_WS_MAX_GLOBAL,
    ):
        self._connections: dict[str, int] = {}
        self._max_per_ip = max_per_ip
        self._max_global = max_global

    def can_connect(self, ip: str) -> bool:
        """Check per-IP limit AND global cap."""
        if self.total >= self._max_global:
            return False
        return self._connections.get(ip, 0) < self._max_per_ip

    def add(self, ip: str) -> None:
        """Register a new connection for IP."""
        self._connections[ip] = self._connections.get(ip, 0) + 1

    def remove(self, ip: str) -> None:
        """Unregister a connection for IP."""
        count = self._connections.get(ip, 0)
        if count <= 1:
            self._connections.pop(ip, None)
        else:
            self._connections[ip] = count - 1

    @property
    def total(self) -> int:
        """Total active WebSocket connections across all IPs."""
        return sum(self._connections.values())


# Global WebSocket manager instance
_ws_manager: Optional[WebSocketManager] = None


def get_ws_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance."""
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WebSocketManager()
    return _ws_manager


async def handle_websocket(request):
    """GET /ws - WebSocket endpoint for real-time event streaming.

    Protocol:
    - Server sends: {"type": "event", "data": {...}}
    - Server sends: {"type": "heartbeat"}
    - Server sends: {"type": "error", "message": "..."}
    - Client sends: any message resets idle timer
    """
    # Auth check BEFORE ws.prepare()
    session = await require_session(request)
    if session is None:
        return web.json_response({"error": "Unauthorized"}, status=401)

    client_ip = get_client_ip(request)
    ws_manager = get_ws_manager()

    # Connection limit check BEFORE ws.prepare()
    if not ws_manager.can_connect(client_ip):
        return web.json_response({"error": "Connection limit exceeded"}, status=429)

    # Upgrade to WebSocket
    ws = web.WebSocketResponse(heartbeat=MONITOR_WS_HEARTBEAT)
    await ws.prepare(request)

    ws_manager.add(client_ip)
    buffer = get_event_buffer()
    queue = await buffer.subscribe()

    log.info(
        f"WebSocket connected: {client_ip} (user={session.username}, "
        f"total={ws_manager.total})"
    )

    try:
        last_client_msg = time.monotonic()

        while True:
            # Check client idle timeout (based on client messages only,
            # not server-side queue activity)
            elapsed = time.monotonic() - last_client_msg
            remaining = MONITOR_WS_IDLE_TIMEOUT - elapsed
            if remaining <= 0:
                log.info(f"WebSocket idle timeout (no client message): {client_ip}")
                break

            # Create tasks for concurrent waiting
            queue_task = asyncio.ensure_future(queue.get())
            ws_task = asyncio.ensure_future(ws.receive())

            done, pending = await asyncio.wait(
                [queue_task, ws_task],
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

            if not done:
                # Timeout with no activity - check idle again at top of loop
                continue

            for task in done:
                result = task.result()

                if task is queue_task:
                    # New event from buffer - send to client
                    # (does NOT reset idle timer per spec)
                    try:
                        await ws.send_json({"type": "event", "data": result})
                    except (ConnectionResetError, Exception):
                        log.debug(f"WebSocket send failed: {client_ip}")
                        return ws

                elif task is ws_task:
                    msg = result
                    if msg.type == web.WSMsgType.TEXT:
                        # Client message resets idle timer
                        last_client_msg = time.monotonic()
                    elif msg.type == web.WSMsgType.CLOSE:
                        log.info(f"WebSocket closed by client: {client_ip}")
                        return ws
                    elif msg.type == web.WSMsgType.ERROR:
                        log.warning(
                            f"WebSocket error: {client_ip}: {ws.exception()}"
                        )
                        return ws

            # Check if session is still valid
            session_store = get_session_store()
            current_session = await session_store.get(session.session_id)
            if current_session is None:
                log.info(f"WebSocket session expired: {client_ip}")
                await ws.send_json({
                    "type": "error",
                    "message": "session_expired",
                })
                await ws.close(code=4001, message=b"Session expired")
                return ws

    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error(f"WebSocket handler error: {client_ip}: {e}")
    finally:
        await buffer.unsubscribe(queue)
        ws_manager.remove(client_ip)
        log.info(
            f"WebSocket disconnected: {client_ip} (total={ws_manager.total})"
        )
        if not ws.closed:
            await ws.close()

    return ws


# =============================================================================
# SERVER LIFECYCLE
# =============================================================================


def create_web_app() -> "web.Application":
    """Create aiohttp web application for monitoring dashboard."""
    if not AIOHTTP_AVAILABLE:
        raise RuntimeError("aiohttp not installed")

    app = web.Application()

    # API routes
    app.router.add_get("/api/status", handle_status)
    app.router.add_get("/api/auth/status", handle_auth_status)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/logout", handle_logout)
    app.router.add_get("/api/events", handle_events)
    app.router.add_get("/api/events/since/{id}", handle_events_since)
    app.router.add_post("/api/clear", handle_clear)

    # WebSocket route (Sprint 48)
    app.router.add_get("/ws", handle_websocket)

    # Page routes
    app.router.add_get("/", handle_index)
    app.router.add_get("/login", handle_login_page)

    # Static files
    if MONITOR_WEB_DIR.exists():
        app.router.add_static("/static/", MONITOR_WEB_DIR, name="static")

    return app


# Module-level server state
_runner: Optional["web.AppRunner"] = None
_site: Optional["web.TCPSite"] = None


async def start_dashboard_server(host: str = "127.0.0.1", port: int = None) -> bool:
    """Start the monitoring dashboard web server.

    Args:
        host: Bind address (default localhost only for security)
        port: HTTP port (default from config)

    Returns:
        True if started successfully, False otherwise
    """
    global _runner, _site

    if not AIOHTTP_AVAILABLE:
        log.warning("aiohttp not installed - dashboard disabled")
        return False

    if port is None:
        port = MONITOR_PORT

    try:
        app = create_web_app()
        _runner = web.AppRunner(app)
        await _runner.setup()

        _site = web.TCPSite(_runner, host, port)
        await _site.start()

        log.info(f"Monitoring Dashboard listening on http://{host}:{port}")
        return True

    except Exception as e:
        log.error(f"Failed to start dashboard server: {e}")
        return False


async def stop_dashboard_server() -> None:
    """Stop the monitoring dashboard web server."""
    global _runner, _site

    if _site:
        await _site.stop()
        _site = None

    if _runner:
        await _runner.cleanup()
        _runner = None

    log.info("Dashboard server stopped")
