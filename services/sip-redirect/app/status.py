"""HTTP status endpoint for SIP Redirect service.

Sprint 44: Provides health, rate limit, and call summary visibility.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from app.audit import get_audit_logger
from app.config import STATUS_ADMIN_KEY, STATUS_HTTP_PORT, RATE_LIMIT_RPS, RATE_LIMIT_BURST, GIT_SHA

log = logging.getLogger(__name__)


class StatusHandler:
    """Simple HTTP handler for /status endpoint.

    Uses Python's asyncio streams for minimal dependencies.
    """

    def __init__(self, get_rate_limiter: Callable):
        """Initialize status handler.

        Args:
            get_rate_limiter: Callable that returns the RateLimiter instance
        """
        self._get_rate_limiter = get_rate_limiter
        self._server: Optional[asyncio.AbstractServer] = None

    async def handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming HTTP request.

        Args:
            reader: Request stream reader
            writer: Response stream writer
        """
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            request_line = request_line.decode("utf-8", errors="ignore").strip()

            if not request_line:
                writer.close()
                await writer.wait_closed()
                return

            parts = request_line.split()
            if len(parts) < 2:
                await self._send_error(writer, 400, "Bad Request")
                return

            method, path = parts[0], parts[1]

            # Read headers
            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                line = line.decode("utf-8", errors="ignore").strip()
                if not line:
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Route request
            if path == "/status" and method == "GET":
                await self._handle_status(writer, headers)
            elif path == "/health" and method == "GET":
                await self._handle_health(writer)
            elif path == "/version" and method == "GET":
                await self._handle_version(writer)
            else:
                await self._send_error(writer, 404, "Not Found")

        except asyncio.TimeoutError:
            await self._send_error(writer, 408, "Request Timeout")
        except Exception as e:
            log.warning(f"Status handler error: {e}")
            try:
                await self._send_error(writer, 500, "Internal Server Error")
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_health(self, writer: asyncio.StreamWriter) -> None:
        """Handle /health endpoint (no auth required).

        Args:
            writer: Response writer
        """
        response = {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
        await self._send_json(writer, 200, response)

    async def _handle_version(self, writer: asyncio.StreamWriter) -> None:
        """Handle /version endpoint (no auth required).

        Args:
            writer: Response writer
        """
        result: dict = {"git_sha": GIT_SHA}
        if GIT_SHA != "unknown":
            result["short_sha"] = GIT_SHA[:7]
        await self._send_json(writer, 200, result)

    async def _handle_status(
        self,
        writer: asyncio.StreamWriter,
        headers: dict[str, str],
    ) -> None:
        """Handle /status endpoint (requires admin key).

        Args:
            writer: Response writer
            headers: Request headers
        """
        # Verify admin key
        if not STATUS_ADMIN_KEY:
            await self._send_error(
                writer,
                503,
                "Status endpoint not configured (VVP_STATUS_ADMIN_KEY not set)",
            )
            return

        admin_key = headers.get("x-admin-key", "")
        if admin_key != STATUS_ADMIN_KEY:
            await self._send_error(writer, 401, "Invalid or missing X-Admin-Key")
            return

        # Build status response
        audit = get_audit_logger()
        rate_limiter = self._get_rate_limiter()

        # Get rate limit states (show prefix only)
        rate_limits = []
        if rate_limiter:
            for key, bucket in rate_limiter._buckets.items():
                rate_limits.append({
                    "api_key_prefix": key[:8] + "...",
                    "tokens_remaining": round(bucket.tokens, 2),
                    "max_tokens": bucket.max_tokens,
                    "refill_rate": bucket.refill_rate,
                })

        # Get call summary and buffer stats
        call_summary = audit.get_call_summary(minutes=10)
        buffer_stats = audit.get_buffer_stats()

        response = {
            "healthy": True,
            "uptime_seconds": round(buffer_stats["uptime_seconds"], 1),
            "rate_limits": rate_limits,
            "recent_calls": call_summary,
            "config": {
                "rate_limit_rps": RATE_LIMIT_RPS,
                "rate_limit_burst": RATE_LIMIT_BURST,
            },
            "audit_buffer": {
                "size": buffer_stats["buffer_size"],
                "max_size": buffer_stats["max_buffer_size"],
            },
        }

        await self._send_json(writer, 200, response)

    async def _send_json(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        data: dict,
    ) -> None:
        """Send JSON response.

        Args:
            writer: Response writer
            status_code: HTTP status code
            data: Response data to serialize as JSON
        """
        body = json.dumps(data, indent=2).encode("utf-8")
        status_text = {200: "OK", 401: "Unauthorized", 404: "Not Found", 503: "Service Unavailable"}.get(
            status_code, "Unknown"
        )

        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")

        writer.write(response + body)
        await writer.drain()

    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        message: str,
    ) -> None:
        """Send error response.

        Args:
            writer: Response writer
            status_code: HTTP status code
            message: Error message
        """
        await self._send_json(writer, status_code, {"error": message})

    async def start(self, host: str = "0.0.0.0", port: int = STATUS_HTTP_PORT) -> None:
        """Start the status HTTP server.

        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self._server = await asyncio.start_server(
            self.handle_request,
            host,
            port,
        )
        log.info(f"Status HTTP server listening on {host}:{port}")

    async def stop(self) -> None:
        """Stop the status HTTP server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            log.info("Status HTTP server stopped")


# Module-level instance
_status_handler: Optional[StatusHandler] = None


async def start_status_server(get_rate_limiter: Callable) -> StatusHandler:
    """Start the status HTTP server.

    Args:
        get_rate_limiter: Callable that returns the RateLimiter instance

    Returns:
        StatusHandler instance
    """
    global _status_handler
    _status_handler = StatusHandler(get_rate_limiter)
    await _status_handler.start()
    return _status_handler


async def stop_status_server() -> None:
    """Stop the status HTTP server."""
    global _status_handler
    if _status_handler:
        await _status_handler.stop()
        _status_handler = None
