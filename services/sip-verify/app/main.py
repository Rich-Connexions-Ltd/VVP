"""VVP SIP Verify Service main entrypoint.

Sprint 44: AsyncIO-based SIP verification service.
Sprint 79: Added HTTP server for logo serving endpoint.
"""

import asyncio
import logging
import os
import re
import signal
from pathlib import Path
from typing import Optional

import aiohttp.web

from common.vvp.sip.transport import run_servers, stop_servers, TransportConfig

from .config import (
    VVP_SIP_VERIFY_HOST,
    VVP_SIP_VERIFY_PORT,
    VVP_SIP_VERIFY_TRANSPORT,
    VVP_LOG_LEVEL,
    VVP_STATUS_ENABLED,
    VVP_STATUS_HTTP_PORT,
    VVP_LOGO_CACHE_DIR,
)
from .verify.handler import handle_verify_invite, get_logo_cache

# Configure logging
logging.basicConfig(
    level=getattr(logging, VVP_LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
log = logging.getLogger(__name__)

# SAID format: E + 43 base64url chars
_SAID_RE = re.compile(r"^E[A-Za-z0-9_-]{43}$")

# Web directory for static assets
_WEB_DIR = Path(__file__).parent.parent / "web"


async def handle_logo(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Serve cached logo by SAID.

    GET /logo/{said} — returns the cached logo image.
    GET /logo/unknown — returns the unknown-brand placeholder.
    """
    said = request.match_info["said"]

    # Special case: unknown brand placeholder
    if said == "unknown":
        svg_path = _WEB_DIR / "unknown-brand.svg"
        if svg_path.exists():
            data = await asyncio.to_thread(svg_path.read_bytes)
            return aiohttp.web.Response(
                body=data,
                content_type="image/svg+xml",
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            )
        return aiohttp.web.Response(status=404)

    # Validate SAID format
    if not _SAID_RE.match(said):
        return aiohttp.web.Response(status=404)

    cache = get_logo_cache()
    filepath = cache.get_file_path(said)
    if filepath is None:
        return aiohttp.web.Response(
            status=404,
            headers={"Cache-Control": "no-store"},
        )

    # Path traversal protection (double-check)
    real_cache = os.path.realpath(VVP_LOGO_CACHE_DIR)
    real_file = os.path.realpath(filepath)
    if not real_file.startswith(real_cache):
        return aiohttp.web.Response(status=404)

    data = await asyncio.to_thread(filepath.read_bytes)
    content_type = cache.get_content_type(said)
    return aiohttp.web.Response(
        body=data,
        content_type=content_type,
        headers={
            "Cache-Control": "public, max-age=86400, immutable",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def handle_healthz(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Health check endpoint."""
    return aiohttp.web.json_response({"status": "ok"})


async def _start_http_server() -> Optional[aiohttp.web.AppRunner]:
    """Start HTTP server for logo serving and health checks."""
    if not VVP_STATUS_ENABLED:
        return None

    app = aiohttp.web.Application()
    app.router.add_get("/logo/{said}", handle_logo)
    app.router.add_get("/healthz", handle_healthz)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "0.0.0.0", VVP_STATUS_HTTP_PORT)
    await site.start()
    log.info(f"HTTP server started on port {VVP_STATUS_HTTP_PORT}")
    return runner


async def main() -> None:
    """Main entrypoint for SIP Verify Service."""
    log.info("Starting VVP SIP Verify Service")
    log.info(f"  Host: {VVP_SIP_VERIFY_HOST}")
    log.info(f"  Port: {VVP_SIP_VERIFY_PORT}")
    log.info(f"  Transport: {VVP_SIP_VERIFY_TRANSPORT}")

    # Configure transport
    config = TransportConfig(
        host=VVP_SIP_VERIFY_HOST,
        port=VVP_SIP_VERIFY_PORT,
        transport=VVP_SIP_VERIFY_TRANSPORT,
    )

    # Set up signal handlers for graceful shutdown
    shutdown_event = asyncio.Event()

    def handle_shutdown(sig: signal.Signals) -> None:
        log.info(f"Received {sig.name}, initiating shutdown...")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_shutdown(s))

    # Start HTTP server for logo serving (Sprint 79)
    http_runner = await _start_http_server()

    # Start SIP servers
    await run_servers(handle_verify_invite, config)
    log.info("SIP servers started")

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Stop servers
    await stop_servers()
    if http_runner:
        await http_runner.cleanup()
    log.info("Servers stopped")


def run() -> None:
    """Run the service."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted by user")


if __name__ == "__main__":
    run()
