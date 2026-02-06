"""VVP SIP Verify Service main entrypoint.

Sprint 44: AsyncIO-based SIP verification service.
"""

import asyncio
import logging
import signal
from typing import Optional

from common.vvp.sip.transport import run_servers, stop_servers, TransportConfig

from .config import (
    VVP_SIP_VERIFY_HOST,
    VVP_SIP_VERIFY_PORT,
    VVP_SIP_VERIFY_UDP_ENABLED,
    VVP_SIP_VERIFY_TCP_ENABLED,
    VVP_LOG_LEVEL,
)
from .verify.handler import handle_verify_invite

# Configure logging
logging.basicConfig(
    level=getattr(logging, VVP_LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
log = logging.getLogger(__name__)


async def main() -> None:
    """Main entrypoint for SIP Verify Service."""
    log.info("Starting VVP SIP Verify Service")
    log.info(f"  Host: {VVP_SIP_VERIFY_HOST}")
    log.info(f"  Port: {VVP_SIP_VERIFY_PORT}")
    log.info(f"  UDP: {'enabled' if VVP_SIP_VERIFY_UDP_ENABLED else 'disabled'}")
    log.info(f"  TCP: {'enabled' if VVP_SIP_VERIFY_TCP_ENABLED else 'disabled'}")

    # Configure transport
    config = TransportConfig(
        host=VVP_SIP_VERIFY_HOST,
        port=VVP_SIP_VERIFY_PORT,
        udp_enabled=VVP_SIP_VERIFY_UDP_ENABLED,
        tcp_enabled=VVP_SIP_VERIFY_TCP_ENABLED,
    )

    # Set up signal handlers for graceful shutdown
    shutdown_event = asyncio.Event()

    def handle_shutdown(sig: signal.Signals) -> None:
        log.info(f"Received {sig.name}, initiating shutdown...")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_shutdown(s))

    # Start SIP servers
    await run_servers(handle_verify_invite, config)
    log.info("SIP servers started")

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Stop servers
    await stop_servers()
    log.info("SIP servers stopped")


def run() -> None:
    """Run the service."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted by user")


if __name__ == "__main__":
    run()
