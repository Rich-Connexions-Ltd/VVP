"""SIP transport layer.

Sprint 42: UDP/TCP/TLS server for SIP INVITE handling.
"""

import asyncio
import logging
import ssl
from typing import Callable, Optional, Awaitable

from app.config import (
    SIP_LISTEN_HOST,
    SIP_LISTEN_PORT,
    SIP_TRANSPORT,
    SIPS_ENABLED,
    SIPS_LISTEN_PORT,
    SIPS_CERT_FILE,
    SIPS_KEY_FILE,
)
from app.sip.builder import build_100_trying
from common.vvp.sip import SIPRequest, SIPResponse, parse_sip_request

log = logging.getLogger(__name__)

# Type for message handler function
MessageHandler = Callable[[SIPRequest], Awaitable[SIPResponse]]


class UDPServerProtocol(asyncio.DatagramProtocol):
    """UDP server protocol for SIP.

    Includes INVITE transaction deduplication: SIP retransmissions (same
    Call-ID) wait for the in-flight request to complete and receive the
    same response, rather than spawning parallel API calls.
    """

    # How long to keep completed transaction responses for late retransmissions
    _TXN_TTL = 32.0  # RFC 3261 Timer B

    def __init__(self, handler: MessageHandler):
        """Initialize protocol.

        Args:
            handler: Async function to handle SIP requests
        """
        self._handler = handler
        self._transport: Optional[asyncio.DatagramTransport] = None
        # In-flight INVITE transactions: call_id -> asyncio.Future[SIPResponse]
        self._inflight: dict[str, asyncio.Future] = {}
        # Completed transaction responses: call_id -> SIPResponse
        self._completed: dict[str, SIPResponse] = {}

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when connection is established."""
        self._transport = transport
        log.info("UDP server ready")

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Handle incoming UDP datagram.

        Args:
            data: Raw SIP message
            addr: Source address (host, port)
        """
        asyncio.create_task(self._handle_datagram(data, addr))

    async def _handle_datagram(self, data: bytes, addr: tuple) -> None:
        """Process datagram with INVITE retransmission deduplication.

        Args:
            data: Raw SIP message
            addr: Source address
        """
        try:
            request = parse_sip_request(data)
            if request is None:
                log.warning(f"Failed to parse SIP from {addr[0]}:{addr[1]}")
                return

            # Sprint 47: Set source address for monitoring dashboard
            request.source_addr = f"{addr[0]}:{addr[1]}"

            log.debug(f"UDP {request.method} from {addr[0]}:{addr[1]}")

            # Non-INVITE methods: process directly (ACK, etc.)
            if not request.is_invite:
                response = await self._handler(request)
                if self._transport and not self._transport.is_closing():
                    self._transport.sendto(response.to_bytes(), addr)
                return

            call_id = request.call_id or ""

            # Check if we already have a completed response for this Call-ID
            if call_id and call_id in self._completed:
                log.debug(f"Retransmit (completed): resending response for {call_id[:16]}")
                if self._transport and not self._transport.is_closing():
                    self._transport.sendto(self._completed[call_id].to_bytes(), addr)
                return

            # Check if there's an in-flight request for this Call-ID
            if call_id and call_id in self._inflight:
                log.debug(f"Retransmit (in-flight): waiting for {call_id[:16]}")
                try:
                    response = await self._inflight[call_id]
                    if self._transport and not self._transport.is_closing():
                        self._transport.sendto(response.to_bytes(), addr)
                except Exception:
                    pass  # Original handler failed; retransmission gets nothing
                return

            # New INVITE — send 100 Trying immediately to reset SIP Timer B.
            # Without this, FreeSWITCH terminates the transaction after 32s
            # (Timer B) even though our TN lookup + VVP create can take 30-35s.
            trying = build_100_trying(request)
            if self._transport and not self._transport.is_closing():
                self._transport.sendto(trying.to_bytes(), addr)
                log.debug(f"Sent 100 Trying for {call_id[:16] if call_id else 'unknown'}")

            # Create a future and process
            fut: asyncio.Future[SIPResponse] = asyncio.get_running_loop().create_future()
            if call_id:
                self._inflight[call_id] = fut

            try:
                response = await self._handler(request)
                fut.set_result(response)
            except Exception as e:
                fut.set_exception(e)
                raise
            finally:
                if call_id:
                    self._inflight.pop(call_id, None)

            # Cache response for late retransmissions
            if call_id:
                self._completed[call_id] = response
                asyncio.get_running_loop().call_later(
                    self._TXN_TTL,
                    self._completed.pop, call_id, None,
                )

            if self._transport and not self._transport.is_closing():
                self._transport.sendto(response.to_bytes(), addr)

        except Exception as e:
            log.error(f"Error handling UDP message: {e}")


class TCPServerProtocol(asyncio.Protocol):
    """TCP server protocol for SIP."""

    def __init__(self, handler: MessageHandler):
        """Initialize protocol.

        Args:
            handler: Async function to handle SIP requests
        """
        self._handler = handler
        self._transport: Optional[asyncio.Transport] = None
        self._buffer = b""
        self._addr: tuple = ("", 0)

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when connection is established."""
        self._transport = transport
        peername = transport.get_extra_info("peername")
        self._addr = peername or ("unknown", 0)
        log.debug(f"TCP connection from {self._addr[0]}:{self._addr[1]}")

    def data_received(self, data: bytes) -> None:
        """Handle incoming TCP data.

        Buffers data until a complete SIP message is received.

        Args:
            data: Raw bytes received
        """
        self._buffer += data

        # Look for end of SIP headers (double CRLF)
        while b"\r\n\r\n" in self._buffer:
            header_end = self._buffer.find(b"\r\n\r\n") + 4

            # Extract Content-Length to determine body size
            headers = self._buffer[:header_end].decode("utf-8", errors="replace")
            content_length = 0
            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                    break

            # Check if we have the complete message
            total_length = header_end + content_length
            if len(self._buffer) < total_length:
                break  # Wait for more data

            # Extract complete message
            message = self._buffer[:total_length]
            self._buffer = self._buffer[total_length:]

            asyncio.create_task(self._handle_message(message))

    async def _handle_message(self, data: bytes) -> None:
        """Process message asynchronously.

        Args:
            data: Complete SIP message
        """
        try:
            request = parse_sip_request(data)
            if request is None:
                log.warning(f"Failed to parse SIP from {self._addr[0]}:{self._addr[1]}")
                return

            # Sprint 47: Set source address for monitoring dashboard
            request.source_addr = f"{self._addr[0]}:{self._addr[1]}"

            log.debug(f"TCP {request.method} from {self._addr[0]}:{self._addr[1]}")

            response = await self._handler(request)
            if self._transport and not self._transport.is_closing():
                self._transport.write(response.to_bytes())

        except Exception as e:
            log.error(f"Error handling TCP message: {e}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is closed."""
        log.debug(f"TCP connection closed from {self._addr[0]}:{self._addr[1]}")


async def start_udp_server(
    handler: MessageHandler,
    host: str = SIP_LISTEN_HOST,
    port: int = SIP_LISTEN_PORT,
) -> asyncio.DatagramTransport:
    """Start UDP server for SIP.

    Args:
        handler: Async function to handle SIP requests
        host: Listen address
        port: Listen port

    Returns:
        UDP transport for the server
    """
    log.info(f"Starting UDP server on {host}:{port}")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(handler),
        local_addr=(host, port),
    )
    return transport


async def start_tcp_server(
    handler: MessageHandler,
    host: str = SIP_LISTEN_HOST,
    port: int = SIP_LISTEN_PORT,
) -> asyncio.Server:
    """Start TCP server for SIP.

    Args:
        handler: Async function to handle SIP requests
        host: Listen address
        port: Listen port

    Returns:
        TCP server instance
    """
    log.info(f"Starting TCP server on {host}:{port}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TCPServerProtocol(handler),
        host=host,
        port=port,
    )
    return server


async def start_tls_server(
    handler: MessageHandler,
    host: str = SIP_LISTEN_HOST,
    port: int = SIPS_LISTEN_PORT,
    cert_file: str = SIPS_CERT_FILE,
    key_file: str = SIPS_KEY_FILE,
) -> asyncio.Server:
    """Start TLS server for SIPS.

    Args:
        handler: Async function to handle SIP requests
        host: Listen address
        port: Listen port (default: 5061)
        cert_file: Path to TLS certificate
        key_file: Path to TLS private key

    Returns:
        TLS server instance
    """
    log.info(f"Starting TLS server on {host}:{port}")

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_file, key_file)

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TCPServerProtocol(handler),
        host=host,
        port=port,
        ssl=ssl_context,
    )
    return server


async def run_servers(handler: MessageHandler) -> list:
    """Start all configured SIP servers.

    Args:
        handler: Async function to handle SIP requests

    Returns:
        List of server transports/instances
    """
    servers = []

    if SIP_TRANSPORT in ("udp", "both", "all"):
        transport = await start_udp_server(handler)
        servers.append(transport)

    if SIP_TRANSPORT in ("tcp", "both", "all"):
        server = await start_tcp_server(handler)
        servers.append(server)

    if SIPS_ENABLED and SIPS_CERT_FILE and SIPS_KEY_FILE:
        server = await start_tls_server(handler)
        servers.append(server)
        log.info("SIPS/TLS enabled")

    return servers
