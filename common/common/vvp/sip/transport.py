"""SIP transport layer.

Sprint 44: AsyncIO UDP/TCP/TLS server for SIP INVITE handling.
Configurable for use by both sip-redirect and sip-verify services.
"""

import asyncio
import logging
import ssl
from dataclasses import dataclass
from typing import Callable, Optional, Awaitable, List, Union

from common.vvp.sip.models import SIPRequest, SIPResponse
from common.vvp.sip.parser import parse_sip_request

log = logging.getLogger(__name__)

# Type for message handler function.
# Handler may return None to silently drop a request (no response sent).
MessageHandler = Callable[[SIPRequest], Awaitable[Optional[SIPResponse]]]


@dataclass
class TransportConfig:
    """Configuration for SIP transport servers.

    Attributes:
        host: Listen address (default: 0.0.0.0)
        port: SIP port (default: 5060)
        transport: Transport type - "udp", "tcp", "both", "all"
        tls_enabled: Enable TLS/SIPS server
        tls_port: TLS port (default: 5061)
        tls_cert_file: Path to TLS certificate
        tls_key_file: Path to TLS private key
    """

    host: str = "0.0.0.0"
    port: int = 5060
    transport: str = "udp"  # udp, tcp, both, all
    tls_enabled: bool = False
    tls_port: int = 5061
    tls_cert_file: str = ""
    tls_key_file: str = ""


class UDPServerProtocol(asyncio.DatagramProtocol):
    """UDP server protocol for SIP."""

    def __init__(self, handler: MessageHandler):
        """Initialize protocol.

        Args:
            handler: Async function to handle SIP requests
        """
        self._handler = handler
        self._transport: Optional[asyncio.DatagramTransport] = None

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
        """Process datagram asynchronously.

        Args:
            data: Raw SIP message
            addr: Source address
        """
        try:
            request = parse_sip_request(data)
            if request is None:
                log.warning(f"Failed to parse SIP from {addr[0]}:{addr[1]}")
                return

            log.debug(f"UDP {request.method} from {addr[0]}:{addr[1]}")

            response = await self._handler(request)
            if response is not None and self._transport and not self._transport.is_closing():
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

            log.debug(f"TCP {request.method} from {self._addr[0]}:{self._addr[1]}")

            response = await self._handler(request)
            if response is not None and self._transport and not self._transport.is_closing():
                self._transport.write(response.to_bytes())

        except Exception as e:
            log.error(f"Error handling TCP message: {e}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is closed."""
        log.debug(f"TCP connection closed from {self._addr[0]}:{self._addr[1]}")


async def start_udp_server(
    handler: MessageHandler,
    host: str = "0.0.0.0",
    port: int = 5060,
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
    host: str = "0.0.0.0",
    port: int = 5060,
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
    host: str = "0.0.0.0",
    port: int = 5061,
    cert_file: str = "",
    key_file: str = "",
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


async def run_servers(
    handler: MessageHandler,
    config: Optional[TransportConfig] = None,
) -> List[Union[asyncio.DatagramTransport, asyncio.Server]]:
    """Start all configured SIP servers.

    Args:
        handler: Async function to handle SIP requests
        config: Transport configuration (uses defaults if None)

    Returns:
        List of server transports/instances
    """
    if config is None:
        config = TransportConfig()

    servers: List[Union[asyncio.DatagramTransport, asyncio.Server]] = []

    if config.transport in ("udp", "both", "all"):
        transport = await start_udp_server(handler, config.host, config.port)
        servers.append(transport)

    if config.transport in ("tcp", "both", "all"):
        server = await start_tcp_server(handler, config.host, config.port)
        servers.append(server)

    if config.tls_enabled and config.tls_cert_file and config.tls_key_file:
        server = await start_tls_server(
            handler,
            config.host,
            config.tls_port,
            config.tls_cert_file,
            config.tls_key_file,
        )
        servers.append(server)
        log.info("SIPS/TLS enabled")

    return servers


async def stop_servers(
    servers: List[Union[asyncio.DatagramTransport, asyncio.Server]],
) -> None:
    """Stop all running SIP servers.

    Args:
        servers: List of server transports/instances to stop
    """
    for server in servers:
        if isinstance(server, asyncio.DatagramTransport):
            server.abort()
        elif isinstance(server, asyncio.Server):
            server.close()
            await server.wait_closed()

    log.info("All SIP servers stopped")
