#!/usr/bin/env python3
"""
Mock SIP Redirect Server for VVP Header Validation

This server listens on UDP port 5070 and returns SIP 302 Moved Temporarily
responses with X-VVP-* headers. Used to validate that FreeSWITCH preserves
these headers when following redirects.

Usage:
    python3 mock_redirect.py [--port 5070] [--target 9999@localhost:5060]

Test:
    fs_cli -x "originate sofia/gateway/vvp-redirect/+15551234567 &park()"

Expected flow:
    1. FreeSWITCH sends INVITE to this server (port 5070)
    2. This server returns 302 with Contact and X-VVP-* headers
    3. FreeSWITCH follows redirect to the Contact address (9999@localhost:5060)
    4. The loopback extension (9999) logs the received VVP headers
"""

import asyncio
import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class SIPRequest:
    """Parsed SIP request"""
    method: str
    uri: str
    version: str
    headers: dict
    body: str

    @property
    def call_id(self) -> Optional[str]:
        return self.headers.get('Call-ID') or self.headers.get('call-id')

    @property
    def from_header(self) -> Optional[str]:
        return self.headers.get('From') or self.headers.get('from')

    @property
    def to_header(self) -> Optional[str]:
        return self.headers.get('To') or self.headers.get('to')

    @property
    def via(self) -> Optional[str]:
        return self.headers.get('Via') or self.headers.get('via')

    @property
    def cseq(self) -> Optional[str]:
        return self.headers.get('CSeq') or self.headers.get('cseq')


def parse_sip_request(data: bytes) -> Optional[SIPRequest]:
    """Parse a SIP request from raw bytes"""
    try:
        text = data.decode('utf-8')
        lines = text.split('\r\n')

        if not lines:
            return None

        # Parse request line: METHOD sip:uri SIP/2.0
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return None

        method = parts[0]
        uri = parts[1]
        version = parts[2]

        # Parse headers
        headers = {}
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Parse body (if any)
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''

        return SIPRequest(
            method=method,
            uri=uri,
            version=version,
            headers=headers,
            body=body
        )
    except Exception as e:
        logger.error(f"Failed to parse SIP request: {e}")
        return None


def build_302_response(
    request: SIPRequest,
    redirect_target: str,
    brand_name: str = "Test Corp",
    brand_logo: str = "https://example.com/logo.png",
    status: str = "VALID"
) -> bytes:
    """Build a SIP 302 Moved Temporarily response with VVP headers"""

    # Extract tag from From header for To header
    from_tag = ""
    if request.from_header:
        tag_match = re.search(r'tag=([^;>\s]+)', request.from_header)
        if tag_match:
            from_tag = tag_match.group(1)

    # Build To header with tag
    to_header = request.to_header or ""
    if ";tag=" not in to_header:
        to_header += f";tag=mock-{from_tag[:8]}" if from_tag else ";tag=mock-server"

    # Build response
    response_lines = [
        "SIP/2.0 302 Moved Temporarily",
        f"Via: {request.via}",
        f"From: {request.from_header}",
        f"To: {to_header}",
        f"Call-ID: {request.call_id}",
        f"CSeq: {request.cseq}",
        f"Contact: <sip:{redirect_target}>",
        # Standard STIR Identity header (simplified for testing)
        "Identity: eyJ0eXAiOiJwYXNzcG9ydCIsImFsZyI6IkVkRFNBIiwicHB0IjoidnZwIn0;info=<https://witness.rcnx.io/oobi/test>;alg=EdDSA;ppt=vvp",
        # VVP custom headers
        "P-VVP-Identity: eyJwcHQiOiJ2dnAiLCJraWQiOiJodHRwczovL3dpdG5lc3MucmNueC5pby9vb2JpL3Rlc3QiLCJldmQiOiJodHRwczovL2lzc3Vlci5yY254LmlvL2Rvc3NpZXIvdGVzdCIsImlhdCI6MTcwNzAwMDAwMCwiZXhwIjoxNzA3MDAwMzAwfQ",
        "P-VVP-Passport: eyJhbGciOiJFZERTQSIsInBwdCI6InZ2cCIsImtpZCI6Imh0dHBzOi8vd2l0bmVzcy5yY254LmlvL29vYmkvdGVzdCJ9.eyJpYXQiOjE3MDcwMDAwMDAsIm9yaWciOnsidG4iOlsiKzE1NTUxMjM0NTY3Il19LCJkZXN0Ijp7InRuIjpbIisxNDQ0NTY3ODkwMSJdfSwiZXZkIjoiaHR0cHM6Ly9pc3N1ZXIucmNueC5pby9kb3NzaWVyL3Rlc3QifQ.test-signature",
        f"X-VVP-Brand-Name: {brand_name}",
        f"X-VVP-Brand-Logo: {brand_logo}",
        f"X-VVP-Status: {status}",
        "Content-Length: 0",
        "",
        ""
    ]

    return '\r\n'.join(response_lines).encode('utf-8')


def build_400_response(request: SIPRequest, reason: str = "Bad Request") -> bytes:
    """Build a SIP 400 Bad Request response"""
    to_header = request.to_header or ""
    if ";tag=" not in to_header:
        to_header += ";tag=mock-error"

    response_lines = [
        f"SIP/2.0 400 {reason}",
        f"Via: {request.via}",
        f"From: {request.from_header}",
        f"To: {to_header}",
        f"Call-ID: {request.call_id}",
        f"CSeq: {request.cseq}",
        "Content-Length: 0",
        "",
        ""
    ]

    return '\r\n'.join(response_lines).encode('utf-8')


class MockSIPRedirectProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for mock SIP redirect server"""

    def __init__(self, redirect_target: str):
        self.redirect_target = redirect_target
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Mock SIP Redirect Server ready")

    def datagram_received(self, data: bytes, addr: tuple):
        logger.info(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")

        # Parse the SIP request
        request = parse_sip_request(data)
        if not request:
            logger.error("Failed to parse SIP request")
            return

        logger.info(f"Parsed: {request.method} {request.uri}")
        logger.info(f"  Call-ID: {request.call_id}")
        logger.info(f"  From: {request.from_header}")
        logger.info(f"  To: {request.to_header}")

        # Only handle INVITE requests
        if request.method != 'INVITE':
            logger.info(f"Ignoring non-INVITE method: {request.method}")
            response = build_400_response(request, "Method Not Allowed")
            self.transport.sendto(response, addr)
            return

        # Build and send 302 response with VVP headers
        response = build_302_response(
            request,
            redirect_target=self.redirect_target,
            brand_name="Test Corp",
            brand_logo="https://example.com/logo.png",
            status="VALID"
        )

        logger.info(f"Sending 302 Moved Temporarily -> {self.redirect_target}")
        logger.info("  With headers: X-VVP-Brand-Name, X-VVP-Brand-Logo, X-VVP-Status")

        self.transport.sendto(response, addr)


async def run_server(host: str, port: int, redirect_target: str):
    """Run the mock SIP redirect server"""
    logger.info("=" * 60)
    logger.info("VVP Mock SIP Redirect Server")
    logger.info("=" * 60)
    logger.info(f"Listening on: {host}:{port} (UDP)")
    logger.info(f"Redirect target: {redirect_target}")
    logger.info("")
    logger.info("Test with:")
    logger.info('  fs_cli -x "originate sofia/gateway/vvp-redirect/+15551234567 &park()"')
    logger.info("")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MockSIPRedirectProtocol(redirect_target),
        local_addr=(host, port)
    )

    try:
        # Run forever
        await asyncio.Future()
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(
        description="Mock SIP Redirect Server for VVP Header Validation"
    )
    parser.add_argument(
        '--host', '-H',
        default='0.0.0.0',
        help='Listen host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5070,
        help='Listen port (default: 5070)'
    )
    parser.add_argument(
        '--target', '-t',
        default='9999@localhost:5060',
        help='Redirect target (default: 9999@localhost:5060)'
    )

    args = parser.parse_args()

    try:
        asyncio.run(run_server(args.host, args.port, args.target))
    except KeyboardInterrupt:
        logger.info("Server stopped")
        sys.exit(0)


if __name__ == '__main__':
    main()
