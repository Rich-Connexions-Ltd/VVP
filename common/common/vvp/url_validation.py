"""URL validation for SSRF prevention.

Single responsibility: validate that a URL is safe to fetch.
Checks scheme, resolves DNS (async), and blocks non-routable IPs.

This module is domain-agnostic — it raises URLValidationError (not
dossier-specific FetchError). Callers catch and re-raise as their
own domain exception (FetchError, ResolutionFailedError, etc.).

Sprint 78: Created as part of SIP call performance optimization.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


class URLValidationError(Exception):
    """Raised when a URL fails SSRF validation.

    Domain-agnostic exception. Callers should catch and re-raise
    as their specific error type (FetchError, ResolutionFailedError, etc.).
    """


async def validate_url_target(url: str, *, allow_http: bool = False) -> None:
    """Validate that a URL is safe to fetch (not targeting internal services).

    Args:
        url: The URL to validate.
        allow_http: If False (default), only https:// is permitted.
            Set True for OOBI URLs where local witnesses use http://.

    Raises:
        URLValidationError: If the URL targets a non-routable address,
            uses a disallowed scheme, or fails DNS resolution.
    """
    parsed = urlparse(url)

    # Scheme validation
    allowed_schemes = ("http", "https") if allow_http else ("https",)
    if parsed.scheme not in allowed_schemes:
        raise URLValidationError(
            f"Invalid URL scheme: {parsed.scheme} "
            f"(allowed: {', '.join(allowed_schemes)})"
        )
    if not parsed.netloc:
        raise URLValidationError("Invalid URL: missing host")

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("Invalid URL: missing hostname")

    # Async DNS resolution — does not block the event loop
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise URLValidationError(f"DNS resolution failed for {hostname}: {e}")

    for family, _, _, _, sockaddr in addr_info:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise URLValidationError(
                f"URL targets non-routable address: {hostname} -> {ip}"
            )
