"""Bearer token authentication for KERI Agent inter-service communication.

Simple middleware that validates Authorization: Bearer <token> on all
requests except health probe endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

import app.config as _config

log = logging.getLogger(__name__)

# Paths exempt from bearer token auth (health probes)
EXEMPT_PATHS: set[str] = {"/livez", "/healthz", "/readyz", "/version"}


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Validates bearer token on all non-exempt requests.

    If AGENT_AUTH_TOKEN is empty, auth is disabled (development mode).
    Reads the token from app.config at request time (not import time)
    so that config reloads in tests take effect.
    """

    async def dispatch(self, request: Request, call_next):
        # Skip auth for exempt paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Read token at request time (supports config reload in tests)
        auth_token = _config.AGENT_AUTH_TOKEN

        # Skip auth if no token configured (development mode)
        if not auth_token:
            return await call_next(request)

        # Validate Authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Strip "Bearer " prefix
        if token != auth_token:
            log.warning(f"Invalid bearer token from {request.client.host}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)
