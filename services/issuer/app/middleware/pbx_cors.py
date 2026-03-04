"""Path-scoped CORS middleware for the PBX portal.

Allows https://pbx.rcnx.io to call issuer PBX API endpoints cross-origin.
CORS scope is restricted to an explicit allowlist of specific /pbx/ endpoints
(see _PBX_CORS_PATHS) — NOT a broad /pbx/* prefix. New endpoints added under
/pbx/ do NOT automatically receive CORS access; they must be explicitly added
to the allowlist. Generic organization endpoints are accessed via PBX facade
endpoints (also under /pbx/) specifically to keep the CORS scope narrow.

Sprint 77: Required so the static PBX management UI on pbx.rcnx.io can call
the issuer's PBX backend (which remains on vvp-issuer.rcnx.io because it
depends on the issuer's database, auth, and Azure SDK).
"""

import re

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# The only allowed cross-origin caller — no wildcards.
PBX_ORIGIN = "https://pbx.rcnx.io"

# Explicit allowlist of paths accessible cross-origin from pbx.rcnx.io.
# Using an allowlist (not startswith) prevents accidental CORS exposure if
# new /pbx/* endpoints are added that should not be cross-origin accessible.
_PBX_CORS_PATHS = [
    re.compile(r"^/pbx/config$"),
    re.compile(r"^/pbx/deploy$"),
    re.compile(r"^/pbx/dialplan-preview$"),
    re.compile(r"^/pbx/organizations/names$"),
    # org_id restricted to alphanumeric + hyphen + underscore — prevents any
    # dot-segment or traversal-like patterns in the org_id path segment.
    re.compile(r"^/pbx/organizations/[a-zA-Z0-9][a-zA-Z0-9_-]*/api-keys$"),
]


def _is_pbx_cors_path(path: str) -> bool:
    return any(p.match(path) for p in _PBX_CORS_PATHS)


class PbxCorsMiddleware(BaseHTTPMiddleware):
    """CORS middleware scoped to an explicit allowlist of /pbx/* paths.

    All other issuer endpoints (credential issuance, dossier, admin, org CRUD)
    are not CORS-accessible from pbx.rcnx.io.

    Transport security: The issuer enforces HTTPS-only via Azure Container Apps
    TLS termination and the Strict-Transport-Security response header set by
    the issuer's HSTS configuration. The PBX_ORIGIN constant and ISSUER_BASE_URL
    in the portal frontend are both hardcoded to https:// URLs.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        origin = request.headers.get("origin", "")
        is_pbx_path = _is_pbx_cors_path(path)
        is_pbx_origin = origin == PBX_ORIGIN

        # Handle CORS preflight for allowed PBX paths from the PBX portal only.
        if request.method == "OPTIONS" and is_pbx_origin and is_pbx_path:
            resp = Response()
            resp.headers["Access-Control-Allow-Origin"] = PBX_ORIGIN
            resp.headers["Access-Control-Allow-Methods"] = "GET, PUT, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "X-API-Key, Content-Type"
            resp.headers["Access-Control-Allow-Credentials"] = "false"
            resp.headers["Access-Control-Max-Age"] = "3600"
            resp.headers["Vary"] = "Origin"
            return resp

        response = await call_next(request)

        # Add CORS headers to actual responses for allowed PBX paths from PBX portal.
        if is_pbx_origin and is_pbx_path:
            response.headers["Access-Control-Allow-Origin"] = PBX_ORIGIN
            response.headers["Access-Control-Allow-Credentials"] = "false"
            response.headers["Vary"] = "Origin"

        return response
