"""HTTP client for the VVP Issuer API.

Provides a thin wrapper around httpx for calling issuer endpoints.
Configuration via environment variables:
  VVP_ISSUER_URL  - Base URL (default: http://localhost:8001)
  VVP_API_KEY     - API key for authentication

If VVP_API_KEY is not set, attempts to read from scripts/.e2e-config.
"""

import os
from pathlib import Path
from typing import Any

import httpx


_config_cache: dict[str, str] | None = None


def _load_e2e_config() -> dict[str, str]:
    """Load key=value pairs from scripts/.e2e-config."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    _config_cache = {}
    for parent in Path(__file__).resolve().parents:
        config_path = parent / "scripts" / ".e2e-config"
        if config_path.exists():
            for line in config_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    _config_cache[k.strip()] = v.strip().strip('"').strip("'")
            break
    return _config_cache


# Admin-only path prefixes that need the admin API key
_ADMIN_PATHS = ("/admin/", "/organizations")


def _find_api_key(path: str = "") -> str | None:
    """Resolve API key from environment or .e2e-config file.

    Uses VVP_ADMIN_KEY for admin endpoints, VVP_API_KEY/VVP_TEST_API_KEY otherwise.
    """
    # Check if this path needs admin auth
    needs_admin = any(path.startswith(p) for p in _ADMIN_PATHS)

    # Environment override takes precedence
    if needs_admin:
        key = os.environ.get("VVP_ADMIN_KEY")
        if key:
            return key
    key = os.environ.get("VVP_API_KEY")
    if key:
        return key

    # Fall back to .e2e-config
    config = _load_e2e_config()
    if needs_admin and "VVP_ADMIN_KEY" in config:
        return config["VVP_ADMIN_KEY"]
    return config.get("VVP_TEST_API_KEY")


def _base_url() -> str:
    """Get issuer base URL from environment."""
    return os.environ.get("VVP_ISSUER_URL", "http://localhost:8001")


def issuer_request(
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    admin: bool = False,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Make an authenticated request to the issuer API.

    Args:
        method: HTTP method (GET, POST, PATCH, DELETE).
        path: API path (e.g., "/organizations").
        json_body: JSON request body.
        params: Query parameters.
        api_key: Override API key (default: from env/config).
        base_url: Override base URL (default: from env).
        admin: Force admin key selection (for paths that need admin
            auth but don't match _ADMIN_PATHS, e.g. /credential with org_id).
        timeout: Request timeout in seconds.

    Returns:
        Response as dict with 'status_code', 'ok', and 'data' keys.
    """
    url = (base_url or _base_url()).rstrip("/") + path
    key = api_key or _find_api_key(path if not admin else "/admin/")

    headers: dict[str, str] = {}
    if key:
        headers["X-API-Key"] = key

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.request(
                method=method.upper(),
                url=url,
                json=json_body,
                params=params,
                headers=headers,
            )

            # Try to parse JSON response
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}

            return {
                "status_code": resp.status_code,
                "ok": resp.is_success,
                "data": data,
            }
    except httpx.ConnectError:
        return {
            "status_code": 0,
            "ok": False,
            "data": {"error": f"Connection refused: {url}. Is the issuer running?"},
        }
    except httpx.TimeoutException:
        return {
            "status_code": 0,
            "ok": False,
            "data": {"error": f"Request timed out after {timeout}s: {url}"},
        }
    except Exception as e:
        return {
            "status_code": 0,
            "ok": False,
            "data": {"error": f"{type(e).__name__}: {e}"},
        }
