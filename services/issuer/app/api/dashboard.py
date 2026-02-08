"""Central service dashboard health aggregation API (Sprint 52)."""
import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter

from app.config import (
    DASHBOARD_SERVICES,
    DASHBOARD_SIP_REDIRECT_URL,
    DASHBOARD_SIP_REDIRECT_HEALTH,
    DASHBOARD_SIP_VERIFY_URL,
    DASHBOARD_SIP_VERIFY_HEALTH,
    DASHBOARD_SIP_MONITOR_URL,
    DASHBOARD_REQUEST_TIMEOUT,
)

log = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])


def _build_health_url(base_url: str, health_path: str) -> str:
    """Build health check URL with proper slash normalization."""
    return base_url.rstrip("/") + "/" + health_path.lstrip("/")


async def _check_service(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    health_path: str,
    category: str,
) -> dict:
    """Check a single service's health endpoint."""
    health_url = _build_health_url(url, health_path)
    start = time.monotonic()
    try:
        resp = await client.get(health_url)
        elapsed = (time.monotonic() - start) * 1000
        is_healthy = 200 <= resp.status_code < 300

        # Safe JSON parsing — some services return plain text or empty body
        version = None
        try:
            data = resp.json()
            version = data.get("version") or data.get("git_sha")
        except Exception:
            pass

        return {
            "name": name,
            "url": url,
            "status": "healthy" if is_healthy else "unhealthy",
            "response_time_ms": round(elapsed, 1),
            "version": version,
            "error": None if is_healthy else f"HTTP {resp.status_code}",
            "category": category,
        }
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return {
            "name": name,
            "url": url,
            "status": "unhealthy",
            "response_time_ms": round(elapsed, 1),
            "version": None,
            "error": str(type(e).__name__) + ": " + str(e),
            "category": category,
        }


def _build_service_checks() -> list[dict[str, str]]:
    """Build the list of services to check from configuration."""
    services = []

    # Core + witness + infrastructure services from VVP_DASHBOARD_SERVICES
    for svc in DASHBOARD_SERVICES:
        if svc.get("url"):
            services.append({
                "name": svc.get("name", "Unknown"),
                "url": svc["url"],
                "health_path": svc.get("health_path", "/healthz"),
                "category": svc.get("category", "core"),
            })

    # SIP redirect
    if DASHBOARD_SIP_REDIRECT_URL:
        services.append({
            "name": "SIP Redirect",
            "url": DASHBOARD_SIP_REDIRECT_URL,
            "health_path": DASHBOARD_SIP_REDIRECT_HEALTH,
            "category": "sip",
        })

    # SIP verify
    if DASHBOARD_SIP_VERIFY_URL:
        services.append({
            "name": "SIP Verify",
            "url": DASHBOARD_SIP_VERIFY_URL,
            "health_path": DASHBOARD_SIP_VERIFY_HEALTH,
            "category": "sip",
        })

    return services


def _compute_overall_status(results: list[dict]) -> str:
    """Compute overall status from individual service results."""
    if not results:
        return "unknown"

    statuses = [r["status"] for r in results]
    if all(s == "healthy" for s in statuses):
        return "healthy"
    if all(s == "unhealthy" for s in statuses):
        return "unhealthy"
    return "degraded"


@router.get("/api/dashboard/status")
async def dashboard_status():
    """Aggregate health status from all configured VVP services."""
    services_config = _build_service_checks()

    if not services_config:
        return {
            "overall_status": "unknown",
            "services": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "sip_monitor_url": DASHBOARD_SIP_MONITOR_URL or None,
        }

    async with httpx.AsyncClient(timeout=DASHBOARD_REQUEST_TIMEOUT) as client:
        tasks = [
            _check_service(
                client,
                svc["name"],
                svc["url"],
                svc["health_path"],
                svc["category"],
            )
            for svc in services_config
        ]
        results = await asyncio.gather(*tasks)

    return {
        "overall_status": _compute_overall_status(list(results)),
        "services": list(results),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "sip_monitor_url": DASHBOARD_SIP_MONITOR_URL or None,
    }
