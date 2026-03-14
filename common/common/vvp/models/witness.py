"""Shared witness recovery DTOs for cross-service communication.

Used by both the KERI Agent (endpoint) and Issuer (proxy).

Sprint 86: Witness State Resilience.
"""
from pydantic import BaseModel


class WitnessRepublishRequest(BaseModel):
    """Request body for witness republish operations."""

    force: bool = False  # Bypass circuit breaker and cooldown


class WitnessRepublishResponse(BaseModel):
    """Typed response for witness republish operations.

    Redacted: omits internal witness URLs and raw error details.
    Use /admin/readyz for full diagnostic information.
    """

    action: str
    witnesses_checked: int
    witnesses_degraded: int
    identities_published: int
    identities_total: int
    identities_verified: int
    identities_failed: int
    fully_recovered: bool
    elapsed_seconds: float
    error_codes: list[str] = []
