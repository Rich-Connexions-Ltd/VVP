"""KERI Agent HTTP client for the VVP Issuer.

Async HTTP client that replaces direct app.keri.* imports. Proxies all
KERI operations to the standalone KERI Agent service.

Key features:
- Bearer token auth (VVP_KERI_AGENT_AUTH_TOKEN)
- Retry with backoff on idempotent GETs (max 3 attempts)
- Circuit breaker (5 failures → open 30s → half-open probe)
- Error mapping (agent 4xx → issuer HTTPException, 5xx → 503)
- Idempotency-Key header on mutating requests

Sprint 68: KERI Agent Service Extraction.
"""
import asyncio
import logging
import time
import uuid
from typing import Optional

import httpx
from fastapi import HTTPException

from common.vvp.models.keri_agent import (
    AgentHealthResponse,
    AgentStatsResponse,
    BootstrapStatusResponse,
    BuildDossierRequest,
    CreateIdentityRequest,
    CreateRegistryRequest,
    CreateVVPAttestationRequest,
    CredentialResponse,
    DossierResponse,
    IdentityResponse,
    IssueCredentialRequest,
    RegistryResponse,
    RotateKeysRequest,
    RotationResponse,
    VVPAttestationResponse,
)

log = logging.getLogger(__name__)


class KeriAgentUnavailableError(Exception):
    """Raised when the KERI Agent is unreachable or circuit is open."""

    def __init__(self, message: str = "KERI Agent unavailable"):
        self.message = message
        super().__init__(message)


# =============================================================================
# Circuit Breaker
# =============================================================================


class CircuitBreaker:
    """Simple circuit breaker for the KERI Agent connection.

    States:
    - closed: Normal operation, all calls pass through
    - open: Agent is considered down, calls fail immediately
    - half_open: One probe call allowed to test recovery
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        failure_window: float = 60.0,
        recovery_timeout: float = 30.0,
    ):
        self.failure_threshold = failure_threshold
        self.failure_window = failure_window
        self.recovery_timeout = recovery_timeout

        self._state = "closed"
        self._failures: list[float] = []
        self._opened_at: float = 0.0
        self._half_open_in_flight = False

    @property
    def state(self) -> str:
        if self._state == "open":
            if time.monotonic() - self._opened_at >= self.recovery_timeout:
                self._state = "half_open"
                self._half_open_in_flight = False
        return self._state

    def record_success(self) -> None:
        """Record a successful call — reset circuit."""
        if self._state in ("half_open", "open"):
            log.info("KERI Agent circuit breaker: closed (recovery successful)")
        self._state = "closed"
        self._failures.clear()
        self._half_open_in_flight = False

    def record_failure(self) -> None:
        """Record a failed call — may trip the circuit."""
        now = time.monotonic()
        self._failures = [t for t in self._failures if now - t < self.failure_window]
        self._failures.append(now)

        if self._state == "half_open":
            self._state = "open"
            self._opened_at = now
            log.warning("KERI Agent circuit breaker: open (half-open probe failed)")
        elif len(self._failures) >= self.failure_threshold:
            self._state = "open"
            self._opened_at = now
            log.warning(
                f"KERI Agent circuit breaker: open "
                f"({len(self._failures)} failures in {self.failure_window}s)"
            )

    def allow_request(self) -> bool:
        """Check if a request should be allowed."""
        state = self.state
        if state == "closed":
            return True
        if state == "half_open":
            if not self._half_open_in_flight:
                self._half_open_in_flight = True
                return True
            return False
        return False  # open


# =============================================================================
# Singleton
# =============================================================================

_client: Optional["KeriAgentClient"] = None


def get_keri_client() -> "KeriAgentClient":
    """Get or create the KERI Agent client singleton."""
    global _client
    if _client is None:
        from app.config import (
            KERI_AGENT_URL,
            KERI_AGENT_AUTH_TOKEN,
            KERI_AGENT_TIMEOUT,
            KERI_AGENT_WRITE_TIMEOUT,
        )
        _client = KeriAgentClient(
            base_url=KERI_AGENT_URL,
            auth_token=KERI_AGENT_AUTH_TOKEN,
            read_timeout=KERI_AGENT_TIMEOUT,
            write_timeout=KERI_AGENT_WRITE_TIMEOUT,
        )
    return _client


def reset_keri_client() -> None:
    """Reset the singleton (for testing)."""
    global _client
    if _client is not None:
        # Don't await close in reset — tests handle cleanup separately
        _client = None


async def close_keri_client() -> None:
    """Close the HTTP client (call during shutdown)."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None


# =============================================================================
# Client
# =============================================================================


class KeriAgentClient:
    """Async HTTP client for the KERI Agent service.

    Replaces direct app.keri.* manager imports in the issuer. All KERI
    operations are proxied to the standalone KERI Agent via REST.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8002",
        auth_token: str = "",
        read_timeout: float = 30.0,
        write_timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._read_timeout = read_timeout
        self._write_timeout = write_timeout
        self._circuit = CircuitBreaker()

        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=httpx.Timeout(read_timeout, connect=10.0),
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    @property
    def circuit_state(self) -> str:
        """Current circuit breaker state."""
        return self._circuit.state

    def is_circuit_closed(self) -> bool:
        """Whether the circuit breaker is closed (agent considered reachable)."""
        return self._circuit.state == "closed"

    # -------------------------------------------------------------------------
    # Internal request helpers
    # -------------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        timeout: float | None = None,
        retry: bool = False,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        """Send a request to the KERI Agent with circuit breaker and retry.

        Args:
            method: HTTP method
            path: URL path (e.g., "/identities")
            json: Request body
            params: Query parameters
            timeout: Override timeout
            retry: If True, retry on 5xx (only for idempotent GETs)
            idempotency_key: Value for the Idempotency-Key header
        """
        if not self._circuit.allow_request():
            raise KeriAgentUnavailableError(
                "KERI Agent circuit breaker is open — agent considered unavailable"
            )

        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        request_timeout = timeout or (
            self._write_timeout if method != "GET" else self._read_timeout
        )

        max_attempts = 3 if retry else 1
        last_error: Exception | None = None

        for attempt in range(max_attempts):
            try:
                response = await self._http.request(
                    method,
                    path,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=request_timeout,
                )

                if response.status_code >= 500:
                    self._circuit.record_failure()
                    if retry and attempt < max_attempts - 1:
                        backoff = 0.5 * (2 ** attempt)  # 0.5s, 1s, 2s
                        log.warning(
                            f"KERI Agent {method} {path} returned {response.status_code}, "
                            f"retry {attempt + 1}/{max_attempts} in {backoff}s"
                        )
                        await asyncio.sleep(backoff)
                        continue
                    raise KeriAgentUnavailableError(
                        f"KERI Agent returned {response.status_code}: "
                        f"{response.text[:200]}"
                    )

                self._circuit.record_success()
                return response

            except httpx.TimeoutException as e:
                self._circuit.record_failure()
                last_error = e
                if retry and attempt < max_attempts - 1:
                    backoff = 0.5 * (2 ** attempt)
                    log.warning(
                        f"KERI Agent {method} {path} timed out, "
                        f"retry {attempt + 1}/{max_attempts} in {backoff}s"
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise KeriAgentUnavailableError(
                    f"KERI Agent request timed out: {e}"
                ) from e

            except httpx.ConnectError as e:
                self._circuit.record_failure()
                last_error = e
                if retry and attempt < max_attempts - 1:
                    backoff = 0.5 * (2 ** attempt)
                    log.warning(
                        f"KERI Agent {method} {path} connection failed, "
                        f"retry {attempt + 1}/{max_attempts} in {backoff}s"
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise KeriAgentUnavailableError(
                    f"KERI Agent connection failed: {e}"
                ) from e

        # Should not reach here, but just in case
        raise KeriAgentUnavailableError(
            f"KERI Agent request failed after {max_attempts} attempts"
        ) from last_error

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Map agent error responses to issuer HTTPExceptions."""
        if response.status_code < 400:
            return

        try:
            body = response.json()
            detail = body.get("detail", response.text[:200])
        except Exception:
            detail = response.text[:200]

        raise HTTPException(status_code=response.status_code, detail=detail)

    async def _get(self, path: str, *, params: dict | None = None) -> httpx.Response:
        """GET with retry on 5xx."""
        response = await self._request("GET", path, params=params, retry=True)
        self._handle_error_response(response)
        return response

    async def _post(
        self, path: str, *, json: dict | None = None, idempotency_key: str | None = None,
    ) -> httpx.Response:
        """POST without retry (mutating). Sends Idempotency-Key header."""
        key = idempotency_key or str(uuid.uuid4())
        response = await self._request(
            "POST", path, json=json, idempotency_key=key
        )
        self._handle_error_response(response)
        return response

    async def _delete(self, path: str) -> httpx.Response:
        """DELETE without retry (mutating)."""
        response = await self._request("DELETE", path)
        self._handle_error_response(response)
        return response

    async def _get_bytes(self, path: str) -> bytes:
        """GET returning raw bytes (for CESR responses)."""
        response = await self._request("GET", path, retry=True)
        self._handle_error_response(response)
        return response.content

    # =========================================================================
    # Identity
    # =========================================================================

    async def create_identity(self, req: CreateIdentityRequest) -> IdentityResponse:
        """Create a new KERI identity."""
        resp = await self._post("/identities", json=req.model_dump())
        return IdentityResponse.model_validate(resp.json())

    async def list_identities(self) -> list[IdentityResponse]:
        """List all identities."""
        resp = await self._get("/identities")
        return [IdentityResponse.model_validate(item) for item in resp.json()]

    async def get_identity(self, name: str) -> IdentityResponse | None:
        """Get identity by name. Returns None if not found."""
        try:
            resp = await self._get(f"/identities/{name}")
            return IdentityResponse.model_validate(resp.json())
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise

    async def rotate_keys(self, name: str, req: RotateKeysRequest) -> RotationResponse:
        """Rotate identity keys."""
        resp = await self._post(f"/identities/{name}/rotate", json=req.model_dump())
        return RotationResponse.model_validate(resp.json())

    async def get_oobi(self, name: str) -> str:
        """Get OOBI URL for an identity."""
        resp = await self._get(f"/identities/{name}/oobi")
        data = resp.json()
        return data.get("oobi", data.get("url", ""))

    async def get_kel(self, name: str) -> bytes:
        """Get KEL bytes for an identity."""
        return await self._get_bytes(f"/identities/{name}/kel")

    async def publish_identity(self, name: str) -> None:
        """Publish identity to witnesses."""
        await self._post(f"/identities/{name}/publish")

    async def get_identity_by_aid(self, aid: str) -> IdentityResponse | None:
        """Look up identity by AID. Returns None if not found."""
        resp = await self._get("/identities", params={"aid": aid})
        items = resp.json()
        if not items:
            return None
        return IdentityResponse.model_validate(items[0])

    async def delete_identity(self, name: str) -> None:
        """Delete an identity by name. Raises HTTPException on error."""
        await self._delete(f"/identities/{name}")

    # =========================================================================
    # Registry
    # =========================================================================

    async def create_registry(self, req: CreateRegistryRequest) -> RegistryResponse:
        """Create a credential registry."""
        resp = await self._post("/registries", json=req.model_dump())
        return RegistryResponse.model_validate(resp.json())

    async def list_registries(self) -> list[RegistryResponse]:
        """List all registries."""
        resp = await self._get("/registries")
        return [RegistryResponse.model_validate(item) for item in resp.json()]

    async def get_registry(self, name: str) -> RegistryResponse | None:
        """Get registry by name. Returns None if not found."""
        try:
            resp = await self._get(f"/registries/{name}")
            return RegistryResponse.model_validate(resp.json())
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise

    async def get_tel(self, name: str) -> bytes:
        """Get TEL bytes for a registry."""
        return await self._get_bytes(f"/registries/{name}/tel")

    async def get_registry_by_key(self, registry_key: str) -> RegistryResponse | None:
        """Look up registry by registry key. Returns None if not found."""
        resp = await self._get("/registries", params={"registry_key": registry_key})
        items = resp.json()
        if not items:
            return None
        return RegistryResponse.model_validate(items[0])

    async def delete_registry(self, name: str) -> None:
        """Delete a registry by name. Raises HTTPException on error."""
        await self._delete(f"/registries/{name}")

    # =========================================================================
    # Credentials
    # =========================================================================

    async def issue_credential(self, req: IssueCredentialRequest) -> CredentialResponse:
        """Issue an ACDC credential."""
        resp = await self._post("/credentials/issue", json=req.model_dump())
        return CredentialResponse.model_validate(resp.json())

    async def revoke_credential(self, said: str, publish: bool = True) -> CredentialResponse:
        """Revoke a credential."""
        resp = await self._post(
            f"/credentials/{said}/revoke",
            json={"publish": publish},
        )
        return CredentialResponse.model_validate(resp.json())

    async def list_credentials(
        self,
        registry_key: str | None = None,
        status: str | None = None,
    ) -> list[CredentialResponse]:
        """List credentials with optional filtering."""
        params = {}
        if registry_key:
            params["registry_key"] = registry_key
        if status:
            params["status"] = status
        resp = await self._get("/credentials", params=params or None)
        return [CredentialResponse.model_validate(item) for item in resp.json()]

    async def get_credential(self, said: str) -> CredentialResponse | None:
        """Get credential by SAID. Returns None if not found."""
        try:
            resp = await self._get(f"/credentials/{said}")
            return CredentialResponse.model_validate(resp.json())
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise

    async def get_credential_cesr(self, said: str) -> bytes:
        """Get CESR-encoded credential bytes."""
        return await self._get_bytes(f"/credentials/{said}/cesr")

    async def get_credential_tel(self, said: str) -> bytes | None:
        """Get CESR-encoded TEL issuance event for a credential.

        Returns the TEL iss event (sn=0) for inclusion in dossiers.
        Returns None if no TEL event exists for the credential (e.g. externally
        issued credentials held as edges in the local registry).
        """
        try:
            return await self._get_bytes(f"/credentials/{said}/tel")
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise

    async def delete_credential(self, said: str) -> None:
        """Delete a credential by SAID. Raises HTTPException on error."""
        await self._delete(f"/credentials/{said}")

    async def bulk_cleanup_credentials(self, saids: list[str], force: bool = True) -> dict:
        """Bulk delete credentials by SAID list via KERI Agent admin endpoint.

        Sprint 73: Returns dict with deleted_saids, failed, blocked_saids, etc.
        """
        resp = await self._post(
            "/admin/cleanup/credentials",
            json={"saids": saids, "force": force, "dry_run": False},
        )
        return resp.json()

    async def bulk_cleanup_identities(self, body: dict) -> dict:
        """Bulk delete identities via KERI Agent admin endpoint.

        Sprint 73: Returns dict with deleted_names, failed, blocked_names, etc.
        """
        resp = await self._post("/admin/cleanup/identities", json=body)
        return resp.json()

    # =========================================================================
    # Dossier
    # =========================================================================

    async def build_dossier(self, req: BuildDossierRequest) -> DossierResponse:
        """Build a dossier from a credential chain."""
        resp = await self._post("/dossiers/build", json=req.model_dump())
        return DossierResponse.model_validate(resp.json())

    async def get_dossier(self, said: str) -> DossierResponse | None:
        """Get a previously built dossier by SAID."""
        try:
            resp = await self._get(f"/dossiers/{said}")
            return DossierResponse.model_validate(resp.json())
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise

    async def get_dossier_cesr(self, said: str) -> bytes:
        """Get dossier as concatenated CESR stream."""
        return await self._get_bytes(f"/dossiers/{said}/cesr")

    # =========================================================================
    # VVP
    # =========================================================================

    async def create_vvp_attestation(
        self, req: CreateVVPAttestationRequest
    ) -> VVPAttestationResponse:
        """Create a VVP attestation (PASSporT + VVP-Identity header)."""
        resp = await self._post("/vvp/create", json=req.model_dump())
        return VVPAttestationResponse.model_validate(resp.json())

    # =========================================================================
    # Bootstrap
    # =========================================================================

    async def get_bootstrap_status(self) -> BootstrapStatusResponse:
        """Get mock vLEI bootstrap status from the agent."""
        resp = await self._get("/bootstrap/status")
        return BootstrapStatusResponse.model_validate(resp.json())

    async def initialize_mock_vlei(self) -> BootstrapStatusResponse:
        """Initialize mock vLEI infrastructure on the agent."""
        resp = await self._post("/bootstrap/mock-vlei")
        return BootstrapStatusResponse.model_validate(resp.json())

    async def reinitialize_mock_vlei(self) -> BootstrapStatusResponse:
        """Reinitialize mock vLEI infrastructure (fresh identities)."""
        resp = await self._post("/bootstrap/reinitialize")
        return BootstrapStatusResponse.model_validate(resp.json())

    # =========================================================================
    # Operational
    # =========================================================================

    async def health(self) -> AgentHealthResponse:
        """Check KERI Agent health."""
        resp = await self._get("/healthz")
        return AgentHealthResponse.model_validate(resp.json())

    async def stats(self) -> AgentStatsResponse:
        """Get KERI Agent statistics."""
        resp = await self._get("/stats")
        return AgentStatsResponse.model_validate(resp.json())

    async def is_healthy(self) -> bool:
        """Quick health check — returns True if agent is reachable and healthy."""
        try:
            health = await self.health()
            return health.status == "ok"
        except (KeriAgentUnavailableError, HTTPException, Exception):
            return False
