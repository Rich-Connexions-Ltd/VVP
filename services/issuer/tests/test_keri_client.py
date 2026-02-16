"""Tests for the KERI Agent HTTP client.

Tests circuit breaker, retry logic, error mapping, and all client methods
using a mock HTTP transport (no real KERI Agent needed).

Sprint 68: KERI Agent Service Extraction.
"""
import asyncio
import json
import time

import httpx
import pytest
from fastapi import HTTPException

from app.keri_client import (
    CircuitBreaker,
    KeriAgentClient,
    KeriAgentUnavailableError,
    get_keri_client,
    reset_keri_client,
)
from common.vvp.models.keri_agent import (
    BuildDossierRequest,
    CreateIdentityRequest,
    CreateRegistryRequest,
    CreateVVPAttestationRequest,
    IssueCredentialRequest,
    RotateKeysRequest,
)


# =============================================================================
# Mock transport for httpx
# =============================================================================


class MockTransport(httpx.AsyncBaseTransport):
    """Mock HTTP transport that returns canned responses."""

    def __init__(self):
        self.responses: list[httpx.Response] = []
        self.requests: list[httpx.Request] = []
        self._call_count = 0

    def add_response(
        self,
        status_code: int = 200,
        json_data: dict | list | None = None,
        content: bytes = b"",
        headers: dict | None = None,
    ):
        """Queue a response to be returned by the next request."""
        if json_data is not None:
            content = json.dumps(json_data).encode()
            headers = headers or {}
            headers["content-type"] = "application/json"
        self.responses.append(
            httpx.Response(
                status_code=status_code,
                content=content,
                headers=headers or {},
            )
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._call_count < len(self.responses):
            resp = self.responses[self._call_count]
            self._call_count += 1
            return resp
        return httpx.Response(500, content=b'{"detail": "No mock response queued"}')


class TimeoutTransport(httpx.AsyncBaseTransport):
    """Transport that always times out."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Mock timeout")


class ConnectErrorTransport(httpx.AsyncBaseTransport):
    """Transport that always fails to connect."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")


# =============================================================================
# Fixtures
# =============================================================================

SAMPLE_IDENTITY = {
    "aid": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "name": "test-id",
    "created_at": "2025-01-01T00:00:00Z",
    "witness_count": 3,
    "key_count": 1,
    "sequence_number": 0,
    "transferable": True,
}

SAMPLE_REGISTRY = {
    "registry_key": "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs",
    "name": "test-registry",
    "identity_aid": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "identity_name": "test-id",
    "credential_count": 0,
}

SAMPLE_CREDENTIAL = {
    "said": "EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A",
    "issuer_aid": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "recipient_aid": None,
    "registry_key": "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs",
    "schema_said": "EKE3i2pNFsH5mGbej7xEMVO9wJdWPyl6o3FUQP2mRNJv",
    "issuance_dt": "2025-01-01T00:00:00Z",
    "status": "issued",
    "revocation_dt": None,
    "attributes": {"i": "test", "LEI": "1234"},
    "edges": None,
    "rules": None,
}

SAMPLE_DOSSIER = {
    "root_said": "EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A",
    "root_saids": ["EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A"],
    "credential_saids": ["EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A"],
    "is_aggregate": False,
    "warnings": [],
}

SAMPLE_VVP_ATTESTATION = {
    "vvp_identity_header": "eyJ0ZXN0IjogdHJ1ZX0",
    "passport_jwt": "eyJhbGciOiJFZERTQSJ9.test.sig",
    "identity_header": 'info:<sip:+15551001@example.com>;alg=ES256',
    "dossier_url": "https://issuer.example.com/dossiers/test/cesr",
    "kid_oobi": "http://witness.example.com/oobi/EBfd",
    "iat": 1700000000,
    "exp": 1700000300,
}

SAMPLE_BOOTSTRAP_STATUS = {
    "initialized": True,
    "gleif_aid": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "gleif_registry_key": "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs",
    "qvi_aid": "EKE3i2pNFsH5mGbej7xEMVO9wJdWPyl6o3FUQP2mRNJv",
    "qvi_registry_key": "EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A",
    "gsma_aid": None,
    "gsma_registry_key": None,
    "gleif_name": "mock-gleif",
    "qvi_name": "mock-qvi",
    "gsma_name": None,
}

SAMPLE_HEALTH = {
    "status": "ok",
    "identity_count": 2,
    "registry_count": 1,
    "credential_count": 5,
    "lmdb_accessible": True,
}

SAMPLE_STATS = {
    "identity_count": 2,
    "registry_count": 1,
    "credential_count": 5,
}


def _make_client(transport: httpx.AsyncBaseTransport) -> KeriAgentClient:
    """Create a client with a mock transport."""
    client = KeriAgentClient(
        base_url="http://test-agent:8002",
        auth_token="test-token",
    )
    # Replace the HTTP client with one using our mock transport
    client._http = httpx.AsyncClient(
        transport=transport,
        base_url="http://test-agent:8002",
        headers={"Authorization": "Bearer test-token"},
    )
    return client


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


class TestCircuitBreaker:
    """Test circuit breaker state transitions."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "closed"

    def test_success_keeps_closed(self):
        cb = CircuitBreaker()
        cb.record_success()
        assert cb.state == "closed"

    def test_failures_below_threshold_stay_closed(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"

    def test_failures_at_threshold_opens_circuit(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(5):
            cb.record_failure()
        assert cb.state == "open"

    def test_open_circuit_blocks_requests(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=30.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        assert cb.allow_request() is False

    def test_open_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.02)
        assert cb.state == "half_open"

    def test_half_open_allows_one_probe(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.allow_request() is True
        assert cb.allow_request() is False  # second request blocked

    def test_half_open_success_closes_circuit(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.record_success()
        assert cb.state == "closed"

    def test_half_open_failure_reopens_circuit(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == "half_open"
        cb.record_failure()
        assert cb.state == "open"

    def test_old_failures_outside_window_dont_count(self):
        cb = CircuitBreaker(failure_threshold=3, failure_window=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)  # failures expire
        cb.record_failure()
        assert cb.state == "closed"  # only 1 recent failure

    def test_closed_allows_requests(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True


# =============================================================================
# Client Error Mapping Tests
# =============================================================================


class TestErrorMapping:
    """Test that agent error responses map to correct issuer exceptions."""

    @pytest.mark.asyncio
    async def test_agent_400_maps_to_http_400(self):
        transport = MockTransport()
        transport.add_response(400, {"detail": "Bad request data"})
        client = _make_client(transport)

        with pytest.raises(HTTPException) as exc_info:
            await client._get("/test")
        assert exc_info.value.status_code == 400
        assert "Bad request" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_agent_404_maps_to_http_404(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Not found"})
        client = _make_client(transport)

        with pytest.raises(HTTPException) as exc_info:
            await client._get("/test")
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_agent_409_maps_to_http_409(self):
        transport = MockTransport()
        transport.add_response(409, {"detail": "Duplicate name"})
        client = _make_client(transport)

        with pytest.raises(HTTPException) as exc_info:
            await client._get("/test")
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_agent_500_raises_unavailable(self):
        transport = MockTransport()
        transport.add_response(500, {"detail": "Internal error"})
        client = _make_client(transport)

        with pytest.raises(KeriAgentUnavailableError):
            await client._get("/test")

    @pytest.mark.asyncio
    async def test_timeout_raises_unavailable(self):
        client = _make_client(TimeoutTransport())
        with pytest.raises(KeriAgentUnavailableError) as exc_info:
            await client._get("/test")
        assert "timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_error_raises_unavailable(self):
        client = _make_client(ConnectErrorTransport())
        with pytest.raises(KeriAgentUnavailableError) as exc_info:
            await client._get("/test")
        assert "connection failed" in str(exc_info.value).lower()


# =============================================================================
# Retry Tests
# =============================================================================


class TestRetry:
    """Test retry logic for GET requests."""

    @pytest.mark.asyncio
    async def test_get_retries_on_500(self):
        transport = MockTransport()
        transport.add_response(500, {"detail": "Error"})
        transport.add_response(500, {"detail": "Error"})
        transport.add_response(200, {"status": "ok"})
        client = _make_client(transport)

        # GET retries, so this should succeed after 2 failures
        resp = await client._request("GET", "/test", retry=True)
        assert resp.status_code == 200
        assert len(transport.requests) == 3

    @pytest.mark.asyncio
    async def test_get_exhausts_retries(self):
        transport = MockTransport()
        for _ in range(3):
            transport.add_response(500, {"detail": "Error"})
        client = _make_client(transport)

        with pytest.raises(KeriAgentUnavailableError):
            await client._request("GET", "/test", retry=True)
        assert len(transport.requests) == 3

    @pytest.mark.asyncio
    async def test_post_does_not_retry(self):
        transport = MockTransport()
        transport.add_response(500, {"detail": "Error"})
        client = _make_client(transport)

        with pytest.raises(KeriAgentUnavailableError):
            await client._request("POST", "/test")
        assert len(transport.requests) == 1


# =============================================================================
# Idempotency Key Tests
# =============================================================================


class TestIdempotencyKey:
    """Test that mutating calls include Idempotency-Key header."""

    @pytest.mark.asyncio
    async def test_post_sends_idempotency_key(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_IDENTITY)
        client = _make_client(transport)

        await client._post("/identities", json={"name": "test"})

        request = transport.requests[0]
        assert b"idempotency-key" in request.headers.raw[2][0] or \
            "Idempotency-Key" in dict(request.headers) or \
            any(k.lower() == "idempotency-key" for k in request.headers.keys())

    @pytest.mark.asyncio
    async def test_post_with_custom_idempotency_key(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_IDENTITY)
        client = _make_client(transport)

        await client._post(
            "/identities",
            json={"name": "test"},
            idempotency_key="custom-key-123",
        )

        request = transport.requests[0]
        key_value = request.headers.get("idempotency-key")
        assert key_value == "custom-key-123"


# =============================================================================
# Circuit Breaker Integration Tests
# =============================================================================


class TestCircuitBreakerIntegration:
    """Test circuit breaker behavior with the HTTP client."""

    @pytest.mark.asyncio
    async def test_circuit_opens_after_consecutive_failures(self):
        transport = MockTransport()
        for _ in range(5):
            transport.add_response(500, {"detail": "Error"})
        client = _make_client(transport)
        client._circuit = CircuitBreaker(failure_threshold=5, failure_window=60.0)

        # Trigger 5 failures
        for _ in range(5):
            with pytest.raises(KeriAgentUnavailableError):
                await client._request("POST", "/test")

        assert client.circuit_state == "open"

        # Next request should fail immediately without calling transport
        with pytest.raises(KeriAgentUnavailableError) as exc_info:
            await client._request("POST", "/test")
        assert "circuit breaker is open" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_success_resets_circuit(self):
        transport = MockTransport()
        # 4 failures then a success
        for _ in range(4):
            transport.add_response(500, {"detail": "Error"})
        transport.add_response(200, {"status": "ok"})
        client = _make_client(transport)
        client._circuit = CircuitBreaker(failure_threshold=5)

        for _ in range(4):
            with pytest.raises(KeriAgentUnavailableError):
                await client._request("POST", "/test")

        assert client.circuit_state == "closed"  # still below threshold
        resp = await client._request("GET", "/test", retry=False)
        assert resp.status_code == 200
        assert client.circuit_state == "closed"


# =============================================================================
# Identity Method Tests
# =============================================================================


class TestIdentityMethods:

    @pytest.mark.asyncio
    async def test_create_identity(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_IDENTITY)
        client = _make_client(transport)

        result = await client.create_identity(
            CreateIdentityRequest(name="test-id")
        )
        assert result.aid == SAMPLE_IDENTITY["aid"]
        assert result.name == "test-id"

    @pytest.mark.asyncio
    async def test_list_identities(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_IDENTITY])
        client = _make_client(transport)

        result = await client.list_identities()
        assert len(result) == 1
        assert result[0].name == "test-id"

    @pytest.mark.asyncio
    async def test_get_identity_found(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_IDENTITY)
        client = _make_client(transport)

        result = await client.get_identity("test-id")
        assert result is not None
        assert result.name == "test-id"

    @pytest.mark.asyncio
    async def test_get_identity_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Not found"})
        client = _make_client(transport)

        result = await client.get_identity("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_rotate_keys(self):
        transport = MockTransport()
        transport.add_response(200, {
            "aid": SAMPLE_IDENTITY["aid"],
            "name": "test-id",
            "previous_sequence_number": 0,
            "new_sequence_number": 1,
            "new_key_count": 1,
        })
        client = _make_client(transport)

        result = await client.rotate_keys("test-id", RotateKeysRequest())
        assert result.new_sequence_number == 1

    @pytest.mark.asyncio
    async def test_get_oobi(self):
        transport = MockTransport()
        transport.add_response(200, {"oobi": "http://witness/oobi/EBfd"})
        client = _make_client(transport)

        result = await client.get_oobi("test-id")
        assert result == "http://witness/oobi/EBfd"

    @pytest.mark.asyncio
    async def test_publish_identity(self):
        transport = MockTransport()
        transport.add_response(200, {"published": True})
        client = _make_client(transport)

        await client.publish_identity("test-id")
        assert len(transport.requests) == 1
        assert transport.requests[0].method == "POST"

    @pytest.mark.asyncio
    async def test_get_identity_by_aid_found(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_IDENTITY])
        client = _make_client(transport)

        result = await client.get_identity_by_aid(SAMPLE_IDENTITY["aid"])
        assert result is not None
        assert result.aid == SAMPLE_IDENTITY["aid"]
        assert b"aid=" in transport.requests[0].url.raw_path

    @pytest.mark.asyncio
    async def test_get_identity_by_aid_not_found(self):
        transport = MockTransport()
        transport.add_response(200, [])
        client = _make_client(transport)

        result = await client.get_identity_by_aid("ENotARealAID")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_identity(self):
        transport = MockTransport()
        transport.add_response(204)
        client = _make_client(transport)

        await client.delete_identity("test-id")
        assert len(transport.requests) == 1
        assert transport.requests[0].method == "DELETE"
        assert b"/identities/test-id" in transport.requests[0].url.raw_path

    @pytest.mark.asyncio
    async def test_delete_identity_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Identity not found: nonexistent"})
        client = _make_client(transport)

        with pytest.raises(HTTPException) as exc_info:
            await client.delete_identity("nonexistent")
        assert exc_info.value.status_code == 404


# =============================================================================
# Registry Method Tests
# =============================================================================


class TestRegistryMethods:

    @pytest.mark.asyncio
    async def test_create_registry(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_REGISTRY)
        client = _make_client(transport)

        result = await client.create_registry(
            CreateRegistryRequest(name="test-registry", identity_name="test-id")
        )
        assert result.registry_key == SAMPLE_REGISTRY["registry_key"]

    @pytest.mark.asyncio
    async def test_list_registries(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_REGISTRY])
        client = _make_client(transport)

        result = await client.list_registries()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_registry_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Not found"})
        client = _make_client(transport)

        result = await client.get_registry("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_registry_by_key_found(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_REGISTRY])
        client = _make_client(transport)

        result = await client.get_registry_by_key(SAMPLE_REGISTRY["registry_key"])
        assert result is not None
        assert result.registry_key == SAMPLE_REGISTRY["registry_key"]
        assert b"registry_key=" in transport.requests[0].url.raw_path

    @pytest.mark.asyncio
    async def test_get_registry_by_key_not_found(self):
        transport = MockTransport()
        transport.add_response(200, [])
        client = _make_client(transport)

        result = await client.get_registry_by_key("ENotARealKey")
        assert result is None


# =============================================================================
# Credential Method Tests
# =============================================================================


class TestCredentialMethods:

    @pytest.mark.asyncio
    async def test_issue_credential(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_CREDENTIAL)
        client = _make_client(transport)

        result = await client.issue_credential(IssueCredentialRequest(
            identity_name="test-id",
            registry_name="test-registry",
            schema_said="EKE3i2pNFsH5mGbej7xEMVO9wJdWPyl6o3FUQP2mRNJv",
            attributes={"i": "test", "LEI": "1234"},
        ))
        assert result.said == SAMPLE_CREDENTIAL["said"]

    @pytest.mark.asyncio
    async def test_revoke_credential(self):
        transport = MockTransport()
        revoked = {**SAMPLE_CREDENTIAL, "status": "revoked", "revocation_dt": "2025-01-02T00:00:00Z"}
        transport.add_response(200, revoked)
        client = _make_client(transport)

        result = await client.revoke_credential(SAMPLE_CREDENTIAL["said"])
        assert result.status == "revoked"

    @pytest.mark.asyncio
    async def test_list_credentials(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_CREDENTIAL])
        client = _make_client(transport)

        result = await client.list_credentials()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_credentials_with_filters(self):
        transport = MockTransport()
        transport.add_response(200, [SAMPLE_CREDENTIAL])
        client = _make_client(transport)

        await client.list_credentials(registry_key="EFgnk", status="issued")
        request = transport.requests[0]
        assert b"registry_key=EFgnk" in request.url.raw_path
        assert b"status=issued" in request.url.raw_path

    @pytest.mark.asyncio
    async def test_get_credential_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Not found"})
        client = _make_client(transport)

        result = await client.get_credential("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_credential_cesr(self):
        transport = MockTransport()
        cesr_bytes = b"\x00\x01\x02CESR-data"
        transport.add_response(200, content=cesr_bytes)
        client = _make_client(transport)

        result = await client.get_credential_cesr(SAMPLE_CREDENTIAL["said"])
        assert result == cesr_bytes

    @pytest.mark.asyncio
    async def test_delete_credential(self):
        transport = MockTransport()
        transport.add_response(204)
        client = _make_client(transport)

        await client.delete_credential(SAMPLE_CREDENTIAL["said"])
        assert len(transport.requests) == 1
        assert transport.requests[0].method == "DELETE"

    @pytest.mark.asyncio
    async def test_delete_credential_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Credential not found"})
        client = _make_client(transport)

        with pytest.raises(HTTPException) as exc_info:
            await client.delete_credential("Enonexistent")
        assert exc_info.value.status_code == 404


# =============================================================================
# Dossier Method Tests
# =============================================================================


class TestDossierMethods:

    @pytest.mark.asyncio
    async def test_build_dossier(self):
        transport = MockTransport()
        transport.add_response(201, SAMPLE_DOSSIER)
        client = _make_client(transport)

        result = await client.build_dossier(
            BuildDossierRequest(root_said="EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A")
        )
        assert result.root_said == SAMPLE_DOSSIER["root_said"]
        assert len(result.credential_saids) == 1

    @pytest.mark.asyncio
    async def test_get_dossier_not_found(self):
        transport = MockTransport()
        transport.add_response(404, {"detail": "Not found"})
        client = _make_client(transport)

        result = await client.get_dossier("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_dossier_cesr(self):
        transport = MockTransport()
        cesr_data = b"CESR-dossier-stream"
        transport.add_response(200, content=cesr_data)
        client = _make_client(transport)

        result = await client.get_dossier_cesr("EHyKQS68x")
        assert result == cesr_data


# =============================================================================
# VVP Method Tests
# =============================================================================


class TestVVPMethods:

    @pytest.mark.asyncio
    async def test_create_vvp_attestation(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_VVP_ATTESTATION)
        client = _make_client(transport)

        result = await client.create_vvp_attestation(
            CreateVVPAttestationRequest(
                identity_name="test-id",
                dossier_said="EHyKQS68x",
                orig_tn="+15551001",
                dest_tn=["+15551006"],
            )
        )
        assert result.passport_jwt == SAMPLE_VVP_ATTESTATION["passport_jwt"]
        assert result.iat == 1700000000


# =============================================================================
# Bootstrap Method Tests
# =============================================================================


class TestBootstrapMethods:

    @pytest.mark.asyncio
    async def test_get_bootstrap_status(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_BOOTSTRAP_STATUS)
        client = _make_client(transport)

        result = await client.get_bootstrap_status()
        assert result.initialized is True
        assert result.gleif_aid is not None

    @pytest.mark.asyncio
    async def test_initialize_mock_vlei(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_BOOTSTRAP_STATUS)
        client = _make_client(transport)

        result = await client.initialize_mock_vlei()
        assert result.initialized is True
        # Verify it was a POST
        assert transport.requests[0].method == "POST"


# =============================================================================
# Operational Method Tests
# =============================================================================


class TestOperationalMethods:

    @pytest.mark.asyncio
    async def test_health(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_HEALTH)
        client = _make_client(transport)

        result = await client.health()
        assert result.status == "ok"
        assert result.identity_count == 2

    @pytest.mark.asyncio
    async def test_stats(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_STATS)
        client = _make_client(transport)

        result = await client.stats()
        assert result.identity_count == 2
        assert result.credential_count == 5

    @pytest.mark.asyncio
    async def test_is_healthy_true(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_HEALTH)
        client = _make_client(transport)

        assert await client.is_healthy() is True

    @pytest.mark.asyncio
    async def test_is_healthy_false_on_error(self):
        client = _make_client(ConnectErrorTransport())
        assert await client.is_healthy() is False

    @pytest.mark.asyncio
    async def test_is_healthy_false_on_unhealthy(self):
        transport = MockTransport()
        transport.add_response(200, {**SAMPLE_HEALTH, "status": "unhealthy"})
        client = _make_client(transport)

        assert await client.is_healthy() is False


# =============================================================================
# Singleton Tests
# =============================================================================


class TestSingleton:

    def test_reset_clears_singleton(self):
        reset_keri_client()
        # After reset, get_keri_client creates a new instance
        client = get_keri_client()
        assert client is not None
        reset_keri_client()

    def test_get_returns_same_instance(self):
        reset_keri_client()
        c1 = get_keri_client()
        c2 = get_keri_client()
        assert c1 is c2
        reset_keri_client()


# =============================================================================
# Auth Header Tests
# =============================================================================


class TestAuthHeaders:

    @pytest.mark.asyncio
    async def test_bearer_token_sent_in_header(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_HEALTH)
        client = _make_client(transport)

        await client.health()
        request = transport.requests[0]
        assert request.headers.get("authorization") == "Bearer test-token"

    @pytest.mark.asyncio
    async def test_no_auth_header_when_token_empty(self):
        transport = MockTransport()
        transport.add_response(200, SAMPLE_HEALTH)
        client = KeriAgentClient(base_url="http://test:8002", auth_token="")
        client._http = httpx.AsyncClient(
            transport=transport,
            base_url="http://test:8002",
        )

        await client.health()
        request = transport.requests[0]
        assert "authorization" not in request.headers
