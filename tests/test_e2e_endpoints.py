"""End-to-end integration tests for /verify and /verify-callee endpoints.

Tests VVP §16.9: End-to-end integration tests covering the full verification flow.
"""

import base64
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pysodium
from fastapi.testclient import TestClient

from app.main import app
from app.vvp.api_models import ClaimStatus, ErrorCode


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


def generate_keypair():
    """Generate a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def encode_keri_key(pk: bytes) -> str:
    """Encode Ed25519 public key in KERI format."""
    return "B" + base64.urlsafe_b64encode(pk).decode().rstrip("=")


def create_test_passport(sk: bytes, kid: str, iat: int = None) -> str:
    """Create a minimal test PASSporT JWT."""
    if iat is None:
        iat = int(datetime.now(timezone.utc).timestamp())

    header = {"alg": "EdDSA", "typ": "passport", "kid": kid}
    payload = {"iat": iat, "orig": {"tn": ["+15551234567"]}, "dest": {"tn": ["+15559876543"]}}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = pysodium.crypto_sign_detached(signing_input, sk)
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def create_test_vvp_identity(sk: bytes, kid: str, iat: int = None) -> str:
    """Create a test VVP-Identity JWT."""
    if iat is None:
        iat = int(datetime.now(timezone.utc).timestamp())

    header = {"alg": "EdDSA", "typ": "vvp-identity", "kid": kid}
    payload = {"iat": iat, "sub": "+15551234567"}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = pysodium.crypto_sign_detached(signing_input, sk)
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def make_call_context(call_id: str = "abc123@sip.example.com") -> dict:
    """Create a valid call context for requests."""
    return {
        "call_id": call_id,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }


def make_call_context_with_sip(
    call_id: str = "abc123@sip.example.com",
    cseq: int = 1,
) -> dict:
    """Create a call context with SIP fields for callee verification."""
    return {
        "call_id": call_id,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "sip": {
            "from_uri": "sip:+15551234567@example.com",
            "to_uri": "sip:+15559876543@example.com",
            "invite_time": datetime.now(timezone.utc).isoformat(),
            "cseq": cseq,
        },
    }


@pytest.mark.e2e
class TestHealthEndpoints:
    """E2E tests for health and version endpoints."""

    def test_healthz_endpoint(self, client):
        """Health check endpoint returns 200."""
        response = client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True

    def test_version_endpoint(self, client):
        """Version endpoint returns version info."""
        response = client.get("/version")
        assert response.status_code == 200
        data = response.json()
        assert "git_sha" in data


@pytest.mark.e2e
class TestVerifyEndpointE2E:
    """E2E tests for /verify endpoint."""

    def test_missing_passport_returns_error(self, client):
        """Missing passport_jwt returns 422 (validation error)."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={"context": make_call_context()},  # Missing passport_jwt
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 422  # Pydantic validation error

    def test_missing_context_returns_error(self, client):
        """Missing context returns 422 (validation error)."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={"passport_jwt": passport},  # Missing context
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 422  # Pydantic validation error

    def test_malformed_passport_returns_invalid(self, client):
        """Malformed PASSporT returns INVALID status."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": "not_a_valid_jwt",
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["overall_status"] == ClaimStatus.INVALID.value

    def test_forbidden_algorithm_returns_invalid(self, client):
        """PASSporT with forbidden algorithm returns INVALID."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        # Create PASSporT with RS256 (forbidden)
        header = {"alg": "RS256", "typ": "passport", "kid": kid}
        payload = {"iat": int(datetime.now(timezone.utc).timestamp()), "orig": {"tn": ["+15551234567"]}, "dest": {"tn": ["+15559876543"]}}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")

        passport = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Create valid VVP-Identity with EdDSA
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["overall_status"] == ClaimStatus.INVALID.value

    def test_response_structure_matches_spec(self, client):
        """Response structure matches spec §4.2A."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()

        # Response must have overall_status and request_id per spec
        assert "overall_status" in data
        assert data["overall_status"] in [s.value for s in ClaimStatus]
        assert "request_id" in data

    def test_valid_tokens_processed(self, client):
        """Valid tokens are processed and return a response."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        iat = int(datetime.now(timezone.utc).timestamp())
        passport = create_test_passport(sk, kid, iat)
        vvp_identity = create_test_vvp_identity(sk, kid, iat)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()

        # Should have processed and returned a status (may be INDETERMINATE
        # due to OOBI resolution failure without mocking)
        assert data["overall_status"] in [s.value for s in ClaimStatus]


@pytest.mark.e2e
class TestVerifyCalleeEndpointE2E:
    """E2E tests for /verify-callee endpoint."""

    def test_missing_call_id_returns_error(self, client):
        """Missing call_id in context returns 400."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": {
                    "call_id": "",  # Empty call_id
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "sip": {
                        "from_uri": "sip:+15551234567@example.com",
                        "to_uri": "sip:+15559876543@example.com",
                        "invite_time": datetime.now(timezone.utc).isoformat(),
                        "cseq": 1,
                    },
                },
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 400

    def test_missing_sip_context_returns_error(self, client):
        """Missing SIP context returns 400."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": {
                    "call_id": "abc123@sip.example.com",
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    # Missing sip context
                },
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 400

    def test_missing_cseq_returns_error(self, client):
        """Missing cseq in SIP context returns 400."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": {
                    "call_id": "abc123@sip.example.com",
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "sip": {
                        "from_uri": "sip:+15551234567@example.com",
                        "to_uri": "sip:+15559876543@example.com",
                        "invite_time": datetime.now(timezone.utc).isoformat(),
                        # Missing cseq
                    },
                },
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 400

    def test_missing_vvp_identity_returns_error(self, client):
        """Missing VVP-Identity header returns 400."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": make_call_context_with_sip(),
            },
            # No VVP-Identity header
        )
        assert response.status_code == 400

    def test_valid_request_returns_response(self, client):
        """Valid request returns response with status."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": make_call_context_with_sip(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()
        assert "overall_status" in data

    def test_response_structure_matches_spec(self, client):
        """Response structure matches spec §4.3."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify-callee",
            json={
                "passport_jwt": passport,
                "context": make_call_context_with_sip(),
            },
            headers={"VVP-Identity": vvp_identity},
        )

        assert response.status_code == 200
        data = response.json()

        # Response must have overall_status field
        assert "overall_status" in data
        assert data["overall_status"] in [s.value for s in ClaimStatus]


@pytest.mark.e2e
class TestErrorCodeCoverage:
    """Verify error codes from spec §4.2A are testable."""

    def test_algorithm_forbidden_error(self, client):
        """Forbidden algorithm produces correct error."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        # Create PASSporT with HS256 (forbidden HMAC)
        header = {"alg": "HS256", "typ": "passport", "kid": kid}
        payload = {"iat": int(datetime.now(timezone.utc).timestamp()), "orig": {"tn": ["+15551234567"]}, "dest": {"tn": ["+15559876543"]}}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"fake_hmac_signature").decode().rstrip("=")

        passport = f"{header_b64}.{payload_b64}.{sig_b64}"
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["overall_status"] == ClaimStatus.INVALID.value

    def test_missing_iat_error(self, client):
        """Missing iat produces error."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        # PASSporT without iat
        header = {"alg": "EdDSA", "typ": "passport", "kid": kid}
        payload = {"orig": {"tn": ["+15551234567"]}, "dest": {"tn": ["+15559876543"]}}  # No iat

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = pysodium.crypto_sign_detached(signing_input, sk)
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        passport = f"{header_b64}.{payload_b64}.{sig_b64}"

        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={"VVP-Identity": vvp_identity},
        )
        assert response.status_code == 200
        data = response.json()
        # Missing iat should produce INVALID
        assert data["overall_status"] == ClaimStatus.INVALID.value


@pytest.mark.e2e
class TestAdminEndpoint:
    """E2E tests for admin endpoints."""

    def test_admin_config_returns_categories(self, client):
        """Admin endpoint returns configuration categories."""
        response = client.get("/admin")
        # Admin may be disabled in production
        if response.status_code == 404:
            pytest.skip("Admin endpoint disabled")

        assert response.status_code == 200
        data = response.json()

        # Should have config categories
        assert "normative" in data or "config" in data


@pytest.mark.e2e
class TestContentTypeHandling:
    """E2E tests for content type handling."""

    def test_json_content_type_accepted(self, client):
        """JSON content type is accepted."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)
        passport = create_test_passport(sk, kid)
        vvp_identity = create_test_vvp_identity(sk, kid)

        response = client.post(
            "/verify",
            json={
                "passport_jwt": passport,
                "context": make_call_context(),
            },
            headers={
                "Content-Type": "application/json",
                "VVP-Identity": vvp_identity,
            },
        )
        assert response.status_code == 200
