"""Tests for KERI Agent VVP attestation creation endpoint.

Sprint 68: KERI Agent Service Extraction.
"""
import importlib
import os
import tempfile
import uuid

import pytest
from httpx import AsyncClient, ASGITransport

from app.keri.identity import reset_identity_manager, close_identity_manager
from app.keri.registry import reset_registry_manager, close_registry_manager
from app.keri.issuer import reset_credential_issuer, close_credential_issuer
from app.keri.persistence import reset_persistence_manager
from app.keri.witness import reset_witness_publisher
from app.dossier.builder import reset_dossier_builder
from app.mock_vlei import reset_mock_vlei_manager


TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


def unique_name(prefix: str = "test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _reset_all():
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_dossier_builder()
    reset_mock_vlei_manager()


@pytest.fixture
async def vvp_client():
    """Create test client with mock vLEI enabled for VVP attestation tests.

    The VVP create endpoint needs:
    1. A signing identity
    2. A dossier (requires a credential)
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")
        original_auth_token = os.environ.get("VVP_KERI_AGENT_AUTH_TOKEN")
        original_mock_vlei = os.environ.get("VVP_MOCK_VLEI_ENABLED")

        os.environ["VVP_KERI_AGENT_DATA_DIR"] = tmpdir
        os.environ["VVP_KERI_AGENT_AUTH_TOKEN"] = ""
        os.environ["VVP_MOCK_VLEI_ENABLED"] = "false"

        _reset_all()

        import app.config as config_module
        importlib.reload(config_module)
        import app.main as main_module
        importlib.reload(main_module)

        async with AsyncClient(
            transport=ASGITransport(app=main_module.app),
            base_url="http://test",
        ) as async_client:
            yield async_client

        await close_credential_issuer()
        await close_registry_manager()
        await close_identity_manager()

        _reset_all()

        if original_data_dir is not None:
            os.environ["VVP_KERI_AGENT_DATA_DIR"] = original_data_dir
        elif "VVP_KERI_AGENT_DATA_DIR" in os.environ:
            del os.environ["VVP_KERI_AGENT_DATA_DIR"]
        if original_auth_token is not None:
            os.environ["VVP_KERI_AGENT_AUTH_TOKEN"] = original_auth_token
        elif "VVP_KERI_AGENT_AUTH_TOKEN" in os.environ:
            del os.environ["VVP_KERI_AGENT_AUTH_TOKEN"]
        if original_mock_vlei is not None:
            os.environ["VVP_MOCK_VLEI_ENABLED"] = original_mock_vlei
        elif "VVP_MOCK_VLEI_ENABLED" in os.environ:
            del os.environ["VVP_MOCK_VLEI_ENABLED"]

        importlib.reload(config_module)


# =============================================================================
# VVP Attestation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_vvp_create_identity_not_found(vvp_client: AsyncClient):
    """Test 404 when signing identity doesn't exist."""
    response = await vvp_client.post(
        "/vvp/create",
        json={
            "identity_name": "nonexistent-identity",
            "dossier_said": "Etest1234567890123456789012345678901234567",
            "orig_tn": "+12025551234",
            "dest_tn": "+12025555678",
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_vvp_create_success(vvp_client: AsyncClient):
    """Test successful VVP attestation creation.

    Creates identity, registry, credential, dossier, then attestation.
    """
    # 1. Create signing identity
    name = unique_name("vvp-signer")
    id_response = await vvp_client.post(
        "/identities",
        json={"name": name},
    )
    assert id_response.status_code == 201

    # 2. Create registry
    reg_name = unique_name("vvp-registry")
    reg_response = await vvp_client.post(
        "/registries",
        json={"name": reg_name, "identity_name": name},
    )
    assert reg_response.status_code == 201

    # 3. Issue credential
    cred_response = await vvp_client.post(
        "/credentials/issue",
        json={
            "identity_name": name,
            "registry_name": reg_name,
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert cred_response.status_code == 201
    cred_said = cred_response.json()["said"]

    # 4. Build dossier
    dossier_response = await vvp_client.post(
        "/dossiers/build",
        json={"root_said": cred_said},
    )
    assert dossier_response.status_code == 201

    # 5. Create VVP attestation
    response = await vvp_client.post(
        "/vvp/create",
        json={
            "identity_name": name,
            "dossier_said": cred_said,
            "orig_tn": "+12025551234",
            "dest_tn": "+12025555678",
            "exp_seconds": 60,
        },
    )
    assert response.status_code == 200, f"VVP create failed: {response.text}"
    data = response.json()

    assert "vvp_identity_header" in data
    assert "passport_jwt" in data
    assert "identity_header" in data
    assert "dossier_url" in data
    assert "kid_oobi" in data
    assert data["iat"] > 0
    assert data["exp"] > data["iat"]
    assert data["exp"] - data["iat"] <= 300  # Max 300s


@pytest.mark.asyncio
async def test_vvp_create_exp_clamped_to_300(vvp_client: AsyncClient):
    """Test that exp_seconds is clamped to max 300."""
    name = unique_name("vvp-clamp")
    await vvp_client.post("/identities", json={"name": name})

    reg_name = unique_name("vvp-reg")
    await vvp_client.post(
        "/registries",
        json={"name": reg_name, "identity_name": name},
    )

    cred_response = await vvp_client.post(
        "/credentials/issue",
        json={
            "identity_name": name,
            "registry_name": reg_name,
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    cred_said = cred_response.json()["said"]

    await vvp_client.post(
        "/dossiers/build",
        json={"root_said": cred_said},
    )

    response = await vvp_client.post(
        "/vvp/create",
        json={
            "identity_name": name,
            "dossier_said": cred_said,
            "orig_tn": "+12025551234",
            "dest_tn": "+12025555678",
            "exp_seconds": 9999,  # Should be clamped to 300
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["exp"] - data["iat"] <= 300
