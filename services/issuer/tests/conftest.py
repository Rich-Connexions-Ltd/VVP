"""Pytest fixtures for VVP Issuer tests."""
import asyncio
import importlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import bcrypt
import pytest
from httpx import AsyncClient, ASGITransport

from app.auth.api_key import reset_api_key_store
from app.auth.session import reset_session_store, reset_rate_limiter
from app.auth.users import reset_user_store
from app.audit.logger import reset_audit_logger
from app.dossier.builder import reset_dossier_builder
import app.keri_client as keri_client_module
from app.keri_client import reset_keri_client
from app.org.trust_anchors import reset_trust_anchor_manager
from common.vvp.models.keri_agent import (
    AgentHealthResponse,
    BootstrapStatusResponse,
    CredentialResponse,
    DossierResponse,
    IdentityResponse,
    RegistryResponse,
    RotationResponse,
    VVPAttestationResponse,
)


# =============================================================================
# Test API Keys (pre-generated for consistent testing)
# =============================================================================

# Raw keys for use in test headers
TEST_ADMIN_KEY = "test-admin-key-12345"
TEST_OPERATOR_KEY = "test-operator-key-12345"
TEST_READONLY_KEY = "test-readonly-key-12345"
TEST_REVOKED_KEY = "test-revoked-key-12345"

# Pre-computed bcrypt hashes (cost factor 4 for fast tests)
TEST_ADMIN_HASH = bcrypt.hashpw(TEST_ADMIN_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_OPERATOR_HASH = bcrypt.hashpw(TEST_OPERATOR_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_READONLY_HASH = bcrypt.hashpw(TEST_READONLY_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_REVOKED_HASH = bcrypt.hashpw(TEST_REVOKED_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()


def get_test_api_keys_config() -> dict:
    """Get test API keys configuration."""
    return {
        "keys": [
            {
                "id": "test-admin",
                "name": "Test Admin",
                "hash": TEST_ADMIN_HASH,
                "roles": ["issuer:admin", "issuer:operator", "issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-operator",
                "name": "Test Operator",
                "hash": TEST_OPERATOR_HASH,
                "roles": ["issuer:operator", "issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-readonly",
                "name": "Test Readonly",
                "hash": TEST_READONLY_HASH,
                "roles": ["issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-revoked",
                "name": "Test Revoked",
                "hash": TEST_REVOKED_HASH,
                "roles": ["issuer:admin"],
                "revoked": True,
            },
        ],
        "version": 1,
    }


# =============================================================================
# Mock KERI Agent Client (Sprint 68b)
# =============================================================================

# Default deterministic response data for MockKeriAgentClient
_DEFAULT_AID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
_DEFAULT_REGISTRY_KEY = "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs"
_DEFAULT_QVI_AID = "EKE3i2pNFsH5mGbej7xEMVO9wJdWPyl6o3FUQP2mRNJv"
_DEFAULT_CRED_SAID = "EHyKQS68x_oAx-5j0_RKGS_BSAAGO0-mmhBQeMdh6b0A"


class MockKeriAgentClient:
    """Pre-configured mock KeriAgentClient that returns deterministic responses.

    Sprint 68b: Used by issuer tests after routers are migrated from
    direct app.keri.* imports to keri_client calls. Provides realistic
    mock responses without requiring LMDB or keripy.

    Usage in tests:
        async def test_something(client, mock_keri):
            mock_keri.create_identity.return_value = IdentityResponse(...)
            response = await client.post("/identity", ...)
            assert mock_keri.create_identity.called
    """

    def __init__(self):
        # Identity tracking — stores created identities by name and AID
        self._created_identities: dict[str, IdentityResponse] = {}
        self._identities_by_aid: dict[str, IdentityResponse] = {}

        # create_identity echoes back the requested name and tracks it
        async def _create_identity(req):
            from fastapi import HTTPException
            # Check for duplicate name
            if req.name in self._created_identities:
                raise HTTPException(status_code=400, detail=f"Identity already exists: {req.name}")
            aid = f"E{uuid.uuid4().hex[:47]}"
            transferable = getattr(req, 'transferable', True)
            identity = IdentityResponse(
                aid=aid, name=req.name,
                created_at="2025-01-01T00:00:00Z",
                witness_count=3, key_count=1, sequence_number=0,
                transferable=transferable,
            )
            self._created_identities[req.name] = identity
            self._identities_by_aid[aid] = identity
            return identity
        self.create_identity = AsyncMock(side_effect=_create_identity)

        async def _list_identities():
            return list(self._created_identities.values())
        self.list_identities = AsyncMock(side_effect=_list_identities)

        # get_identity returns tracked identity or None for unknown names
        async def _get_identity(name):
            return self._created_identities.get(name)
        self.get_identity = AsyncMock(side_effect=_get_identity)

        # get_identity_by_aid returns tracked identity or None for unknown AIDs
        async def _get_identity_by_aid(aid):
            return self._identities_by_aid.get(aid)
        self.get_identity_by_aid = AsyncMock(side_effect=_get_identity_by_aid)

        # rotate_keys updates the tracked identity's sequence number
        async def _rotate_keys(name, req):
            identity = self._created_identities.get(name)
            prev_sn = identity.sequence_number if identity else 0
            new_sn = prev_sn + 1
            aid = identity.aid if identity else _DEFAULT_AID
            # Update tracking
            if identity:
                updated = IdentityResponse(
                    aid=identity.aid, name=identity.name,
                    created_at=identity.created_at,
                    witness_count=identity.witness_count,
                    key_count=identity.key_count,
                    sequence_number=new_sn,
                    transferable=identity.transferable,
                )
                self._created_identities[name] = updated
                self._identities_by_aid[identity.aid] = updated
            return RotationResponse(
                aid=aid, name=name,
                previous_sequence_number=prev_sn,
                new_sequence_number=new_sn,
                new_key_count=getattr(req, 'new_key_count', 1) or 1,
            )
        self.rotate_keys = AsyncMock(side_effect=_rotate_keys)

        # get_oobi returns a URL containing the identity's AID
        async def _get_oobi(name):
            identity = self._created_identities.get(name)
            aid = identity.aid if identity else _DEFAULT_AID
            return f"http://witness:5642/oobi/{aid}"
        self.get_oobi = AsyncMock(side_effect=_get_oobi)
        self.get_kel = AsyncMock(return_value=b"KERI-data")
        self.publish_identity = AsyncMock(return_value=None)

        # delete_identity removes from tracking
        async def _delete_identity(name):
            identity = self._created_identities.pop(name, None)
            if identity:
                self._identities_by_aid.pop(identity.aid, None)
        self.delete_identity = AsyncMock(side_effect=_delete_identity)

        # Registry methods — track created registries for get_registry lookups
        self._created_registries: dict[str, RegistryResponse] = {}

        async def _create_registry(req):
            from fastapi import HTTPException
            # Check for duplicate name
            if req.name in self._created_registries:
                raise HTTPException(status_code=400, detail=f"Registry already exists: {req.name}")
            # Resolve identity AID from tracking (falls back to default)
            identity = self._created_identities.get(req.identity_name)
            identity_aid = identity.aid if identity else _DEFAULT_AID
            reg = RegistryResponse(
                registry_key=f"E{uuid.uuid4().hex[:47]}",
                name=req.name,
                identity_aid=identity_aid, identity_name=req.identity_name,
                credential_count=0,
                no_backers=getattr(req, 'no_backers', True),
            )
            self._created_registries[req.name] = reg
            return reg
        self.create_registry = AsyncMock(side_effect=_create_registry)

        async def _list_registries():
            return list(self._created_registries.values())
        self.list_registries = AsyncMock(side_effect=_list_registries)

        # get_registry returns the previously created registry, or None
        async def _get_registry(name):
            return self._created_registries.get(name)
        self.get_registry = AsyncMock(side_effect=_get_registry)

        # get_registry_by_key returns a registry if any created one matches the key
        async def _get_registry_by_key(key):
            for reg in self._created_registries.values():
                if reg.registry_key == key:
                    return reg
            return None
        self.get_registry_by_key = AsyncMock(side_effect=_get_registry_by_key)
        self.get_tel = AsyncMock(return_value=b"TEL-data")

        # delete_registry removes from tracking dict
        async def _delete_registry(name):
            self._created_registries.pop(name, None)
        self.delete_registry = AsyncMock(side_effect=_delete_registry)

        # Credential methods — track issued credentials for lookups
        self._issued_credentials: dict[str, CredentialResponse] = {}

        async def _issue_credential(req):
            unique_said = f"E{uuid.uuid4().hex[:47]}"
            reg = self._created_registries.get(req.registry_name)
            reg_key = reg.registry_key if reg else _DEFAULT_REGISTRY_KEY
            # Resolve issuer AID from registry identity or identity tracking
            issuer_aid = _DEFAULT_AID
            if reg:
                issuer_aid = reg.identity_aid
            elif req.identity_name and req.identity_name in self._created_identities:
                issuer_aid = self._created_identities[req.identity_name].aid
            cred = CredentialResponse(
                said=unique_said, issuer_aid=issuer_aid, recipient_aid=req.recipient_aid,
                registry_key=reg_key,
                schema_said=req.schema_said,
                issuance_dt="2025-01-01T00:00:00Z", status="issued",
                revocation_dt=None, attributes=req.attributes, edges=req.edges, rules=req.rules,
            )
            self._issued_credentials[unique_said] = cred
            return cred
        self.issue_credential = AsyncMock(side_effect=_issue_credential)

        async def _revoke_credential(said, publish=True):
            from fastapi import HTTPException
            cred = self._issued_credentials.get(said)
            if not cred:
                raise HTTPException(status_code=404, detail=f"Credential not found: {said}")
            if cred.status == "revoked":
                raise HTTPException(status_code=400, detail=f"Credential already revoked: {said}")
            revoked = CredentialResponse(
                said=said, issuer_aid=cred.issuer_aid, recipient_aid=cred.recipient_aid,
                registry_key=cred.registry_key, schema_said=cred.schema_said,
                issuance_dt=cred.issuance_dt, status="revoked",
                revocation_dt="2025-01-02T00:00:00Z",
                attributes=cred.attributes, edges=cred.edges, rules=cred.rules,
            )
            self._issued_credentials[said] = revoked
            return revoked
        self.revoke_credential = AsyncMock(side_effect=_revoke_credential)

        async def _list_credentials(registry_key=None, status=None):
            creds = list(self._issued_credentials.values())
            if registry_key:
                creds = [c for c in creds if c.registry_key == registry_key]
            if status:
                creds = [c for c in creds if c.status == status]
            return creds
        self.list_credentials = AsyncMock(side_effect=_list_credentials)

        async def _get_credential(said):
            return self._issued_credentials.get(said)
        self.get_credential = AsyncMock(side_effect=_get_credential)
        async def _get_credential_cesr(said):
            # Return CESR-like bytes containing the credential SAID
            return f'{{"d":"{said}","v":"ACDC10JSON"}}'.encode()
        self.get_credential_cesr = AsyncMock(side_effect=_get_credential_cesr)
        async def _delete_credential(said):
            self._issued_credentials.pop(said, None)
        self.delete_credential = AsyncMock(side_effect=_delete_credential)

        # Sprint 73: Bulk cleanup methods
        async def _bulk_cleanup_credentials(saids, force=True):
            deleted = []
            for said in saids:
                self._issued_credentials.pop(said, None)
                deleted.append(said)
            return {
                "deleted_count": len(deleted), "deleted_saids": deleted,
                "failed": [], "blocked_saids": [], "dry_run": False,
            }
        self.bulk_cleanup_credentials = AsyncMock(side_effect=_bulk_cleanup_credentials)

        async def _bulk_cleanup_identities(body):
            return {
                "deleted_count": 0, "deleted_names": [],
                "failed": [], "blocked_names": [],
                "cascaded_credential_count": 0, "dry_run": body.get("dry_run", False),
            }
        self.bulk_cleanup_identities = AsyncMock(side_effect=_bulk_cleanup_identities)

        # Dossier methods
        self.build_dossier = AsyncMock(return_value=DossierResponse(
            root_said=_DEFAULT_CRED_SAID, root_saids=[_DEFAULT_CRED_SAID],
            credential_saids=[_DEFAULT_CRED_SAID], is_aggregate=False, warnings=[],
        ))
        self.get_dossier = AsyncMock(return_value=None)
        self.get_dossier_cesr = AsyncMock(return_value=b"CESR-dossier")

        # VVP methods
        self.create_vvp_attestation = AsyncMock(return_value=VVPAttestationResponse(
            vvp_identity_header="eyJ0ZXN0IjogdHJ1ZX0",
            passport_jwt="eyJhbGciOiJFZERTQSJ9.test.sig",
            identity_header='info:<sip:+15551001@example.com>;alg=ES256',
            dossier_url="https://issuer.example.com/dossiers/test/cesr",
            kid_oobi="http://witness.example.com/oobi/EBfd",
            iat=1700000000, exp=1700000300,
        ))

        # Bootstrap methods
        self.get_bootstrap_status = AsyncMock(return_value=BootstrapStatusResponse(
            initialized=True, gleif_aid=_DEFAULT_AID,
            gleif_registry_key=_DEFAULT_REGISTRY_KEY,
            qvi_aid=_DEFAULT_QVI_AID,
            qvi_registry_key=_DEFAULT_REGISTRY_KEY,
            gleif_name="mock-gleif", qvi_name="mock-qvi",
            qvi_credential_said=_DEFAULT_CRED_SAID,
        ))
        self.initialize_mock_vlei = AsyncMock(return_value=BootstrapStatusResponse(
            initialized=True, gleif_aid=_DEFAULT_AID,
            gleif_registry_key=_DEFAULT_REGISTRY_KEY,
            qvi_aid=_DEFAULT_QVI_AID,
            qvi_registry_key=_DEFAULT_REGISTRY_KEY,
            gleif_name="mock-gleif", qvi_name="mock-qvi",
            qvi_credential_said=_DEFAULT_CRED_SAID,
        ))
        self.reinitialize_mock_vlei = AsyncMock(return_value=BootstrapStatusResponse(
            initialized=True, gleif_aid=_DEFAULT_AID,
            gleif_registry_key=_DEFAULT_REGISTRY_KEY,
            qvi_aid=_DEFAULT_QVI_AID,
            qvi_registry_key=_DEFAULT_REGISTRY_KEY,
            gleif_name="mock-gleif", qvi_name="mock-qvi",
            qvi_credential_said=_DEFAULT_CRED_SAID,
        ))

        # Operational methods
        self.health = AsyncMock(return_value=AgentHealthResponse(
            status="ok", identity_count=2, registry_count=1,
            credential_count=5, lmdb_accessible=True,
        ))
        self.stats = AsyncMock()
        self.is_healthy = AsyncMock(return_value=True)
        self.close = AsyncMock(return_value=None)

        # Circuit breaker property
        self.circuit_state = "closed"


@pytest.fixture
def mock_keri() -> MockKeriAgentClient:
    """Provide a MockKeriAgentClient for tests that need explicit mock control.

    Sprint 68b: Use this fixture in tests after their router has been
    migrated to keri_client. Configure mock return values as needed:

        async def test_create_identity(client, mock_keri):
            mock_keri.create_identity.return_value = IdentityResponse(...)
            response = await client.post("/identity", ...)
            assert mock_keri.create_identity.called
    """
    return MockKeriAgentClient()


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Auth Header Fixtures
# =============================================================================

@pytest.fixture
def admin_headers() -> dict:
    """Headers with admin API key."""
    return {"X-API-Key": TEST_ADMIN_KEY}


@pytest.fixture
def operator_headers() -> dict:
    """Headers with operator API key."""
    return {"X-API-Key": TEST_OPERATOR_KEY}


@pytest.fixture
def readonly_headers() -> dict:
    """Headers with readonly API key."""
    return {"X-API-Key": TEST_READONLY_KEY}


@pytest.fixture
def revoked_headers() -> dict:
    """Headers with revoked API key."""
    return {"X-API-Key": TEST_REVOKED_KEY}


@pytest.fixture
def invalid_headers() -> dict:
    """Headers with invalid API key."""
    return {"X-API-Key": "invalid-key-that-does-not-exist"}


@pytest.fixture
def temp_dir():
    """Create temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def identity_with_registry(
    client: AsyncClient,
) -> AsyncGenerator[dict, None]:
    """Create an identity for registry tests.

    Uses the client fixture to ensure proper singleton initialization,
    then creates an identity that can be used for registry creation.
    Cleans up the identity after the test completes.
    """
    import uuid
    # Create a test identity via API with unique name
    identity_name = f"test-issuer-{uuid.uuid4().hex[:8]}"
    response = await client.post(
        "/identity",
        json={"name": identity_name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    identity_data = response.json()
    identity = identity_data["identity"]

    yield identity

    # Cleanup: Delete the identity after test
    try:
        await client.delete(f"/identity/{identity['aid']}")
    except Exception:
        pass  # Best effort cleanup


@pytest.fixture
async def client(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client for API testing with isolated temp storage.

    Sets VVP_ISSUER_DATA_DIR to a temp directory so tests don't pollute
    the user's home directory or leak state between test runs.

    NOTE: Auth is DISABLED by default to avoid breaking existing tests.
    Use client_with_auth fixture for testing authentication.
    """
    # Set environment variable BEFORE importing the app
    # so config.py picks up the temp directory
    original_data_dir = os.environ.get("VVP_ISSUER_DATA_DIR")
    original_auth_enabled = os.environ.get("VVP_AUTH_ENABLED")

    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_AUTH_ENABLED"] = "false"  # Disable auth for backward compatibility

    # Reset singletons to pick up new config
    reset_api_key_store()
    reset_user_store()
    reset_session_store()
    reset_rate_limiter()
    reset_audit_logger()
    reset_dossier_builder()
    reset_keri_client()
    reset_trust_anchor_manager()

    # Sprint 68b: Install MockKeriAgentClient so KERI endpoints work in tests
    keri_client_module._client = MockKeriAgentClient()

    # Import and reload config module to pick up the new env var
    import app.config as config_module
    importlib.reload(config_module)

    # Reload main to pick up new config
    import app.main as main_module
    importlib.reload(main_module)

    async with AsyncClient(
        transport=ASGITransport(app=main_module.app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    # Cleanup after test
    reset_api_key_store()
    reset_user_store()
    reset_session_store()
    reset_rate_limiter()
    reset_audit_logger()
    reset_dossier_builder()
    reset_keri_client()
    reset_trust_anchor_manager()

    # Restore original environment
    if original_data_dir is not None:
        os.environ["VVP_ISSUER_DATA_DIR"] = original_data_dir
    elif "VVP_ISSUER_DATA_DIR" in os.environ:
        del os.environ["VVP_ISSUER_DATA_DIR"]

    if original_auth_enabled is not None:
        os.environ["VVP_AUTH_ENABLED"] = original_auth_enabled
    elif "VVP_AUTH_ENABLED" in os.environ:
        del os.environ["VVP_AUTH_ENABLED"]

    # Reload config to restore original values for other tests
    importlib.reload(config_module)


@pytest.fixture
async def client_with_auth(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with authentication ENABLED.

    Uses test API keys config for authentication testing.
    """
    # Save original environment
    original_data_dir = os.environ.get("VVP_ISSUER_DATA_DIR")
    original_auth_enabled = os.environ.get("VVP_AUTH_ENABLED")
    original_api_keys = os.environ.get("VVP_API_KEYS")

    # Set up test environment with auth enabled
    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_AUTH_ENABLED"] = "true"
    os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

    # Reset singletons
    reset_api_key_store()
    reset_user_store()
    reset_session_store()
    reset_rate_limiter()
    reset_audit_logger()
    reset_dossier_builder()
    reset_keri_client()
    reset_trust_anchor_manager()

    # Sprint 68b: Install MockKeriAgentClient so KERI endpoints work in tests
    keri_client_module._client = MockKeriAgentClient()

    # Reload config and main
    import app.config as config_module
    importlib.reload(config_module)

    import app.main as main_module
    importlib.reload(main_module)

    async with AsyncClient(
        transport=ASGITransport(app=main_module.app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    # Cleanup
    reset_api_key_store()
    reset_user_store()
    reset_session_store()
    reset_rate_limiter()
    reset_audit_logger()
    reset_dossier_builder()
    reset_keri_client()
    reset_trust_anchor_manager()

    # Restore environment
    if original_data_dir is not None:
        os.environ["VVP_ISSUER_DATA_DIR"] = original_data_dir
    elif "VVP_ISSUER_DATA_DIR" in os.environ:
        del os.environ["VVP_ISSUER_DATA_DIR"]

    if original_auth_enabled is not None:
        os.environ["VVP_AUTH_ENABLED"] = original_auth_enabled
    elif "VVP_AUTH_ENABLED" in os.environ:
        del os.environ["VVP_AUTH_ENABLED"]

    if original_api_keys is not None:
        os.environ["VVP_API_KEYS"] = original_api_keys
    elif "VVP_API_KEYS" in os.environ:
        del os.environ["VVP_API_KEYS"]

    importlib.reload(config_module)
