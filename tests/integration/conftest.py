"""Pytest fixtures for VVP integration tests.

This module provides fixtures for cross-service testing between
the issuer and verifier services, supporting local, docker, and
Azure deployment modes.
"""

import os
from dataclasses import dataclass
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from .helpers import (
    IssuerClient,
    VerifierClient,
    MockDossierServer,
    AzureBlobDossierServer,
    AZURE_AVAILABLE,
)


# =============================================================================
# Environment Configuration
# =============================================================================

@dataclass
class EnvironmentConfig:
    """Configuration for the test environment."""

    mode: str  # local, docker, azure
    issuer_url: str
    verifier_url: str
    api_key: str
    azure_storage_connection_string: str | None = None
    org_id: str | None = None

    @property
    def is_azure(self) -> bool:
        return self.mode == "azure"

    @property
    def is_local(self) -> bool:
        return self.mode == "local"


@pytest.fixture(scope="session")
def environment_config() -> EnvironmentConfig:
    """Determine test environment from environment variables.

    Environment Variables:
        VVP_TEST_MODE: Test mode (local, docker, azure). Default: local
        VVP_ISSUER_URL: Issuer service URL. Default: http://localhost:8001
        VVP_VERIFIER_URL: Verifier service URL. Default: http://localhost:8000
        VVP_TEST_API_KEY: API key for authentication. Default: test-admin-key-12345
        VVP_AZURE_STORAGE_CONNECTION_STRING: Azure Storage connection string (Azure mode only)
        VVP_TEST_ORG_ID: Organization ID for credential issuance (Sprint 67+)
    """
    return EnvironmentConfig(
        mode=os.getenv("VVP_TEST_MODE", "local"),
        issuer_url=os.getenv("VVP_ISSUER_URL", "http://localhost:8001"),
        verifier_url=os.getenv("VVP_VERIFIER_URL", "http://localhost:8000"),
        api_key=os.getenv("VVP_TEST_API_KEY", "test-admin-key-12345"),
        azure_storage_connection_string=os.getenv("VVP_AZURE_STORAGE_CONNECTION_STRING"),
        org_id=os.getenv("VVP_TEST_ORG_ID"),
    )


# =============================================================================
# Service Clients
# =============================================================================

@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def issuer_client(
    environment_config: EnvironmentConfig,
) -> AsyncGenerator[IssuerClient, None]:
    """Create issuer API client based on environment."""
    client = IssuerClient(
        base_url=environment_config.issuer_url,
        api_key=environment_config.api_key,
        default_organization_id=environment_config.org_id,
    )
    yield client
    await client.close()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def verifier_client(
    environment_config: EnvironmentConfig,
) -> AsyncGenerator[VerifierClient, None]:
    """Create verifier API client."""
    client = VerifierClient(base_url=environment_config.verifier_url)
    yield client
    await client.close()


# =============================================================================
# Mock Dossier Server (for local/docker tests)
# =============================================================================

@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def mock_dossier_server(
    environment_config: EnvironmentConfig,
) -> AsyncGenerator[MockDossierServer | None, None]:
    """Start mock dossier server for local/docker tests.

    Returns None in Azure mode (uses Azure Blob Storage instead).
    """
    if environment_config.is_azure:
        yield None
        return

    server = MockDossierServer()
    base_url = await server.start()
    server.base_url = base_url
    yield server
    await server.stop()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def azure_blob_server(
    environment_config: EnvironmentConfig,
) -> AsyncGenerator[AzureBlobDossierServer | None, None]:
    """Start Azure Blob Storage dossier server for Azure tests.

    Returns None in local/docker mode (uses mock server instead).
    """
    if not environment_config.is_azure:
        yield None
        return

    if not AZURE_AVAILABLE:
        pytest.skip("azure-storage-blob not installed")
        yield None
        return

    if not environment_config.azure_storage_connection_string:
        pytest.skip("VVP_AZURE_STORAGE_CONNECTION_STRING not set")
        yield None
        return

    server = AzureBlobDossierServer(
        connection_string=environment_config.azure_storage_connection_string
    )
    await server.start()
    yield server
    await server.stop()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def dossier_server(
    environment_config: EnvironmentConfig,
    mock_dossier_server: MockDossierServer | None,
    azure_blob_server: AzureBlobDossierServer | None,
):
    """Unified dossier server fixture for both local and Azure modes.

    Returns the appropriate dossier server based on the test environment:
    - Local/Docker: MockDossierServer (in-memory HTTP server)
    - Azure: AzureBlobDossierServer (Azure Blob Storage with SAS URLs)

    Both implementations share the same interface:
    - serve_dossier(said, content, content_type) -> url
    - get_dossier_url(said, format) -> url
    - clear()
    """
    if environment_config.is_azure:
        if azure_blob_server is None:
            pytest.skip("Azure blob server not available")
        return azure_blob_server
    else:
        if mock_dossier_server is None:
            pytest.skip("Mock dossier server not available")
        return mock_dossier_server


# =============================================================================
# Test Identity and Registry Fixtures
# =============================================================================

@pytest_asyncio.fixture(loop_scope="session")
async def test_identity(
    issuer_client: IssuerClient,
    environment_config: EnvironmentConfig,
) -> dict:
    """Get or create a test identity for credential issuance.

    When VVP_TEST_ORG_ID is set (Sprint 67+), returns the org's identity
    so credentials are issued under the org's AID. Otherwise creates a
    fresh identity for local/pre-org testing.
    """
    if environment_config.org_id:
        # Use the org's identity — credential endpoint uses org AID for issuance
        org_info = await issuer_client.get_organization(environment_config.org_id)
        org_aid = org_info["aid"]
        identity = await issuer_client.get_identity(org_aid)
        return identity
    else:
        import uuid
        name = f"test-identity-{uuid.uuid4().hex[:8]}"
        result = await issuer_client.create_identity(name, publish_to_witnesses=False)
        return result["identity"]


@pytest_asyncio.fixture(loop_scope="session")
async def test_registry(
    issuer_client: IssuerClient,
    test_identity: dict,
    environment_config: EnvironmentConfig,
) -> dict:
    """Get or create a test registry linked to test identity.

    When VVP_TEST_ORG_ID is set, returns the org's registry (derived from
    the org identity name). Otherwise creates a fresh registry.
    """
    if environment_config.org_id:
        # Org registry name follows the pattern: org-{org_id[:8]}-registry
        org_identity_name = f"org-{environment_config.org_id[:8]}"
        return {"name": f"{org_identity_name}-registry"}
    else:
        import uuid
        name = f"test-registry-{uuid.uuid4().hex[:8]}"
        result = await issuer_client.create_registry(
            name=name,
            identity_name=test_identity["name"],
        )
        return result["registry"]


# =============================================================================
# Configurable Thresholds
# =============================================================================

@pytest.fixture(scope="session")
def benchmark_thresholds() -> dict:
    """Get benchmark thresholds from environment or defaults.

    Thresholds can be overridden via environment variables for
    different environments (local vs Azure may have different latencies).
    """
    return {
        "single_credential_p95": float(
            os.getenv("VVP_BENCHMARK_SINGLE_P95", "5.0")
        ),
        "single_credential_p99": float(
            os.getenv("VVP_BENCHMARK_SINGLE_P99", "10.0")
        ),
        "chained_credential_p95": float(
            os.getenv("VVP_BENCHMARK_CHAINED_P95", "10.0")
        ),
        "chained_credential_p99": float(
            os.getenv("VVP_BENCHMARK_CHAINED_P99", "20.0")
        ),
        "concurrent_p95": float(os.getenv("VVP_BENCHMARK_CONCURRENT_P95", "15.0")),
        "concurrent_p99": float(os.getenv("VVP_BENCHMARK_CONCURRENT_P99", "30.0")),
    }


# =============================================================================
# Schema SAIDs
# =============================================================================

TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
# Sprint 67: Integration tests use Extended Brand Credential instead of Legal Entity
# because both TN Alloc and Extended Brand are authorized for "regular" org type.
# Legal Entity requires "qvi" org type which can't issue TN Alloc credentials.
# Tests exercise credential lifecycle mechanics, not schema-specific behavior.
LEGAL_ENTITY_SCHEMA = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"  # Extended Brand Credential


@pytest.fixture
def tn_allocation_schema() -> str:
    """TN Allocation schema SAID."""
    return TN_ALLOCATION_SCHEMA


@pytest.fixture
def legal_entity_schema() -> str:
    """Extended Brand Credential schema SAID (aliased as legal_entity for test compat)."""
    return LEGAL_ENTITY_SCHEMA
