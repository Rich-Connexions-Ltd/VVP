"""
Integration tests for local witness infrastructure.

These tests verify connectivity to local KERI witnesses started via docker-compose.
They require witnesses to be running (via ./scripts/local-witnesses.sh start).

Run with: pytest tests/test_local_witnesses.py -v --run-local-witnesses

NOTE: These tests are skipped by default. Use --run-local-witnesses to enable them.
The pytest hooks (pytest_addoption, pytest_configure, pytest_collection_modifyitems)
and the witness_base_url fixture are defined in conftest.py.
"""

import httpx
import pytest

# Known demo witness AIDs from kli witness demo (deterministic salts)
DEMO_WITNESS_AIDS = {
    "wan": "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
    "wil": "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
    "wes": "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
}

DEMO_WITNESS_PORTS = {
    "wan": 5642,
    "wil": 5643,
    "wes": 5644,
}


class TestWitnessConnectivity:
    """Test basic connectivity to local witnesses."""

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_witness_wan_responds(self, witness_base_url):
        """Verify wan witness responds on port 5642."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{witness_base_url}:5642/")
            # Witnesses may return various status codes, just verify connectivity
            assert response.status_code in (200, 404, 405), (
                f"wan witness not responding: {response.status_code}"
            )

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_witness_wil_responds(self, witness_base_url):
        """Verify wil witness responds on port 5643."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{witness_base_url}:5643/")
            assert response.status_code in (200, 404, 405), (
                f"wil witness not responding: {response.status_code}"
            )

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_witness_wes_responds(self, witness_base_url):
        """Verify wes witness responds on port 5644."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{witness_base_url}:5644/")
            assert response.status_code in (200, 404, 405), (
                f"wes witness not responding: {response.status_code}"
            )


class TestWitnessOOBI:
    """Test OOBI endpoint functionality."""

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_oobi_endpoint_returns_keri_data(self, witness_base_url):
        """Verify OOBI endpoint returns KERI reply messages for wan witness."""
        wan_aid = DEMO_WITNESS_AIDS["wan"]
        url = f"{witness_base_url}:5642/oobi/{wan_aid}/controller"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)

            # OOBI endpoint should return 200 with KERI data
            assert response.status_code == 200, (
                f"OOBI endpoint returned {response.status_code}"
            )

            # Response should contain KERI messages
            content = response.content
            assert len(content) > 0, "OOBI response is empty"

            # Should contain KERI message markers (JSON with 't' or 'v' field)
            text = content.decode("utf-8", errors="replace")
            has_keri_markers = '"t"' in text or '"v"' in text
            assert has_keri_markers, (
                f"OOBI response doesn't look like KERI data: {text[:200]}"
            )

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_all_witness_oobis_respond(self, witness_base_url):
        """Verify all three witness OOBI endpoints return data."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for name, aid in DEMO_WITNESS_AIDS.items():
                port = DEMO_WITNESS_PORTS[name]
                url = f"{witness_base_url}:{port}/oobi/{aid}/controller"

                response = await client.get(url)
                assert response.status_code == 200, (
                    f"{name} OOBI failed: {response.status_code}"
                )
                assert len(response.content) > 0, (
                    f"{name} OOBI response is empty"
                )

    @pytest.mark.local_witnesses
    @pytest.mark.asyncio
    async def test_unknown_aid_returns_empty_or_404(self, witness_base_url):
        """Verify unknown AID returns empty response or 404."""
        unknown_aid = "Exxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        url = f"{witness_base_url}:5642/oobi/{unknown_aid}/controller"

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)

            # Unknown AID may return 404 or 200 with empty/minimal body
            assert response.status_code in (200, 404), (
                f"Unexpected status for unknown AID: {response.status_code}"
            )


class TestConfigIntegration:
    """Test VVP config integration with local witnesses."""

    @pytest.mark.local_witnesses
    def test_parse_witness_urls_from_env(self, monkeypatch):
        """Verify _parse_witness_urls reads from VVP_LOCAL_WITNESS_URLS."""
        # Set the environment variable
        local_urls = "http://127.0.0.1:5642,http://127.0.0.1:5643,http://127.0.0.1:5644"
        monkeypatch.setenv("VVP_LOCAL_WITNESS_URLS", local_urls)

        # Re-import to pick up new env var (need fresh import)
        from importlib import reload
        from app.core import config

        reload(config)

        # Check the parsed URLs
        assert len(config.PROVENANT_WITNESS_URLS) == 3
        assert "http://127.0.0.1:5642" in config.PROVENANT_WITNESS_URLS
        assert "http://127.0.0.1:5643" in config.PROVENANT_WITNESS_URLS
        assert "http://127.0.0.1:5644" in config.PROVENANT_WITNESS_URLS

    @pytest.mark.local_witnesses
    def test_parse_witness_urls_uses_defaults_when_empty(self, monkeypatch):
        """Verify _parse_witness_urls uses defaults when env var is not set."""
        # Clear the environment variable
        monkeypatch.delenv("VVP_LOCAL_WITNESS_URLS", raising=False)

        from importlib import reload
        from app.core import config

        reload(config)

        # Should use Provenant staging defaults
        assert len(config.PROVENANT_WITNESS_URLS) == 3
        assert any("provenant" in url for url in config.PROVENANT_WITNESS_URLS)


class TestWitnessPoolIntegration:
    """Test WitnessPool with local witnesses."""

    @pytest.mark.local_witnesses
    def test_witness_pool_accepts_local_urls(self):
        """Verify WitnessPool can be constructed with local witness URLs."""
        from app.vvp.keri.witness_pool import WitnessPool

        local_urls = [
            "http://127.0.0.1:5642",
            "http://127.0.0.1:5643",
            "http://127.0.0.1:5644",
        ]

        pool = WitnessPool(
            config_witnesses=local_urls,
            gleif_discovery_enabled=False,
        )

        assert pool.configured_count == 3
        assert pool.total_count >= 3

        urls = pool.get_witness_urls()
        assert "http://127.0.0.1:5642" in urls
        assert "http://127.0.0.1:5643" in urls
        assert "http://127.0.0.1:5644" in urls
