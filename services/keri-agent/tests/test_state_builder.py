"""Tests for KERI state builder (deterministic rebuild).

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import importlib
import json
import os
import shutil
from pathlib import Path

import pytest

from app.keri.seed_store import get_seed_store, reset_seed_store
from app.keri.state_builder import KeriStateBuilder, RebuildReport


@pytest.fixture
async def rebuild_env(tmp_path):
    """Set up environment for rebuild tests with isolated DB and LMDB."""
    original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")
    original_mock_vlei = os.environ.get("VVP_MOCK_VLEI_ENABLED")

    lmdb_dir = tmp_path / "lmdb"
    lmdb_dir.mkdir()
    db_path = tmp_path / "seeds.db"

    os.environ["VVP_KERI_AGENT_DATA_DIR"] = str(lmdb_dir)
    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["VVP_MOCK_VLEI_ENABLED"] = "false"

    import app.config as config_module
    importlib.reload(config_module)
    import app.db.session as db_session_module
    importlib.reload(db_session_module)
    db_session_module.init_database()

    from app.keri.identity import reset_identity_manager, close_identity_manager
    from app.keri.registry import reset_registry_manager, close_registry_manager
    from app.keri.issuer import reset_credential_issuer, close_credential_issuer
    from app.keri.persistence import reset_persistence_manager
    from app.keri.witness import reset_witness_publisher

    reset_seed_store()
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()

    yield {
        "lmdb_dir": lmdb_dir,
        "db_path": db_path,
        "tmp_path": tmp_path,
    }

    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()

    reset_seed_store()
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()

    if original_data_dir is not None:
        os.environ["VVP_KERI_AGENT_DATA_DIR"] = original_data_dir
    elif "VVP_KERI_AGENT_DATA_DIR" in os.environ:
        del os.environ["VVP_KERI_AGENT_DATA_DIR"]

    if original_db_url is not None:
        os.environ["VVP_KERI_AGENT_DATABASE_URL"] = original_db_url
    elif "VVP_KERI_AGENT_DATABASE_URL" in os.environ:
        del os.environ["VVP_KERI_AGENT_DATABASE_URL"]

    if original_mock_vlei is not None:
        os.environ["VVP_MOCK_VLEI_ENABLED"] = original_mock_vlei
    elif "VVP_MOCK_VLEI_ENABLED" in os.environ:
        del os.environ["VVP_MOCK_VLEI_ENABLED"]

    importlib.reload(config_module)


class TestRebuildReport:
    """Tests for RebuildReport."""

    def test_str_format(self):
        report = RebuildReport(
            total_seconds=5.2,
            identities_rebuilt=3,
            registries_rebuilt=2,
            credentials_rebuilt=10,
        )
        s = str(report)
        assert "5.2s" in s
        assert "3 identities" in s

    def test_str_with_errors(self):
        report = RebuildReport(errors=["error1"])
        s = str(report)
        assert "1 errors" in s


class TestIdentityRebuild:
    """Tests for identity rebuild from seeds."""

    @pytest.mark.asyncio
    async def test_round_trip_identity(self, rebuild_env):
        """Create identity, wipe LMDB, rebuild from seeds, verify AID matches."""
        from app.keri.identity import get_identity_manager, reset_identity_manager, close_identity_manager

        # Phase 1: Create identity (seeds persisted automatically)
        identity_mgr = await get_identity_manager()
        info = await identity_mgr.create_identity(
            name="test-identity",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=[],
        )
        original_aid = info.aid

        # Verify seed was stored
        seed_store = get_seed_store()
        seeds = seed_store.get_all_identity_seeds()
        assert len(seeds) >= 1
        identity_seed = [s for s in seeds if s.name == "test-identity"][0]
        assert identity_seed.expected_aid == original_aid

        # Phase 2: Close and wipe LMDB
        await close_identity_manager()
        reset_identity_manager()

        lmdb_dir = rebuild_env["lmdb_dir"]
        for item in lmdb_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        # Phase 3: Re-initialize (uses stored salt) and rebuild
        from app.keri.persistence import reset_persistence_manager
        reset_persistence_manager()

        identity_mgr = await get_identity_manager()
        builder = KeriStateBuilder()
        report = await builder.rebuild()

        # Phase 4: Verify AID matches
        assert report.identities_rebuilt >= 1
        rebuilt = identity_mgr.hby.habByName("test-identity")
        assert rebuilt is not None
        assert rebuilt.pre == original_aid

    @pytest.mark.asyncio
    async def test_rebuild_no_seeds(self, rebuild_env):
        """Rebuild with empty seed store should succeed with zero counts."""
        from app.keri.identity import get_identity_manager

        await get_identity_manager()
        builder = KeriStateBuilder()
        report = await builder.rebuild()
        assert report.identities_rebuilt == 0
        assert report.errors == []

    @pytest.mark.asyncio
    async def test_rebuild_multiple_identities(self, rebuild_env):
        """Create multiple identities, rebuild all."""
        from app.keri.identity import get_identity_manager, reset_identity_manager, close_identity_manager
        from app.keri.persistence import reset_persistence_manager

        identity_mgr = await get_identity_manager()

        aids = {}
        for name in ["id-alpha", "id-beta", "id-gamma"]:
            info = await identity_mgr.create_identity(
                name=name, transferable=True,
                icount=1, isith="1", ncount=1, nsith="1",
                witness_aids=[],
            )
            aids[name] = info.aid

        # Wipe LMDB
        await close_identity_manager()
        reset_identity_manager()
        lmdb_dir = rebuild_env["lmdb_dir"]
        for item in lmdb_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        reset_persistence_manager()
        identity_mgr = await get_identity_manager()

        builder = KeriStateBuilder()
        report = await builder.rebuild()

        # All three identities should be rebuilt with correct AIDs
        # +1 for the habery's own identity (vvp-issuer)
        assert report.identities_rebuilt >= 3
        for name, original_aid in aids.items():
            hab = identity_mgr.hby.habByName(name)
            assert hab is not None, f"Identity {name} not rebuilt"
            assert hab.pre == original_aid, f"AID mismatch for {name}"


class TestRegistryRebuild:
    """Tests for registry rebuild from seeds."""

    @pytest.mark.asyncio
    async def test_round_trip_registry(self, rebuild_env):
        """Create identity + registry, wipe LMDB, rebuild, verify registry key."""
        from app.keri.identity import get_identity_manager, reset_identity_manager, close_identity_manager
        from app.keri.registry import get_registry_manager, reset_registry_manager, close_registry_manager
        from app.keri.persistence import reset_persistence_manager

        # Create identity and registry
        identity_mgr = await get_identity_manager()
        id_info = await identity_mgr.create_identity(
            name="reg-test-issuer", transferable=True,
            icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[],
        )

        registry_mgr = await get_registry_manager()
        reg_info = await registry_mgr.create_registry(
            name="test-registry", issuer_aid=id_info.aid, no_backers=True,
        )
        original_regk = reg_info.registry_key

        # Verify registry seed was stored
        seed_store = get_seed_store()
        reg_seeds = seed_store.get_all_registry_seeds()
        assert len(reg_seeds) >= 1

        # Wipe LMDB
        await close_registry_manager()
        await close_identity_manager()
        reset_registry_manager()
        reset_identity_manager()
        lmdb_dir = rebuild_env["lmdb_dir"]
        for item in lmdb_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        reset_persistence_manager()

        # Rebuild
        await get_identity_manager()
        await get_registry_manager()

        builder = KeriStateBuilder()
        report = await builder.rebuild()

        assert report.registries_rebuilt >= 1
        assert len(report.errors) == 0, f"Errors: {report.errors}"


class TestCredentialRebuild:
    """Tests for credential rebuild from seeds."""

    @pytest.mark.asyncio
    async def test_round_trip_credential(self, rebuild_env):
        """Create identity + registry + credential, wipe LMDB, rebuild, verify SAID."""
        from app.keri.identity import get_identity_manager, reset_identity_manager, close_identity_manager
        from app.keri.registry import get_registry_manager, reset_registry_manager, close_registry_manager
        from app.keri.issuer import get_credential_issuer, reset_credential_issuer, close_credential_issuer
        from app.keri.persistence import reset_persistence_manager

        # Create identity, registry, credential
        identity_mgr = await get_identity_manager()
        id_info = await identity_mgr.create_identity(
            name="cred-test-issuer", transferable=True,
            icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[],
        )

        registry_mgr = await get_registry_manager()
        await registry_mgr.create_registry(
            name="cred-test-registry", issuer_aid=id_info.aid, no_backers=True,
        )

        cred_issuer = await get_credential_issuer()
        cred_info, _ = await cred_issuer.issue_credential(
            registry_name="cred-test-registry",
            schema_said="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
            attributes={"dt": "2026-01-01T00:00:00.000000+00:00", "LEI": "1234567890"},
        )
        original_said = cred_info.said

        # Verify credential seed was stored
        seed_store = get_seed_store()
        cred_seeds = seed_store.get_all_credential_seeds()
        assert len(cred_seeds) >= 1
        assert cred_seeds[0].expected_said == original_said

        # Wipe LMDB
        await close_credential_issuer()
        await close_registry_manager()
        await close_identity_manager()
        reset_credential_issuer()
        reset_registry_manager()
        reset_identity_manager()
        lmdb_dir = rebuild_env["lmdb_dir"]
        for item in lmdb_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        reset_persistence_manager()

        # Rebuild
        await get_identity_manager()
        await get_registry_manager()
        await get_credential_issuer()

        builder = KeriStateBuilder()
        report = await builder.rebuild()

        assert report.credentials_rebuilt >= 1
        assert len(report.errors) == 0, f"Errors: {report.errors}"


class TestWitnessPublishing:
    """Tests for witness re-publishing during rebuild (Sprint 70)."""

    def test_report_includes_witness_fields(self):
        """RebuildReport should include witness publishing stats."""
        report = RebuildReport(
            witnesses_published=2,
            witness_publish_seconds=1.5,
        )
        s = str(report)
        assert "2 witness publications" in s
        assert "1.5s" in s

    def test_report_zero_witnesses(self):
        """RebuildReport with no witness publishing should show 0."""
        report = RebuildReport()
        assert report.witnesses_published == 0
        assert report.witness_publish_seconds == 0.0
        s = str(report)
        assert "0 witness publications" in s

    @pytest.mark.asyncio
    async def test_publish_skips_identities_without_witnesses(self, rebuild_env):
        """Identities created without witnesses should not trigger publishing."""
        from app.keri.identity import get_identity_manager
        from unittest.mock import AsyncMock, patch

        identity_mgr = await get_identity_manager()

        # Create identity directly via makeHab with wits=[] to bypass
        # create_identity's default witness fallback ([] is falsy)
        hab = identity_mgr.hby.makeHab(
            name="no-witness-id",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            wits=[],
            toad=0,
        )
        seed_store = get_seed_store()
        seed_store.save_identity_seed(
            name="no-witness-id",
            expected_aid=hab.pre,
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=[],
            toad=0,
        )

        mock_publisher = AsyncMock()
        with patch(
            "app.keri.witness.get_witness_publisher",
            return_value=mock_publisher,
        ):
            builder = KeriStateBuilder()
            report = await builder.rebuild()

        # publish_oobi should never be called — no habs have witnesses
        mock_publisher.publish_oobi.assert_not_called()
        assert report.witnesses_published == 0

    @pytest.mark.asyncio
    async def test_publish_called_for_identities_with_witnesses(self, rebuild_env):
        """Identities with witnesses should be published after rebuild."""
        from app.keri.identity import get_identity_manager
        from app.keri.witness import PublishResult, WitnessResult
        from unittest.mock import AsyncMock, patch

        identity_mgr = await get_identity_manager()

        # Create identity with fake witness AIDs
        fake_witness_aids = ["BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"]
        await identity_mgr.create_identity(
            name="witnessed-id",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=fake_witness_aids,
        )

        mock_publisher = AsyncMock()
        mock_publisher.publish_oobi.return_value = PublishResult(
            aid="test",
            success_count=1,
            total_count=1,
            threshold_met=True,
            witnesses=[WitnessResult(url="http://witness:5642", success=True)],
        )

        with patch(
            "app.keri.witness.get_witness_publisher",
            return_value=mock_publisher,
        ):
            builder = KeriStateBuilder()
            report = await builder.rebuild()

        # publish_oobi should be called for the witnessed identity
        assert mock_publisher.publish_oobi.call_count >= 1
        assert report.witnesses_published >= 1
        assert report.witness_publish_seconds > 0

    @pytest.mark.asyncio
    async def test_publish_failure_does_not_block_startup(self, rebuild_env):
        """Witness publish failures should not prevent rebuild from completing."""
        from app.keri.identity import get_identity_manager
        from unittest.mock import AsyncMock, patch

        identity_mgr = await get_identity_manager()

        fake_witness_aids = ["BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"]
        await identity_mgr.create_identity(
            name="fail-witness-id",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=fake_witness_aids,
        )

        mock_publisher = AsyncMock()
        mock_publisher.publish_oobi.side_effect = Exception("Connection refused")

        with patch(
            "app.keri.witness.get_witness_publisher",
            return_value=mock_publisher,
        ):
            builder = KeriStateBuilder()
            report = await builder.rebuild()

        # Rebuild should complete despite witness failure
        assert report.identities_rebuilt >= 1
        assert report.witnesses_published == 0
        # Error should be logged in report
        witness_errors = [e for e in report.errors if "Witness publish" in e]
        assert len(witness_errors) >= 1

    @pytest.mark.asyncio
    async def test_publish_concurrent_multiple_identities(self, rebuild_env):
        """Multiple identities with witnesses should be published concurrently."""
        from app.keri.identity import get_identity_manager
        from app.keri.witness import PublishResult, WitnessResult
        from unittest.mock import AsyncMock, patch

        identity_mgr = await get_identity_manager()

        fake_witness_aids = ["BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"]
        for name in ["concurrent-a", "concurrent-b"]:
            await identity_mgr.create_identity(
                name=name,
                transferable=True,
                icount=1,
                isith="1",
                ncount=1,
                nsith="1",
                witness_aids=fake_witness_aids,
            )

        call_count = 0

        async def mock_publish(aid, kel_bytes, hby=None):
            nonlocal call_count
            call_count += 1
            return PublishResult(
                aid=aid,
                success_count=1,
                total_count=1,
                threshold_met=True,
                witnesses=[WitnessResult(url="http://witness:5642", success=True)],
            )

        mock_publisher = AsyncMock()
        mock_publisher.publish_oobi = mock_publish

        with patch(
            "app.keri.witness.get_witness_publisher",
            return_value=mock_publisher,
        ):
            builder = KeriStateBuilder()
            report = await builder.rebuild()

        # Both witnessed identities should be published
        assert call_count >= 2
        assert report.witnesses_published >= 2
