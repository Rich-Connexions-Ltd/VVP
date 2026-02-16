"""Tests for KERI Agent seed store.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import json
import os
import importlib
import tempfile
from pathlib import Path

import pytest

from app.db.models import (
    KeriCredentialSeed,
    KeriHaberySalt,
    KeriIdentitySeed,
    KeriRegistrySeed,
    KeriRotationSeed,
)
from app.keri.seed_store import (
    SeedStore,
    extract_edge_saids,
    _insertion_order_json,
    reset_seed_store,
)


@pytest.fixture
def seed_db(tmp_path):
    """Set up an isolated SQLite seed database for testing."""
    db_path = tmp_path / "test_seeds.db"
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")
    original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")

    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["VVP_KERI_AGENT_DATA_DIR"] = str(tmp_path)

    # Reload config and session to pick up new DB URL
    import app.config as config_module
    importlib.reload(config_module)
    import app.db.session as session_module
    importlib.reload(session_module)

    # Create tables
    from app.db.session import init_database
    init_database()

    reset_seed_store()
    store = SeedStore()

    yield store

    reset_seed_store()

    if original_db_url is not None:
        os.environ["VVP_KERI_AGENT_DATABASE_URL"] = original_db_url
    elif "VVP_KERI_AGENT_DATABASE_URL" in os.environ:
        del os.environ["VVP_KERI_AGENT_DATABASE_URL"]

    if original_data_dir is not None:
        os.environ["VVP_KERI_AGENT_DATA_DIR"] = original_data_dir
    elif "VVP_KERI_AGENT_DATA_DIR" in os.environ:
        del os.environ["VVP_KERI_AGENT_DATA_DIR"]

    importlib.reload(config_module)


# ============================================================================
# Helper function tests
# ============================================================================


class TestInsertionOrderJson:
    """Tests for _insertion_order_json helper."""

    def test_none_returns_none(self):
        assert _insertion_order_json(None) is None

    def test_dict_preserves_order(self):
        data = {"z": 1, "a": 2, "m": 3}
        result = _insertion_order_json(data)
        assert result == '{"z":1,"a":2,"m":3}'

    def test_no_whitespace(self):
        data = {"key": "value", "num": 42}
        result = _insertion_order_json(data)
        assert " " not in result

    def test_nested_dict(self):
        data = {"outer": {"inner": "value"}}
        result = _insertion_order_json(data)
        assert result == '{"outer":{"inner":"value"}}'

    def test_list(self):
        data = [1, 2, 3]
        result = _insertion_order_json(data)
        assert result == "[1,2,3]"

    def test_roundtrip_preserves_order(self):
        original = {"z": 1, "a": 2, "m": 3}
        serialized = _insertion_order_json(original)
        deserialized = json.loads(serialized)
        assert list(deserialized.keys()) == ["z", "a", "m"]


class TestExtractEdgeSaids:
    """Tests for extract_edge_saids helper."""

    def test_none_returns_none(self):
        assert extract_edge_saids(None) is None

    def test_empty_dict_returns_none(self):
        assert extract_edge_saids({}) is None

    def test_extracts_n_values(self):
        edges = {
            "d": "ESAID...",  # Edge block's own SAID (skipped)
            "qviCredential": {"n": "EABC123", "s": "ESchemaXYZ"},
            "leCredential": {"n": "EDEF456", "s": "ESchemaABC"},
        }
        result = extract_edge_saids(edges)
        assert result == ["EABC123", "EDEF456"]

    def test_skips_d_key(self):
        edges = {"d": "ESAID", "cred": {"n": "EABC"}}
        result = extract_edge_saids(edges)
        assert result == ["EABC"]

    def test_no_n_values_returns_none(self):
        edges = {"d": "ESAID"}
        result = extract_edge_saids(edges)
        assert result is None


# ============================================================================
# Habery Salt tests
# ============================================================================


class TestHaberySalt:
    """Tests for Habery salt save/get."""

    def test_save_and_get(self, seed_db: SeedStore):
        seed_db.save_habery_salt("0ABCsalt123456789012345678901234", "vvp-issuer")
        result = seed_db.get_habery_salt("vvp-issuer")
        assert result == "0ABCsalt123456789012345678901234"

    def test_get_nonexistent(self, seed_db: SeedStore):
        result = seed_db.get_habery_salt("nonexistent")
        assert result is None

    def test_save_idempotent(self, seed_db: SeedStore):
        seed_db.save_habery_salt("0ABCsalt_first", "vvp-issuer")
        seed_db.save_habery_salt("0ABCsalt_first", "vvp-issuer")
        result = seed_db.get_habery_salt("vvp-issuer")
        assert result == "0ABCsalt_first"

    def test_save_does_not_overwrite(self, seed_db: SeedStore):
        """Second save with different salt should NOT overwrite."""
        seed_db.save_habery_salt("0ABCsalt_first", "vvp-issuer")
        seed_db.save_habery_salt("0ABCsalt_second", "vvp-issuer")
        result = seed_db.get_habery_salt("vvp-issuer")
        assert result == "0ABCsalt_first"


# ============================================================================
# Identity Seed tests
# ============================================================================


class TestIdentitySeed:
    """Tests for identity seed CRUD."""

    def test_save_and_get_all(self, seed_db: SeedStore):
        seed_db.save_identity_seed(
            name="mock-gleif",
            expected_aid="EABC123456789012345678901234567890",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=["BWitness1", "BWitness2"],
            toad=2,
        )
        seeds = seed_db.get_all_identity_seeds()
        assert len(seeds) == 1
        assert seeds[0].name == "mock-gleif"
        assert seeds[0].expected_aid == "EABC123456789012345678901234567890"
        assert seeds[0].transferable is True
        assert json.loads(seeds[0].witness_aids) == ["BWitness1", "BWitness2"]

    def test_save_idempotent(self, seed_db: SeedStore):
        seed_db.save_identity_seed(
            name="test-id", expected_aid="EABC", transferable=True,
            icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[], toad=0,
        )
        seed_db.save_identity_seed(
            name="test-id", expected_aid="EABC", transferable=True,
            icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[], toad=0,
        )
        seeds = seed_db.get_all_identity_seeds()
        assert len(seeds) == 1

    def test_save_with_metadata(self, seed_db: SeedStore):
        seed_db.save_identity_seed(
            name="org-123", expected_aid="EORG",
            transferable=True, icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[], toad=0,
            metadata={"type": "organization", "org_id": "123"},
        )
        seeds = seed_db.get_all_identity_seeds()
        assert seeds[0].metadata_json is not None
        meta = json.loads(seeds[0].metadata_json)
        assert meta["type"] == "organization"

    def test_multiple_ordered_by_creation(self, seed_db: SeedStore):
        for i in range(3):
            seed_db.save_identity_seed(
                name=f"id-{i}", expected_aid=f"EAID{i}",
                transferable=True, icount=1, isith="1", ncount=1, nsith="1",
                witness_aids=[], toad=0,
            )
        seeds = seed_db.get_all_identity_seeds()
        assert len(seeds) == 3
        assert [s.name for s in seeds] == ["id-0", "id-1", "id-2"]


# ============================================================================
# Registry Seed tests
# ============================================================================


class TestRegistrySeed:
    """Tests for registry seed CRUD."""

    def test_save_and_get_all(self, seed_db: SeedStore):
        seed_db.save_registry_seed(
            name="mock-gleif-registry",
            identity_name="mock-gleif",
            expected_registry_key="EREG123",
            no_backers=True,
            nonce="ENONCE123",
        )
        seeds = seed_db.get_all_registry_seeds()
        assert len(seeds) == 1
        assert seeds[0].name == "mock-gleif-registry"
        assert seeds[0].nonce == "ENONCE123"
        assert seeds[0].no_backers is True

    def test_save_idempotent(self, seed_db: SeedStore):
        seed_db.save_registry_seed(
            name="reg", identity_name="id", expected_registry_key="EREG",
            no_backers=True,
        )
        seed_db.save_registry_seed(
            name="reg", identity_name="id", expected_registry_key="EREG",
            no_backers=True,
        )
        seeds = seed_db.get_all_registry_seeds()
        assert len(seeds) == 1

    def test_nonce_optional(self, seed_db: SeedStore):
        seed_db.save_registry_seed(
            name="reg-no-nonce", identity_name="id",
            expected_registry_key="EREG", no_backers=True,
        )
        seeds = seed_db.get_all_registry_seeds()
        assert seeds[0].nonce is None


# ============================================================================
# Rotation Seed tests
# ============================================================================


class TestRotationSeed:
    """Tests for rotation seed CRUD."""

    def test_save_and_get(self, seed_db: SeedStore):
        seed_db.save_rotation_seed(
            identity_name="mock-gleif",
            sequence_number=1,
            ncount=2,
            nsith="2",
        )
        rotations = seed_db.get_rotations_for_identity("mock-gleif")
        assert len(rotations) == 1
        assert rotations[0].sequence_number == 1
        assert rotations[0].ncount == 2

    def test_save_idempotent(self, seed_db: SeedStore):
        seed_db.save_rotation_seed(
            identity_name="id", sequence_number=1,
        )
        seed_db.save_rotation_seed(
            identity_name="id", sequence_number=1,
        )
        rotations = seed_db.get_rotations_for_identity("id")
        assert len(rotations) == 1

    def test_multiple_rotations_ordered(self, seed_db: SeedStore):
        for sn in [3, 1, 2]:  # Insert out of order
            seed_db.save_rotation_seed(
                identity_name="id", sequence_number=sn,
            )
        rotations = seed_db.get_rotations_for_identity("id")
        assert len(rotations) == 3
        assert [r.sequence_number for r in rotations] == [1, 2, 3]

    def test_get_empty(self, seed_db: SeedStore):
        rotations = seed_db.get_rotations_for_identity("nonexistent")
        assert rotations == []


# ============================================================================
# Credential Seed tests
# ============================================================================


class TestCredentialSeed:
    """Tests for credential seed CRUD."""

    def test_save_and_get_all(self, seed_db: SeedStore):
        seed_db.save_credential_seed(
            expected_said="ESAID123",
            registry_name="reg",
            schema_said="ESCHEMA",
            issuer_identity_name="issuer",
            recipient_aid="ERECIP",
            attributes={"dt": "2026-01-01T00:00:00Z", "LEI": "1234"},
            edges=None,
            rules=None,
            private=False,
            rebuild_order=0,
        )
        seeds = seed_db.get_all_credential_seeds()
        assert len(seeds) == 1
        assert seeds[0].expected_said == "ESAID123"
        assert seeds[0].rebuild_order == 0
        attrs = json.loads(seeds[0].attributes_json)
        assert attrs["LEI"] == "1234"

    def test_save_idempotent(self, seed_db: SeedStore):
        for _ in range(2):
            seed_db.save_credential_seed(
                expected_said="ESAID", registry_name="reg",
                schema_said="ES", issuer_identity_name="iss",
                recipient_aid=None, attributes={"dt": "now"},
                edges=None, rules=None, private=False, rebuild_order=0,
            )
        seeds = seed_db.get_all_credential_seeds()
        assert len(seeds) == 1

    def test_insertion_order_preserved(self, seed_db: SeedStore):
        """Verify attributes_json preserves insertion order."""
        attrs = {"z_last": "1", "a_first": "2", "m_middle": "3"}
        seed_db.save_credential_seed(
            expected_said="EORDER", registry_name="reg",
            schema_said="ES", issuer_identity_name="iss",
            recipient_aid=None, attributes=attrs,
            edges=None, rules=None, private=False, rebuild_order=0,
        )
        seeds = seed_db.get_all_credential_seeds()
        loaded = json.loads(seeds[0].attributes_json)
        assert list(loaded.keys()) == ["z_last", "a_first", "m_middle"]

    def test_with_edges_and_rules(self, seed_db: SeedStore):
        edges = {"qvi": {"n": "EQVI_SAID", "s": "ESCHEMA"}}
        rules = {"d": "", "usageDisclaimer": {"l": "..."}}
        seed_db.save_credential_seed(
            expected_said="EEDGE", registry_name="reg",
            schema_said="ES", issuer_identity_name="iss",
            recipient_aid=None, attributes={"dt": "now"},
            edges=edges, rules=rules, private=False,
            rebuild_order=1, edge_saids=["EQVI_SAID"],
        )
        seeds = seed_db.get_all_credential_seeds()
        assert seeds[0].edges_json is not None
        assert seeds[0].rules_json is not None
        loaded_edges = json.loads(seeds[0].edges_json)
        assert loaded_edges["qvi"]["n"] == "EQVI_SAID"
        loaded_edge_saids = json.loads(seeds[0].edge_saids)
        assert loaded_edge_saids == ["EQVI_SAID"]

    def test_ordered_by_rebuild_order(self, seed_db: SeedStore):
        for order in [2, 0, 1]:
            seed_db.save_credential_seed(
                expected_said=f"ESAID_{order}", registry_name="reg",
                schema_said="ES", issuer_identity_name="iss",
                recipient_aid=None, attributes={"dt": "now"},
                edges=None, rules=None, private=False,
                rebuild_order=order,
            )
        seeds = seed_db.get_all_credential_seeds()
        assert [s.rebuild_order for s in seeds] == [0, 1, 2]


# ============================================================================
# Topological rebuild order tests
# ============================================================================


class TestComputeRebuildOrder:
    """Tests for compute_rebuild_order."""

    def test_no_edges_returns_zero(self, seed_db: SeedStore):
        assert seed_db.compute_rebuild_order(None) == 0
        assert seed_db.compute_rebuild_order([]) == 0

    def test_with_existing_dependency(self, seed_db: SeedStore):
        # Create a dependency at rebuild_order=0
        seed_db.save_credential_seed(
            expected_said="EPARENT", registry_name="reg",
            schema_said="ES", issuer_identity_name="iss",
            recipient_aid=None, attributes={"dt": "now"},
            edges=None, rules=None, private=False, rebuild_order=0,
        )
        # Child depends on parent
        order = seed_db.compute_rebuild_order(["EPARENT"])
        assert order == 1

    def test_deep_chain(self, seed_db: SeedStore):
        # Create chain: A(0) -> B(1) -> C(2)
        seed_db.save_credential_seed(
            expected_said="EA", registry_name="reg",
            schema_said="ES", issuer_identity_name="iss",
            recipient_aid=None, attributes={"dt": "now"},
            edges=None, rules=None, private=False, rebuild_order=0,
        )
        seed_db.save_credential_seed(
            expected_said="EB", registry_name="reg",
            schema_said="ES", issuer_identity_name="iss",
            recipient_aid=None, attributes={"dt": "now"},
            edges=None, rules=None, private=False, rebuild_order=1,
        )
        order = seed_db.compute_rebuild_order(["EB"])
        assert order == 2

    def test_unknown_dependency_returns_zero(self, seed_db: SeedStore):
        """If edge SAID doesn't exist in DB, treat as no dependency."""
        order = seed_db.compute_rebuild_order(["EUNKNOWN"])
        assert order == 0


# ============================================================================
# has_seeds tests
# ============================================================================


class TestHasSeeds:
    """Tests for has_seeds check."""

    def test_empty_db(self, seed_db: SeedStore):
        assert seed_db.has_seeds() is False

    def test_after_identity_seed(self, seed_db: SeedStore):
        seed_db.save_identity_seed(
            name="test", expected_aid="EAID",
            transferable=True, icount=1, isith="1", ncount=1, nsith="1",
            witness_aids=[], toad=0,
        )
        assert seed_db.has_seeds() is True
