"""Tests for SeedStore delete methods and query helpers.

Sprint 73: Credential & Identity Cleanup — Cascade Delete and Bulk Purge.
"""
import json
import os
import importlib

import pytest

from app.db.models import (
    KeriCredentialSeed,
    KeriIdentitySeed,
    KeriRotationSeed,
)
from app.keri.seed_store import SeedStore, reset_seed_store


@pytest.fixture
def seed_db(tmp_path):
    """Set up an isolated SQLite seed database for testing."""
    db_path = tmp_path / "test_seeds.db"
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")
    original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")

    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["VVP_KERI_AGENT_DATA_DIR"] = str(tmp_path)

    import app.config as config_module
    importlib.reload(config_module)
    import app.db.session as session_module
    importlib.reload(session_module)

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


def _add_identity(store, name, aid, metadata=None):
    """Helper to add an identity seed."""
    store.save_identity_seed(
        name=name, expected_aid=aid,
        transferable=True, icount=1, isith="1", ncount=1, nsith="1",
        witness_aids=[], toad=0, metadata=metadata,
    )


def _add_credential(store, said, issuer_name="issuer", schema="ESCHEMA", rebuild_order=0, edge_saids=None):
    """Helper to add a credential seed."""
    store.save_credential_seed(
        expected_said=said, registry_name="reg",
        schema_said=schema, issuer_identity_name=issuer_name,
        recipient_aid=None, attributes={"dt": "2026-01-01T00:00:00Z"},
        edges=None, rules=None, private=False,
        rebuild_order=rebuild_order, edge_saids=edge_saids,
    )


# ============================================================================
# Credential Seed Delete
# ============================================================================


class TestDeleteCredentialSeed:
    """Tests for delete_credential_seed."""

    def test_delete_existing(self, seed_db: SeedStore):
        _add_credential(seed_db, "ESAID1")
        assert seed_db.delete_credential_seed("ESAID1") is True
        assert seed_db.get_all_credential_seeds() == []

    def test_delete_nonexistent(self, seed_db: SeedStore):
        assert seed_db.delete_credential_seed("ENOEXIST") is False

    def test_delete_one_of_many(self, seed_db: SeedStore):
        _add_credential(seed_db, "ESAID1")
        _add_credential(seed_db, "ESAID2")
        _add_credential(seed_db, "ESAID3")
        seed_db.delete_credential_seed("ESAID2")
        remaining = seed_db.get_all_credential_seeds()
        assert [s.expected_said for s in remaining] == ["ESAID1", "ESAID3"]


class TestDeleteCredentialSeedsBulk:
    """Tests for delete_credential_seeds_bulk."""

    def test_bulk_delete(self, seed_db: SeedStore):
        for i in range(5):
            _add_credential(seed_db, f"ESAID{i}")
        count = seed_db.delete_credential_seeds_bulk(["ESAID1", "ESAID3"])
        assert count == 2
        remaining = seed_db.get_all_credential_seeds()
        assert len(remaining) == 3

    def test_bulk_delete_empty_list(self, seed_db: SeedStore):
        _add_credential(seed_db, "ESAID1")
        count = seed_db.delete_credential_seeds_bulk([])
        assert count == 0
        assert len(seed_db.get_all_credential_seeds()) == 1

    def test_bulk_delete_nonexistent(self, seed_db: SeedStore):
        _add_credential(seed_db, "ESAID1")
        count = seed_db.delete_credential_seeds_bulk(["ENOEXIST"])
        assert count == 0
        assert len(seed_db.get_all_credential_seeds()) == 1


# ============================================================================
# Identity Seed Delete
# ============================================================================


class TestDeleteIdentitySeed:
    """Tests for delete_identity_seed."""

    def test_delete_existing(self, seed_db: SeedStore):
        _add_identity(seed_db, "test-id", "EAID1")
        assert seed_db.delete_identity_seed("test-id") is True
        assert seed_db.get_all_identity_seeds() == []

    def test_delete_nonexistent(self, seed_db: SeedStore):
        assert seed_db.delete_identity_seed("nope") is False

    def test_delete_cascades_rotation_seeds(self, seed_db: SeedStore):
        _add_identity(seed_db, "rotating-id", "EAID1")
        seed_db.save_rotation_seed("rotating-id", sequence_number=1)
        seed_db.save_rotation_seed("rotating-id", sequence_number=2)

        seed_db.delete_identity_seed("rotating-id")

        assert seed_db.get_all_identity_seeds() == []
        assert seed_db.get_rotations_for_identity("rotating-id") == []

    def test_delete_does_not_affect_other_identities(self, seed_db: SeedStore):
        _add_identity(seed_db, "id-1", "EAID1")
        _add_identity(seed_db, "id-2", "EAID2")
        seed_db.save_rotation_seed("id-1", sequence_number=1)
        seed_db.save_rotation_seed("id-2", sequence_number=1)

        seed_db.delete_identity_seed("id-1")

        assert len(seed_db.get_all_identity_seeds()) == 1
        assert seed_db.get_all_identity_seeds()[0].name == "id-2"
        assert len(seed_db.get_rotations_for_identity("id-2")) == 1


class TestDeleteIdentitySeedByAid:
    """Tests for delete_identity_seed_by_aid."""

    def test_delete_by_aid(self, seed_db: SeedStore):
        _add_identity(seed_db, "test-id", "EAID_TO_DELETE")
        assert seed_db.delete_identity_seed_by_aid("EAID_TO_DELETE") is True
        assert seed_db.get_all_identity_seeds() == []

    def test_delete_by_aid_nonexistent(self, seed_db: SeedStore):
        assert seed_db.delete_identity_seed_by_aid("ENOEXIST") is False

    def test_delete_by_aid_cascades_rotations(self, seed_db: SeedStore):
        _add_identity(seed_db, "rot-id", "EAID_ROT")
        seed_db.save_rotation_seed("rot-id", sequence_number=1)
        seed_db.save_rotation_seed("rot-id", sequence_number=2)

        seed_db.delete_identity_seed_by_aid("EAID_ROT")

        assert seed_db.get_all_identity_seeds() == []
        assert seed_db.get_rotations_for_identity("rot-id") == []


class TestDeleteIdentitySeedsBulk:
    """Tests for delete_identity_seeds_bulk."""

    def test_bulk_delete(self, seed_db: SeedStore):
        for i in range(4):
            _add_identity(seed_db, f"id-{i}", f"EAID{i}")
        count = seed_db.delete_identity_seeds_bulk(["id-0", "id-2"])
        assert count == 2
        remaining = seed_db.get_all_identity_seeds()
        assert len(remaining) == 2
        assert {s.name for s in remaining} == {"id-1", "id-3"}

    def test_bulk_delete_cascades_rotations(self, seed_db: SeedStore):
        _add_identity(seed_db, "id-a", "EAIDA")
        _add_identity(seed_db, "id-b", "EAIDB")
        seed_db.save_rotation_seed("id-a", sequence_number=1)
        seed_db.save_rotation_seed("id-b", sequence_number=1)

        seed_db.delete_identity_seeds_bulk(["id-a"])

        assert seed_db.get_rotations_for_identity("id-a") == []
        assert len(seed_db.get_rotations_for_identity("id-b")) == 1


# ============================================================================
# Query Helpers
# ============================================================================


class TestGetCredentialSeedsByIssuer:
    """Tests for get_credential_seeds_by_issuer."""

    def test_filter_by_issuer(self, seed_db: SeedStore):
        _add_credential(seed_db, "ECRED1", issuer_name="alice")
        _add_credential(seed_db, "ECRED2", issuer_name="bob")
        _add_credential(seed_db, "ECRED3", issuer_name="alice")

        alice_creds = seed_db.get_credential_seeds_by_issuer("alice")
        assert len(alice_creds) == 2
        assert {s.expected_said for s in alice_creds} == {"ECRED1", "ECRED3"}

    def test_empty_result(self, seed_db: SeedStore):
        _add_credential(seed_db, "ECRED1", issuer_name="alice")
        assert seed_db.get_credential_seeds_by_issuer("nobody") == []


class TestGetCredentialSeedsBySchema:
    """Tests for get_credential_seeds_by_schema."""

    def test_filter_by_schema(self, seed_db: SeedStore):
        _add_credential(seed_db, "ECRED1", schema="ESCHEMA_A")
        _add_credential(seed_db, "ECRED2", schema="ESCHEMA_B")
        _add_credential(seed_db, "ECRED3", schema="ESCHEMA_A")

        result = seed_db.get_credential_seeds_by_schema("ESCHEMA_A")
        assert len(result) == 2


class TestGetIdentitySeedByAid:
    """Tests for get_identity_seed_by_aid."""

    def test_found(self, seed_db: SeedStore):
        _add_identity(seed_db, "my-id", "EAID_MINE")
        seed = seed_db.get_identity_seed_by_aid("EAID_MINE")
        assert seed is not None
        assert seed.name == "my-id"

    def test_not_found(self, seed_db: SeedStore):
        assert seed_db.get_identity_seed_by_aid("ENOEXIST") is None
