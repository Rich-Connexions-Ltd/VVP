"""Tests for Sprint 63: Dossier Creation Wizard.

Tests cover:
- GET /organizations/names endpoint (purpose=ap, purpose=osp, scoping)
- GET /credential filters (schema_said, org_id)
- POST /dossier/create endpoint (edge validation, access control, OSP association)
- GET /dossier/associated endpoint (org-scoped, admin, filtering)
- DossierOspAssociation model (cascade, uniqueness)
- Route ordering (associated vs {said})
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock, AsyncMock

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth.api_key import Principal
from app.db.models import (
    Base,
    DossierOspAssociation,
    ManagedCredential,
    Organization,
)


# =============================================================================
# Schema SAIDs (must match DOSSIER_EDGE_DEFS in app/api/dossier.py)
# =============================================================================

DOSSIER_SCHEMA_SAID = "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"
TNALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"

# Edge-to-schema mapping (from DOSSIER_EDGE_DEFS)
EDGE_SCHEMAS = {
    "vetting": None,        # No schema constraint
    "alloc": GCD_SCHEMA_SAID,
    "tnalloc": TNALLOC_SCHEMA_SAID,
    "delsig": GCD_SCHEMA_SAID,
    "bownr": None,
    "bproxy": None,
}


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )

    # Enable foreign key enforcement (required for CASCADE in SQLite)
    @event.listens_for(engine, "connect")
    def _set_fk_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def ap_org(in_memory_db):
    """Create an AP (Accountable Party) organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="ACME AP Corp",
        pseudo_lei="5493001234567890AB12",
        aid="EAbcdefghijklmnopqrstuvwxyz012345678901234",
        registry_key="Eregkey1234567890123456789012345678901234",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def osp_org(in_memory_db):
    """Create an OSP (Originating Service Provider) organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="TelCo OSP Corp",
        pseudo_lei="5493009876543210XY34",
        aid="Eosp_aid_abcdefghijklmnopqrstuvwxyz012345",
        registry_key="Eospregkey123456789012345678901234567890",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def disabled_org(in_memory_db):
    """Create a disabled organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Disabled Corp",
        pseudo_lei="5493005555555555ZZ56",
        enabled=False,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


def make_admin_principal(organization_id=None):
    """Create admin principal."""
    return Principal(
        key_id="test-admin",
        name="Test Admin",
        roles={"issuer:admin", "issuer:operator", "issuer:readonly"},
        organization_id=organization_id,
    )


def make_operator_principal(organization_id):
    """Create operator principal scoped to an org."""
    return Principal(
        key_id="test-operator",
        name="Test Operator",
        roles={"issuer:operator", "issuer:readonly"},
        organization_id=organization_id,
    )


def make_dossier_manager_principal(organization_id):
    """Create org:dossier_manager principal."""
    return Principal(
        key_id="test-dm",
        name="Test DM",
        roles={"org:dossier_manager"},
        organization_id=organization_id,
    )


def _make_edge_mock(edge_name, owner_aid, **overrides):
    """Create a mock credential for the given edge with correct schema."""
    c = MagicMock()
    c.status = overrides.get("status", "issued")
    c.schema_said = overrides.get("schema_said", EDGE_SCHEMAS.get(edge_name) or GCD_SCHEMA_SAID)
    c.recipient_aid = overrides.get("recipient_aid", owner_aid)
    c.issuer_aid = overrides.get("issuer_aid", owner_aid)
    return c


# =============================================================================
# DossierOspAssociation Model Tests
# =============================================================================


class TestDossierOspAssociation:
    """Unit tests for the DossierOspAssociation model."""

    def test_create_association(self, in_memory_db, ap_org, osp_org):
        """Test creating a dossier-OSP association."""
        assoc = DossierOspAssociation(
            dossier_said="Edossier_said_1234567890123456789012345",
            owner_org_id=ap_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc)
        in_memory_db.commit()
        in_memory_db.refresh(assoc)

        assert assoc.id is not None
        assert assoc.dossier_said == "Edossier_said_1234567890123456789012345"
        assert assoc.owner_org_id == ap_org.id
        assert assoc.osp_org_id == osp_org.id
        assert assoc.created_at is not None

    def test_unique_constraint(self, in_memory_db, ap_org, osp_org):
        """Test unique constraint on (dossier_said, osp_org_id)."""
        said = "Edossier_unique_test_1234567890123456789012"
        assoc1 = DossierOspAssociation(
            dossier_said=said,
            owner_org_id=ap_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc1)
        in_memory_db.commit()

        # Duplicate should fail
        assoc2 = DossierOspAssociation(
            dossier_said=said,
            owner_org_id=ap_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc2)
        with pytest.raises(Exception):  # IntegrityError
            in_memory_db.commit()
        in_memory_db.rollback()

    def test_cascade_delete_owner_org(self, in_memory_db, ap_org, osp_org):
        """Test cascade deletion when owner org is deleted."""
        assoc = DossierOspAssociation(
            dossier_said="Ecascade_test_owner_12345678901234567890",
            owner_org_id=ap_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc)
        in_memory_db.commit()

        # Delete the owner org
        in_memory_db.delete(ap_org)
        in_memory_db.commit()

        # Association should be gone (CASCADE)
        remaining = in_memory_db.query(DossierOspAssociation).filter(
            DossierOspAssociation.dossier_said == "Ecascade_test_owner_12345678901234567890"
        ).all()
        assert len(remaining) == 0

    def test_cascade_delete_osp_org(self, in_memory_db, ap_org, osp_org):
        """Test cascade deletion when OSP org is deleted."""
        assoc = DossierOspAssociation(
            dossier_said="Ecascade_test_osp_123456789012345678901",
            owner_org_id=ap_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc)
        in_memory_db.commit()

        # Delete the OSP org
        in_memory_db.delete(osp_org)
        in_memory_db.commit()

        remaining = in_memory_db.query(DossierOspAssociation).filter(
            DossierOspAssociation.dossier_said == "Ecascade_test_osp_123456789012345678901"
        ).all()
        assert len(remaining) == 0


# =============================================================================
# Organization Names Endpoint Tests
# =============================================================================


def _init_app_db():
    """Ensure app database tables exist (lifespan not invoked in tests)."""
    from app.db.session import init_database
    init_database()


class TestOrganizationNames:
    """Tests for GET /organizations/names endpoint."""

    @pytest.mark.asyncio
    async def test_names_returns_only_enabled(self, client_with_auth, admin_headers):
        """Admin sees all enabled orgs, not disabled ones."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org1 = Organization(
                id=str(uuid.uuid4()),
                name=f"Enabled Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            org2 = Organization(
                id=str(uuid.uuid4()),
                name=f"Disabled Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=False,
            )
            db.add(org1)
            db.add(org2)
            db.commit()
            enabled_name = org1.name
            disabled_name = org2.name
        finally:
            db.close()

        response = await client_with_auth.get(
            "/organizations/names", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()

        org_names = [o["name"] for o in data["organizations"]]
        assert enabled_name in org_names
        assert disabled_name not in org_names

    @pytest.mark.asyncio
    async def test_names_requires_auth(self, client_with_auth):
        """Unauthenticated request returns 401."""
        response = await client_with_auth.get("/organizations/names")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_names_returns_id_and_name_only(self, client_with_auth, admin_headers):
        """Response contains only id and name, no sensitive fields."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Sensitive Fields Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid="Esensitive_aid_1234567890123456789012345",
                registry_key="Esensitive_regkey_12345678901234567890",
                le_credential_said="Esensitive_le_cred_12345678901234567890",
                enabled=True,
            )
            db.add(org)
            db.commit()
        finally:
            db.close()

        response = await client_with_auth.get(
            "/organizations/names", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()

        for org in data["organizations"]:
            assert "id" in org
            assert "name" in org
            assert "aid" not in org
            assert "registry_key" not in org
            assert "le_credential_said" not in org
            assert "pseudo_lei" not in org

    @pytest.mark.asyncio
    async def test_names_invalid_purpose(self, client_with_auth, admin_headers):
        """Invalid purpose returns 400."""
        response = await client_with_auth.get(
            "/organizations/names?purpose=invalid", headers=admin_headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_names_osp_purpose_returns_all_for_any_user(
        self, client_with_auth, readonly_headers
    ):
        """OSP purpose returns all enabled orgs for any authenticated user."""
        _init_app_db()
        from app.db.session import SessionLocal

        unique_name = f"OSP Visible Corp {uuid.uuid4().hex[:8]}"
        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=unique_name,
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
        finally:
            db.close()

        response = await client_with_auth.get(
            "/organizations/names?purpose=osp", headers=readonly_headers
        )
        assert response.status_code == 200
        data = response.json()

        org_names = [o["name"] for o in data["organizations"]]
        assert unique_name in org_names


# =============================================================================
# Credential Filter Tests
# =============================================================================


class TestCredentialFilters:
    """Tests for schema_said and org_id query parameters on GET /credential."""

    @pytest.mark.asyncio
    async def test_org_id_filter_requires_admin(
        self, client_with_auth, operator_headers
    ):
        """Non-admin gets 403 when using org_id filter."""
        response = await client_with_auth.get(
            f"/credential?org_id={uuid.uuid4()}", headers=operator_headers
        )
        assert response.status_code == 403
        assert "admin" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_org_id_filter_invalid_uuid(
        self, client_with_auth, admin_headers
    ):
        """Malformed UUID returns 400."""
        response = await client_with_auth.get(
            "/credential?org_id=not-a-uuid", headers=admin_headers
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_org_id_filter_unknown_org(
        self, client_with_auth, admin_headers
    ):
        """Unknown org UUID returns 404."""
        _init_app_db()
        fake_id = str(uuid.uuid4())
        response = await client_with_auth.get(
            f"/credential?org_id={fake_id}", headers=admin_headers
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_schema_said_filter(self, client):
        """Schema SAID filter returns only matching credentials."""
        from tests.test_credential import setup_identity_and_registry

        identity, registry = await setup_identity_and_registry(client)

        # Issue a TN Allocation credential
        resp1 = await client.post("/credential/issue", json={
            "registry_name": registry["name"],
            "schema_said": TNALLOC_SCHEMA_SAID,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        })
        assert resp1.status_code == 200

        # Issue a GCD credential
        resp2 = await client.post("/credential/issue", json={
            "registry_name": registry["name"],
            "schema_said": GCD_SCHEMA_SAID,
            "attributes": {"d": "", "dt": "2024-01-01T00:00:00Z"},
            "publish_to_witnesses": False,
        })
        assert resp2.status_code == 200

        # Filter by TNALLOC schema
        response = await client.get(f"/credential?schema_said={TNALLOC_SCHEMA_SAID}")
        assert response.status_code == 200
        data = response.json()

        for cred in data["credentials"]:
            assert cred["schema_said"] == TNALLOC_SCHEMA_SAID


# =============================================================================
# Edge Validation Tests (unit tests via mocking)
# =============================================================================


class TestEdgeValidation:
    """Unit tests for _validate_dossier_edges helper."""

    @pytest.mark.asyncio
    async def test_missing_required_edge(self, in_memory_db, ap_org):
        """Omitting a required edge raises 400."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        # Provide only vetting + alloc, missing tnalloc and delsig
        edges = {
            "vetting": "Evetting_said_12345678901234567890123",
            "alloc": "Ealloc_said_123456789012345678901234567",
        }

        with pytest.raises(HTTPException) as exc_info:
            await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
        assert exc_info.value.status_code == 400
        assert "tnalloc" in exc_info.value.detail or "delsig" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_unknown_edge_name(self, in_memory_db, ap_org):
        """Unknown edge name raises 400."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        # Pad SAIDs to 44 chars
        edges = {
            "vetting": "Ev1".ljust(44, "X"),
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
            "unknown_edge": "Eu1".ljust(44, "X"),
        }

        # Register managed creds for all edges so ap_org access checks pass
        for said in edges.values():
            mc = ManagedCredential(
                said=said,
                organization_id=ap_org.id,
                schema_said=GCD_SCHEMA_SAID,
                issuer_aid=ap_org.aid,
            )
            in_memory_db.add(mc)
        in_memory_db.commit()

        def make_cred(said):
            # Determine which edge this SAID belongs to
            for ename, esaid in edges.items():
                if esaid == said:
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "unknown" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_credential_not_found(self, in_memory_db, ap_org):
        """Non-existent credential SAID raises 404."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()
        edges = {
            "vetting": "Enotfound_1234567890123456789012345678",
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
        }

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(return_value=None)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_revoked_credential(self, in_memory_db, ap_org):
        """Revoked credential raises 400."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()
        edges = {
            "vetting": "Erevoked_1234567890123456789012345678",
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
        }

        mock_cred = MagicMock()
        mock_cred.status = "revoked"

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(return_value=mock_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "revoked" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_schema_mismatch(self, in_memory_db, ap_org):
        """Wrong schema on constrained edge raises 400."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        alloc_said = "Ewrong_schema_1234567890123456789012345"

        # Register a managed credential for the AP org
        mc = ManagedCredential(
            said=alloc_said,
            organization_id=ap_org.id,
            schema_said=LE_SCHEMA_SAID,  # Wrong schema for alloc slot
            issuer_aid=ap_org.aid,
        )
        in_memory_db.add(mc)
        in_memory_db.commit()

        edges = {
            "vetting": "Evetting_ok_12345678901234567890123456",
            "alloc": alloc_said,
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
        }

        def make_cred(said):
            if said == alloc_said:
                # alloc slot requires GCD schema but this credential has LE schema
                return _make_edge_mock("alloc", ap_org.aid, schema_said=LE_SCHEMA_SAID)
            for ename, esaid in edges.items():
                if esaid == said:
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "schema" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_delsig_issuer_must_be_ap(self, in_memory_db, ap_org):
        """delsig credential issuer must be the AP org's AID."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        edges = {
            "vetting": "Ev1_ok".ljust(44, "X"),
            "alloc": "Ea1_ok".ljust(44, "X"),
            "tnalloc": "Et1_ok".ljust(44, "X"),
            "delsig": "Ed1_wrong_issuer".ljust(44, "X"),
        }

        # Register managed creds for all edges
        for said in edges.values():
            mc = ManagedCredential(
                said=said,
                organization_id=ap_org.id,
                schema_said=GCD_SCHEMA_SAID,
                issuer_aid=ap_org.aid,
            )
            in_memory_db.add(mc)
        in_memory_db.commit()

        def make_cred(said):
            for ename, esaid in edges.items():
                if esaid == said:
                    if ename == "delsig":
                        # delsig issuer is NOT the AP
                        return _make_edge_mock(
                            ename, ap_org.aid,
                            issuer_aid="Ewrong_issuer_aid_12345678901234567890",
                        )
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "delsig" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_bproxy_required_when_bownr_and_op_differs(self, in_memory_db, ap_org):
        """bproxy is required when bownr present and OP differs from AP (section 6.3.4)."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()
        different_op_aid = "Eop_aid_different_from_ap_12345678901234"

        edges = {
            "vetting": "Ev1".ljust(44, "X"),
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
            "bownr": "Eb1".ljust(44, "X"),
            # No bproxy!
        }

        # Register managed creds
        for said in edges.values():
            mc = ManagedCredential(
                said=said,
                organization_id=ap_org.id,
                schema_said=GCD_SCHEMA_SAID,
                issuer_aid=ap_org.aid,
            )
            in_memory_db.add(mc)
        in_memory_db.commit()

        def make_cred(said):
            for ename, esaid in edges.items():
                if esaid == said:
                    if ename == "delsig":
                        # delsig issuee (recipient) is a different AID → OP != AP
                        return _make_edge_mock(
                            ename, ap_org.aid,
                            recipient_aid=different_op_aid,
                        )
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "bproxy" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_bownr_without_bproxy_ok_when_op_equals_ap(self, in_memory_db, ap_org):
        """bownr without bproxy is OK when OP == AP (self-signing)."""
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        edges = {
            "vetting": "Ev1".ljust(44, "X"),
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1".ljust(44, "X"),
            "bownr": "Eb1".ljust(44, "X"),
        }

        # Register managed creds
        for said in edges.values():
            mc = ManagedCredential(
                said=said,
                organization_id=ap_org.id,
                schema_said=GCD_SCHEMA_SAID,
                issuer_aid=ap_org.aid,
            )
            in_memory_db.add(mc)
        in_memory_db.commit()

        def make_cred(said):
            for ename, esaid in edges.items():
                if esaid == said:
                    # All creds: issuer=AP, recipient=AP (OP == AP)
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            result_edges, delsig_issuee = await _validate_dossier_edges(
                in_memory_db, principal, ap_org, edges
            )
            # Should succeed — no HTTPException
            assert "vetting" in result_edges
            assert "bownr" in result_edges
            assert delsig_issuee == ap_org.aid


# =============================================================================
# Associated Dossiers Endpoint Tests
# =============================================================================


class TestAssociatedDossiers:
    """Tests for GET /dossier/associated endpoint."""

    @pytest.mark.asyncio
    async def test_associated_requires_auth(self, client_with_auth):
        """Unauthenticated request returns 401."""
        response = await client_with_auth.get("/dossier/associated")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_associated_admin_sees_all(self, client_with_auth, admin_headers):
        """Admin sees all associations."""
        _init_app_db()
        from app.db.session import SessionLocal

        dossier_said = f"Eassoc_test_{uuid.uuid4().hex[:32]}"

        db = SessionLocal()
        try:
            org1 = Organization(
                id=str(uuid.uuid4()),
                name=f"Assoc AP Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            org2 = Organization(
                id=str(uuid.uuid4()),
                name=f"Assoc OSP Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            db.add(org1)
            db.add(org2)
            db.flush()

            assoc = DossierOspAssociation(
                dossier_said=dossier_said,
                owner_org_id=org1.id,
                osp_org_id=org2.id,
            )
            db.add(assoc)
            db.commit()
            ap_name = org1.name
            osp_name = org2.name
        finally:
            db.close()

        response = await client_with_auth.get(
            "/dossier/associated", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] >= 1

        # Should include org names
        found = False
        for a in data["associations"]:
            if a["dossier_said"] == dossier_said:
                found = True
                assert a["owner_org_name"] == ap_name
                assert a["osp_org_name"] == osp_name
        assert found

    @pytest.mark.asyncio
    async def test_associated_empty_for_no_org_principal(self, client_with_auth, admin_headers):
        """Principal without org gets empty list (admin override sees all though)."""
        _init_app_db()
        # The admin_headers principal has no organization_id but is_system_admin
        # so it sees all. This test verifies the endpoint doesn't crash.
        response = await client_with_auth.get(
            "/dossier/associated", headers=admin_headers
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_associated_admin_org_id_filter(self, client_with_auth, admin_headers):
        """Admin with org_id filter sees only associations for that OSP org."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            ap = Organization(
                id=str(uuid.uuid4()),
                name=f"Filter AP {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            osp1 = Organization(
                id=str(uuid.uuid4()),
                name=f"Filter OSP1 {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            osp2 = Organization(
                id=str(uuid.uuid4()),
                name=f"Filter OSP2 {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=True,
            )
            db.add_all([ap, osp1, osp2])
            db.flush()

            # Associate dossier A with osp1 and dossier B with osp2
            assoc1 = DossierOspAssociation(
                dossier_said=f"Efilter_a_{uuid.uuid4().hex[:32]}",
                owner_org_id=ap.id,
                osp_org_id=osp1.id,
            )
            assoc2 = DossierOspAssociation(
                dossier_said=f"Efilter_b_{uuid.uuid4().hex[:32]}",
                owner_org_id=ap.id,
                osp_org_id=osp2.id,
            )
            db.add_all([assoc1, assoc2])
            db.commit()
            osp1_id = osp1.id
            said_a = assoc1.dossier_said
            said_b = assoc2.dossier_said
        finally:
            db.close()

        # Filter by osp1
        response = await client_with_auth.get(
            f"/dossier/associated?org_id={osp1_id}", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        returned_saids = [a["dossier_said"] for a in data["associations"]]
        assert said_a in returned_saids
        assert said_b not in returned_saids


# =============================================================================
# Route Ordering Tests
# =============================================================================


class TestRouteOrdering:
    """Test that /create and /associated don't get captured by /{said}."""

    @pytest.mark.asyncio
    async def test_associated_not_captured_by_said(self, client_with_auth, admin_headers):
        """GET /dossier/associated returns 200, not routed to GET /dossier/{said}."""
        _init_app_db()
        response = await client_with_auth.get(
            "/dossier/associated", headers=admin_headers
        )
        # Should be 200 (associated endpoint), not 404 (dossier not found)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_not_captured_by_said(self, client_with_auth, admin_headers):
        """POST /dossier/create goes to create handler, not /{said} handler."""
        response = await client_with_auth.post(
            "/dossier/create",
            json={"owner_org_id": str(uuid.uuid4()), "edges": {}},
            headers=admin_headers,
        )
        # Should be a validation error (400 or 404 for missing org), not a routing error
        assert response.status_code in (400, 404, 422)


# =============================================================================
# Dossier Create API Tests
# =============================================================================


class TestDossierCreateAPI:
    """API-level tests for POST /dossier/create."""

    @pytest.mark.asyncio
    async def test_create_requires_auth(self, client_with_auth):
        """Unauthenticated request returns 401."""
        response = await client_with_auth.post(
            "/dossier/create",
            json={"owner_org_id": str(uuid.uuid4()), "edges": {}},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_org_not_found(self, client_with_auth, admin_headers):
        """Non-existent org returns 404."""
        _init_app_db()
        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": str(uuid.uuid4()),
                "edges": {
                    "vetting": "Ev",
                    "alloc": "Ea",
                    "tnalloc": "Et",
                    "delsig": "Ed",
                },
            },
            headers=admin_headers,
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_disabled_org(self, client_with_auth, admin_headers):
        """Disabled org returns 400."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Create Disabled Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                enabled=False,
            )
            db.add(org)
            db.commit()
            org_id = org.id
        finally:
            db.close()

        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": org_id,
                "edges": {
                    "vetting": "Ev",
                    "alloc": "Ea",
                    "tnalloc": "Et",
                    "delsig": "Ed",
                },
            },
            headers=admin_headers,
        )
        assert response.status_code == 400
        assert "disabled" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_missing_required_edge(self, client_with_auth, admin_headers):
        """Missing required edge returns 400."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Missing Edge Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            org_id = org.id
        finally:
            db.close()

        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": org_id,
                "edges": {
                    "vetting": "Ev1",
                    # Missing alloc, tnalloc, delsig
                },
            },
            headers=admin_headers,
        )
        assert response.status_code == 400


# =============================================================================
# Credential List Integration Tests (with auth disabled client)
# =============================================================================


class TestCredentialListIntegration:
    """Integration tests for credential listing with schema filters."""

    @pytest.mark.asyncio
    async def test_schema_filter_empty_result(self, client):
        """Filtering by schema with no matches returns empty list."""
        response = await client.get(
            f"/credential?schema_said={DOSSIER_SCHEMA_SAID}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 0
        assert data["credentials"] == []


# =============================================================================
# Additional Edge Validation Tests (reviewer-requested)
# =============================================================================


class TestDelsigIssueeValidation:
    """Tests for delsig recipient_aid (OP) presence enforcement."""

    @pytest.mark.asyncio
    async def test_delsig_without_recipient_raises(self, in_memory_db, ap_org):
        """delsig credential with no recipient AID raises 400."""
        from fastapi import HTTPException
        from app.api.dossier import _validate_dossier_edges

        principal = make_admin_principal()

        edges = {
            "vetting": "Ev1".ljust(44, "X"),
            "alloc": "Ea1".ljust(44, "X"),
            "tnalloc": "Et1".ljust(44, "X"),
            "delsig": "Ed1_no_rcpt".ljust(44, "X"),
        }

        for said in edges.values():
            mc = ManagedCredential(
                said=said,
                organization_id=ap_org.id,
                schema_said=GCD_SCHEMA_SAID,
                issuer_aid=ap_org.aid,
            )
            in_memory_db.add(mc)
        in_memory_db.commit()

        def make_cred(said):
            for ename, esaid in edges.items():
                if esaid == said:
                    if ename == "delsig":
                        # delsig with no recipient (NI2I, recipient_aid is None)
                        return _make_edge_mock(
                            ename, ap_org.aid, recipient_aid=None,
                        )
                    return _make_edge_mock(ename, ap_org.aid)
            return _make_edge_mock("vetting", ap_org.aid)

        mock_issuer = AsyncMock()
        mock_issuer.get_credential = AsyncMock(side_effect=make_cred)

        with patch("app.api.dossier.get_credential_issuer", return_value=mock_issuer):
            with pytest.raises(HTTPException) as exc_info:
                await _validate_dossier_edges(in_memory_db, principal, ap_org, edges)
            assert exc_info.value.status_code == 400
            assert "recipient" in exc_info.value.detail.lower() or "OP" in exc_info.value.detail


class TestOspConsistency:
    """Tests for strict OSP organization validation."""

    @pytest.mark.asyncio
    async def test_osp_without_aid_rejected(self, client_with_auth, admin_headers):
        """OSP org without AID returns 400 during dossier creation."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            # AP org with full credentials
            ap = Organization(
                id=str(uuid.uuid4()),
                name=f"Strict AP {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            # OSP org WITHOUT aid
            osp = Organization(
                id=str(uuid.uuid4()),
                name=f"No AID OSP {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=None,  # No AID
                enabled=True,
            )
            db.add(ap)
            db.add(osp)
            db.commit()
            ap_id = ap.id
            osp_id = osp.id
        finally:
            db.close()

        # Mock edge validation to pass — isolate OSP validation
        mock_edges = ({"vetting": {"n": "Ev"}}, f"E{uuid.uuid4().hex[:43]}")
        with patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev",
                        "alloc": "Ea",
                        "tnalloc": "Et",
                        "delsig": "Ed",
                    },
                    "osp_org_id": osp_id,
                },
                headers=admin_headers,
            )
        # OSP validation runs before credential issuance, so we get a clean 400
        # (OSP has no AID), not a side-effect-producing error later
        assert response.status_code == 400
        assert "AID" in response.json()["detail"] or "aid" in response.json()["detail"].lower()


# =============================================================================
# Audit Logging Tests
# =============================================================================


class TestDossierAuditLogging:
    """Tests verifying audit logging call counts and arguments."""

    def _setup_happy_path_mocks(self, org_aid, dossier_said):
        """Build mock objects for a successful dossier creation."""
        from app.keri.issuer import CredentialInfo

        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            None,
        )
        mock_cred = CredentialInfo(
            said=dossier_said, issuer_aid=org_aid, recipient_aid=None,
            registry_key=f"E{uuid.uuid4().hex[:43]}", schema_said=DOSSIER_SCHEMA_SAID,
            issuance_dt="2026-01-01T00:00:00.000000+00:00", status="issued",
            revocation_dt=None, attributes={"d": "", "dt": "2026-01-01T00:00:00.000000+00:00"},
            edges=None, rules=None,
        )
        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        return mock_edges, mock_issuer, mock_reg_mgr

    @pytest.mark.asyncio
    async def test_create_org_not_found_no_audit(self, client_with_auth, admin_headers):
        """Failed creation (org not found) does not produce audit log."""
        _init_app_db()

        mock_audit = MagicMock()
        with patch("app.api.dossier.get_audit_logger", return_value=mock_audit):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": str(uuid.uuid4()),
                    "edges": {"vetting": "Ev", "alloc": "Ea", "tnalloc": "Et", "delsig": "Ed"},
                },
                headers=admin_headers,
            )
        assert response.status_code == 404
        mock_audit.log_access.assert_not_called()

    @pytest.mark.asyncio
    async def test_success_emits_create_audit(self, client_with_auth, admin_headers):
        """Successful creation emits exactly one dossier.create audit event."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Audit Org {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            org_id, org_aid = org.id, org.aid
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges, mock_issuer, mock_reg_mgr = self._setup_happy_path_mocks(org_aid, dossier_said)
        mock_audit = MagicMock()

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),
            patch("app.api.dossier.get_audit_logger", return_value=mock_audit),
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": org_id,
                    "edges": {"vetting": "Ev", "alloc": "Ea", "tnalloc": "Et", "delsig": "Ed"},
                },
                headers=admin_headers,
            )

        assert response.status_code == 200
        # Exactly 1 audit call: dossier.create (no OSP)
        assert mock_audit.log_access.call_count == 1
        call_args = mock_audit.log_access.call_args
        assert call_args.kwargs["action"] == "dossier.create"
        assert call_args.kwargs["resource"] == dossier_said
        assert call_args.kwargs["details"]["owner_org_id"] == org_id
        assert call_args.kwargs["details"]["osp_org_id"] is None

    @pytest.mark.asyncio
    async def test_success_with_osp_emits_two_audit_events(self, client_with_auth, admin_headers):
        """Successful creation with OSP emits dossier.create + dossier.osp_associate."""
        _init_app_db()
        from app.db.session import SessionLocal

        osp_aid = f"E{uuid.uuid4().hex[:43]}"
        db = SessionLocal()
        try:
            ap = Organization(
                id=str(uuid.uuid4()),
                name=f"Audit AP {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            osp = Organization(
                id=str(uuid.uuid4()),
                name=f"Audit OSP {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=osp_aid,
                enabled=True,
            )
            db.add(ap)
            db.add(osp)
            db.commit()
            ap_id, ap_aid = ap.id, ap.aid
            osp_id = osp.id
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            osp_aid,
        )
        mock_edges_tuple, mock_issuer, mock_reg_mgr = self._setup_happy_path_mocks(ap_aid, dossier_said)
        mock_audit = MagicMock()

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),
            patch("app.api.dossier.get_audit_logger", return_value=mock_audit),
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {"vetting": "Ev", "alloc": "Ea", "tnalloc": "Et", "delsig": "Ed"},
                    "osp_org_id": osp_id,
                },
                headers=admin_headers,
            )

        assert response.status_code == 200
        # Exactly 2 audit calls: dossier.create + dossier.osp_associate
        assert mock_audit.log_access.call_count == 2
        actions = [c.kwargs["action"] for c in mock_audit.log_access.call_args_list]
        assert actions == ["dossier.create", "dossier.osp_associate"]
        # Verify OSP details in second call
        osp_call = mock_audit.log_access.call_args_list[1]
        assert osp_call.kwargs["details"]["osp_org_id"] == osp_id


class TestDossierCreateEdgeValidationAPI:
    """API-level tests for edge validation within POST /dossier/create."""

    @pytest.mark.asyncio
    async def test_create_with_unknown_edge_returns_400(self, client_with_auth, admin_headers):
        """Unknown edge name in create request returns 400."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Unknown Edge Corp {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            org_id = org.id
        finally:
            db.close()

        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": org_id,
                "edges": {
                    "vetting": "Ev", "alloc": "Ea", "tnalloc": "Et", "delsig": "Ed",
                    "bogus_edge": "Eb",
                },
            },
            headers=admin_headers,
        )
        # Unknown edge name is caught in fast-fail validation before KERI init
        assert response.status_code == 400
        assert "unknown" in response.json()["detail"].lower()


# =============================================================================
# Happy-Path Tests (reviewer-requested: successful creation, OSP, witness fail)
# =============================================================================


class TestDossierCreateHappyPath:
    """End-to-end happy-path tests for POST /dossier/create with mocked KERI."""

    def _setup_org(self, db, *, aid=None, registry_key=None, enabled=True):
        """Create and persist an Organization, returning it."""
        org = Organization(
            id=str(uuid.uuid4()),
            name=f"HappyOrg {uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=aid or f"E{uuid.uuid4().hex[:43]}",
            registry_key=registry_key or f"E{uuid.uuid4().hex[:43]}",
            enabled=enabled,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return org

    def _mock_cred_info(self, said, issuer_aid):
        """Build a mock CredentialInfo matching issue_credential return."""
        from app.keri.issuer import CredentialInfo
        return CredentialInfo(
            said=said,
            issuer_aid=issuer_aid,
            recipient_aid=None,
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            schema_said=DOSSIER_SCHEMA_SAID,
            issuance_dt="2026-01-01T00:00:00.000000+00:00",
            status="issued",
            revocation_dt=None,
            attributes={"d": "", "dt": "2026-01-01T00:00:00.000000+00:00"},
            edges=None,
            rules=None,
        )

    @pytest.mark.asyncio
    async def test_create_required_edges_only(self, client_with_auth, admin_headers):
        """Successful dossier creation with 4 required edges, no optional."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            ap = self._setup_org(db)
            ap_id, ap_aid = ap.id, ap.aid
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {
                "vetting": {"n": "Ev"},
                "alloc": {"n": "Ea"},
                "tnalloc": {"n": "Et"},
                "delsig": {"n": "Ed"},
            },
            None,  # delsig_issuee_aid
        )
        mock_cred = self._mock_cred_info(dossier_said, ap_aid)

        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))
        mock_issuer.get_anchor_ixn_bytes = AsyncMock(return_value=b"\x00")

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),  # no witnesses
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea",
                        "tnalloc": "Et", "delsig": "Ed",
                    },
                    "name": "Test Dossier",
                },
                headers=admin_headers,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["dossier_said"] == dossier_said
        assert body["issuer_aid"] == ap_aid
        assert body["schema_said"] == DOSSIER_SCHEMA_SAID
        assert body["edge_count"] == 4
        assert body["name"] == "Test Dossier"
        assert body["osp_org_id"] is None
        assert body["publish_results"] is None  # no witnesses configured

        # Verify ManagedCredential persisted in DB
        db2 = SessionLocal()
        try:
            mc = db2.query(ManagedCredential).filter(ManagedCredential.said == dossier_said).first()
            assert mc is not None
            assert mc.organization_id == ap_id
            assert mc.schema_said == DOSSIER_SCHEMA_SAID
        finally:
            db2.close()

    @pytest.mark.asyncio
    async def test_create_with_optional_edges(self, client_with_auth, admin_headers):
        """Successful dossier creation with all 6 edges (4 required + 2 optional)."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            ap = self._setup_org(db)
            ap_id, ap_aid = ap.id, ap.aid
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {
                "vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
                "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"},
                "bownr": {"n": "Eb"}, "bproxy": {"n": "Ep"},
            },
            f"E{uuid.uuid4().hex[:43]}",  # delsig issuee AID
        )
        mock_cred = self._mock_cred_info(dossier_said, ap_aid)

        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea", "tnalloc": "Et",
                        "delsig": "Ed", "bownr": "Eb", "bproxy": "Ep",
                    },
                },
                headers=admin_headers,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["edge_count"] == 6
        assert body["dossier_said"] == dossier_said

    @pytest.mark.asyncio
    async def test_create_with_osp_association(self, client_with_auth, admin_headers):
        """Successful creation + OSP association persists DossierOspAssociation."""
        _init_app_db()
        from app.db.session import SessionLocal

        osp_aid = f"E{uuid.uuid4().hex[:43]}"
        db = SessionLocal()
        try:
            ap = self._setup_org(db)
            osp = self._setup_org(db, aid=osp_aid)
            ap_id, ap_aid = ap.id, ap.aid
            osp_id = osp.id
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            osp_aid,  # delsig issuee matches OSP AID
        )
        mock_cred = self._mock_cred_info(dossier_said, ap_aid)

        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea",
                        "tnalloc": "Et", "delsig": "Ed",
                    },
                    "osp_org_id": osp_id,
                },
                headers=admin_headers,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["osp_org_id"] == osp_id
        assert body["dossier_said"] == dossier_said

        # Verify DossierOspAssociation persisted
        db2 = SessionLocal()
        try:
            assoc = db2.query(DossierOspAssociation).filter(
                DossierOspAssociation.dossier_said == dossier_said
            ).first()
            assert assoc is not None
            assert assoc.owner_org_id == ap_id
            assert assoc.osp_org_id == osp_id
        finally:
            db2.close()

    @pytest.mark.asyncio
    async def test_witness_publish_failure_nonfatal(self, client_with_auth, admin_headers):
        """Witness publish failure does not block dossier creation."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            ap = self._setup_org(db)
            ap_id, ap_aid = ap.id, ap.aid
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            None,
        )
        mock_cred = self._mock_cred_info(dossier_said, ap_aid)

        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))
        mock_issuer.get_anchor_ixn_bytes = AsyncMock(side_effect=Exception("IXN bytes not found"))

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", ["http://witness:5642"]),
        ):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea",
                        "tnalloc": "Et", "delsig": "Ed",
                    },
                },
                headers=admin_headers,
            )

        # Dossier creation succeeds despite witness publish failure
        assert response.status_code == 200
        body = response.json()
        assert body["dossier_said"] == dossier_said
        assert body["publish_results"] is None  # failure path logs error, returns None

    @pytest.mark.asyncio
    async def test_osp_aid_mismatch_rejected(self, client_with_auth, admin_headers):
        """OSP AID differing from delsig issuee AID returns 400."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            ap = self._setup_org(db)
            osp = self._setup_org(db, aid=f"E{uuid.uuid4().hex[:43]}")
            ap_id = ap.id
            osp_id = osp.id
        finally:
            db.close()

        # Edge validation returns a delsig_issuee_aid that does NOT match OSP
        different_aid = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            different_aid,  # different from osp.aid
        )

        with patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges):
            response = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": ap_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea",
                        "tnalloc": "Et", "delsig": "Ed",
                    },
                    "osp_org_id": osp_id,
                },
                headers=admin_headers,
            )

        assert response.status_code == 400
        assert "delsig" in response.json()["detail"].lower()
        assert "AID" in response.json()["detail"]


# =============================================================================
# Cross-Org Access Control Tests (reviewer-requested)
# =============================================================================


class TestCrossOrgAccess:
    """Tests verifying tenant isolation for non-admin principals."""

    @pytest.mark.asyncio
    async def test_nonadmin_cross_org_create_rejected(self, client_with_auth, operator_headers):
        """Non-admin operator attempting to create dossier for another org gets 403."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            # Create an org that the operator principal does NOT belong to
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Other Org {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            org_id = org.id
        finally:
            db.close()

        # Operator has issuer:operator (passes write role check) but
        # has organization_id=None — mismatch triggers cross-org 403
        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": org_id,
                "edges": {
                    "vetting": "Ev", "alloc": "Ea",
                    "tnalloc": "Et", "delsig": "Ed",
                },
            },
            headers=operator_headers,
        )
        assert response.status_code == 403
        assert "own organization" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_readonly_cannot_create_dossier(self, client_with_auth, readonly_headers):
        """Readonly principal cannot create dossiers (insufficient write role)."""
        _init_app_db()
        response = await client_with_auth.post(
            "/dossier/create",
            json={
                "owner_org_id": str(uuid.uuid4()),
                "edges": {
                    "vetting": "Ev", "alloc": "Ea",
                    "tnalloc": "Et", "delsig": "Ed",
                },
            },
            headers=readonly_headers,
        )
        assert response.status_code == 403


# =============================================================================
# Dossier Create-then-Build Integration Test (reviewer-requested)
# =============================================================================


class TestDossierBuildability:
    """Verify that a created dossier can be built via POST /dossier/build."""

    @pytest.mark.asyncio
    async def test_created_dossier_is_buildable(self, client_with_auth, admin_headers):
        """After successful creation, the dossier SAID can be used with /dossier/build."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Build Test Org {uuid.uuid4().hex[:8]}",
                pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
                aid=f"E{uuid.uuid4().hex[:43]}",
                registry_key=f"E{uuid.uuid4().hex[:43]}",
                enabled=True,
            )
            db.add(org)
            db.commit()
            org_id, org_aid = org.id, org.aid
        finally:
            db.close()

        dossier_said = f"E{uuid.uuid4().hex[:43]}"
        mock_edges = (
            {"vetting": {"n": "Ev"}, "alloc": {"n": "Ea"},
             "tnalloc": {"n": "Et"}, "delsig": {"n": "Ed"}},
            None,
        )

        from app.keri.issuer import CredentialInfo
        mock_cred = CredentialInfo(
            said=dossier_said,
            issuer_aid=org_aid,
            recipient_aid=None,
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            schema_said=DOSSIER_SCHEMA_SAID,
            issuance_dt="2026-01-01T00:00:00.000000+00:00",
            status="issued",
            revocation_dt=None,
            attributes={"d": "", "dt": "2026-01-01T00:00:00.000000+00:00"},
            edges=None,
            rules=None,
        )

        mock_issuer = AsyncMock()
        mock_issuer.issue_credential = AsyncMock(return_value=(mock_cred, b"\x00"))

        mock_registry_info = MagicMock()
        mock_registry_info.name = "test-registry"
        mock_reg_mgr = AsyncMock()
        mock_reg_mgr.get_registry = AsyncMock(return_value=mock_registry_info)

        # Step 1: Create the dossier
        with (
            patch("app.api.dossier._validate_dossier_edges", new_callable=AsyncMock, return_value=mock_edges),
            patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer),
            patch("app.keri.registry.get_registry_manager", new_callable=AsyncMock, return_value=mock_reg_mgr),
            patch("app.api.dossier.WITNESS_IURLS", []),
        ):
            create_resp = await client_with_auth.post(
                "/dossier/create",
                json={
                    "owner_org_id": org_id,
                    "edges": {
                        "vetting": "Ev", "alloc": "Ea",
                        "tnalloc": "Et", "delsig": "Ed",
                    },
                },
                headers=admin_headers,
            )
        assert create_resp.status_code == 200
        created_said = create_resp.json()["dossier_said"]

        # Step 2: Verify the created dossier is known to the build endpoint
        # (build will try KERI lookup which is mocked, so we expect a build error
        # not a "credential not found in managed table" error)
        build_resp = await client_with_auth.post(
            "/dossier/build",
            json={"root_said": created_said, "format": "json"},
            headers=admin_headers,
        )
        # The dossier SAID exists in ManagedCredential, so access control passes.
        # The actual build fails because KERI credential data is mocked, but we
        # verify the dossier is accessible (not 403/404 from access control).
        assert build_resp.status_code != 403, "Dossier should be accessible after creation"
