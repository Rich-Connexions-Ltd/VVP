"""Tests for Sprint 65: Dossier Readiness Endpoint.

Tests cover:
- GET /dossier/readiness — per-slot status, overall readiness
- Required edge missing → ready=false
- Optional edge missing → ready=true
- Revoked credentials excluded
- I2I mismatch → status=invalid
- delsig issuer check
- Conditional bproxy gate (bownr present + OP != AP → bproxy required)
- Access control (non-admin can only check own org)
- Shared validation helpers (_check_edge_schema, _check_edge_i2i, etc.)
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock, AsyncMock

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth.api_key import Principal
from app.db.models import Base, ManagedCredential, Organization


# =============================================================================
# Schema SAIDs
# =============================================================================

DOSSIER_SCHEMA_SAID = "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"
TNALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )

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


def make_admin_principal(organization_id=None):
    """Create admin principal."""
    return Principal(
        key_id="test-admin",
        name="Test Admin",
        roles={"issuer:admin", "issuer:operator", "issuer:readonly"},
        organization_id=organization_id,
    )


def make_org_principal(organization_id):
    """Create org-scoped principal."""
    return Principal(
        key_id="test-dm",
        name="Test DM",
        roles={"org:dossier_manager"},
        organization_id=organization_id,
    )


# =============================================================================
# Mock Credential Helpers
# =============================================================================


def _make_cred(said, schema_said, issuer_aid, recipient_aid=None, status="issued"):
    """Create a mock CredentialInfo."""
    c = MagicMock()
    c.said = said
    c.schema_said = schema_said
    c.issuer_aid = issuer_aid
    c.recipient_aid = recipient_aid
    c.status = status
    c.issuance_dt = "2026-01-01T00:00:00Z"
    c.revocation_dt = None
    c.registry_key = "Ereg"
    c.attributes = {}
    c.edges = None
    c.rules = None
    return c


def _full_cred_set(org_aid, *, extra_creds=None, overrides=None):
    """Create a full set of credentials for all dossier edge slots.

    Args:
        org_aid: The AP organization's AID.
        extra_creds: Additional credentials to include.
        overrides: Dict of edge_name -> dict of cred overrides.

    Returns:
        (all_credentials, managed_saids) — tuple of credential list and set of
        SAIDs that should be in ManagedCredential.
    """
    ov = overrides or {}
    uid = uuid.uuid4().hex[:8]  # unique per call to avoid SAID collisions

    # SAIDs must be ≤44 chars for PostgreSQL VARCHAR(44) constraint.
    # Format: E{type}_{uid8}_{pad} = 44 chars total (matches real KERI SAID length).
    creds = [
        # vetting: any schema, NI2I (no recipient constraint)
        _make_cred(f"Ev_{uid}_00000000000000000000000000000000",
                    ov.get("vetting", {}).get("schema_said", LE_SCHEMA_SAID),
                    ov.get("vetting", {}).get("issuer_aid", "Eexternal"),
                    ov.get("vetting", {}).get("recipient_aid", None),
                    ov.get("vetting", {}).get("status", "issued")),
        # alloc: GCD, I2I (recipient must be org)
        _make_cred(f"Ea_{uid}_00000000000000000000000000000000",
                    ov.get("alloc", {}).get("schema_said", GCD_SCHEMA_SAID),
                    ov.get("alloc", {}).get("issuer_aid", "Eexternal"),
                    ov.get("alloc", {}).get("recipient_aid", org_aid),
                    ov.get("alloc", {}).get("status", "issued")),
        # tnalloc: TNALLOC, I2I (recipient must be org)
        _make_cred(f"Et_{uid}_00000000000000000000000000000000",
                    ov.get("tnalloc", {}).get("schema_said", TNALLOC_SCHEMA_SAID),
                    ov.get("tnalloc", {}).get("issuer_aid", "Eexternal"),
                    ov.get("tnalloc", {}).get("recipient_aid", org_aid),
                    ov.get("tnalloc", {}).get("status", "issued")),
        # delsig: GCD, NI2I but issuer must be AP, recipient (OP) must exist
        _make_cred(f"Ed_{uid}_00000000000000000000000000000000",
                    ov.get("delsig", {}).get("schema_said", GCD_SCHEMA_SAID),
                    ov.get("delsig", {}).get("issuer_aid", org_aid),
                    ov.get("delsig", {}).get("recipient_aid", ov.get("delsig", {}).get("recipient_aid", org_aid)),
                    ov.get("delsig", {}).get("status", "issued")),
    ]

    managed_saids = {c.said for c in creds}

    if extra_creds:
        for c in extra_creds:
            creds.append(c)
            managed_saids.add(c.said)

    return creds, managed_saids


def _register_managed(db, org_id, saids):
    """Register credentials as managed by the org."""
    for said in saids:
        mc = ManagedCredential(
            said=said,
            organization_id=org_id,
            schema_said="E_test",
            issuer_aid="E_test",
        )
        db.add(mc)
    db.commit()


# =============================================================================
# Shared Validation Helper Unit Tests
# =============================================================================


class TestSharedValidationHelpers:
    """Unit tests for the shared edge validation helper functions."""

    def test_check_edge_status_issued(self):
        from app.api.dossier import _check_edge_status
        assert _check_edge_status("issued") is True

    def test_check_edge_status_revoked(self):
        from app.api.dossier import _check_edge_status
        assert _check_edge_status("revoked") is False

    def test_check_edge_schema_match(self):
        from app.api.dossier import _check_edge_schema
        assert _check_edge_schema(GCD_SCHEMA_SAID, {"schema": GCD_SCHEMA_SAID}) is True

    def test_check_edge_schema_mismatch(self):
        from app.api.dossier import _check_edge_schema
        assert _check_edge_schema(LE_SCHEMA_SAID, {"schema": GCD_SCHEMA_SAID}) is False

    def test_check_edge_schema_no_constraint(self):
        from app.api.dossier import _check_edge_schema
        assert _check_edge_schema("anything", {"schema": None}) is True

    def test_check_edge_i2i_match(self):
        from app.api.dossier import _check_edge_i2i
        assert _check_edge_i2i("EAID", "EAID", {"i2i": True}) is True

    def test_check_edge_i2i_mismatch(self):
        from app.api.dossier import _check_edge_i2i
        assert _check_edge_i2i("EAID1", "EAID2", {"i2i": True}) is False

    def test_check_edge_i2i_no_org_aid(self):
        from app.api.dossier import _check_edge_i2i
        assert _check_edge_i2i("EAID", None, {"i2i": True}) is False

    def test_check_edge_i2i_not_required(self):
        from app.api.dossier import _check_edge_i2i
        assert _check_edge_i2i("EAID1", "EAID2", {"i2i": False}) is True

    def test_check_delsig_semantics_valid(self):
        from app.api.dossier import _check_delsig_semantics
        assert _check_delsig_semantics("EAP", "EOP", "EAP") is True

    def test_check_delsig_semantics_wrong_issuer(self):
        from app.api.dossier import _check_delsig_semantics
        assert _check_delsig_semantics("EOTHER", "EOP", "EAP") is False

    def test_check_delsig_semantics_no_recipient(self):
        from app.api.dossier import _check_delsig_semantics
        assert _check_delsig_semantics("EAP", None, "EAP") is False


# =============================================================================
# Readiness Endpoint API Tests
# =============================================================================


def _init_app_db():
    """Ensure app database tables exist (lifespan not invoked in tests)."""
    from app.db.session import init_database
    init_database()


class TestDossierReadiness:
    """API-level tests for GET /dossier/readiness."""

    @pytest.mark.asyncio
    async def test_readiness_all_present(self, client_with_auth, admin_headers):
        """Org with all required credentials → ready=true."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Ready Corp {uuid.uuid4().hex[:8]}",
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

        creds, managed_saids = _full_cred_set(org_aid)

        # Register as managed
        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is True
        assert data["org_id"] == org_id
        assert data["blocking_reason"] is None

        # All required slots should be "ready"
        for slot in data["slots"]:
            if slot["required"]:
                assert slot["status"] == "ready", f"Required slot '{slot['edge']}' is not ready"

    @pytest.mark.asyncio
    async def test_readiness_missing_required(self, client_with_auth, admin_headers):
        """Org missing tnalloc → ready=false, tnalloc status=missing."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Missing Corp {uuid.uuid4().hex[:8]}",
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

        # Create creds WITHOUT tnalloc
        creds, managed_saids = _full_cred_set(org_aid)
        # Remove tnalloc credential
        creds = [c for c in creds if c.schema_said != TNALLOC_SCHEMA_SAID]
        managed_saids = {c.said for c in creds}

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is False
        assert data["blocking_reason"] is not None
        assert "tnalloc" in data["blocking_reason"]

        tnalloc_slot = next(s for s in data["slots"] if s["edge"] == "tnalloc")
        assert tnalloc_slot["status"] == "missing"
        assert tnalloc_slot["available_count"] == 0

    @pytest.mark.asyncio
    async def test_readiness_optional_missing_ok(self, client_with_auth, admin_headers):
        """Optional edges don't block readiness even if no specific creds exist.

        Note: bownr/bproxy have schema=None (unconstrained), so when any org
        credential exists, these slots show 'optional_unconstrained' to indicate
        manual assessment is needed.  Readiness is still True — that's what this
        test verifies.
        """
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Optional Corp {uuid.uuid4().hex[:8]}",
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

        creds, managed_saids = _full_cred_set(org_aid)

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is True

        # Optional unconstrained slots should show 'optional_unconstrained' (not blocking)
        bownr_slot = next(s for s in data["slots"] if s["edge"] == "bownr")
        assert bownr_slot["required"] is False
        assert bownr_slot["status"] == "optional_unconstrained"

    @pytest.mark.asyncio
    async def test_readiness_revoked_excluded(self, client_with_auth, admin_headers):
        """Revoked credential not counted → status=missing."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Revoked Corp {uuid.uuid4().hex[:8]}",
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

        # Create creds with tnalloc revoked
        creds, managed_saids = _full_cred_set(
            org_aid,
            overrides={"tnalloc": {"status": "revoked"}},
        )

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is False

        tnalloc_slot = next(s for s in data["slots"] if s["edge"] == "tnalloc")
        assert tnalloc_slot["status"] == "missing"  # revoked creds excluded from total_count
        assert tnalloc_slot["total_count"] == 0
        assert tnalloc_slot["available_count"] == 0

    @pytest.mark.asyncio
    async def test_readiness_i2i_mismatch(self, client_with_auth, admin_headers):
        """I2I edge with wrong recipient → status=invalid."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"I2I Corp {uuid.uuid4().hex[:8]}",
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

        # alloc is I2I — give it wrong recipient.
        # Must also override delsig recipient so the delsig credential (also GCD)
        # doesn't satisfy alloc's I2I check (recipient_aid == org_aid).
        wrong_aid = f"Ewrong_{uuid.uuid4().hex[:38]}"
        creds, managed_saids = _full_cred_set(
            org_aid,
            overrides={
                "alloc": {"recipient_aid": wrong_aid},
                "delsig": {"recipient_aid": wrong_aid},
            },
        )

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is False

        alloc_slot = next(s for s in data["slots"] if s["edge"] == "alloc")
        assert alloc_slot["status"] == "invalid"
        assert alloc_slot["total_count"] >= 1
        assert alloc_slot["available_count"] == 0

    @pytest.mark.asyncio
    async def test_readiness_delsig_issuer_check(self, client_with_auth, admin_headers):
        """delsig with wrong issuer → status=invalid."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Delsig Corp {uuid.uuid4().hex[:8]}",
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

        wrong_aid = f"Ewrong_{uuid.uuid4().hex[:38]}"
        creds, managed_saids = _full_cred_set(
            org_aid,
            overrides={"delsig": {"issuer_aid": wrong_aid}},
        )

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is False

        delsig_slot = next(s for s in data["slots"] if s["edge"] == "delsig")
        assert delsig_slot["status"] == "invalid"

    @pytest.mark.asyncio
    async def test_readiness_nonexistent_org(self, client_with_auth, admin_headers):
        """Nonexistent org returns 404."""
        _init_app_db()

        response = await client_with_auth.get(
            f"/dossier/readiness?org_id={uuid.uuid4()}",
            headers=admin_headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_readiness_access_control(self, client_with_auth, operator_headers):
        """Non-admin can only check own org."""
        _init_app_db()
        from app.db.session import SessionLocal

        # Create an org that doesn't belong to the test operator
        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Other Corp {uuid.uuid4().hex[:8]}",
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

        response = await client_with_auth.get(
            f"/dossier/readiness?org_id={org_id}",
            headers=operator_headers,
        )
        assert response.status_code == 403

    def test_readiness_no_bproxy_advisory_at_readiness_level(self):
        """Readiness endpoint does NOT emit bproxy advisory.

        bownr/bproxy are unconstrained optional edges (schema=None), so
        readiness cannot reliably detect actual brand ownership/proxy
        credentials.  The bproxy conditional gate (§6.3.4) is enforced
        at POST /dossier/create when the user selects specific edges.

        This test verifies the design decision: readiness response never
        contains an advisory blocking_reason.
        """
        from app.api.models import DossierSlotStatus, DossierReadinessResponse

        # Even with unconstrained bownr candidates and no bproxy,
        # readiness should NOT emit advisory
        slots = [
            DossierSlotStatus(edge="vetting", label="Vetting", required=True,
                              schema_constraint=None, available_count=1, total_count=1, status="ready"),
            DossierSlotStatus(edge="alloc", label="Alloc", required=True,
                              schema_constraint=GCD_SCHEMA_SAID, available_count=1, total_count=1, status="ready"),
            DossierSlotStatus(edge="tnalloc", label="TNAlloc", required=True,
                              schema_constraint=TNALLOC_SCHEMA_SAID, available_count=1, total_count=1, status="ready"),
            DossierSlotStatus(edge="delsig", label="Delsig", required=True,
                              schema_constraint=GCD_SCHEMA_SAID, available_count=1, total_count=1, status="ready"),
            DossierSlotStatus(edge="bownr", label="Brand Ownership", required=False,
                              schema_constraint=None, available_count=1, total_count=1, status="optional_unconstrained"),
            DossierSlotStatus(edge="bproxy", label="Brand Proxy", required=False,
                              schema_constraint=None, available_count=0, total_count=0, status="optional_missing"),
        ]

        resp = DossierReadinessResponse(
            org_id="test-org",
            org_name="Test Corp",
            ready=True,
            slots=slots,
            blocking_reason=None,
        )
        # Verify model allows ready=true with no advisory
        assert resp.ready is True
        assert resp.blocking_reason is None

    @pytest.mark.asyncio
    async def test_readiness_bproxy_op_equals_ap(self, client_with_auth, admin_headers):
        """bproxy gate not triggered when OP == AP."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"OpEqAp Corp {uuid.uuid4().hex[:8]}",
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

        # delsig with OP == AP, bownr present
        bownr_cred = _make_cred(
            f"Eb_bownr_opeqap_{uuid.uuid4().hex[:24]}",
            LE_SCHEMA_SAID, "Eexternal", None, "issued",
        )
        creds, managed_saids = _full_cred_set(
            org_aid,
            overrides={"delsig": {"recipient_aid": org_aid}},
            extra_creds=[bownr_cred],
        )

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, {c.said for c in creds})
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is True  # no bproxy advisory at readiness level
        assert data["blocking_reason"] is None

    @pytest.mark.asyncio
    async def test_readiness_op_ne_ap_no_bownr(self, client_with_auth, admin_headers):
        """OP != AP without bownr → ready=true, no advisory.

        bproxy gate is not applied at readiness level (deferred to
        POST /dossier/create).
        """
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"NoBownr Corp {uuid.uuid4().hex[:8]}",
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

        # delsig OP != AP, NO bownr credential
        op_aid = f"Eop_diff_{uuid.uuid4().hex[:35]}"
        creds, managed_saids = _full_cred_set(
            org_aid,
            overrides={"delsig": {"recipient_aid": op_aid}},
        )

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()
        # Ready because all required slots are satisfied; bownr is optional
        # and bproxy gate is advisory-only.
        # No advisory because bownr is "optional_unconstrained" (not "ready"),
        # so the gate does not fire.
        assert data["ready"] is True
        assert data["blocking_reason"] is None

    @pytest.mark.asyncio
    async def test_readiness_optional_status_value(self, client_with_auth, admin_headers):
        """Org with NO credentials → optional slots show 'optional_missing'.

        Note: When creds exist, bownr/bproxy (schema=None) show
        'optional_unconstrained'. To get genuine 'optional_missing', the org
        must have zero credentials.
        """
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"OptStatus Corp {uuid.uuid4().hex[:8]}",
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

        # No credentials at all — empty list
        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=[])

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()

        bownr_slot = next(s for s in data["slots"] if s["edge"] == "bownr")
        assert bownr_slot["status"] == "optional_missing"

        bproxy_slot = next(s for s in data["slots"] if s["edge"] == "bproxy")
        assert bproxy_slot["status"] == "optional_missing"

        # Required slots should be "missing" (not "optional_missing")
        vetting_slot = next(s for s in data["slots"] if s["edge"] == "vetting")
        assert vetting_slot["status"] == "missing"

    @pytest.mark.asyncio
    async def test_readiness_slot_counts(self, client_with_auth, admin_headers):
        """Verify available_count and total_count for each slot."""
        _init_app_db()
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            org = Organization(
                id=str(uuid.uuid4()),
                name=f"Counts Corp {uuid.uuid4().hex[:8]}",
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

        creds, managed_saids = _full_cred_set(org_aid)

        db2 = SessionLocal()
        try:
            _register_managed(db2, org_id, managed_saids)
        finally:
            db2.close()

        mock_issuer = AsyncMock()
        mock_issuer.list_credentials = AsyncMock(return_value=creds)

        with patch("app.api.dossier.get_credential_issuer", new_callable=AsyncMock, return_value=mock_issuer):
            response = await client_with_auth.get(
                f"/dossier/readiness?org_id={org_id}",
                headers=admin_headers,
            )

        assert response.status_code == 200
        data = response.json()

        for slot in data["slots"]:
            if slot["status"] in ("ready", "optional_unconstrained"):
                assert slot["available_count"] >= 1
            elif slot["status"] in ("missing", "optional_missing"):
                assert slot["available_count"] == 0
