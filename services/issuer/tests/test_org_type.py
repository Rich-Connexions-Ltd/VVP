"""Tests for Sprint 67 Phase 1: Organization Type Model.

Tests cover:
- OrgType enum values
- org_type column defaults and persistence
- org_type in API responses
- Trust anchor org_type immutability
- Bootstrap idempotency
- Name collision safety
"""

import uuid

import pytest
from httpx import AsyncClient

from app.db.models import Organization, OrgType, MockVLEIState as MockVLEIStateModel


def _init_app_db():
    """Ensure app database tables exist."""
    from app.db.session import init_database
    init_database()


def unique_name(prefix: str = "test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_db_org(*, name=None, org_type="regular", aid=None):
    """Create an org directly in the database."""
    _init_app_db()
    from app.db.session import SessionLocal

    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=name or unique_name("org"),
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=aid or f"E{uuid.uuid4().hex[:43]}",
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=True,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return {"id": org.id, "name": org.name, "aid": org.aid, "org_type": org.org_type}
    finally:
        db.close()


# =============================================================================
# OrgType enum
# =============================================================================


def test_org_type_enum_values():
    """OrgType enum has the four expected values."""
    assert OrgType.ROOT_AUTHORITY.value == "root_authority"
    assert OrgType.QVI.value == "qvi"
    assert OrgType.VETTER_AUTHORITY.value == "vetter_authority"
    assert OrgType.REGULAR.value == "regular"


def test_org_type_enum_is_str():
    """OrgType enum members are strings."""
    assert isinstance(OrgType.REGULAR, str)
    assert OrgType.REGULAR == "regular"


# =============================================================================
# org_type column default and persistence
# =============================================================================


def test_org_type_defaults_to_regular():
    """New orgs without explicit org_type get 'regular'."""
    _init_app_db()
    from app.db.session import SessionLocal

    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=unique_name("default-type"),
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            enabled=True,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        assert org.org_type == "regular"
    finally:
        db.close()


def test_org_type_persists_across_sessions():
    """org_type survives DB reload."""
    _init_app_db()
    from app.db.session import SessionLocal

    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=unique_name("persist"),
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            org_type=OrgType.VETTER_AUTHORITY.value,
            enabled=True,
        )
        db.add(org)
        db.commit()
    finally:
        db.close()

    # Reload in new session
    db2 = SessionLocal()
    try:
        reloaded = db2.query(Organization).filter(Organization.id == org_id).first()
        assert reloaded is not None
        assert reloaded.org_type == "vetter_authority"
    finally:
        db2.close()


def test_trust_anchor_org_types():
    """Trust anchor orgs can be created with non-regular types."""
    for ot in [OrgType.ROOT_AUTHORITY, OrgType.QVI, OrgType.VETTER_AUTHORITY]:
        org = _create_db_org(org_type=ot.value)
        assert org["org_type"] == ot.value


# =============================================================================
# API responses include org_type
# =============================================================================


@pytest.mark.asyncio
async def test_get_org_includes_org_type(client: AsyncClient):
    """GET /organizations/{id} returns org_type."""
    org = _create_db_org(org_type="vetter_authority")
    response = await client.get(f"/organizations/{org['id']}")
    assert response.status_code == 200
    data = response.json()
    assert data["org_type"] == "vetter_authority"


@pytest.mark.asyncio
async def test_list_orgs_includes_org_type(client: AsyncClient):
    """GET /organizations returns org_type in each org."""
    org = _create_db_org(org_type="qvi")
    response = await client.get("/organizations")
    assert response.status_code == 200
    data = response.json()
    # Find our org
    found = [o for o in data["organizations"] if o["id"] == org["id"]]
    assert len(found) == 1
    assert found[0]["org_type"] == "qvi"


@pytest.mark.asyncio
async def test_create_org_defaults_to_regular(client: AsyncClient):
    """POST /organizations creates org with regular type by default.

    Sprint 68b: Uses MockKeriAgentClient (installed by client fixture) for
    identity/registry creation. Only mock_vlei and trust_anchor_manager
    need explicit patching since they're not behind the keri_client.
    """
    from unittest.mock import patch, AsyncMock, MagicMock

    name = unique_name("api-create")

    # mock_vlei is still accessed directly (not via keri_client)
    # trust_anchor_manager.get_mock_vlei_state() provides qvi_aid for LE credential recording
    mock_tam_state = MagicMock()
    mock_tam_state.qvi_aid = f"E{uuid.uuid4().hex[:43]}"

    with patch("app.api.organization.get_mock_vlei_manager") as mock_vlei, \
         patch("app.org.trust_anchors.get_trust_anchor_manager") as mock_tam:

        mock_vlei.return_value.issue_le_credential = AsyncMock(return_value=f"E{uuid.uuid4().hex[:43]}")
        mock_tam.return_value.get_mock_vlei_state.return_value = mock_tam_state

        response = await client.post("/organizations", json={"name": name})

    assert response.status_code == 200, f"Create org failed: {response.text}"
    data = response.json()
    assert data["org_type"] == "regular"


# =============================================================================
# MockVLEIState org_id columns
# =============================================================================


def test_mock_vlei_state_org_id_columns():
    """MockVLEIState DB model has org_id columns."""
    _init_app_db()
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        # Clean up any existing state
        db.query(MockVLEIStateModel).delete()
        db.commit()

        state = MockVLEIStateModel(
            gleif_aid="EGLEIF_AID_TEST1234567890123456789012345",
            gleif_registry_key="EREG_GLEIF_TEST123456789012345678901234",
            qvi_aid="EQVI_AID_TEST12345678901234567890123456",
            qvi_credential_said="EQVI_CRED_TEST1234567890123456789012345",
            qvi_registry_key="EREG_QVI_TEST1234567890123456789012345",
            gleif_org_id="11111111-1111-1111-1111-111111111111",
            qvi_org_id="22222222-2222-2222-2222-222222222222",
            gsma_org_id="33333333-3333-3333-3333-333333333333",
        )
        db.add(state)
        db.commit()
        db.refresh(state)

        assert state.gleif_org_id == "11111111-1111-1111-1111-111111111111"
        assert state.qvi_org_id == "22222222-2222-2222-2222-222222222222"
        assert state.gsma_org_id == "33333333-3333-3333-3333-333333333333"
    finally:
        # Clean up
        db.query(MockVLEIStateModel).delete()
        db.commit()
        db.close()


# =============================================================================
# Trust anchor promotion (mock_vlei._promote_trust_anchors)
# =============================================================================


def test_promote_trust_anchors_creates_orgs():
    """_promote_trust_anchors creates Organization records for each trust anchor."""
    _init_app_db()
    from app.db.session import SessionLocal
    from app.org.mock_vlei import MockVLEIManager, MockVLEIState

    mgr = MockVLEIManager()
    mgr._state = MockVLEIState(
        gleif_aid=f"E{uuid.uuid4().hex[:43]}",
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=f"E{uuid.uuid4().hex[:43]}",
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
        gsma_aid=f"E{uuid.uuid4().hex[:43]}",
        gsma_registry_key=f"E{uuid.uuid4().hex[:43]}",
    )

    mgr._promote_trust_anchors()

    assert mgr._state.gleif_org_id != ""
    assert mgr._state.qvi_org_id != ""
    assert mgr._state.gsma_org_id != ""

    # Verify orgs exist in DB with correct types
    db = SessionLocal()
    try:
        gleif_org = db.query(Organization).filter(Organization.id == mgr._state.gleif_org_id).first()
        assert gleif_org is not None
        assert gleif_org.org_type == "root_authority"

        qvi_org = db.query(Organization).filter(Organization.id == mgr._state.qvi_org_id).first()
        assert qvi_org is not None
        assert qvi_org.org_type == "qvi"

        gsma_org = db.query(Organization).filter(Organization.id == mgr._state.gsma_org_id).first()
        assert gsma_org is not None
        assert gsma_org.org_type == "vetter_authority"
    finally:
        db.close()


def test_promote_trust_anchors_idempotent():
    """Running _promote_trust_anchors twice produces same org_ids, no duplicates."""
    _init_app_db()
    from app.db.session import SessionLocal
    from app.org.mock_vlei import MockVLEIManager, MockVLEIState

    gleif_aid = f"E{uuid.uuid4().hex[:43]}"
    qvi_aid = f"E{uuid.uuid4().hex[:43]}"

    mgr = MockVLEIManager()
    mgr._state = MockVLEIState(
        gleif_aid=gleif_aid,
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=qvi_aid,
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
    )

    mgr._promote_trust_anchors()
    first_gleif_id = mgr._state.gleif_org_id
    first_qvi_id = mgr._state.qvi_org_id

    # Run again with persisted org_ids
    mgr._promote_trust_anchors()
    assert mgr._state.gleif_org_id == first_gleif_id
    assert mgr._state.qvi_org_id == first_qvi_id

    # Verify no duplicate orgs
    db = SessionLocal()
    try:
        gleif_orgs = db.query(Organization).filter(Organization.aid == gleif_aid).all()
        assert len(gleif_orgs) == 1
    finally:
        db.close()


def test_name_collision_safety():
    """Creating a regular org with the same name as a trust anchor triggers disambiguation."""
    _init_app_db()
    from app.db.session import SessionLocal
    from app.org.mock_vlei import MockVLEIManager, MockVLEIState

    # Use unique collision name to avoid cross-test interference
    collision_name = unique_name("collision")

    # Create a regular org with that name
    regular_org = _create_db_org(name=collision_name, org_type="regular")

    # Create manager that will try to use the same name via MOCK_GLEIF_NAME override
    gleif_aid = f"E{uuid.uuid4().hex[:43]}"
    mgr = MockVLEIManager()
    mgr._state = MockVLEIState(
        gleif_aid=gleif_aid,
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=f"E{uuid.uuid4().hex[:43]}",
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
    )

    # Patch MOCK_GLEIF_NAME to match the collision name
    # Sprint 68b: promotion delegates to trust_anchors.py, so patch there too
    from unittest.mock import patch
    with patch("app.org.mock_vlei.MOCK_GLEIF_NAME", collision_name), \
         patch("app.org.trust_anchors.MOCK_GLEIF_NAME", collision_name):
        mgr._promote_trust_anchors()

    # The regular org should be untouched
    db = SessionLocal()
    try:
        reg = db.query(Organization).filter(Organization.id == regular_org["id"]).first()
        assert reg.org_type == "regular"
        assert reg.name == collision_name

        # The trust anchor org should have a disambiguated name
        ta = db.query(Organization).filter(Organization.id == mgr._state.gleif_org_id).first()
        assert ta is not None
        assert ta.org_type == "root_authority"
        assert ta.name.startswith(f"{collision_name}-ta-")
    finally:
        db.close()


@pytest.mark.asyncio
async def test_patch_org_type_mutation_rejected(client: AsyncClient):
    """PATCH /organizations/{id} rejects org_type field (extra='forbid')."""
    org = _create_db_org(org_type="regular")
    response = await client.patch(
        f"/organizations/{org['id']}",
        json={"org_type": "root_authority"},
    )
    # Pydantic extra='forbid' triggers 422 Unprocessable Entity
    assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"
    # Verify the error mentions the forbidden field
    detail = response.json().get("detail", [])
    assert any("org_type" in str(err) for err in detail), f"Error should mention org_type: {detail}"


@pytest.mark.asyncio
async def test_patch_org_type_with_valid_fields_succeeds(client: AsyncClient):
    """PATCH /organizations/{id} with only valid fields (name, enabled) succeeds."""
    org = _create_db_org(org_type="regular", name=f"rename-test-{uuid.uuid4().hex[:8]}")
    new_name = f"renamed-{uuid.uuid4().hex[:8]}"
    response = await client.patch(
        f"/organizations/{org['id']}",
        json={"name": new_name},
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    assert response.json()["name"] == new_name
    # org_type should remain unchanged
    assert response.json()["org_type"] == "regular"


def test_migration_backfill():
    """Pre-Sprint67 MockVLEIState without org_ids triggers promotion on load."""
    _init_app_db()
    from app.db.session import SessionLocal
    from app.org.mock_vlei import MockVLEIManager, MockVLEIState

    gleif_aid = f"E{uuid.uuid4().hex[:43]}"

    # Simulate pre-Sprint67: state has AIDs but no org_ids
    mgr = MockVLEIManager()
    mgr._state = MockVLEIState(
        gleif_aid=gleif_aid,
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=f"E{uuid.uuid4().hex[:43]}",
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
        gleif_org_id="",  # Not set
        qvi_org_id="",    # Not set
    )

    mgr._promote_trust_anchors()

    # Now org_ids should be populated
    assert mgr._state.gleif_org_id != ""
    assert mgr._state.qvi_org_id != ""

    # Verify org exists
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == mgr._state.gleif_org_id).first()
        assert org is not None
        assert org.aid == gleif_aid
        assert org.org_type == "root_authority"
    finally:
        db.close()
