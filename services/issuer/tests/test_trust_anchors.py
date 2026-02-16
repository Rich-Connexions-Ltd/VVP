"""Tests for TrustAnchorManager (Sprint 68b).

Tests cover:
- sync_from_agent() creates Organization records from BootstrapStatusResponse
- get_mock_vlei_state() returns cached state or DB fallback
- Idempotent sync (running twice produces same org_ids)
- Uninitialized agent returns None state
"""

import uuid

import pytest

from common.vvp.models.keri_agent import BootstrapStatusResponse

from app.db.models import Organization, OrgType, MockVLEIState as MockVLEIStateModel
from app.org.mock_vlei import MockVLEIState
from app.org.trust_anchors import (
    TrustAnchorManager,
    get_trust_anchor_manager,
    reset_trust_anchor_manager,
)


def _init_app_db():
    """Ensure app database tables exist."""
    from app.db.session import init_database
    init_database()


def _clean_db():
    """Clean DB state from previous tests."""
    _init_app_db()
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        db.query(MockVLEIStateModel).delete()
        # Only delete trust-anchor orgs (by name prefix), not all orgs
        for name_prefix in ("mock-gleif", "mock-qvi", "mock-gsma"):
            db.query(Organization).filter(
                Organization.name.like(f"{name_prefix}%")
            ).delete(synchronize_session="fetch")
        db.commit()
    finally:
        db.close()
    reset_trust_anchor_manager()


def _make_bootstrap_status(
    *,
    initialized: bool = True,
    gleif_aid: str | None = None,
    qvi_aid: str | None = None,
    gsma_aid: str | None = None,
) -> BootstrapStatusResponse:
    """Create a BootstrapStatusResponse with random AIDs."""
    return BootstrapStatusResponse(
        initialized=initialized,
        gleif_aid=gleif_aid or f"E{uuid.uuid4().hex[:43]}",
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=qvi_aid or f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
        gsma_aid=gsma_aid or f"E{uuid.uuid4().hex[:43]}",
        gsma_registry_key=f"E{uuid.uuid4().hex[:43]}",
        gleif_name="mock-gleif",
        qvi_name="mock-qvi",
        gsma_name="mock-gsma",
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        gsma_governance_said=f"E{uuid.uuid4().hex[:43]}",
    )


# =============================================================================
# Singleton Tests
# =============================================================================


def test_singleton():
    """get_trust_anchor_manager returns same instance."""
    reset_trust_anchor_manager()
    tam1 = get_trust_anchor_manager()
    tam2 = get_trust_anchor_manager()
    assert tam1 is tam2
    reset_trust_anchor_manager()


def test_reset_clears_singleton():
    """reset_trust_anchor_manager clears the singleton."""
    reset_trust_anchor_manager()
    tam1 = get_trust_anchor_manager()
    reset_trust_anchor_manager()
    tam2 = get_trust_anchor_manager()
    assert tam1 is not tam2
    reset_trust_anchor_manager()


# =============================================================================
# State Access Tests
# =============================================================================


def test_initial_state_is_none():
    """get_mock_vlei_state returns None before any sync."""
    _clean_db()
    tam = TrustAnchorManager()
    state = tam.get_mock_vlei_state()
    assert state is None


def test_state_cached_after_sync():
    """After sync_from_agent, get_mock_vlei_state returns cached state."""
    _clean_db()
    tam = TrustAnchorManager()
    status = _make_bootstrap_status()

    tam.sync_from_agent(status)
    state = tam.get_mock_vlei_state()

    assert state is not None
    assert state.gleif_aid == status.gleif_aid
    assert state.qvi_aid == status.qvi_aid
    assert state.gsma_aid == status.gsma_aid
    assert state.qvi_credential_said == status.qvi_credential_said
    assert state.gsma_governance_said == status.gsma_governance_said


def test_uninitialized_agent_skips_sync():
    """sync_from_agent with initialized=False does nothing."""
    _clean_db()
    tam = TrustAnchorManager()
    status = BootstrapStatusResponse(initialized=False)

    tam.sync_from_agent(status)
    assert tam.get_mock_vlei_state() is None


# =============================================================================
# Trust Anchor Promotion Tests
# =============================================================================


def test_sync_creates_org_records():
    """sync_from_agent creates Organization records for GLEIF, QVI, GSMA."""
    _clean_db()
    from app.db.session import SessionLocal

    tam = TrustAnchorManager()
    status = _make_bootstrap_status()

    tam.sync_from_agent(status)
    state = tam.get_mock_vlei_state()

    assert state.gleif_org_id != ""
    assert state.qvi_org_id != ""
    assert state.gsma_org_id != ""

    db = SessionLocal()
    try:
        gleif_org = db.query(Organization).filter(
            Organization.id == state.gleif_org_id
        ).first()
        assert gleif_org is not None
        assert gleif_org.org_type == OrgType.ROOT_AUTHORITY.value

        qvi_org = db.query(Organization).filter(
            Organization.id == state.qvi_org_id
        ).first()
        assert qvi_org is not None
        assert qvi_org.org_type == OrgType.QVI.value

        gsma_org = db.query(Organization).filter(
            Organization.id == state.gsma_org_id
        ).first()
        assert gsma_org is not None
        assert gsma_org.org_type == OrgType.VETTER_AUTHORITY.value
    finally:
        db.close()


def test_sync_idempotent():
    """Running sync_from_agent twice with same data produces same org_ids."""
    _clean_db()
    from app.db.session import SessionLocal

    status = _make_bootstrap_status()

    tam = TrustAnchorManager()
    tam.sync_from_agent(status)
    first_gleif_id = tam.get_mock_vlei_state().gleif_org_id
    first_qvi_id = tam.get_mock_vlei_state().qvi_org_id

    # Second sync should find existing orgs by persisted org_id
    tam2 = TrustAnchorManager()
    tam2.sync_from_agent(status)
    assert tam2.get_mock_vlei_state().gleif_org_id == first_gleif_id
    assert tam2.get_mock_vlei_state().qvi_org_id == first_qvi_id

    # No duplicate orgs
    db = SessionLocal()
    try:
        gleif_orgs = db.query(Organization).filter(
            Organization.aid == status.gleif_aid
        ).all()
        assert len(gleif_orgs) == 1
    finally:
        db.close()


def test_sync_without_gsma():
    """sync_from_agent works when GSMA is not set."""
    _clean_db()
    status = BootstrapStatusResponse(
        initialized=True,
        gleif_aid=f"E{uuid.uuid4().hex[:43]}",
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
        gsma_aid=None,
        gsma_registry_key=None,
        gleif_name="mock-gleif",
        qvi_name="mock-qvi",
        gsma_name=None,
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        gsma_governance_said=None,
    )

    tam = TrustAnchorManager()
    tam.sync_from_agent(status)
    state = tam.get_mock_vlei_state()

    assert state.gleif_org_id != ""
    assert state.qvi_org_id != ""
    assert state.gsma_org_id == ""  # Not created


# =============================================================================
# DB Persistence Tests
# =============================================================================


def test_state_survives_manager_restart():
    """State persisted by sync_from_agent is loadable by a new manager."""
    _clean_db()
    status = _make_bootstrap_status()

    tam1 = TrustAnchorManager()
    tam1.sync_from_agent(status)

    # New manager should load from DB
    tam2 = TrustAnchorManager()
    state = tam2.get_mock_vlei_state()

    assert state is not None
    assert state.gleif_aid == status.gleif_aid
    assert state.qvi_aid == status.qvi_aid
    assert state.qvi_credential_said == status.qvi_credential_said


# =============================================================================
# MockVLEIManager Delegation Tests
# =============================================================================


def test_mock_vlei_manager_delegates_promote():
    """MockVLEIManager._promote_trust_anchors delegates to TrustAnchorManager."""
    _clean_db()
    from app.db.session import SessionLocal
    from app.org.mock_vlei import MockVLEIManager

    mgr = MockVLEIManager()
    mgr._state = MockVLEIState(
        gleif_aid=f"E{uuid.uuid4().hex[:43]}",
        gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
        qvi_aid=f"E{uuid.uuid4().hex[:43]}",
        qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
        qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
    )

    mgr._promote_trust_anchors()

    assert mgr._state.gleif_org_id != ""
    assert mgr._state.qvi_org_id != ""

    db = SessionLocal()
    try:
        gleif_org = db.query(Organization).filter(
            Organization.id == mgr._state.gleif_org_id
        ).first()
        assert gleif_org is not None
        assert gleif_org.org_type == OrgType.ROOT_AUTHORITY.value
    finally:
        db.close()


def test_mock_vlei_manager_get_mock_vlei_state():
    """MockVLEIManager.get_mock_vlei_state delegates to TrustAnchorManager."""
    _clean_db()
    from app.org.mock_vlei import MockVLEIManager

    status = _make_bootstrap_status()
    tam = get_trust_anchor_manager()
    tam.sync_from_agent(status)

    mgr = MockVLEIManager()
    state = mgr.get_mock_vlei_state()

    assert state is not None
    assert state.gleif_aid == status.gleif_aid
