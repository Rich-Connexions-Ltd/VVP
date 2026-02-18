"""Tests for credential list pagination (Sprint 72).

Tests the ``limit`` and ``offset`` query parameters on ``GET /credential``.
"""
import uuid

import pytest
from httpx import AsyncClient


TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


def _create_test_org(org_type: str = "regular") -> str:
    """Create a test org in DB. Returns org_id."""
    from app.db.session import init_database, SessionLocal
    from app.db.models import Organization

    init_database()
    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=f"pagination-test-{uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=f"E{uuid.uuid4().hex[:43]}",
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=True,
        )
        db.add(org)
        db.commit()
        return org_id
    finally:
        db.close()


async def _setup(client: AsyncClient):
    """Create identity, registry, and org for credential tests."""
    org_id = _create_test_org()
    name = f"pagtest-{uuid.uuid4().hex[:8]}"
    res = await client.post("/identity", json={"name": name, "publish_to_witnesses": False})
    assert res.status_code == 200
    identity = res.json()["identity"]

    reg_name = f"{name}-registry"
    res = await client.post("/registry", json={
        "identity_name": identity["name"],
        "name": reg_name,
    })
    assert res.status_code == 200
    registry = res.json()["registry"]

    # Bind org AID and registry to the DB org
    from app.db.session import SessionLocal
    from app.db.models import Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        org.aid = identity["aid"]
        org.registry_key = registry["registry_key"]
        db.commit()
    finally:
        db.close()

    return identity, registry, org_id


async def _issue_credential(client, registry_name, org_id, tn_suffix):
    """Issue a single TN credential. Returns the credential SAID."""
    res = await client.post("/credential/issue", json={
        "registry_name": registry_name,
        "schema_said": TN_ALLOCATION_SCHEMA,
        "attributes": {
            "numbers": {"tn": [f"+120255500{tn_suffix:02d}"]},
            "channel": "voice",
            "doNotOriginate": False,
        },
        "publish_to_witnesses": False,
        "organization_id": org_id,
    })
    assert res.status_code == 200, f"Issue failed: {res.text}"
    return res.json()["credential"]["said"]


@pytest.mark.asyncio
async def test_pagination_default_response_shape(client: AsyncClient):
    """Paginated response includes total, limit, offset fields."""
    res = await client.get("/credential")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert data["limit"] == 50  # default
    assert data["offset"] == 0  # default


@pytest.mark.asyncio
async def test_pagination_limit_and_offset(client: AsyncClient):
    """Limit and offset control the returned page."""
    identity, registry, org_id = await _setup(client)

    # Issue 5 credentials
    saids = []
    for i in range(5):
        said = await _issue_credential(client, registry["name"], org_id, i + 10)
        saids.append(said)

    # Page 1: limit=2, offset=0
    res = await client.get("/credential?limit=2&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert data["total"] >= 5
    assert data["limit"] == 2
    assert data["offset"] == 0

    # Page 2: limit=2, offset=2
    res = await client.get("/credential?limit=2&offset=2")
    assert res.status_code == 200
    data2 = res.json()
    assert data2["count"] == 2
    assert data2["offset"] == 2

    # Pages should have different credentials
    page1_saids = {c["said"] for c in data["credentials"]}
    page2_saids = {c["said"] for c in data2["credentials"]}
    assert page1_saids.isdisjoint(page2_saids)


@pytest.mark.asyncio
async def test_pagination_offset_beyond_total(client: AsyncClient):
    """Offset beyond total returns empty list."""
    res = await client.get("/credential?limit=10&offset=999999")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 0
    assert len(data["credentials"]) == 0
    assert data["total"] >= 0


@pytest.mark.asyncio
async def test_pagination_with_schema_filter(client: AsyncClient):
    """Pagination works together with schema_said filter."""
    identity, registry, org_id = await _setup(client)

    # Issue 3 TN credentials
    for i in range(3):
        await _issue_credential(client, registry["name"], org_id, i + 20)

    res = await client.get(
        f"/credential?schema_said={TN_ALLOCATION_SCHEMA}&limit=2&offset=0"
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] <= 2
    assert data["limit"] == 2
    # All returned creds should match the schema filter
    for cred in data["credentials"]:
        assert cred["schema_said"] == TN_ALLOCATION_SCHEMA


@pytest.mark.asyncio
async def test_pagination_invalid_limit(client: AsyncClient):
    """Limit=0 or limit>200 returns 422."""
    res = await client.get("/credential?limit=0")
    assert res.status_code == 422

    res = await client.get("/credential?limit=201")
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_pagination_negative_offset(client: AsyncClient):
    """Negative offset returns 422."""
    res = await client.get("/credential?offset=-1")
    assert res.status_code == 422
