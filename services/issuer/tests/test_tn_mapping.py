"""Tests for Sprint 42 TN Mapping module.

Tests cover:
- TNMappingStore CRUD operations
- Organization scoping (cross-org access denied)
- Duplicate TN rejection
- TN lookup with valid/invalid API keys
- TN lookup for unmapped numbers
- TN ownership validation
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock, AsyncMock

import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.api_key import Principal
from app.db.models import (
    Base,
    Organization,
    OrgAPIKey,
    OrgAPIKeyRole,
    ManagedCredential,
    TNMapping,
    DossierOspAssociation,
)
from app.tn.store import TNMappingStore
from app.tn.lookup import (
    lookup_tn_with_validation,
    validate_tn_ownership,
    tn_in_ranges,
    tn_to_int,
    TNLookupResult,
)

# Patch targets for auth functions (they are imported inside lookup_tn_with_validation)
GET_API_KEY_STORE_PATCH = "app.auth.api_key.get_api_key_store"
VERIFY_ORG_API_KEY_PATCH = "app.auth.api_key.verify_org_api_key"
GET_KERI_CLIENT_PATCH = "app.keri_client.get_keri_client"


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def test_org(in_memory_db):
    """Create a test organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Test Telecom",
        pseudo_lei="5493001234567890AB12",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def other_org(in_memory_db):
    """Create another test organization."""
    org = Organization(
        id=str(uuid.uuid4()),
        name="Other Telecom",
        pseudo_lei="5493009876543210XY34",
        enabled=True,
    )
    in_memory_db.add(org)
    in_memory_db.commit()
    in_memory_db.refresh(org)
    return org


@pytest.fixture
def test_org_api_key(in_memory_db, test_org):
    """Create a test org API key."""
    raw_key = "test-org-api-key-tn-12345"
    key = OrgAPIKey(
        id=str(uuid.uuid4()),
        name="Test TN API Key",
        key_hash=bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode(),
        organization_id=test_org.id,
        revoked=False,
    )
    in_memory_db.add(key)

    # Add dossier_manager role
    role = OrgAPIKeyRole(
        key_id=key.id,
        role="org:dossier_manager",
    )
    in_memory_db.add(role)

    in_memory_db.commit()
    in_memory_db.refresh(key)
    return key, raw_key


@pytest.fixture
def test_tn_mapping(in_memory_db, test_org):
    """Create a test TN mapping."""
    mapping = TNMapping(
        id=str(uuid.uuid4()),
        tn="+15551234567",
        organization_id=test_org.id,
        dossier_said="E" + "a" * 43,  # 44 char SAID
        identity_name="test-identity",
        brand_name="Test Telecom",
        brand_logo_url="https://example.com/logo.png",
        enabled=True,
    )
    in_memory_db.add(mapping)
    in_memory_db.commit()
    in_memory_db.refresh(mapping)
    return mapping


# =============================================================================
# TNMappingStore Tests
# =============================================================================


class TestTNMappingStore:
    """Test TNMappingStore CRUD operations."""

    def test_create_mapping(self, in_memory_db, test_org):
        """Test creating a TN mapping."""
        store = TNMappingStore(in_memory_db)

        mapping = store.create(
            org_id=test_org.id,
            tn="+15559876543",
            dossier_said="E" + "b" * 43,
            identity_name="new-identity",
            brand_name="New Brand",
            brand_logo_url="https://example.com/new-logo.png",
        )

        assert mapping is not None
        assert mapping.tn == "+15559876543"
        assert mapping.organization_id == test_org.id
        assert mapping.dossier_said == "E" + "b" * 43
        assert mapping.identity_name == "new-identity"
        assert mapping.brand_name == "New Brand"
        assert mapping.enabled is True

    def test_get_mapping_by_id(self, in_memory_db, test_tn_mapping):
        """Test getting a mapping by ID."""
        store = TNMappingStore(in_memory_db)

        mapping = store.get(test_tn_mapping.id)

        assert mapping is not None
        assert mapping.id == test_tn_mapping.id
        assert mapping.tn == "+15551234567"

    def test_get_mapping_by_tn(self, in_memory_db, test_org, test_tn_mapping):
        """Test getting a mapping by TN."""
        store = TNMappingStore(in_memory_db)

        # With org filter
        mapping = store.get_by_tn("+15551234567", test_org.id)
        assert mapping is not None
        assert mapping.tn == "+15551234567"

        # Without org filter
        mapping = store.get_by_tn("+15551234567")
        assert mapping is not None

        # Non-existent TN
        mapping = store.get_by_tn("+19999999999")
        assert mapping is None

    def test_list_by_org(self, in_memory_db, test_org, other_org, test_tn_mapping):
        """Test listing mappings by organization."""
        store = TNMappingStore(in_memory_db)

        # Create another mapping in other_org
        store.create(
            org_id=other_org.id,
            tn="+15551111111",
            dossier_said="E" + "c" * 43,
            identity_name="other-identity",
        )

        # Test org mappings
        mappings = store.list_by_org(test_org.id)
        assert len(mappings) == 1
        assert mappings[0].tn == "+15551234567"

        # Other org mappings
        mappings = store.list_by_org(other_org.id)
        assert len(mappings) == 1
        assert mappings[0].tn == "+15551111111"

    def test_update_mapping(self, in_memory_db, test_tn_mapping):
        """Test updating a TN mapping."""
        store = TNMappingStore(in_memory_db)

        # Update dossier_said
        updated = store.update(
            test_tn_mapping.id,
            dossier_said="E" + "d" * 43,
            brand_name="Updated Brand",
        )

        assert updated is not None
        assert updated.dossier_said == "E" + "d" * 43
        assert updated.brand_name == "Updated Brand"
        # TN should be unchanged
        assert updated.tn == "+15551234567"

    def test_update_enabled(self, in_memory_db, test_tn_mapping):
        """Test disabling a TN mapping."""
        store = TNMappingStore(in_memory_db)

        updated = store.update(test_tn_mapping.id, enabled=False)

        assert updated is not None
        assert updated.enabled is False

        # Disabled mapping should not be found by get_by_tn
        mapping = store.get_by_tn("+15551234567")
        assert mapping is None

    def test_delete_mapping(self, in_memory_db, test_tn_mapping):
        """Test deleting a TN mapping."""
        store = TNMappingStore(in_memory_db)

        result = store.delete(test_tn_mapping.id)
        assert result is True

        # Should not exist anymore
        mapping = store.get(test_tn_mapping.id)
        assert mapping is None

    def test_exists(self, in_memory_db, test_org, test_tn_mapping):
        """Test checking if mapping exists."""
        store = TNMappingStore(in_memory_db)

        assert store.exists("+15551234567", test_org.id) is True
        assert store.exists("+19999999999", test_org.id) is False


class TestDuplicateTNRejection:
    """Test that duplicate TNs are rejected within an organization."""

    def test_duplicate_tn_same_org_fails(self, in_memory_db, test_org, test_tn_mapping):
        """Test that duplicate TN in same org fails."""
        store = TNMappingStore(in_memory_db)

        # Try to create another mapping with same TN in same org
        with pytest.raises(Exception):  # Should raise IntegrityError
            store.create(
                org_id=test_org.id,
                tn="+15551234567",  # Same TN
                dossier_said="E" + "e" * 43,
                identity_name="another-identity",
            )

    def test_same_tn_different_org_allowed(self, in_memory_db, test_org, other_org, test_tn_mapping):
        """Test that same TN in different org is allowed."""
        store = TNMappingStore(in_memory_db)

        # Should succeed - same TN but different org
        mapping = store.create(
            org_id=other_org.id,
            tn="+15551234567",  # Same TN but other org
            dossier_said="E" + "f" * 43,
            identity_name="other-org-identity",
        )

        assert mapping is not None
        assert mapping.organization_id == other_org.id


# =============================================================================
# TN Lookup Tests
# =============================================================================


class TestTNToInt:
    """Test TN to integer conversion."""

    def test_with_plus(self):
        """Test TN with + prefix."""
        assert tn_to_int("+15551234567") == 15551234567

    def test_without_plus(self):
        """Test TN without + prefix."""
        assert tn_to_int("15551234567") == 15551234567


class TestTNInRanges:
    """Test TN range checking."""

    def test_tn_in_single_number_range(self):
        """Test TN matches single number range."""
        from common.vvp.utils.tn_utils import TNRange

        ranges = [TNRange(start=15551234567, end=15551234567)]
        assert tn_in_ranges("+15551234567", ranges) is True
        assert tn_in_ranges("+15551234568", ranges) is False

    def test_tn_in_range(self):
        """Test TN falls within range."""
        from common.vvp.utils.tn_utils import TNRange

        ranges = [TNRange(start=15550000000, end=15559999999)]
        assert tn_in_ranges("+15551234567", ranges) is True
        assert tn_in_ranges("+15661234567", ranges) is False

    def test_empty_ranges(self):
        """Test TN against empty ranges."""
        assert tn_in_ranges("+15551234567", []) is False


class TestValidateTNOwnership:
    """Test TN ownership validation."""

    @pytest.mark.asyncio
    async def test_no_tn_credentials(self, in_memory_db, test_org):
        """Test validation fails when org has no TN credentials."""
        # No TN allocation credentials
        result = await validate_tn_ownership(in_memory_db, test_org.id, "+15551234567")
        assert result is False

    @pytest.mark.asyncio
    async def test_tn_covered_by_allocation(self, in_memory_db, test_org):
        """Test validation passes when TN is covered."""
        # Create managed TN Allocation credential
        cred = ManagedCredential(
            said="E" + "g" * 43,
            organization_id=test_org.id,
            schema_said="EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # TN Allocation schema
            issuer_aid="A" + "a" * 43,
        )
        in_memory_db.add(cred)
        in_memory_db.commit()

        # Mock the credential issuer to return TN allocation data
        mock_cred_info = MagicMock()
        mock_cred_info.attributes = {
            "numbers": ["+15551234567"],
        }

        with patch(GET_KERI_CLIENT_PATCH) as mock_get_client:
            mock_client = MagicMock()
            mock_client.get_credential = AsyncMock(return_value=mock_cred_info)
            mock_get_client.return_value = mock_client

            result = await validate_tn_ownership(in_memory_db, test_org.id, "+15551234567")
            assert result is True

    @pytest.mark.asyncio
    async def test_tn_not_covered_by_allocation(self, in_memory_db, test_org):
        """Test validation fails when TN is not covered."""
        # Create managed TN Allocation credential with different TN
        cred = ManagedCredential(
            said="E" + "h" * 43,
            organization_id=test_org.id,
            schema_said="EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",
            issuer_aid="A" + "a" * 43,
        )
        in_memory_db.add(cred)
        in_memory_db.commit()

        mock_cred_info = MagicMock()
        mock_cred_info.attributes = {
            "numbers": ["+15559999999"],  # Different TN
        }

        with patch(GET_KERI_CLIENT_PATCH) as mock_get_client:
            mock_client = MagicMock()
            mock_client.get_credential = AsyncMock(return_value=mock_cred_info)
            mock_get_client.return_value = mock_client

            result = await validate_tn_ownership(in_memory_db, test_org.id, "+15551234567")
            assert result is False


class TestLookupTNWithValidation:
    """Test full TN lookup with validation."""

    @pytest.mark.asyncio
    async def test_invalid_api_key(self, in_memory_db, test_tn_mapping):
        """Test lookup fails with invalid API key."""
        mock_store = MagicMock()
        mock_store.verify.return_value = (None, "invalid")

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            with patch(VERIFY_ORG_API_KEY_PATCH, return_value=(None, "invalid")):
                result = await lookup_tn_with_validation(
                    db=in_memory_db,
                    tn="+15551234567",
                    api_key="invalid-key",
                )

                assert result.found is False
                assert "Invalid API key" in result.error

    @pytest.mark.asyncio
    async def test_no_organization(self, in_memory_db, test_tn_mapping):
        """Test lookup fails when API key has no organization."""
        mock_principal = Principal(
            key_id="test-key",
            name="Test Key",
            roles={"issuer:operator"},
            organization_id=None,  # No org
        )
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15551234567",
                api_key="valid-key",
            )

            assert result.found is False
            assert "No organization" in result.error

    @pytest.mark.asyncio
    async def test_tn_not_mapped(self, in_memory_db, test_org, test_org_api_key):
        """Test lookup fails when TN not mapped."""
        key_obj, raw_key = test_org_api_key
        mock_principal = Principal(
            key_id=key_obj.id,
            name="Test Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+19999999999",  # Not mapped
                api_key=raw_key,
                validate_ownership=False,
            )

            assert result.found is False
            assert "No mapping found" in result.error

    @pytest.mark.asyncio
    async def test_successful_lookup_without_ownership_validation(
        self, in_memory_db, test_org, test_tn_mapping, test_org_api_key
    ):
        """Test successful lookup without ownership validation."""
        key_obj, raw_key = test_org_api_key
        mock_principal = Principal(
            key_id=key_obj.id,
            name="Test Key",
            roles={"org:dossier_manager"},
            organization_id=test_org.id,
        )
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15551234567",
                api_key=raw_key,
                validate_ownership=False,  # Skip ownership check
            )

            assert result.found is True
            assert result.tn == "+15551234567"
            assert result.dossier_said == test_tn_mapping.dossier_said
            assert result.identity_name == test_tn_mapping.identity_name
            assert result.brand_name == "Test Telecom"
            assert result.organization_id == test_org.id

    @pytest.mark.asyncio
    async def test_cross_org_access_denied(
        self, in_memory_db, test_org, other_org, test_tn_mapping
    ):
        """Test that API key from one org cannot access another org's mappings."""
        # Create API key for other_org
        raw_key = "other-org-key"
        other_key = OrgAPIKey(
            id=str(uuid.uuid4()),
            name="Other Org Key",
            key_hash=bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode(),
            organization_id=other_org.id,
            revoked=False,
        )
        in_memory_db.add(other_key)
        role = OrgAPIKeyRole(key_id=other_key.id, role="org:dossier_manager")
        in_memory_db.add(role)
        in_memory_db.commit()

        mock_principal = Principal(
            key_id=other_key.id,
            name="Other Org Key",
            roles={"org:dossier_manager"},
            organization_id=other_org.id,  # Different org
        )

        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15551234567",  # Belongs to test_org
                api_key=raw_key,
                validate_ownership=False,
            )

            # Should not find mapping (org scoped)
            assert result.found is False
            assert "No mapping found" in result.error


# =============================================================================
# API Endpoint Tests (optional, if using test client)
# =============================================================================


class TestTNMappingAPI:
    """Test TN mapping API endpoints."""

    # These tests would use httpx TestClient with app
    # For now, we've tested the underlying store and lookup logic
    pass


# =============================================================================
# OSP Delegation TN Lookup Tests
# =============================================================================


class TestOSPDelegationLookup:
    """Test TN lookup via OSP delegation.

    When a dossier is delegated to an OSP via DossierOspAssociation,
    the OSP's API key should be able to discover the dossier by TN.
    """

    @pytest.fixture
    def owner_org(self, in_memory_db):
        """Create the accountable party (owner) organization."""
        org = Organization(
            id=str(uuid.uuid4()),
            name="ACME Telecom (Owner)",
            pseudo_lei="5493001111111111AB12",
            enabled=True,
        )
        in_memory_db.add(org)
        in_memory_db.commit()
        in_memory_db.refresh(org)
        return org

    @pytest.fixture
    def osp_org(self, in_memory_db):
        """Create the OSP organization."""
        org = Organization(
            id=str(uuid.uuid4()),
            name="BigCarrier OSP",
            pseudo_lei="5493002222222222CD34",
            enabled=True,
        )
        in_memory_db.add(org)
        in_memory_db.commit()
        in_memory_db.refresh(org)
        return org

    @pytest.fixture
    def owner_tn_mapping(self, in_memory_db, owner_org):
        """Create a TN mapping owned by the accountable party."""
        mapping = TNMapping(
            id=str(uuid.uuid4()),
            tn="+15557770001",
            organization_id=owner_org.id,
            dossier_said="E" + "d" * 43,
            identity_name="owner-identity",
            brand_name="ACME Brand",
            brand_logo_url="https://example.com/acme-logo.png",
            enabled=True,
        )
        in_memory_db.add(mapping)
        in_memory_db.commit()
        in_memory_db.refresh(mapping)
        return mapping

    @pytest.fixture
    def osp_delegation(self, in_memory_db, owner_org, osp_org, owner_tn_mapping):
        """Create a DossierOspAssociation delegating to the OSP."""
        assoc = DossierOspAssociation(
            dossier_said=owner_tn_mapping.dossier_said,
            owner_org_id=owner_org.id,
            osp_org_id=osp_org.id,
        )
        in_memory_db.add(assoc)
        in_memory_db.commit()
        in_memory_db.refresh(assoc)
        return assoc

    def _make_principal(self, org):
        """Create a mock Principal for an org."""
        return Principal(
            key_id=f"key-{org.id[:8]}",
            name=f"{org.name} Key",
            roles={"org:dossier_manager"},
            organization_id=org.id,
        )

    @pytest.mark.asyncio
    async def test_osp_key_finds_delegated_tn(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """OSP's API key should find TN via delegation when direct lookup fails."""
        mock_principal = self._make_principal(osp_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="osp-api-key",
                validate_ownership=False,
            )

            assert result.found is True
            assert result.tn == "+15557770001"
            assert result.dossier_said == owner_tn_mapping.dossier_said
            assert result.identity_name == "owner-identity"
            assert result.brand_name == "ACME Brand"
            # organization_id should be the OWNER's org (who holds the TN mapping)
            assert result.organization_id == owner_org.id
            assert result.organization_name == "ACME Telecom (Owner)"

    @pytest.mark.asyncio
    async def test_osp_key_without_delegation_fails(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping
    ):
        """OSP's API key should NOT find TN if no delegation exists."""
        # No osp_delegation fixture — no DossierOspAssociation record
        mock_principal = self._make_principal(osp_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="osp-api-key",
                validate_ownership=False,
            )

            assert result.found is False
            assert "No mapping found" in result.error

    @pytest.mark.asyncio
    async def test_owner_key_still_works_directly(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """Owner's API key should find TN directly (not via delegation)."""
        mock_principal = self._make_principal(owner_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="owner-api-key",
                validate_ownership=False,
            )

            assert result.found is True
            assert result.organization_id == owner_org.id

    @pytest.mark.asyncio
    async def test_osp_delegation_validates_against_owner_tn_alloc(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """TN ownership validation should check the owner org's TN Alloc credentials."""
        mock_principal = self._make_principal(osp_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        # Create TN Allocation credential for the OWNER org
        cred = ManagedCredential(
            said="E" + "t" * 43,
            organization_id=owner_org.id,
            schema_said="EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",
            issuer_aid="A" + "a" * 43,
        )
        in_memory_db.add(cred)
        in_memory_db.commit()

        mock_cred_info = MagicMock()
        mock_cred_info.attributes = {"numbers": ["+15557770001"]}

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            with patch(GET_KERI_CLIENT_PATCH) as mock_get_client:
                mock_client = MagicMock()
                mock_client.get_credential = AsyncMock(return_value=mock_cred_info)
                mock_get_client.return_value = mock_client

                result = await lookup_tn_with_validation(
                    db=in_memory_db,
                    tn="+15557770001",
                    api_key="osp-api-key",
                    validate_ownership=True,
                )

                assert result.found is True
                assert result.dossier_said == owner_tn_mapping.dossier_said

    @pytest.mark.asyncio
    async def test_osp_delegation_fails_if_owner_has_no_tn_alloc(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """TN ownership validation should fail if owner has no TN Alloc covering the TN."""
        mock_principal = self._make_principal(osp_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        # No TN Allocation credentials for owner_org

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="osp-api-key",
                validate_ownership=True,
            )

            assert result.found is False
            assert "TN Allocation" in result.error

    @pytest.mark.asyncio
    async def test_osp_delegation_disabled_mapping_not_returned(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """Disabled TN mappings should not be returned even via delegation."""
        # Disable the mapping
        owner_tn_mapping.enabled = False
        in_memory_db.commit()

        mock_principal = self._make_principal(osp_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="osp-api-key",
                validate_ownership=False,
            )

            assert result.found is False

    @pytest.mark.asyncio
    async def test_unrelated_osp_cannot_access_delegation(
        self, in_memory_db, owner_org, osp_org, owner_tn_mapping, osp_delegation
    ):
        """A third org (not the delegated OSP) should not find the TN."""
        third_org = Organization(
            id=str(uuid.uuid4()),
            name="Third Party Corp",
            pseudo_lei="5493003333333333EF56",
            enabled=True,
        )
        in_memory_db.add(third_org)
        in_memory_db.commit()

        mock_principal = self._make_principal(third_org)
        mock_store = MagicMock()
        mock_store.verify.return_value = (mock_principal, None)

        with patch(GET_API_KEY_STORE_PATCH, return_value=mock_store):
            result = await lookup_tn_with_validation(
                db=in_memory_db,
                tn="+15557770001",
                api_key="third-party-key",
                validate_ownership=False,
            )

            assert result.found is False
            assert "No mapping found" in result.error
