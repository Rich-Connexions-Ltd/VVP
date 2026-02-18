"""SQLAlchemy ORM models for VVP Issuer multi-tenant support.

This module defines the database schema for:
- Organizations (tenants with pseudo-LEI and KERI identity)
- Users (belong to organizations with system and org roles)
- Organization API Keys (scoped to organizations)
- Managed Credentials (track credential ownership)
- Mock vLEI State (idempotency for mock infrastructure)
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class OrgType(str, Enum):
    """Organization types in the trust chain hierarchy.

    Sprint 67: Distinguishes trust-anchor organizations from regular tenants.
    - ROOT_AUTHORITY: GLEIF (issues QVI credentials)
    - QVI: Qualified vLEI Issuer (issues LE credentials)
    - VETTER_AUTHORITY: GSMA or similar (issues VetterCertifications)
    - REGULAR: Standard AP organizations (issue Brand, TN Alloc, DE credentials)
    """

    ROOT_AUTHORITY = "root_authority"
    QVI = "qvi"
    VETTER_AUTHORITY = "vetter_authority"
    REGULAR = "regular"


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class Organization(Base):
    """Organization (tenant) with pseudo-LEI and KERI identity.

    Each organization represents a tenant in the multi-tenant issuer system.
    Organizations are onboarded with:
    - A deterministic pseudo-LEI for development/testing
    - A KERI Autonomic Identifier (AID)
    - A Legal Entity credential from the mock QVI
    - A credential registry for issuing credentials
    """

    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False, unique=True)
    pseudo_lei = Column(String(20), nullable=False, unique=True)
    aid = Column(String(44), nullable=True)  # KERI AID (44 chars for Ed25519)
    le_credential_said = Column(String(44), nullable=True)  # Legal Entity credential SAID
    registry_key = Column(String(44), nullable=True)  # TEL registry prefix
    vetter_certification_said = Column(String(44), nullable=True)  # Active VetterCert SAID
    org_type = Column(String(20), default=OrgType.REGULAR.value, nullable=False)  # Sprint 67
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    users = relationship("User", back_populates="organization")
    api_keys = relationship("OrgAPIKey", back_populates="organization")
    credentials = relationship("ManagedCredential", back_populates="organization")

    def __repr__(self) -> str:
        return f"<Organization(id={self.id!r}, name={self.name!r}, pseudo_lei={self.pseudo_lei!r})>"


class User(Base):
    """User belonging to an organization.

    Users can have:
    - System roles (issuer:admin, issuer:operator, issuer:readonly)
    - Organization roles (org:administrator, org:dossier_manager) via UserOrgRole

    Note: Organization roles are stored in the user_org_roles table, NOT here.
    The system_roles field only stores system-level roles as comma-separated values.
    """

    __tablename__ = "users"

    id = Column(String(36), primary_key=True)  # UUID
    email = Column(String(255), nullable=False, unique=True)  # Lowercase, globally unique
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=True)  # bcrypt, empty for OAuth users
    system_roles = Column(String(255), default="", nullable=False)  # Comma-separated
    organization_id = Column(
        String(36), ForeignKey("organizations.id"), nullable=True
    )
    enabled = Column(Boolean, default=True, nullable=False)
    is_oauth_user = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    organization = relationship("Organization", back_populates="users")
    org_roles = relationship("UserOrgRole", back_populates="user", cascade="all, delete-orphan")

    @property
    def system_roles_set(self) -> set[str]:
        """Get system roles as a set."""
        if not self.system_roles:
            return set()
        return {r.strip() for r in self.system_roles.split(",") if r.strip()}

    @system_roles_set.setter
    def system_roles_set(self, roles: set[str]) -> None:
        """Set system roles from a set."""
        self.system_roles = ",".join(sorted(roles)) if roles else ""

    def __repr__(self) -> str:
        return f"<User(id={self.id!r}, email={self.email!r}, org_id={self.organization_id!r})>"


class UserOrgRole(Base):
    """Canonical storage for user organization roles.

    This is the single source of truth for org roles (org:administrator, org:dossier_manager).
    A user can have multiple org roles for their organization.
    """

    __tablename__ = "user_org_roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(50), nullable=False)  # 'org:administrator' or 'org:dossier_manager'
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="org_roles")

    __table_args__ = (
        UniqueConstraint("user_id", "org_id", "role", name="uq_user_org_role"),
    )

    def __repr__(self) -> str:
        return f"<UserOrgRole(user_id={self.user_id!r}, org_id={self.org_id!r}, role={self.role!r})>"


class OrgAPIKey(Base):
    """API key scoped to an organization.

    Organization API keys can be used for programmatic access to org resources.
    They have org roles (not system roles) and are automatically scoped to their org.
    """

    __tablename__ = "org_api_keys"

    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False)  # bcrypt hash
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    roles = relationship("OrgAPIKeyRole", back_populates="api_key", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<OrgAPIKey(id={self.id!r}, name={self.name!r}, org_id={self.organization_id!r})>"


class OrgAPIKeyRole(Base):
    """Roles assigned to an organization API key.

    Organization API keys can have multiple org roles.
    """

    __tablename__ = "org_api_key_roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(
        String(36), ForeignKey("org_api_keys.id", ondelete="CASCADE"), nullable=False
    )
    role = Column(String(50), nullable=False)  # 'org:administrator' or 'org:dossier_manager'

    # Relationships
    api_key = relationship("OrgAPIKey", back_populates="roles")

    __table_args__ = (
        UniqueConstraint("key_id", "role", name="uq_org_api_key_role"),
    )

    def __repr__(self) -> str:
        return f"<OrgAPIKeyRole(key_id={self.key_id!r}, role={self.role!r})>"


class ManagedCredential(Base):
    """Tracks credential ownership by organization.

    When credentials are issued, a ManagedCredential record is created to
    associate the credential SAID with the issuing organization. This enables
    credential scoping - users can only access credentials from their org.
    """

    __tablename__ = "managed_credentials"

    said = Column(String(44), primary_key=True)  # Credential SAID
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    schema_said = Column(String(44), nullable=False)
    issuer_aid = Column(String(44), nullable=False)  # Which identity issued this
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="credentials")

    def __repr__(self) -> str:
        return f"<ManagedCredential(said={self.said!r}, org_id={self.organization_id!r})>"


class MockVLEIState(Base):
    """Persists mock vLEI infrastructure state for idempotency.

    This table stores the state of the mock GLEIF and QVI identities
    created on startup. It ensures that:
    - The same identities are used across restarts
    - Credential issuance is idempotent
    - Registry keys are preserved
    """

    __tablename__ = "mock_vlei_state"

    id = Column(Integer, primary_key=True, autoincrement=True)  # Single row expected
    gleif_aid = Column(String(44), nullable=False)
    gleif_registry_key = Column(String(44), nullable=False)
    qvi_aid = Column(String(44), nullable=False)
    qvi_credential_said = Column(String(44), nullable=False)
    qvi_registry_key = Column(String(44), nullable=False)
    gsma_aid = Column(String(44), nullable=True)
    gsma_registry_key = Column(String(44), nullable=True)
    gsma_governance_said = Column(String(44), nullable=True)  # Sprint 62
    gleif_org_id = Column(String(36), nullable=True)  # Sprint 67: promoted Organization ID
    qvi_org_id = Column(String(36), nullable=True)  # Sprint 67: promoted Organization ID
    gsma_org_id = Column(String(36), nullable=True)  # Sprint 67: promoted Organization ID
    initialized_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<MockVLEIState(id={self.id}, gleif_aid={self.gleif_aid!r}, qvi_aid={self.qvi_aid!r})>"


class TNMapping(Base):
    """Telephone Number to Dossier mapping for SIP redirect signing.

    Sprint 42: Maps E.164 telephone numbers to the dossier and identity used
    for signing VVP attestations. Each organization can have one mapping per TN.

    When an enterprise SBC sends a SIP INVITE to the redirect service:
    1. The TN is extracted from the From header
    2. This table is queried to find the dossier_said and identity_name
    3. The VVP-Identity header and PASSporT are created using that identity
    4. The 302 response includes brand info cached from the dossier
    """

    __tablename__ = "tn_mappings"

    id = Column(String(36), primary_key=True)  # UUID
    tn = Column(String(20), nullable=False)  # E.164 format (+15551234567)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    dossier_said = Column(String(44), nullable=False)  # Root credential SAID
    identity_name = Column(String(255), nullable=False)  # KERI identity name for signing
    brand_name = Column(String(255), nullable=True)  # Cached brand name from dossier
    brand_logo_url = Column(String(1024), nullable=True)  # Cached logo URL
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    organization = relationship("Organization", backref="tn_mappings")

    __table_args__ = (
        UniqueConstraint("organization_id", "tn", name="uq_org_tn"),
        Index("ix_tn_mappings_tn", "tn"),  # Fast TN lookup
    )

    def __repr__(self) -> str:
        return f"<TNMapping(id={self.id!r}, tn={self.tn!r}, org={self.organization_id[:8] if self.organization_id else None!r}...)>"


class DossierOspAssociation(Base):
    """Administrative record: which OSP org can reference which dossier.

    Sprint 63: This is NOT a protocol-level concept and does NOT gate TN mapping
    authorization. The actual cryptographic authorization comes from the delsig
    edge within the dossier. This association is for VISIBILITY ONLY — it allows
    OSP orgs to discover dossiers associated with them via GET /api/dossier/associated.

    Lifecycle:
    - Org deletion: CASCADE on both FK columns removes associations automatically.
    - Dossier revocation: Associations remain (KERI credentials can't be deleted,
      only revoked; the association metadata remains historically meaningful).
    """

    __tablename__ = "dossier_osp_associations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dossier_said = Column(String(44), nullable=False, index=True)
    owner_org_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    osp_org_id = Column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("dossier_said", "osp_org_id", name="uq_dossier_osp"),
    )

    def __repr__(self) -> str:
        return (
            f"<DossierOspAssociation(dossier={self.dossier_said!r}, "
            f"owner={self.owner_org_id!r}, osp={self.osp_org_id!r})>"
        )


class PBXConfig(Base):
    """Singleton PBX configuration for FreeSWITCH dialplan management.

    Stores the API key reference and extension definitions for the PBX.
    There is exactly one PBX, so this table has exactly one row (id=1).

    Extensions are stored as a JSON array in extensions_json:
    [{"ext": 1001, "cli": "+441923311001", "enabled": true, "description": "Primary test"}]
    """

    __tablename__ = "pbx_config"

    id = Column(Integer, primary_key=True, default=1)
    api_key_org_id = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    api_key_id = Column(String(36), ForeignKey("org_api_keys.id"), nullable=True)
    # Raw API key value for dialplan insertion (org_api_keys stores only bcrypt hashes)
    api_key_value = Column(String(255), nullable=True)
    extensions_json = Column(String(4096), default="[]", nullable=False)
    default_caller_id = Column(String(20), default="+441923311000", nullable=False)
    last_deployed_at = Column(DateTime, nullable=True)
    last_deployed_by = Column(String(255), nullable=True)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    def __repr__(self) -> str:
        return f"<PBXConfig(id={self.id}, api_key_org_id={self.api_key_org_id!r})>"


class DBSession(Base):
    """Server-side session stored in PostgreSQL.

    Sprint 73: Replaces in-memory session store for multi-replica support.
    Sessions survive container restarts and are shared across replicas.
    """

    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True)
    key_id = Column(String(255), nullable=False, index=True)
    principal_name = Column(String(255), nullable=False)
    principal_roles = Column(String(1024), default="", nullable=False)  # Comma-separated
    principal_org_id = Column(String(36), nullable=True)
    home_org_id = Column(String(36), nullable=True)
    active_org_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_accessed = Column(DateTime, nullable=False)

    def __repr__(self) -> str:
        return f"<DBSession(id={self.session_id[:8]}..., key_id={self.key_id!r})>"


class DBOAuthState(Base):
    """OAuth state stored in PostgreSQL for CSRF/PKCE protection.

    Sprint 73: Replaces in-memory OAuth state store for multi-replica support.
    """

    __tablename__ = "oauth_states"

    state_id = Column(String(64), primary_key=True)
    state = Column(String(64), nullable=False)
    nonce = Column(String(64), nullable=False)
    code_verifier = Column(String(128), nullable=False)
    redirect_after = Column(String(1024), default="/ui/", nullable=False)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<DBOAuthState(id={self.state_id[:8]}...)>"


# Event listener to normalize email to lowercase before insert/update
@event.listens_for(User.email, "set", propagate=True)
def normalize_email(target: User, value: str, oldvalue: str, initiator) -> str:
    """Normalize email to lowercase."""
    if value is not None:
        return value.lower()
    return value
