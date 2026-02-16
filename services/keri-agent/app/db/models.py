"""SQLAlchemy models for KERI Agent seed persistence.

These tables store the parameters needed to deterministically rebuild
all KERI state (identities, registries, credentials) from scratch.
The master Habery salt plus these seeds allow any container to recreate
identical cryptographic state on local ephemeral LMDB.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class KeriHaberySalt(Base):
    """Master Habery salt — single row table.

    The Habery salt deterministically derives all signing keys for
    all identities. This is the crown jewel of the seed store.
    """
    __tablename__ = "keri_habery_salt"

    id = Column(Integer, primary_key=True)  # Always 1
    salt = Column(String(44), nullable=False)  # qb64-encoded salt
    habery_name = Column(String(100), nullable=False)  # e.g., "vvp-issuer"
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class KeriIdentitySeed(Base):
    """Parameters to replay makeHab() for a specific identity."""
    __tablename__ = "keri_identity_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    expected_aid = Column(String(44), nullable=False)
    transferable = Column(Boolean, default=True, nullable=False)
    icount = Column(Integer, nullable=False)
    isith = Column(String(20), nullable=False)
    ncount = Column(Integer, nullable=False)
    nsith = Column(String(20), nullable=False)
    witness_aids = Column(Text, nullable=False)  # JSON array of witness AIDs
    toad = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    metadata_json = Column(Text, nullable=True)  # JSON: {"type": "mock_gleif", "org_id": "..."}


class KeriRegistrySeed(Base):
    """Parameters to replay makeRegistry() for a specific registry."""
    __tablename__ = "keri_registry_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    identity_name = Column(String(255), nullable=False)  # Which identity owns this registry
    expected_registry_key = Column(String(44), nullable=False)
    no_backers = Column(Boolean, default=True, nullable=False)
    nonce = Column(String(44), nullable=True)  # Registry nonce for deterministic rebuild
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class KeriRotationSeed(Base):
    """Parameters to replay hab.rotate() for key rotation events.

    Each row represents one rotation event. On rebuild, rotations are
    replayed in sequence_number order after identity inception.
    """
    __tablename__ = "keri_rotation_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    identity_name = Column(String(255), nullable=False)
    sequence_number = Column(Integer, nullable=False)  # KEL sequence number of rotation
    ncount = Column(Integer, nullable=True)  # Next key count (None = use default)
    nsith = Column(String(20), nullable=True)  # Next signing threshold
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("identity_name", "sequence_number", name="uq_rotation_identity_sn"),
    )


class KeriCredentialSeed(Base):
    """Parameters to replay issue_credential() for a specific credential."""
    __tablename__ = "keri_credential_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    expected_said = Column(String(44), nullable=False, unique=True)
    registry_name = Column(String(255), nullable=False)
    schema_said = Column(String(44), nullable=False)
    issuer_identity_name = Column(String(255), nullable=False)
    recipient_aid = Column(String(44), nullable=True)
    attributes_json = Column(Text, nullable=False)  # Insertion-order JSON (compact)
    edges_json = Column(Text, nullable=True)  # Insertion-order JSON edge references
    rules_json = Column(Text, nullable=True)  # Insertion-order JSON rules
    private = Column(Boolean, default=False, nullable=False)
    rebuild_order = Column(Integer, nullable=False)  # Topological sort position
    edge_saids = Column(Text, nullable=True)  # JSON list of credential SAIDs this depends on
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
