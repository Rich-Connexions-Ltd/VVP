"""Database session management for VVP KERI Agent.

Provides SQLAlchemy engine and session management for seed persistence.
Follows the same pattern as services/issuer/app/db/session.py.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import DATABASE_URL

log = logging.getLogger(__name__)

if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy.pool import StaticPool

    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }
    log.info("KERI Agent using SQLite database (local development mode)")
else:
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
        "pool_size": 3,
        "max_overflow": 5,
        "pool_recycle": 1800,
    }
    log.info("KERI Agent using PostgreSQL database (production mode)")

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite PRAGMAs for local development."""
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for database sessions in non-request code."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_database() -> None:
    """Initialize the database by creating all tables.

    Called during application startup. Tables are created idempotently.
    """
    from pathlib import Path
    from app.db.models import Base

    log.info(f"Initializing KERI Agent seed database")

    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        if db_path and db_path != ":memory:":
            db_dir = Path(db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)
    log.info("KERI Agent seed tables created successfully")
