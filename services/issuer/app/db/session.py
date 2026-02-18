"""Database session management for VVP Issuer.

This module provides SQLAlchemy engine and session management:
- engine: The SQLAlchemy engine connected to the database
- SessionLocal: Session factory for creating database sessions
- get_db(): FastAPI dependency for request-scoped sessions
- get_db_session(): Context manager for non-request code

Sprint 46: PostgreSQL migration with connection pooling.
SQLite fallback retained for local development.

CI/CD Test: Verifying zero-downtime deployment and data persistence.
"""

import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import DATABASE_URL

log = logging.getLogger(__name__)

# Configure engine based on database type
# PostgreSQL: Full connection pooling for production scalability
# SQLite: StaticPool for local development (single connection)

if DATABASE_URL.startswith("sqlite"):
    # SQLite configuration (local development)
    from sqlalchemy.pool import StaticPool

    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }
    log.info("Using SQLite database (local development mode)")
else:
    # PostgreSQL configuration (production)
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,      # Verify connections before use
        "pool_size": 5,              # Base pool size
        "max_overflow": 10,          # Additional connections if needed
        "pool_recycle": 1800,        # Recycle connections every 30 min
    }
    log.info("Using PostgreSQL database (production mode)")

engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# SQLite PRAGMAs (only for local development)
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite PRAGMAs for local development.

    These settings improve SQLite behavior:
    - foreign_keys=ON: Enforce referential integrity
    - journal_mode=WAL: Better concurrent read performance
    - busy_timeout=5000: Wait up to 5s for locks
    """
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions.

    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            ...

    The session is automatically closed when the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for database sessions in non-request code.

    Usage:
        with get_db_session() as db:
            org = db.query(Organization).filter(...).first()
            ...

    The session is committed on success and rolled back on exception.
    """
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

    This is called during application startup in the lifespan handler.
    Tables are created idempotently (CREATE IF NOT EXISTS).

    For SQLite: Also ensures the database directory exists.
    """
    from pathlib import Path
    from app.db.models import Base

    log.info(f"Initializing database at {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")

    # Ensure the database directory exists for SQLite
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        if db_path and db_path != ":memory:":
            db_dir = Path(db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            log.info(f"Ensured database directory exists: {db_dir}")

    # Create tables first (idempotent — fresh DBs get all columns from models)
    Base.metadata.create_all(bind=engine)
    log.info("Database tables created successfully")

    # Run column migrations for existing databases that predate these sprints
    from app.db.migrations.sprint61_vetter_cert import run_migrations as run_sprint61
    run_sprint61(engine)
    from app.db.migrations.sprint62_gsma_governance import run_migrations as run_sprint62
    run_sprint62(engine)
    from app.db.migrations.sprint67_org_type import run_migrations as run_sprint67
    run_sprint67(engine)
    from app.db.migrations.sprint71_pbx_config import run_migrations as run_sprint71
    run_sprint71(engine)
    from app.db.migrations.sprint73_sessions import run_migrations as run_sprint73
    run_sprint73(engine)
