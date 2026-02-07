"""Database session management for VVP Issuer.

This module provides SQLAlchemy engine and session management:
- engine: The SQLAlchemy engine connected to the database
- SessionLocal: Session factory for creating database sessions
- get_db(): FastAPI dependency for request-scoped sessions
- get_db_session(): Context manager for non-request code

Sprint 45: Added retry logic with exponential backoff for Azure Files SQLite
compatibility. SQLite over SMB has unreliable file locking which can cause
"database is locked" errors during deployment transitions.
"""

import logging
import time
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import DATABASE_URL

log = logging.getLogger(__name__)

# Create engine with SQLite-specific settings
# For SQLite, we need check_same_thread=False for multi-threaded access
# On Azure Files (SMB), we use StaticPool to limit connections to 1
connect_args = {}
pool_class = None
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # Increase SQLite busy timeout to handle SMB latency (30 seconds)
    connect_args["timeout"] = 30
    # Use StaticPool for single connection (required for SQLite on network shares)
    pool_class = StaticPool

engine_kwargs = {
    "connect_args": connect_args,
    "echo": False,  # Set to True for SQL debugging
    "pool_pre_ping": True,  # Verify connections before use
}

# Use StaticPool for SQLite to limit to single connection
if pool_class:
    engine_kwargs["poolclass"] = pool_class

engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# Enable SQLite PRAGMAs for Azure Files compatibility
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite PRAGMAs for reliability on Azure Files (SMB).

    These settings improve SQLite behavior on network file shares:
    - foreign_keys=ON: Enforce referential integrity
    - journal_mode=WAL: Better concurrent read performance (though we're single-writer)
    - synchronous=NORMAL: Balance durability vs performance
    - busy_timeout=30000: Wait up to 30s for locks (SMB can be slow)
    """
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
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


def init_database(max_retries: int = 5, base_delay: float = 2.0) -> None:
    """Initialize the database by creating all tables.

    This is called during application startup in the lifespan handler.

    Sprint 45: Added retry logic with exponential backoff for Azure Files
    SQLite compatibility. During container app deployments, old and new
    revisions may briefly overlap, causing "database is locked" errors.

    Args:
        max_retries: Maximum number of retry attempts (default: 5)
        base_delay: Base delay in seconds for exponential backoff (default: 2.0)

    Raises:
        OperationalError: If database initialization fails after all retries.
    """
    from pathlib import Path
    from app.db.models import Base

    log.info(f"Initializing database at {DATABASE_URL}")

    # Ensure the database directory exists for SQLite
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        if db_path and db_path != ":memory:":
            db_dir = Path(db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            log.info(f"Ensured database directory exists: {db_dir}")

    # Retry loop with exponential backoff for Azure Files lock issues
    for attempt in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            log.info("Database tables created successfully")
            return
        except OperationalError as e:
            error_msg = str(e)
            is_lock_error = "database is locked" in error_msg or "SQLITE_BUSY" in error_msg
            is_retryable = attempt < max_retries - 1

            if is_lock_error and is_retryable:
                delay = base_delay * (2 ** attempt)  # Exponential backoff: 2, 4, 8, 16, 32s
                log.warning(
                    f"Database locked during init, retry {attempt + 1}/{max_retries} "
                    f"in {delay:.1f}s (previous revision may still be active)"
                )
                time.sleep(delay)
            else:
                log.error(f"Database initialization failed: {e}")
                raise
