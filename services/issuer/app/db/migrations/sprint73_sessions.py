"""Sprint 73: PostgreSQL-backed session and OAuth state tables.

The sessions and oauth_states tables are created by Base.metadata.create_all()
from the DBSession and DBOAuthState model definitions. This migration file
exists for the registry pattern in session.py and for future column additions.

This migration is idempotent — safe to run multiple times.
"""

import logging
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)


def run_migrations(engine: Engine) -> None:
    """Run Sprint 73 migrations.

    The sessions and oauth_states tables are created by create_all().
    This placeholder ensures the migration is registered in init_database().

    Args:
        engine: SQLAlchemy engine instance
    """
    backend = engine.url.get_backend_name()
    log.debug(f"Sprint 73 migration check (dialect: {backend}) — tables created by create_all")
