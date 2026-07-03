"""Alembic environment configuration — migrations for acme.api.

Reads model metadata from our SQLAlchemy ORM models and runs migrations via
a synchronous engine so that the standard ``alembic`` CLI commands work
without wrapping every call in an async runner.

For SQLite + aiosqlite URLs, the driver is normalised to plain sqlite so
that synchronous inspection (autogenerate) succeeds against the same database
file used by the application at runtime.
"""

from __future__ import annotations

import re
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# ---------------------------------------------------------------------------
# Alembic config
# ---------------------------------------------------------------------------

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Ensure the project root (parent of this file) is on sys.path so that
# ``acme_api`` imports resolve correctly regardless of invocation directory.
_alembic_dir = Path(__file__).resolve().parent
_project_root = _alembic_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# ---------------------------------------------------------------------------
# Model metadata (autogenerate support)
# ---------------------------------------------------------------------------

from acme_api.models import Base  # noqa: E402

target_metadata = Base.metadata


def _normalise_url(url: str) -> str:
    """Convert an aiosqlite URL to plain sqlite for synchronous migrations.

    ``alembic revision --autogenerate`` runs synchronously, so the dialect
    must be one that supports blocking I/O (sqlite3), not async (aiosqlite).
    The resulting sync engine writes to the *same* database file, which is
    safe because migration scripts execute serially.
    """
    return re.sub(r"^sqlite\+aiosqlite:///", "sqlite:///", url)


def _get_url() -> str:
    """Resolve the SQLAlchemy URL from Alembic config or application settings."""
    url = config.get_main_option("sqlalchemy.url")
    if url != "driver://user:pass@localhost/dbname":
        return _normalise_url(url)

    from acme_api.config import AppSettings, load_config  # noqa: PLC0415

    settings: AppSettings = load_config()
    return _normalise_url(settings.database.url)


# ---------------------------------------------------------------------------
# Migration runners
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Emits SQL to stdout; no database connection is required.
    """
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:  # noqa: PLR0915
    """Run migrations in 'online' mode using a synchronous engine."""
    url = _get_url()

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url

    if "sqlite" in url:
        connectable = engine_from_config(
            section,
            prefix="sqlalchemy.",
            poolclass=pool.StaticPool,
        )
    else:
        connectable = engine_from_config(
            section,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
