"""Async SQLAlchemy engine, session factory, and FastAPI DI dependency."""

from __future__ import annotations

import contextlib
import typing
from pathlib import Path

from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from acme_api.config import AppSettings
from acme_api.models.base import Base

# ---------------------------------------------------------------------------
# Module-level handles populated by init_engine()
# ---------------------------------------------------------------------------
_SESSION_FACTORY: async_sessionmaker[AsyncSession] | None = None
_ENGINE: AsyncEngine | None = None


def _set_sqlite_pragma(dbapi_conn: typing.Any, _connection_record: typing.Any) -> None:
    """Apply SQLite pragmas on each new aiosqlite connection."""
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        result = cursor.fetchone()
        assert result[0] == "wal", f"journal_mode WAL failed: {result}"
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def init_engine(settings: AppSettings) -> AsyncEngine:
    """Create and configure the async SQLAlchemy engine.

    Parameters
    ----------
    settings:
        Application settings providing database.url, pool_size, etc.

    Returns
    -------
    AsyncEngine configured with SQLite pragmas and pool settings.
    """
    global _ENGINE, _SESSION_FACTORY  # pylint: disable=global-statement

    engine = create_async_engine(
        url=settings.database.url,
        echo=False,
        pool_size=settings.database.pool_size,
        max_overflow=10,
        pool_recycle=3600,
        pool_pre_ping=True,
    )

    if engine.url.get_backend_name() == "sqlite":
        sa_event.listen(engine.sync_engine, "connect", _set_sqlite_pragma)

    _ENGINE = engine
    _SESSION_FACTORY = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    return engine


@contextlib.asynccontextmanager
async def get_db() -> typing.AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields an async database session."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> typing.AsyncIterator[AsyncSession]:
    """Yield an async database session for FastAPI dependency injection."""
    async with get_db() as session:
        yield session


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the initialized async session factory."""
    assert _SESSION_FACTORY is not None, "Call init_engine() before mounting routes."
    return _SESSION_FACTORY


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables defined by the Base metadata.

    Intended for test/bootstrap use; Alembic migrations handle production.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def run_migrations(settings: AppSettings) -> None:
    """Run Alembic migrations to the latest revision."""
    from alembic.config import Config

    from alembic import command

    source_root = Path(__file__).resolve().parent.parent
    project_root = next(
        candidate
        for candidate in (Path.cwd(), source_root)
        if (candidate / "alembic.ini").exists() and (candidate / "alembic").is_dir()
    )
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "alembic"))
    config.set_main_option("sqlalchemy.url", settings.database.url)
    command.upgrade(config, "head")
