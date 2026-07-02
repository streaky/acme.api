"""Async SQLAlchemy engine, session factory, and FastAPI DI dependency."""

from __future__ import annotations

import contextlib
import typing

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
_SessionFactory: typing.Optional[async_sessionmaker[AsyncSession]] = None
_engine: typing.Optional[AsyncEngine] = None
def _set_sqlite_pragma(
    dbapi_conn: typing.Any, connection_record: typing.Any
) -> None:
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
    global _engine, _SessionFactory  # noqa: PLW0603

    engine = create_async_engine(
        url=settings.database.url,
        echo=False,
        pool_size=settings.database.pool_size,
        max_overflow=10,
        pool_recycle=3600,
        pool_pre_ping=True,
    )

    # Apply pragmas on each new connection.
    sa_event.listen(engine.sync_engine, "connect", _set_sqlite_pragma)

    _engine = engine
    _SessionFactory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    return engine


@contextlib.asynccontextmanager
async def get_db() -> typing.AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields an async database session."""
    assert _SessionFactory is not None, "Call init_engine() before mounting routes."
    async with _SessionFactory() as session:
        yield session


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables defined by the Base metadata.

    Intended for test/bootstrap use; Alembic migrations handle production.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
