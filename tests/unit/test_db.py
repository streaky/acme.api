"""Tests for async DB engine, session factory, and DI dependency."""

from __future__ import annotations

import uuid as _uuid
from pathlib import Path
from typing import Protocol, cast

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from acme_api.config import AppSettings, DatabaseConfig, DeploymentConfig
from acme_api.db import get_db, get_session_factory, init_db, init_engine
from acme_api.models.certificate import Certificate, CertificateStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _PoolWithSize(Protocol):
    """Model the queue pool API used by the configurable SQLite test engine."""

    def size(self) -> int:
        """Return the configured pool size."""


@pytest.fixture()
def settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path),
    )


# ---------------------------------------------------------------------------
# TestInitEngine
# ---------------------------------------------------------------------------


class TestInitEngine:
    def test_creates_engine_and_session_factory(self, settings: AppSettings) -> None:
        engine = init_engine(settings=settings)

        assert isinstance(engine, AsyncEngine)
        assert callable(get_session_factory())

    def test_pool_size_from_config(self, tmp_path: Path) -> None:
        custom_pool_size = 3
        cfg = AppSettings(
            database=DatabaseConfig(
                url=f"sqlite+aiosqlite:///{tmp_path}/test.db",
                pool_size=custom_pool_size,
            ),
            deployment=DeploymentConfig(directory=tmp_path),
        )

        engine = init_engine(settings=cfg)

        pool_size = cast(_PoolWithSize, engine.pool).size
        assert pool_size() == custom_pool_size


# ---------------------------------------------------------------------------
# TestGetDb
# ---------------------------------------------------------------------------


class TestGetDb:
    @pytest.mark.anyio
    async def test_yields_active_session(self, settings: AppSettings) -> None:
        """get_db yields an AsyncSession that can execute queries."""
        engine = init_engine(settings=settings)
        try:
            await init_db(engine=engine)

            async with get_db() as session:
                assert isinstance(session, AsyncSession)
                result = await session.execute(text("SELECT 1"))
                assert result.scalar_one() == 1
        finally:
            await engine.dispose()

    @pytest.mark.anyio
    async def test_commits_on_success(self, settings: AppSettings) -> None:
        """A value inserted inside get_db persists and is visible from a new session."""
        engine = init_engine(settings=settings)
        try:
            await init_db(engine=engine)

            row_id = _uuid.uuid4()
            async with get_db() as session:
                await session.execute(
                    text("INSERT INTO events (id, event_type, details) VALUES (:id, 'test.event', '{}')"),
                    {"id": str(row_id)},
                )
                await session.commit()

            # Open a fresh session to confirm persistence after commit.
            async with get_db() as verify:
                result = await verify.execute(
                    text("SELECT event_type FROM events WHERE id = :id"),
                    {"id": str(row_id)},
                )
                assert result.scalar_one() == "test.event"
        finally:
            await engine.dispose()

    @pytest.mark.anyio
    async def test_certificate_request_identity_is_unique(self, settings: AppSettings) -> None:
        """The database rejects concurrent-equivalent certificate request rows."""
        engine = init_engine(settings=settings)
        try:
            await init_db(engine=engine)
            async with AsyncSession(engine) as session:
                session.add_all(
                    [
                        Certificate(
                            name="manual-example",
                            domains=["example.com"],
                            acme_account_ref="letsencrypt",
                            challenge_method="dns-persist",
                            key_algorithm="ecdsa",
                            status=CertificateStatus.PENDING_DNS,
                        ),
                        Certificate(
                            name="manual-example",
                            domains=["www.example.com"],
                            acme_account_ref="letsencrypt",
                            challenge_method="dns-persist",
                            key_algorithm="ecdsa",
                            status=CertificateStatus.PENDING_DNS,
                        ),
                    ]
                )
                with pytest.raises(IntegrityError):
                    await session.flush()
        finally:
            await engine.dispose()

    @pytest.mark.anyio
    async def test_rollback_on_exception(self, settings: AppSettings) -> None:
        """An exception inside get_db rolls back so the insert is lost."""
        engine = init_engine(settings=settings)
        try:
            await init_db(engine=engine)

            row_id = _uuid.uuid4()
            try:
                async with get_db() as session:
                    await session.execute(
                        text("INSERT INTO events (id, event_type, details) VALUES (:id, 'rollback.event', '{}')"),
                        {"id": str(row_id)},
                    )
                    raise ValueError("boom")
            except ValueError:
                pass

            # Open a fresh session to confirm the row was rolled back.
            async with get_db() as verify:
                result = await verify.execute(
                    text("SELECT id FROM events WHERE id = :id"),
                    {"id": str(row_id)},
                )
                assert result.scalar_one_or_none() is None
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# TestInitDb
# ---------------------------------------------------------------------------


class TestInitDb:
    @pytest.mark.anyio
    async def test_creates_all_tables(self, settings: AppSettings) -> None:
        engine = init_engine(settings=settings)
        try:
            await init_db(engine=engine)

            async with engine.connect() as conn:
                result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
                table_names = [row[0] for row in result.fetchall()]
        finally:
            await engine.dispose()

        # The concrete model tables must all exist.
        assert "api_keys" in table_names
        assert "certificates" in table_names
        assert "events" in table_names
        assert "renewal_attempts" in table_names
        assert "webhook_configs" in table_names
