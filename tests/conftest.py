"""Shared pytest fixtures for acme.api tests."""

from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Ensure the project root is on sys.path regardless of invocation directory.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
async def db(tmp_path: Path) -> AsyncGenerator[AsyncSession]:
    """Provide an initialized isolated async database session."""
    from acme_api.config import AcmeConfig, AppSettings, DatabaseConfig, DeploymentConfig
    from acme_api.db import get_session_factory, init_db, init_engine

    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certs"),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
    )
    engine = init_engine(settings)
    await init_db(engine)
    try:
        async with get_session_factory()() as session:
            yield session
    finally:
        await engine.dispose()


@pytest.fixture()
def anyio_backend() -> str:
    """Run AnyIO tests on asyncio only."""
    return "asyncio"


@pytest.fixture()
def app(tmp_path: Path) -> FastAPI:
    """Create a FastAPI app with an isolated temporary database path."""
    from acme_api.config import (
        AcmeConfig,
        AppSettings,
        DatabaseConfig,
        DeploymentConfig,
    )
    from acme_api.main import create_app

    db_dir = tmp_path / "data"
    deploy_dir = tmp_path / "certificates"
    db_dir.mkdir(parents=True)
    deploy_dir.mkdir()

    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{db_dir}/acme.db"),
        deployment=DeploymentConfig(directory=deploy_dir),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
    )
    return create_app(settings=settings)


@pytest.fixture()
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient]:
    """Return an async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
