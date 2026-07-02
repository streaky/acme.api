"""Async CRUD tests for Certificate and Event models via SQLAlchemy session."""

from __future__ import annotations

import uuid as _uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.config import AppSettings, DatabaseConfig, DeploymentConfig
from acme_api.db import init_db, init_engine
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path),
    )


@pytest.fixture()
async def engine(settings: AppSettings):
    return init_engine(settings=settings)


@pytest.fixture()
async def session_factory(engine, settings: AppSettings):
    import acme_api.db as db_mod
    return db_mod._SessionFactory  # type: ignore[return-value]


@pytest.fixture()
async def db(engine, session_factory) -> AsyncSession:
    await init_db(engine)
    async with session_factory() as s:
        yield s
        await s.commit()


# ---------------------------------------------------------------------------
# TestCertificateCRUD
# ---------------------------------------------------------------------------


class TestCertificateCRUD:

    @pytest.mark.anyio
    async def test_create_certificate(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="example-cert",
            domains=["example.com"],
            acme_account_ref="letsencrypt-prod",
            dns_provider_ref="cloudflare-main",
        )
        db.add(cert)
        await db.flush()

        row = (await db.execute(select(Certificate).where(Certificate.id == cert.id))).scalar_one()
        assert row.name == "example-cert"
        assert row.domains == ["example.com"]
        assert row.status == CertificateStatus.PENDING

    @pytest.mark.anyio
    async def test_query_by_name(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="my-site-cert",
            domains=["my-site.io"],
            acme_account_ref="acme-account-1",
            dns_provider_ref="dns-provider-1",
        )
        db.add(cert)
        await db.flush()

        result = (await db.execute(select(Certificate).where(Certificate.name == "my-site-cert"))).scalar_one()
        assert result.id == cert.id
        assert result.domains == ["my-site.io"]

    @pytest.mark.anyio
    async def test_update_status(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="update-test-cert",
            domains=["update.example.com"],
            acme_account_ref="acme-account-1",
            dns_provider_ref="dns-provider-1",
        )
        db.add(cert)
        await db.flush()

        assert cert.status == CertificateStatus.PENDING

        cert.status = CertificateStatus.VALID
        await db.commit()
        await db.refresh(cert)

        assert cert.status == CertificateStatus.VALID

        row = (await db.execute(select(Certificate).where(Certificate.id == cert.id))).scalar_one()
        assert row.status == CertificateStatus.VALID

    @pytest.mark.anyio
    async def test_delete_certificate(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="delete-me-cert",
            domains=["del.example.com"],
            acme_account_ref="acme-account-1",
            dns_provider_ref="dns-provider-1",
        )
        db.add(cert)
        await db.flush()

        cert_id = cert.id
        await db.delete(cert)
        await db.commit()

        row = (await db.execute(select(Certificate).where(Certificate.id == cert_id))).scalar_one_or_none()
        assert row is None


# ---------------------------------------------------------------------------
# TestEventCRUD
# ---------------------------------------------------------------------------


class TestEventCRUD:

    @pytest.mark.anyio
    async def test_create_event(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="parent-cert",
            domains=["parent.example.com"],
            acme_account_ref="acme-account-1",
            dns_provider_ref="dns-provider-1",
        )
        db.add(cert)
        await db.flush()

        ev = Event(
            event_type="certificate.created",
            certificate_id=cert.id,
            details={"note": "initial"},
        )
        db.add(ev)
        await db.flush()

        row = (await db.execute(select(Event).where(Event.id == ev.id))).scalar_one()
        assert row.event_type == "certificate.created"
        assert row.certificate_id == cert.id
        assert row.details == {"note": "initial"}

    @pytest.mark.anyio
    async def test_query_events_by_certificate(self, db: AsyncSession) -> None:
        cert = Certificate(
            name="multi-event-cert",
            domains=["multi.example.com"],
            acme_account_ref="acme-account-1",
            dns_provider_ref="dns-provider-1",
        )
        db.add(cert)
        await db.flush()

        ev1 = Event(event_type="certificate.requested", certificate_id=cert.id, details={"step": 1})
        ev2 = Event(event_type="certificate.issued", certificate_id=cert.id, details={"step": 2})
        db.add_all([ev1, ev2])
        await db.flush()

        result = (await db.execute(select(Event).where(Event.certificate_id == cert.id))).scalars().all()
        assert len(result) == 2

    @pytest.mark.anyio
    async def test_standalone_event(self, db: AsyncSession) -> None:
        ev = Event(
            event_type="system.bootstrap",
            certificate_id=None,
            details={"message": "standalone event"},
        )
        db.add(ev)
        await db.flush()

        row = (await db.execute(select(Event).where(Event.id == ev.id))).scalar_one()
        assert row.certificate_id is None
        assert row.event_type == "system.bootstrap"
