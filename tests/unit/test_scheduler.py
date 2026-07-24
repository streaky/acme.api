"""Tests for renewal scheduling and execution."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
from apscheduler.schedulers.asyncio import (  # type: ignore[import-untyped]
    AsyncIOScheduler,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.backend.acmesh_errors import TerminalAcmeShError, TransientAcmeShError
from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult
from acme_api.backend.protocol import ChallengeMethod
from acme_api.config import AppSettings, DatabaseConfig, DeploymentConfig, RenewalConfig
from acme_api.db import get_session_factory, init_db, init_engine
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.models.renewal_attempt import RenewalAttempt
from acme_api.scheduler import RenewalScheduler, next_renewal_run_time


class RecordingBackend:
    """Small backend test double for renewal outcomes."""

    def __init__(self) -> None:
        self.calls = 0
        self.error: Exception | None = None

    async def register_account(self, email: str, server_url: str) -> AccountInfo:
        """Return deterministic account info."""
        return AccountInfo(
            key_path="/acmesh/acct.key",
            email=email,
            server_url=server_url,
        )

    async def make_dns_persist_value(
        self,
        domain: str,
        *,
        wildcard: bool = False,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> str:
        """Return a deterministic value for protocol completeness."""
        del wildcard, account_key_path, server_url
        return f"persist-{domain}"

    async def issue_certificate(
        self,
        domains: list[str],
        method: ChallengeMethod,
        challenge_params: dict[str, Any],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult:
        """Return deterministic issuance info."""
        del method, challenge_params, server_url
        return IssuanceResult(
            account_key_path=account_key_path or "/acmesh/acct.key",
            cert=_cert_expiry(),
            domains=domains,
        )

    async def renew_certificate(self, domains: list[str], force_renewal: bool = False) -> IssuanceResult:
        """Return a successful renewal or raise the configured error."""
        del force_renewal
        self.calls += 1
        if self.error is not None:
            raise self.error
        expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=90)
        return IssuanceResult(
            account_key_path="/acmesh/acct.key",
            cert=_cert_expiry(expires_at),
            domains=domains,
        )

    async def revoke_certificate(
        self,
        domain: str,
        *,
        reason: int | None = None,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> None:
        """Satisfy the ACME backend protocol for scheduler-only tests."""
        del domain, reason, account_key_path, server_url

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry:
        """Return deterministic expiry info."""
        result = _cert_expiry()
        return CertExpiry(
            cert_path=cert_path,
            privkey_path=result.privkey_path,
            chain_path=result.chain_path,
            fullchain_path=result.fullchain_path,
            expires_at=result.expires_at,
        )


def _cert_expiry(expires_at: dt.datetime | None = None) -> CertExpiry:
    """Return a deterministic cert expiry object."""
    return CertExpiry(
        cert_path="/acmesh/cert.pem",
        privkey_path="/acmesh/privkey.pem",
        chain_path="/acmesh/chain.pem",
        fullchain_path="/acmesh/fullchain.pem",
        expires_at=expires_at or dt.datetime.now(dt.UTC) + dt.timedelta(days=90),
    )


@pytest.fixture()
async def session_factory(
    tmp_path: Path,
) -> AsyncGenerator[async_sessionmaker[AsyncSession]]:
    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path),
    )
    engine = init_engine(settings)
    try:
        await init_db(engine)
        yield get_session_factory()
    finally:
        await engine.dispose()


async def _create_certificate(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    expiry: dt.datetime | None = None,
    status: CertificateStatus = CertificateStatus.VALID,
) -> Certificate:
    async with session_factory() as session:
        certificate = Certificate(
            name="renew-me",
            domains=["example.com"],
            acme_account_ref="le",
            dns_provider_ref="cf",
            expiry_date=expiry or dt.datetime.now(dt.UTC),
            status=status,
        )
        session.add(certificate)
        await session.commit()
        await session.refresh(certificate)
        return certificate


def test_next_renewal_run_time_uses_window() -> None:
    """Renewal is scheduled at expiry minus configured window."""
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    expiry = dt.datetime(2026, 3, 1, tzinfo=dt.UTC)

    run_at = next_renewal_run_time(expiry, 30, now_factory=lambda: now)

    assert run_at == dt.datetime(2026, 1, 30, tzinfo=dt.UTC)


def test_next_renewal_run_time_is_immediate_inside_window() -> None:
    """Certs already inside the renewal window run immediately."""
    now = dt.datetime(2026, 1, 20, tzinfo=dt.UTC)
    expiry = dt.datetime(2026, 2, 1, tzinfo=dt.UTC)

    run_at = next_renewal_run_time(expiry, 30, now_factory=lambda: now)

    assert run_at == now


@pytest.mark.anyio
async def test_rebuild_jobs_schedules_valid_certificates(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Startup reconstruction creates one APScheduler job per valid cert."""
    certificate = await _create_certificate(session_factory)
    scheduler = AsyncIOScheduler(timezone=dt.UTC)
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=RecordingBackend(),
        config=RenewalConfig(),
        scheduler=scheduler,
    )

    count = await renewal_scheduler.rebuild_jobs()

    assert count == 1
    assert scheduler.get_job(f"renew:{certificate.id}") is not None


@pytest.mark.anyio
async def test_rebuild_jobs_excludes_held_requests(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Held requests never enter the renewal scheduler, even with an expiry date."""
    certificate = await _create_certificate(session_factory, status=CertificateStatus.HELD)
    scheduler = AsyncIOScheduler(timezone=dt.UTC)
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=RecordingBackend(),
        config=RenewalConfig(),
        scheduler=scheduler,
    )

    assert await renewal_scheduler.rebuild_jobs() == 0
    assert scheduler.get_job(f"renew:{certificate.id}") is None


@pytest.mark.anyio
async def test_rebuild_jobs_records_expiring_event_once(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Startup reconstruction emits one expiring event inside the renewal window."""
    await _create_certificate(
        session_factory,
        expiry=dt.datetime.now(dt.UTC) + dt.timedelta(days=5),
    )
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=RecordingBackend(),
        config=RenewalConfig(window_days=30),
        scheduler=AsyncIOScheduler(timezone=dt.UTC),
    )

    assert await renewal_scheduler.rebuild_jobs() == 1
    assert await renewal_scheduler.rebuild_jobs() == 1

    async with session_factory() as session:
        events = (
            (await session.execute(select(Event).where(Event.event_type == "certificate.expiring"))).scalars().all()
        )

    assert len(events) == 1


@pytest.mark.anyio
async def test_successful_renewal_updates_status_and_records_attempt(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Successful renewal updates expiry, attempt history, and audit events."""
    certificate = await _create_certificate(session_factory)
    backend = RecordingBackend()
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=backend,
        config=RenewalConfig(),
        scheduler=AsyncIOScheduler(timezone=dt.UTC),
    )

    await renewal_scheduler.renew_certificate(certificate.id)

    async with session_factory() as session:
        refreshed = await session.get(Certificate, certificate.id)
        attempts = (await session.execute(select(RenewalAttempt))).scalars().all()
        events = (await session.execute(select(Event).where(Event.event_type == "certificate.renewed"))).scalars().all()

    assert backend.calls == 1
    assert refreshed is not None
    assert refreshed.status == CertificateStatus.VALID
    assert refreshed.expiry_date is not None
    assert len(attempts) == 1
    assert attempts[0].status == "success"
    assert len(events) == 1


@pytest.mark.anyio
async def test_dns_persist_renewal_needs_no_dns_provider(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A valid DNS Persist certificate follows the normal renewal deployment path."""
    certificate = await _create_certificate(session_factory)
    async with session_factory() as session:
        stored = await session.get(Certificate, certificate.id)
        assert stored is not None
        stored.dns_provider_ref = None
        stored.challenge_method = "dns-persist"
        stored.dns_record_type = "TXT"
        stored.dns_record_name = "_validation-persist.example.com"
        stored.dns_record_value = "account-bound-value"
        await session.commit()

    backend = RecordingBackend()
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=backend,
        config=RenewalConfig(),
        scheduler=AsyncIOScheduler(timezone=dt.UTC),
    )
    await renewal_scheduler.renew_certificate(certificate.id)

    assert backend.calls == 1


@pytest.mark.anyio
async def test_transient_failure_records_retry(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Transient backend failures keep the cert valid and schedule retry."""
    certificate = await _create_certificate(session_factory)
    backend = RecordingBackend()
    backend.error = TransientAcmeShError("dns not ready")
    scheduler = AsyncIOScheduler(timezone=dt.UTC)
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=backend,
        config=RenewalConfig(max_retries=1),
        scheduler=scheduler,
    )

    await renewal_scheduler.renew_certificate(certificate.id)

    async with session_factory() as session:
        refreshed = await session.get(Certificate, certificate.id)
        attempt = (await session.execute(select(RenewalAttempt))).scalar_one()

    assert refreshed is not None
    assert refreshed.status == CertificateStatus.VALID
    assert attempt.status == "failed"
    assert attempt.error_category == "transient"
    assert attempt.next_retry_at is not None
    assert scheduler.get_job(f"renew-retry:{certificate.id}") is not None


@pytest.mark.anyio
async def test_terminal_failure_marks_certificate_failed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Terminal backend failures mark the cert failed without retry."""
    certificate = await _create_certificate(session_factory)
    backend = RecordingBackend()
    backend.error = TerminalAcmeShError("account invalid")
    scheduler = AsyncIOScheduler(timezone=dt.UTC)
    renewal_scheduler = RenewalScheduler(
        session_factory=session_factory,
        backend=backend,
        config=RenewalConfig(max_retries=1),
        scheduler=scheduler,
    )

    await renewal_scheduler.renew_certificate(certificate.id)

    async with session_factory() as session:
        refreshed = await session.get(Certificate, certificate.id)
        attempt = (await session.execute(select(RenewalAttempt))).scalar_one()

    assert refreshed is not None
    assert refreshed.status == CertificateStatus.FAILED
    assert attempt.error_category == "terminal"
    assert scheduler.get_job(f"renew-retry:{certificate.id}") is None
