"""Concurrency coverage for durable DNS Persist request transitions."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.config import (
    AcmeAccountConfig,
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
    DnsProviderConfig,
    RenewalConfig,
    WebhookDeliveryConfig,
)
from acme_api.db import get_session_factory, init_db, init_engine
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.services.certificates import CertificateLifecycleService
from tests.helpers.api import ArtifactBackend


def _settings(tmp_path: Path) -> AppSettings:
    """Build settings for isolated DNS Persist lifecycle integration tests."""
    fixture_dir = Path(__file__).resolve().parents[1] / "fixtures"
    return AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certificates"),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        renewal=RenewalConfig(window_days=30, max_retries=1),
        webhooks=WebhookDeliveryConfig(max_retries=0, backoff_seconds=0),
        dns_providers=[
            DnsProviderConfig(
                name="cloudflare-main",
                provider_name="cloudflare",
                env_vars_file_path=fixture_dir / "sample_dns.env",
            )
        ],
        acme_accounts=[AcmeAccountConfig(name="letsencrypt-staging")],
    )


@pytest.mark.anyio
async def test_concurrent_dns_persist_authorizations_start_once(tmp_path: Path) -> None:
    """Exactly one concurrent authorization claims a DNS Persist request."""
    settings = _settings(tmp_path)
    engine = init_engine(settings)
    try:
        await init_db(engine)
        session_factory = get_session_factory()
        async with session_factory() as session:
            certificate = Certificate(
                name="concurrent-manual-cert",
                domains=["example.com"],
                acme_account_ref="letsencrypt-staging",
                challenge_method="dns-persist",
                dns_record_name="_validation-persist.example.com",
                dns_record_value="persist-example.com",
                status=CertificateStatus.PENDING_DNS,
            )
            session.add(certificate)
            await session.commit()
            certificate_id = certificate.id

        service = CertificateLifecycleService(
            session_factory=session_factory,
            backend=ArtifactBackend(tmp_path / "acme-artifacts"),
            settings=settings,
        )
        authorizations = await asyncio.gather(
            service.authorize_dns_persist_certificate(certificate_id),
            service.authorize_dns_persist_certificate(certificate_id),
        )

        assert sum(starts_issuance for _, starts_issuance in authorizations) == 1
        async with session_factory() as session:
            stored_certificate = await session.get(Certificate, certificate_id)
            events = (
                (await session.execute(select(Event).where(Event.certificate_id == certificate_id))).scalars().all()
            )

        assert stored_certificate is not None
        assert stored_certificate.status == CertificateStatus.ISSUING
        assert [event.event_type for event in events] == ["certificate.authorization_requested"]
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_held_authorization_cannot_overwrite_concurrent_release(tmp_path: Path) -> None:
    """A stale held authorization leaves a concurrent release claim intact."""
    settings = _settings(tmp_path)
    engine = init_engine(settings)
    try:
        await init_db(engine)
        session_factory = get_session_factory()
        async with session_factory() as session:
            certificate = Certificate(
                name="held-release-race-cert",
                domains=["example.com"],
                acme_account_ref="letsencrypt-staging",
                challenge_method="dns-persist",
                dns_record_name="_validation-persist.example.com",
                dns_record_value="persist-example.com",
                status=CertificateStatus.HELD,
            )
            session.add(certificate)
            await session.commit()
            certificate_id = certificate.id
            revision = certificate.revision

        backend = ArtifactBackend(tmp_path / "acme-artifacts")
        release_service = CertificateLifecycleService(
            session_factory=session_factory,
            backend=backend,
            settings=settings,
        )
        released = False

        @asynccontextmanager
        async def stale_authorization_session() -> AsyncGenerator[AsyncSession]:
            nonlocal released
            async with session_factory() as session:
                original_execute = session.execute

                async def execute_with_concurrent_release(*args: Any, **kwargs: Any) -> Any:
                    nonlocal released
                    if not released:
                        released = True
                        await release_service.release_held_dns_persist_certificate(
                            certificate_id,
                            revision=revision,
                            idempotency_key="concurrent-release",
                        )
                    return await original_execute(*args, **kwargs)

                with patch.object(session, "execute", side_effect=execute_with_concurrent_release):
                    yield session

        authorization_service = CertificateLifecycleService(
            session_factory=cast(async_sessionmaker[AsyncSession], stale_authorization_session),
            backend=backend,
            settings=settings,
        )
        authorized, starts_issuance = await authorization_service.authorize_dns_persist_certificate(certificate_id)

        assert released is True
        assert starts_issuance is False
        assert authorized.status == CertificateStatus.RELEASED
        assert authorized.release_idempotency_key == "concurrent-release"
        async with session_factory() as session:
            stored_certificate = await session.get(Certificate, certificate_id)
            events = (
                (await session.execute(select(Event).where(Event.certificate_id == certificate_id))).scalars().all()
            )

        assert stored_certificate is not None
        assert stored_certificate.status == CertificateStatus.RELEASED
        assert stored_certificate.release_idempotency_key == "concurrent-release"
        assert [event.event_type for event in events] == ["certificate.released"]
    finally:
        await engine.dispose()
