"""Tests for webhook signing and delivery."""

from __future__ import annotations

import hmac
from collections.abc import AsyncGenerator
from pathlib import Path

import httpx2
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.config import AppSettings, DatabaseConfig, DeploymentConfig
from acme_api.db import get_session_factory, init_db, init_engine
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.models.webhook import WebhookConfig
from acme_api.webhooks import (
    SIGNATURE_HEADER,
    WebhookDeliverySettings,
    WebhookDispatcher,
    WebhookPayload,
    encode_payload,
    sign_payload,
)


@pytest.fixture()
async def session_factory(
    tmp_path: Path,
) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
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


@pytest.fixture()
async def db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    async with session_factory() as session:
        yield session


def test_sign_payload_is_hmac_sha256() -> None:
    """Webhook signatures are stable HMAC-SHA256 values."""
    payload = WebhookPayload(
        event="certificate.renewed",
        certificate_name="example",
        domains=["example.com"],
        expiry=None,
    )
    body = encode_payload(payload)

    signature = sign_payload("secret", body)

    assert signature.startswith("sha256=")
    assert hmac.compare_digest(signature, sign_payload("secret", body))


@pytest.mark.anyio
async def test_dispatch_sends_signed_payload(db_session: AsyncSession) -> None:
    """A matching enabled webhook receives a signed JSON payload."""
    certificate = Certificate(
        name="example-cert",
        domains=["example.com"],
        acme_account_ref="le",
        dns_provider_ref="cf",
        status=CertificateStatus.VALID,
    )
    db_session.add(certificate)
    db_session.add(
        WebhookConfig(
            url="https://hooks.example.test/certs",
            events=["certificate.renewed"],
            secret="shared-secret",
        )
    )
    await db_session.commit()
    captured: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured.append(request)
        return httpx2.Response(204)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        async with WebhookDispatcher(db_session, client=client) as dispatcher:
            delivered = await dispatcher.dispatch_certificate_event(
                "certificate.renewed", certificate
            )

    assert delivered == 1
    assert len(captured) == 1
    assert captured[0].headers[SIGNATURE_HEADER] == sign_payload(
        "shared-secret", captured[0].content
    )


@pytest.mark.anyio
async def test_dispatch_retries_then_succeeds(db_session: AsyncSession) -> None:
    """Transient HTTP failures are retried before success."""
    certificate = Certificate(
        name="retry-cert",
        domains=["retry.example.com"],
        acme_account_ref="le",
        dns_provider_ref="cf",
        status=CertificateStatus.VALID,
    )
    db_session.add(certificate)
    db_session.add(
        WebhookConfig(
            url="https://hooks.example.test/retry",
            events=["*"],
            secret="shared-secret",
        )
    )
    await db_session.commit()
    attempts = 0

    def handler(_request: httpx2.Request) -> httpx2.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx2.Response(503)
        return httpx2.Response(200)

    settings = WebhookDeliverySettings(max_retries=1, backoff_seconds=0)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        async with WebhookDispatcher(db_session, settings, client) as dispatcher:
            delivered = await dispatcher.dispatch_certificate_event(
                "certificate.failed", certificate
            )

    assert delivered == 1
    assert attempts == 2


@pytest.mark.anyio
async def test_dispatch_logs_failed_delivery(db_session: AsyncSession) -> None:
    """Failed webhook delivery writes an audit event."""
    certificate = Certificate(
        name="failed-hook-cert",
        domains=["failed-hook.example.com"],
        acme_account_ref="le",
        dns_provider_ref="cf",
        status=CertificateStatus.VALID,
    )
    db_session.add(certificate)
    db_session.add(
        WebhookConfig(
            url="https://hooks.example.test/fail",
            events=["certificate.failed"],
            secret="shared-secret",
        )
    )
    await db_session.commit()

    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(500)

    settings = WebhookDeliverySettings(max_retries=0, backoff_seconds=0)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        async with WebhookDispatcher(db_session, settings, client) as dispatcher:
            delivered = await dispatcher.dispatch_certificate_event(
                "certificate.failed", certificate
            )

    events = (
        await db_session.execute(
            select(Event).where(Event.event_type == "webhook.delivery_failed")
        )
    ).scalars().all()
    assert delivered == 0
    assert len(events) == 1
    assert events[0].details["event"] == "certificate.failed"
