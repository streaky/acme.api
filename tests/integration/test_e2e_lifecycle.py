"""End-to-end integration coverage for the default mock-backed release gate."""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path
from typing import Any, ClassVar

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import acme_api.main as main_module
from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult
from acme_api.backend.protocol import ChallengeMethod
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
from acme_api.main import create_app
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.models.webhook import WebhookConfig
from acme_api.scheduler import RenewalScheduler
from acme_api.webhooks import SIGNATURE_HEADER, WebhookDispatcher, sign_payload


class ArtifactBackend:
    """Backend double that creates realistic artifact files for deployment."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self.issue_calls = 0
        self.renew_calls = 0
        self.challenge_params: list[dict[str, Any]] = []

    async def register_account(self, email: str, server_url: str) -> AccountInfo:
        """Account registration is not part of this E2E flow."""
        return AccountInfo(
            key_path="account.key",
            email=email,
            server_url=server_url,
        )

    async def issue_certificate(
        self,
        domains: list[str],
        method: ChallengeMethod,
        challenge_params: dict[str, Any],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult:
        """Return deployable certificate artifacts for issuance."""
        assert method == "dns-01"
        del server_url
        self.issue_calls += 1
        self.challenge_params.append(challenge_params)
        return self._result(domains, "issue", account_key_path)

    async def renew_certificate(
        self,
        domains: list[str],
        force_renewal: bool = False,
    ) -> IssuanceResult:
        """Return deployable certificate artifacts for renewal."""
        assert force_renewal is False
        self.renew_calls += 1
        return self._result(domains, "renew", "account.key")

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry:
        """Return deterministic expiry metadata for a certificate path."""
        return CertExpiry(
            cert_path=cert_path,
            privkey_path=cert_path,
            chain_path=cert_path,
            fullchain_path=cert_path,
            expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90),
        )

    def _result(
        self,
        domains: list[str],
        operation: str,
        account_key_path: str | None,
    ) -> IssuanceResult:
        directory = self._root / operation / str(self.issue_calls + self.renew_calls)
        directory.mkdir(parents=True, exist_ok=True)
        paths = {
            "cert": directory / "cert.pem",
            "key": directory / "privkey.pem",
            "chain": directory / "chain.pem",
            "fullchain": directory / "fullchain.pem",
        }
        for name, path in paths.items():
            path.write_text(f"{operation}-{name}", encoding="utf-8")
        return IssuanceResult(
            account_key_path=account_key_path or "account.key",
            cert=CertExpiry(
                cert_path=str(paths["cert"]),
                privkey_path=str(paths["key"]),
                chain_path=str(paths["chain"]),
                fullchain_path=str(paths["fullchain"]),
                expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90),
            ),
            domains=domains,
        )


class CapturingWebhookDispatcher(WebhookDispatcher):
    """Webhook dispatcher that sends through an in-memory HTTP transport."""

    requests: ClassVar[list[httpx2.Request]] = []

    def __init__(
        self,
        session: AsyncSession,
        settings: WebhookDeliveryConfig | None = None,
    ) -> None:
        del settings
        client = httpx2.AsyncClient(transport=httpx2.MockTransport(self._handle))
        super().__init__(session=session, client=client)

    @classmethod
    def reset(cls) -> None:
        """Clear captured webhook requests."""
        cls.requests = []

    @classmethod
    def _handle(cls, request: httpx2.Request) -> httpx2.Response:
        cls.requests.append(request)
        return httpx2.Response(status_code=204)


def _settings(tmp_path: Path) -> AppSettings:
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
        api_keys={
            "admin": "admin-key-12345",
            "operator": "operator-key-12345",
            "readonly": "readonly-key-12345",
        },
    )


def _make_app(tmp_path: Path) -> FastAPI:
    app = create_app(settings=_settings(tmp_path))
    app.state.acme_backend = ArtifactBackend(tmp_path / "acme-artifacts")
    return app


def _operator_headers() -> dict[str, str]:
    return {"Authorization": "Bearer operator-key-12345"}


def test_full_certificate_lifecycle_with_webhooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create, issue, deploy, renew, revoke, audit, and deliver webhooks."""
    monkeypatch.setattr(main_module, "WebhookDispatcher", CapturingWebhookDispatcher)
    monkeypatch.setattr(
        "acme_api.webhooks._resolve_host_ips",
        lambda _host: {ipaddress.ip_address("93.184.216.34")},
    )
    CapturingWebhookDispatcher.reset()

    app = _make_app(tmp_path)
    with TestClient(app) as client:
        _add_webhook_config(client)

        created = client.post(
            "/v1/certificates",
            headers=_operator_headers(),
            json={
                "name": "e2e-cert",
                "domains": ["example.com", "www.example.com"],
                "acme_account_ref": "letsencrypt-staging",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        assert created.status_code == 202
        certificate_id = created.json()["id"]

        detail = client.get(
            f"/v1/certificates/{certificate_id}",
            headers=_operator_headers(),
        )
        assert detail.json()["status"] == "valid"
        assert (tmp_path / "certificates" / "example.com" / "fullchain.pem").is_file()
        backend = app.state.acme_backend
        assert backend.issue_calls == 1
        assert backend.challenge_params == [
            {
                "dns_provider": "cloudflare",
                "env_vars_file": str(Path("tests/fixtures/sample_dns.env").resolve()),
            }
        ]

        renewed = client.post(
            f"/v1/certificates/{certificate_id}/renew",
            headers=_operator_headers(),
        )
        assert renewed.status_code == 202
        assert backend.renew_calls == 1

        revoked = client.delete(
            f"/v1/certificates/{certificate_id}",
            headers=_operator_headers(),
        )
        assert revoked.status_code == 204

        events = client.get("/v1/events", headers=_operator_headers()).json()
        event_types = {event["event_type"] for event in events}
        assert {
            "certificate.created",
            "certificate.issued",
            "certificate.renewal_requested",
            "certificate.renewed",
            "certificate.revoked",
        }.issubset(event_types)

    webhook_events = {
        request.headers["X-Webhook-Event"]
        for request in CapturingWebhookDispatcher.requests
    }
    assert {
        "certificate.created",
        "certificate.issued",
        "certificate.renewed",
        "certificate.revoked",
    }.issubset(webhook_events)
    for request in CapturingWebhookDispatcher.requests:
        assert request.headers[SIGNATURE_HEADER] == sign_payload(
            "shared-secret",
            request.content,
        )


@pytest.mark.anyio
async def test_scheduler_rebuilds_expiring_certificate_jobs(tmp_path: Path) -> None:
    """A valid cert inside the renewal window is scheduled and audited once."""
    settings = _settings(tmp_path)
    engine = init_engine(settings)
    try:
        await init_db(engine)
        session_factory = get_session_factory()
        certificate = await _create_valid_expiring_certificate(session_factory)
        scheduler = RenewalScheduler(
            session_factory=session_factory,
            backend=ArtifactBackend(tmp_path / "acme-artifacts"),
            config=settings.renewal,
        )

        assert await scheduler.rebuild_jobs() == 1
        assert await scheduler.rebuild_jobs() == 1

        async with session_factory() as session:
            events = (
                await session.execute(
                    select(Event).where(Event.event_type == "certificate.expiring")
                )
            ).scalars().all()

        assert len(events) == 1
        assert scheduler.schedule_certificate(certificate) is not None
        scheduler.remove_certificate(certificate.id)
    finally:
        await engine.dispose()


def test_role_matrix_for_integration_endpoints(tmp_path: Path) -> None:
    """Default E2E endpoints enforce API key roles consistently."""
    with TestClient(_make_app(tmp_path)) as client:
        readonly = {"Authorization": "Bearer readonly-key-12345"}
        operator = _operator_headers()

        assert client.get("/v1/certificates").status_code == 401
        assert client.get("/v1/certificates", headers=readonly).status_code == 200
        assert client.get("/v1/accounts", headers=readonly).status_code == 200
        assert client.get("/v1/providers", headers=readonly).status_code == 200
        assert client.get("/v1/events", headers=readonly).status_code == 200
        assert client.post(
            "/v1/certificates",
            headers=readonly,
            json={
                "name": "forbidden",
                "domains": ["forbidden.example.com"],
                "acme_account_ref": "letsencrypt-staging",
                "dns_provider_ref": "cloudflare-main",
            },
        ).status_code == 403
        assert client.post(
            "/v1/certificates",
            headers=operator,
            json={
                "name": "allowed",
                "domains": ["allowed.example.com"],
                "acme_account_ref": "letsencrypt-staging",
                "dns_provider_ref": "cloudflare-main",
            },
        ).status_code == 202


def _add_webhook_config(client: TestClient) -> None:
    session_factory = get_session_factory()

    async def add_config() -> None:
        async with session_factory() as session:
            session.add(
                WebhookConfig(
                    url="https://hooks.example.test/certificates",
                    events=["*"],
                    secret="shared-secret",
                )
            )
            await session.commit()

    assert client.portal is not None
    client.portal.call(add_config)


async def _create_valid_expiring_certificate(
    session_factory: async_sessionmaker[AsyncSession],
) -> Certificate:
    async with session_factory() as session:
        certificate = Certificate(
            name="expiring-e2e",
            domains=["expiring.example.com"],
            acme_account_ref="letsencrypt-staging",
            dns_provider_ref="cloudflare-main",
            expiry_date=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5),
            status=CertificateStatus.VALID,
        )
        session.add(certificate)
        await session.commit()
        await session.refresh(certificate)
        return certificate
