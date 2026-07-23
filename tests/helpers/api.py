"""Reusable authenticated API application test helpers."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import select

from acme_api.auth.hash import api_key_lookup_hash, hash_api_key
from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult
from acme_api.config import (
    AcmeAccountConfig,
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
    DnsProviderConfig,
)
from acme_api.db import get_db
from acme_api.main import create_app
from acme_api.models.api_key import APIKey, APIKeyRole


class ArtifactBackend:
    """Test backend that writes deployable certificate artifacts."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self.issue_calls = 0
        self.fail_issues = False
        self.renew_calls = 0
        self.persist_value_calls = 0
        self.persist_value_error: AcmeShError | None = None
        self.persist_value_requests: list[tuple[str, bool]] = []

    async def register_account(self, email: str, server_url: str) -> AccountInfo:
        """Return deterministic account metadata for protocol completeness."""
        return AccountInfo(key_path="account.key", email=email, server_url=server_url)

    async def make_dns_persist_value(
        self,
        domain: str,
        *,
        wildcard: bool = False,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> str:
        """Return a stable, account-bound test instruction."""
        del account_key_path, server_url
        self.persist_value_calls += 1
        self.persist_value_requests.append((domain, wildcard))
        if self.persist_value_error is not None:
            raise self.persist_value_error
        return f"persist-value-for-{domain}"

    async def issue_certificate(
        self,
        domains: list[str],
        method: str,
        challenge_params: dict[str, object],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult:
        del method, challenge_params, server_url
        self.issue_calls += 1
        if self.fail_issues:
            raise TransientAcmeShError("DNS propagation may still be in progress")
        return self._result(domains, "issue", account_key_path)

    async def renew_certificate(
        self,
        domains: list[str],
        force_renewal: bool = False,
    ) -> IssuanceResult:
        del force_renewal
        self.renew_calls += 1
        return self._result(domains, "renew", "account.key")

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry:
        raise NotImplementedError

    def _result(self, domains: list[str], operation: str, account_key_path: str | None) -> IssuanceResult:
        directory = self._root / operation / str(self.issue_calls + self.renew_calls)
        directory.mkdir(parents=True, exist_ok=True)
        paths = {
            name: directory / filename
            for name, filename in {
                "cert": "cert.pem",
                "key": "privkey.pem",
                "chain": "chain.pem",
                "fullchain": "fullchain.pem",
            }.items()
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
                expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=90),
            ),
            domains=domains,
        )


def make_api_app(tmp_path: Path, *, generation_aware: bool = False) -> FastAPI:
    """Create an application seeded with API clients and artifact backend."""
    env_file = tmp_path / "cloudflare.env"
    env_file.write_text("CF_Token=test\n", encoding="utf-8")
    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certs", generation_aware=generation_aware),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        dns_providers=[
            DnsProviderConfig(name="cloudflare-main", provider_name="cloudflare", env_vars_file_path=env_file)
        ],
        acme_accounts=[AcmeAccountConfig(name="letsencrypt-production")],
    )
    app = create_app(settings=settings)
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def seeded_lifespan(application: FastAPI) -> AsyncGenerator[None]:
        async with original_lifespan(application):
            async with get_db() as session:
                has_client = await session.scalar(select(APIKey.id).limit(1))
                if has_client is None:
                    for role, raw_key in (
                        (APIKeyRole.ADMIN, "admin-key-12345"),
                        (APIKeyRole.OPERATOR, "operator-key-12345"),
                        (APIKeyRole.READONLY, "readonly-key-12345"),
                    ):
                        session.add(
                            APIKey(
                                name=f"test-{role.value}",
                                hashed_key=hash_api_key(raw_key),
                                key_lookup_hash=api_key_lookup_hash(raw_key),
                                role=role,
                            )
                        )
                    await session.commit()
            yield

    app.router.lifespan_context = seeded_lifespan
    app.state.acme_backend = ArtifactBackend(tmp_path / "acme-artifacts")
    return app
