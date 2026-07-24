"""AcmeBackend Protocol — domain-model-agnostic interface for ACME CA operations."""

from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult


ChallengeMethod = t.Literal["dns-01", "dns-persist", "webroot"]


class AcmeBackend(t.Protocol):
    """Interface a concrete ACME backend must implement.

    Return types are intentionally domain-model-agnostic (dataclasses) so the API
    layer can map them to SQLAlchemy models without importing from this package.
    """

    async def register_account(
        self,
        email: str,
        server_url: str,
    ) -> AccountInfo: ...

    async def make_dns_persist_value(
        self,
        domain: str,
        *,
        wildcard: bool = False,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> str: ...

    async def issue_certificate(
        self,
        domains: list[str],
        method: ChallengeMethod,
        challenge_params: dict[str, t.Any],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult: ...

    async def renew_certificate(
        self,
        domains: list[str],
        force_renewal: bool = False,
    ) -> IssuanceResult: ...

    async def revoke_certificate(
        self,
        domain: str,
        *,
        reason: int | None = None,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> None: ...

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry: ...
