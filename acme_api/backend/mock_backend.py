"""In-memory ACME backend for API and service tests."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult
from acme_api.backend.protocol import ChallengeMethod


class MockAcmeBackend:
    """Deterministic backend that does not shell out to acme.sh."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    async def register_account(self, email: str, server_url: str) -> AccountInfo:
        """Return a predictable account record."""
        key_path = self.base_dir / "acct.key"
        return AccountInfo(key_path=str(key_path), email=email, server_url=server_url)

    async def issue_certificate(
        self,
        domains: list[str],
        method: ChallengeMethod,
        challenge_params: dict[str, object],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult:
        """Return a predictable issuance result."""
        del method, challenge_params, server_url
        return IssuanceResult(
            account_key_path=account_key_path or str(self.base_dir / "acct.key"),
            cert=self._cert_expiry(domains[0]),
            domains=domains,
        )

    async def renew_certificate(
        self,
        domains: list[str],
        force_renewal: bool = False,
    ) -> IssuanceResult:
        """Return a predictable renewal result."""
        del force_renewal
        return IssuanceResult(
            account_key_path=str(self.base_dir / "acct.key"),
            cert=self._cert_expiry(domains[0]),
            domains=domains,
        )

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry:
        """Return a predictable expiry for the supplied certificate path."""
        cert = self._cert_expiry("example.com")
        return CertExpiry(
            cert_path=cert_path,
            privkey_path=cert.privkey_path,
            chain_path=cert.chain_path,
            fullchain_path=cert.fullchain_path,
            expires_at=cert.expires_at,
        )

    def _cert_expiry(self, domain: str) -> CertExpiry:
        safe_domain = domain.replace("*.", "wildcard.")
        cert_dir = self.base_dir / safe_domain
        return CertExpiry(
            cert_path=str(cert_dir / "cert.pem"),
            privkey_path=str(cert_dir / "privkey.pem"),
            chain_path=str(cert_dir / "chain.pem"),
            fullchain_path=str(cert_dir / "fullchain.pem"),
            expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90),
        )
