"""Certificate lifecycle orchestration service."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.backend.acmesh_backend import AcmeShBackend
from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.backend.protocol import AcmeBackend
from acme_api.config import AcmeAccountConfig, AppSettings, DnsProviderConfig
from acme_api.deployer import DeploymentError, DeploymentOptions, deploy_issuance_result
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.schemas.certificate import CertificateCreate
from acme_api.webhooks import WebhookDispatcher


class CertificateLifecycleError(Exception):
    """Base exception for lifecycle service errors."""


class CertificateConflictError(CertificateLifecycleError):
    """Raised when a certificate cannot be created due to a uniqueness conflict."""


class CertificateNotFoundError(CertificateLifecycleError):
    """Raised when a certificate row does not exist."""


class CertificateNotRenewableError(CertificateLifecycleError):
    """Raised when a certificate is not eligible for renewal."""


class RenewalSchedulerProtocol(Protocol):
    """Scheduler operations used by the certificate lifecycle service."""

    def schedule_certificate(self, certificate: Certificate) -> object | None:
        """Schedule future renewal for a certificate."""

    def remove_certificate(self, certificate_id: uuid.UUID) -> None:
        """Remove queued renewal jobs for a certificate."""


WebhookDispatcherFactory = Callable[[AsyncSession], WebhookDispatcher]


class CertificateLifecycleService:
    """Coordinates certificate DB state, ACME backend, deployment, and webhooks."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        backend: AcmeBackend,
        settings: AppSettings,
        scheduler: RenewalSchedulerProtocol | None = None,
        webhook_dispatcher_factory: WebhookDispatcherFactory | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._backend = backend
        self._settings = settings
        self._scheduler = scheduler
        self._webhook_dispatcher_factory = webhook_dispatcher_factory

    async def create_certificate(self, payload: CertificateCreate) -> Certificate:
        """Create a pending certificate row and emit the creation event."""
        async with self._session_factory() as session:
            certificate = Certificate(
                name=payload.name,
                domains=payload.domains,
                acme_account_ref=payload.acme_account_ref,
                dns_provider_ref=payload.dns_provider_ref,
                key_algorithm=payload.key_algorithm,
                status=CertificateStatus.PENDING,
            )
            session.add(certificate)
            try:
                await session.flush()
            except IntegrityError as exc:
                await session.rollback()
                raise CertificateConflictError(
                    "Certificate name already exists."
                ) from exc

            await self._record_event(
                session,
                certificate,
                "certificate.created",
                {"name": certificate.name, "domains": certificate.domains},
            )
            await session.commit()
            await session.refresh(certificate)
            await self._dispatch_webhook(session, "certificate.created", certificate)
            return certificate

    async def issue_certificate(self, certificate_id: uuid.UUID) -> None:
        """Issue a pending certificate and deploy successful artifacts."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                return
            if certificate.status != CertificateStatus.PENDING:
                return

            certificate.status = CertificateStatus.ISSUING
            await session.commit()

            try:
                provider = self._dns_provider(certificate.dns_provider_ref)
                account = self._acme_account(certificate.acme_account_ref)
                result = await self._backend.issue_certificate(
                    domains=certificate.domains,
                    method="dns-01",
                    challenge_params={
                        "dns_provider": provider.provider_name,
                        "env_vars_file": str(provider.env_vars_file_path),
                    },
                    account_key_path=_account_key_path(account),
                    server_url=account.server_url,
                )
                deployed = deploy_issuance_result(
                    result,
                    self._settings.deployment.directory,
                    options=DeploymentOptions(
                        permissions_cert=self._settings.deployment.permissions_cert,
                        permissions_key=self._settings.deployment.permissions_key,
                        issuer=certificate.acme_account_ref,
                        allowed_source_roots=(
                            [self._settings.acme.home_dir]
                            if isinstance(self._backend, AcmeShBackend)
                            else None
                        ),
                    ),
                )
            except (AcmeShError, DeploymentError) as exc:
                await self._mark_failed(session, certificate, exc)
                return

            certificate.expiry_date = result.cert.expires_at
            certificate.status = CertificateStatus.VALID
            await self._record_event(
                session,
                certificate,
                "certificate.issued",
                {
                    "domains": certificate.domains,
                    "expires_at": result.cert.expires_at.isoformat(),
                    "deployment_path": str(deployed.directory),
                },
            )
            await session.commit()
            await session.refresh(certificate)
            await self._dispatch_webhook(session, "certificate.issued", certificate)
            if self._scheduler is not None:
                self._scheduler.schedule_certificate(certificate)

    async def revoke_certificate(self, certificate_id: uuid.UUID) -> None:
        """Soft-delete a certificate by marking it revoked and unscheduling renewal."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.")

            certificate.status = CertificateStatus.REVOKED
            await self._record_event(
                session,
                certificate,
                "certificate.revoked",
                {"name": certificate.name},
            )
            await session.commit()
            await self._dispatch_webhook(session, "certificate.revoked", certificate)

        if self._scheduler is not None:
            self._scheduler.remove_certificate(certificate_id)

    async def request_manual_renewal(self, certificate_id: uuid.UUID) -> Certificate:
        """Record a manual renewal request without doing DNS work inline."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.")
            if certificate.status != CertificateStatus.VALID:
                raise CertificateNotRenewableError("Certificate is not renewable.")

            await self._record_event(
                session,
                certificate,
                "certificate.renewal_requested",
                {"name": certificate.name},
            )
            await session.commit()
            await session.refresh(certificate)
            return certificate

    async def _mark_failed(
        self,
        session: AsyncSession,
        certificate: Certificate,
        error: Exception,
    ) -> None:
        certificate.status = CertificateStatus.FAILED
        await self._record_event(
            session,
            certificate,
            "certificate.failed",
            {
                "category": _error_category(error),
                "error": str(error),
            },
        )
        await session.commit()
        await session.refresh(certificate)
        await self._dispatch_webhook(session, "certificate.failed", certificate)

    async def _record_event(
        self,
        session: AsyncSession,
        certificate: Certificate,
        event_type: str,
        details: dict[str, object],
    ) -> None:
        session.add(
            Event(
                event_type=event_type,
                certificate_id=certificate.id,
                details=details,
            )
        )

    async def _dispatch_webhook(
        self,
        session: AsyncSession,
        event_type: str,
        certificate: Certificate,
    ) -> None:
        if self._webhook_dispatcher_factory is None:
            return
        async with self._webhook_dispatcher_factory(session) as dispatcher:
            await dispatcher.dispatch_certificate_event(event_type, certificate)

    def _dns_provider(self, name: str) -> DnsProviderConfig:
        for provider in self._settings.dns_providers:
            if provider.name == name:
                return provider
        raise DeploymentError(f"DNS provider not configured: {name}")

    def _acme_account(self, name: str) -> AcmeAccountConfig:
        for account in self._settings.acme_accounts:
            if account.name == name:
                return account
        raise DeploymentError(f"ACME account not configured: {name}")


async def expiring_event_exists(
    session: AsyncSession,
    certificate_id: uuid.UUID,
) -> bool:
    """Return true when an expiring event was already recorded for a certificate."""
    result = await session.execute(
        select(Event).where(
            Event.certificate_id == certificate_id,
            Event.event_type == "certificate.expiring",
        )
    )
    return result.scalar_one_or_none() is not None


def _account_key_path(account: AcmeAccountConfig) -> str | None:
    if account.account_key_path is None:
        return None
    return str(Path(account.account_key_path))


def _error_category(error: Exception) -> str:
    if isinstance(error, TransientAcmeShError):
        return "transient"
    if isinstance(error, AcmeShError):
        return "terminal"
    return "deployment"
