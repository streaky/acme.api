"""Certificate lifecycle orchestration service."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.backend.acmesh_backend import AcmeShBackend
from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.backend.protocol import AcmeBackend, ChallengeMethod
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


class CertificateBackendUnavailableError(CertificateLifecycleError):
    """Raised when a transient ACME backend failure prevents request creation."""


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
        """Create a request or resume the same durable DNS Persist request."""
        account = self._acme_account(payload.acme_account_ref)
        if payload.challenge_method == "dns-01" and payload.dns_provider_ref is None:
            raise CertificateLifecycleError("dns_provider_ref is required for dns-01 certificates.")
        if payload.held and payload.challenge_method != "dns-persist":
            raise CertificateLifecycleError("Only DNS Persist requests can be held.")

        async with self._session_factory() as session:
            existing = await self._find_request(session, payload)
            if existing is not None:
                return self._resume_or_reject(existing, payload)

            if payload.challenge_method == "dns-persist":
                dns_persist_domain, wildcard_policy = _dns_persist_scope(payload.domains)
                try:
                    dns_value = await self._backend.make_dns_persist_value(
                        dns_persist_domain,
                        wildcard=wildcard_policy,
                        account_key_path=_account_key_path(account),
                        server_url=account.server_url,
                    )
                except TransientAcmeShError as exc:
                    raise CertificateBackendUnavailableError(
                        f"Unable to generate DNS Persist instructions: {exc}"
                    ) from exc
                except AcmeShError as exc:
                    raise CertificateLifecycleError(f"Unable to generate DNS Persist instructions: {exc}") from exc
                certificate = Certificate(
                    name=payload.name,
                    domains=payload.domains,
                    acme_account_ref=payload.acme_account_ref,
                    dns_provider_ref=None,
                    challenge_method="dns-persist",
                    dns_record_name=f"_validation-persist.{dns_persist_domain}",
                    dns_record_value=dns_value,
                    key_algorithm=payload.key_algorithm,
                    status=CertificateStatus.HELD if payload.held else CertificateStatus.PENDING_DNS,
                )
            else:
                certificate = Certificate(
                    name=payload.name,
                    domains=payload.domains,
                    acme_account_ref=payload.acme_account_ref,
                    dns_provider_ref=payload.dns_provider_ref,
                    challenge_method="dns-01",
                    key_algorithm=payload.key_algorithm,
                    status=CertificateStatus.PENDING,
                )
            session.add(certificate)
            try:
                await session.flush()
            except IntegrityError as exc:
                await session.rollback()
                existing = await self._find_request(session, payload)
                if existing is not None:
                    return self._resume_or_reject(existing, payload)
                raise CertificateConflictError("Certificate request already exists.") from exc

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

    async def _find_request(
        self,
        session: AsyncSession,
        payload: CertificateCreate,
    ) -> Certificate | None:
        """Return the durable request identified by name, account, and method."""
        request = await session.scalar(
            select(Certificate).where(
                Certificate.name == payload.name,
                Certificate.acme_account_ref == payload.acme_account_ref,
                Certificate.challenge_method == payload.challenge_method,
            )
        )
        return request

    @staticmethod
    def _resume_or_reject(existing: Certificate, payload: CertificateCreate) -> Certificate:
        """Resume an identical DNS Persist request or reject an identity collision."""
        if (
            existing.challenge_method == "dns-persist"
            and existing.status not in (CertificateStatus.REVOKED, CertificateStatus.CANCELLED)
            and existing.domains == payload.domains
        ):
            return existing
        raise CertificateConflictError(
            "Certificate name, ACME account, and challenge method already identify another request."
        )

    async def issue_certificate(self, certificate_id: uuid.UUID) -> None:
        """Issue a queued DNS-provider certificate and deploy successful artifacts."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None or certificate.status != CertificateStatus.PENDING:
                return
            certificate.status = CertificateStatus.ISSUING
            await session.commit()
            await self._issue_and_deploy(session, certificate, method="dns-01")

    async def authorize_dns_persist_certificate(self, certificate_id: uuid.UUID) -> tuple[Certificate, bool]:
        """Record that a held request's DNS authorization is ready without issuing it."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.")
            if certificate.challenge_method != "dns-persist":
                raise CertificateLifecycleError("Certificate does not use DNS Persist.")
            if certificate.status == CertificateStatus.HELD:
                result = await session.execute(
                    update(Certificate)
                    .where(
                        Certificate.id == certificate_id,
                        Certificate.status == CertificateStatus.HELD,
                        Certificate.revision == certificate.revision,
                    )
                    .values(
                        status=CertificateStatus.AUTHORIZATION_READY,
                        revision=Certificate.revision + 1,
                    )
                    .returning(Certificate.id)
                )
                if result.scalar_one_or_none() is None:
                    await session.rollback()
                    certificate = await session.get(Certificate, certificate_id)
                    if certificate is None:
                        raise CertificateNotFoundError("Certificate not found.")
                    return certificate, False
                await session.refresh(certificate)
                await self._record_event(session, certificate, "certificate.authorization_ready", {})
                await session.commit()
                return certificate, False
            if certificate.status not in (CertificateStatus.PENDING_DNS, CertificateStatus.FAILED):
                return certificate, False
            result = await session.execute(
                update(Certificate)
                .where(
                    Certificate.id == certificate_id,
                    Certificate.status.in_((CertificateStatus.PENDING_DNS, CertificateStatus.FAILED)),
                )
                .values(status=CertificateStatus.ISSUING)
                .returning(Certificate.id)
            )
            if result.scalar_one_or_none() is None:
                await session.rollback()
                certificate = await session.get(Certificate, certificate_id)
                if certificate is None:
                    raise CertificateNotFoundError("Certificate not found.")
                return certificate, False
            await session.refresh(certificate)
            await self._record_event(session, certificate, "certificate.authorization_requested", {})
            await session.commit()
            return certificate, True

    async def release_held_dns_persist_certificate(
        self,
        certificate_id: uuid.UUID,
        *,
        revision: int,
        idempotency_key: str,
    ) -> tuple[Certificate, bool]:
        """Release the current held revision exactly once for asynchronous issuance."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.")
            if certificate.challenge_method != "dns-persist":
                raise CertificateLifecycleError("Certificate does not use DNS Persist.")
            if certificate.release_idempotency_key == idempotency_key:
                return certificate, False
            result = await session.execute(
                update(Certificate)
                .where(
                    Certificate.id == certificate_id,
                    Certificate.revision == revision,
                    Certificate.release_idempotency_key.is_(None),
                    Certificate.status.in_((CertificateStatus.HELD, CertificateStatus.AUTHORIZATION_READY)),
                )
                .values(
                    status=CertificateStatus.RELEASED,
                    revision=Certificate.revision + 1,
                    release_idempotency_key=idempotency_key,
                )
                .returning(Certificate.id)
            )
            if result.scalar_one_or_none() is None:
                await session.rollback()
                certificate = await session.get(Certificate, certificate_id)
                if certificate is None:
                    raise CertificateNotFoundError("Certificate not found.")
                if certificate.release_idempotency_key == idempotency_key:
                    return certificate, False
                raise CertificateLifecycleError("Certificate revision is stale or cannot be released.")
            await session.refresh(certificate)
            await self._record_event(session, certificate, "certificate.released", {"revision": revision})
            await session.commit()
            return certificate, True

    async def issue_released_dns_persist_certificate(self, certificate_id: uuid.UUID) -> None:
        """Claim a released held request and issue it once."""
        async with self._session_factory() as session:
            result = await session.execute(
                update(Certificate)
                .where(Certificate.id == certificate_id, Certificate.status == CertificateStatus.RELEASED)
                .values(status=CertificateStatus.ISSUING)
                .returning(Certificate.id)
            )
            if result.scalar_one_or_none() is None:
                return
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                return
            await session.commit()
            await self._issue_and_deploy(session, certificate, method="dns-persist")

    async def issue_dns_persist_certificate(self, certificate_id: uuid.UUID) -> None:
        """Issue an explicitly authorized DNS Persist request."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None or certificate.status != CertificateStatus.ISSUING:
                return
            await self._issue_and_deploy(session, certificate, method="dns-persist")

    async def resume_released_dns_persist_certificates(self) -> None:
        """Resume released requests, including issuance interrupted by a process stop."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Certificate.id, Certificate.status).where(
                    Certificate.challenge_method == "dns-persist",
                    Certificate.release_idempotency_key.is_not(None),
                    Certificate.status.in_((CertificateStatus.RELEASED, CertificateStatus.ISSUING)),
                )
            )
            certificates = list(result.all())
        for certificate_id, certificate_status in certificates:
            if certificate_status == CertificateStatus.RELEASED:
                await self.issue_released_dns_persist_certificate(certificate_id)
            else:
                await self.issue_dns_persist_certificate(certificate_id)

    async def _issue_and_deploy(
        self,
        session: AsyncSession,
        certificate: Certificate,
        *,
        method: ChallengeMethod,
    ) -> None:
        """Issue one certificate using its persisted challenge configuration."""
        try:
            account = self._acme_account(certificate.acme_account_ref)
            challenge_params: dict[str, object] = {}
            if method == "dns-01":
                if certificate.dns_provider_ref is None:
                    raise DeploymentError("DNS provider is required for dns-01 issuance.")
                provider = self._dns_provider(certificate.dns_provider_ref)
                challenge_params = {
                    "dns_provider": provider.provider_name,
                    "env_vars_file": str(provider.env_vars_file_path),
                }
            result = await self._backend.issue_certificate(
                domains=certificate.domains,
                method=method,
                challenge_params=challenge_params,
                account_key_path=_account_key_path(account),
                server_url=account.server_url,
            )
            deployed = deploy_issuance_result(
                result,
                self._settings.deployment.directory,
                options=DeploymentOptions(
                    permissions_cert=self._settings.deployment.permissions_cert,
                    permissions_key=self._settings.deployment.permissions_key,
                    artifact_group_id=self._settings.deployment.artifact_group_id,
                    issuer=certificate.acme_account_ref,
                    allowed_source_roots=(
                        [self._settings.acme.home_dir] if isinstance(self._backend, AcmeShBackend) else None
                    ),
                ),
            )
        except (AcmeShError, DeploymentError) as exc:
            await self._mark_failed(session, certificate, exc)
            return
        transition = await session.execute(
            update(Certificate)
            .where(Certificate.id == certificate.id, Certificate.status == CertificateStatus.ISSUING)
            .values(expiry_date=result.cert.expires_at, status=CertificateStatus.VALID)
            .returning(Certificate.id)
        )
        if transition.scalar_one_or_none() is None:
            await session.rollback()
            return
        await session.refresh(certificate)
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
        """Soft-delete a certificate, cancelling held requests before issuance."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.")

            held_lifecycle_statuses = (
                CertificateStatus.HELD,
                CertificateStatus.AUTHORIZATION_READY,
                CertificateStatus.RELEASED,
            )
            is_held_lifecycle_request = certificate.status in held_lifecycle_statuses or (
                certificate.status == CertificateStatus.ISSUING and certificate.release_idempotency_key is not None
            )
            certificate.status = CertificateStatus.CANCELLED if is_held_lifecycle_request else CertificateStatus.REVOKED
            event_type = "certificate.cancelled" if is_held_lifecycle_request else "certificate.revoked"
            await self._record_event(session, certificate, event_type, {"name": certificate.name})
            await session.commit()
            await self._dispatch_webhook(session, event_type, certificate)

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


def _dns_persist_scope(domains: list[str]) -> tuple[str, bool]:
    """Return the primary DNS Persist scope and whether it needs wildcard policy."""
    scope = domains[0].removeprefix("*.")
    if any(
        domain.removeprefix("*.") != scope and not domain.removeprefix("*.").endswith(f".{scope}") for domain in domains
    ):
        raise CertificateLifecycleError(
            "DNS Persist SANs must be the primary domain or its subdomains; "
            "create separate requests for unrelated domains."
        )
    return scope, len(domains) > 1 or domains[0].startswith("*.")


def _account_key_path(account: AcmeAccountConfig) -> str | None:
    return str(account.account_key_path) if account.account_key_path is not None else None


def _error_category(error: Exception) -> str:
    if isinstance(error, TransientAcmeShError):
        return "transient"
    return "terminal" if isinstance(error, AcmeShError) else "deployment"
