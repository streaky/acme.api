"""Automatic certificate renewal scheduler."""

from __future__ import annotations

import dataclasses as dc
import datetime as dt
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Awaitable

from apscheduler.schedulers.asyncio import (  # type: ignore[import-untyped]
    AsyncIOScheduler,
)
from apscheduler.triggers.date import DateTrigger  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.backend.dataclasses import IssuanceResult
from acme_api.backend.protocol import AcmeBackend
from acme_api.config import RenewalConfig
from acme_api.deployer import DeploymentError, DeploymentOptions, deploy_issuance_result
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.models.renewal_attempt import RenewalAttempt
from acme_api.services.certificates import expiring_event_exists
from acme_api.webhooks import WebhookDispatcher

WebhookDispatcherFactory = Callable[[AsyncSession], WebhookDispatcher]


@dc.dataclass(frozen=True)
class RenewalDeploymentConfig:
    """Filesystem deployment settings for successful renewals."""

    root: Path
    permissions_cert: int = 0o644
    permissions_key: int = 0o600
    allowed_source_roots: list[Path] | None = None


class RenewalScheduler:
    """Schedules and executes automatic certificate renewals."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        session_factory: async_sessionmaker[AsyncSession],
        backend: AcmeBackend,
        config: RenewalConfig,
        webhook_dispatcher_factory: WebhookDispatcherFactory | None = None,
        deployment: RenewalDeploymentConfig | None = None,
        scheduler: AsyncIOScheduler | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._backend = backend
        self._config = config
        self._webhook_dispatcher_factory = webhook_dispatcher_factory
        self._deployment = deployment
        self._scheduler = scheduler or AsyncIOScheduler(timezone=dt.timezone.utc)

    async def start(self) -> None:
        """Start APScheduler and reconstruct renewal jobs from the database."""
        if not self._config.enabled:
            return
        if not self._scheduler.running:
            self._scheduler.start()
        await self.rebuild_jobs()

    async def shutdown(self) -> None:
        """Stop the scheduler and wait for running jobs to finish."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=True)

    async def rebuild_jobs(self) -> int:
        """Schedule renewal jobs for all renewable certificates."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Certificate).where(Certificate.status == CertificateStatus.VALID)
            )
            certificates = list(result.scalars().all())
            for certificate in certificates:
                await self._emit_expiring_if_due(session, certificate)

        for certificate in certificates:
            self.schedule_certificate(certificate)
        return len(certificates)

    def schedule_certificate(self, certificate: Certificate) -> dt.datetime | None:
        """Schedule a renewal job for a certificate and return its run time."""
        run_at = next_renewal_run_time(certificate.expiry_date, self._config.window_days)
        if run_at is None:
            return None

        self._scheduler.add_job(
            self.renew_certificate,
            trigger=DateTrigger(run_date=run_at),
            args=[certificate.id],
            id=_job_id(certificate.id),
            replace_existing=True,
            misfire_grace_time=3600,
        )
        return run_at

    def remove_certificate(self, certificate_id: uuid.UUID) -> None:
        """Remove queued renewal and retry jobs for a certificate."""
        for job_id in (_job_id(certificate_id), _retry_job_id(certificate_id)):
            job = self._scheduler.get_job(job_id)
            if job is not None:
                job.remove()

    async def renew_certificate(self, certificate_id: uuid.UUID) -> None:
        """Run one renewal attempt for the latest certificate row state."""
        async with self._session_factory() as session:
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None or certificate.status != CertificateStatus.VALID:
                return

            certificate.status = CertificateStatus.RENEWING
            await session.commit()

            try:
                result = await self._backend.renew_certificate(
                    domains=certificate.domains,
                    force_renewal=False,
                )
            except TransientAcmeShError as exc:
                await self._record_failure(
                    session=session,
                    certificate=certificate,
                    error=exc,
                    transient=True,
                )
                return
            except AcmeShError as exc:
                await self._record_failure(
                    session=session,
                    certificate=certificate,
                    error=exc,
                    transient=False,
                )
                return
            except DeploymentError as exc:
                await self._record_failure(
                    session=session,
                    certificate=certificate,
                    error=exc,
                    transient=False,
                )
                return

            try:
                deployment_path = self._deploy_result(result, certificate.acme_account_ref)
            except DeploymentError as exc:
                await self._record_failure(
                    session=session,
                    certificate=certificate,
                    error=exc,
                    transient=False,
                )
                return

            certificate.expiry_date = result.cert.expires_at
            certificate.status = CertificateStatus.VALID
            session.add(
                RenewalAttempt(
                    certificate_id=certificate.id,
                    status="success",
                )
            )
            session.add(
                Event(
                    event_type="certificate.renewed",
                    certificate_id=certificate.id,
                    details={
                        "domains": certificate.domains,
                        "expires_at": result.cert.expires_at.isoformat(),
                        "deployment_path": str(deployment_path)
                        if deployment_path is not None
                        else None,
                    },
                )
            )
            await session.commit()
            await self._dispatch_webhook(session, "certificate.renewed", certificate)

            self.schedule_certificate(certificate)

    async def _emit_expiring_if_due(
        self,
        session: AsyncSession,
        certificate: Certificate,
    ) -> None:
        """Emit one expiring event for certificates inside the renewal window."""
        if certificate.expiry_date is None:
            return
        expiry = _as_utc(certificate.expiry_date)
        now = dt.datetime.now(dt.timezone.utc)
        if expiry - dt.timedelta(days=self._config.window_days) > now:
            return
        if await expiring_event_exists(session, certificate.id):
            return

        session.add(
            Event(
                event_type="certificate.expiring",
                certificate_id=certificate.id,
                details={
                    "domains": certificate.domains,
                    "expires_at": expiry.isoformat(),
                },
            )
        )
        await session.commit()
        await self._dispatch_webhook(session, "certificate.expiring", certificate)

    def _deploy_result(
        self,
        result: IssuanceResult,
        issuer: str | None,
    ) -> Path | None:
        """Deploy renewed artifacts when deployment is enabled for the scheduler."""
        if self._deployment is None:
            return None
        deployed = deploy_issuance_result(
            result,
            self._deployment.root,
            options=DeploymentOptions(
                permissions_cert=self._deployment.permissions_cert,
                permissions_key=self._deployment.permissions_key,
                issuer=issuer,
                allowed_source_roots=self._deployment.allowed_source_roots,
            ),
        )
        return deployed.directory

    async def _record_failure(
        self,
        *,
        session: AsyncSession,
        certificate: Certificate,
        error: Exception,
        transient: bool,
    ) -> None:
        """Record a failed renewal attempt and schedule retry if applicable."""
        attempts = await _attempt_count(session, certificate.id)
        next_retry_at = None
        if transient and attempts < self._config.max_retries:
            next_retry_at = _retry_time(attempts)
            certificate.status = CertificateStatus.VALID
            self._scheduler.add_job(
                self.renew_certificate,
                trigger=DateTrigger(run_date=next_retry_at),
                args=[certificate.id],
                id=_retry_job_id(certificate.id),
                replace_existing=True,
            )
        else:
            certificate.status = CertificateStatus.FAILED

        category = "transient" if transient else "terminal"
        session.add(
            RenewalAttempt(
                certificate_id=certificate.id,
                status="failed",
                error_category=category,
                error_details={"message": str(error)},
                next_retry_at=next_retry_at,
            )
        )
        session.add(
            Event(
                event_type="certificate.failed",
                certificate_id=certificate.id,
                details={"category": category, "error": str(error)},
            )
        )
        await session.commit()
        await self._dispatch_webhook(session, "certificate.failed", certificate)

    async def _dispatch_webhook(
        self,
        session: AsyncSession,
        event_type: str,
        certificate: Certificate,
    ) -> None:
        """Dispatch a lifecycle webhook when a dispatcher factory is configured."""
        if self._webhook_dispatcher_factory is None:
            return
        async with self._webhook_dispatcher_factory(session) as dispatcher:
            await dispatcher.dispatch_certificate_event(event_type, certificate)


def next_renewal_run_time(
    expiry_date: dt.datetime | None,
    window_days: int,
    now_factory: Callable[[], dt.datetime] | None = None,
) -> dt.datetime | None:
    """Calculate when a certificate should be renewed."""
    if expiry_date is None:
        return None
    now = now_factory() if now_factory else dt.datetime.now(dt.timezone.utc)
    expiry = _as_utc(expiry_date)
    scheduled = expiry - dt.timedelta(days=window_days)
    return now if scheduled <= now else scheduled


def build_scheduler_task(
    renewal_scheduler: RenewalScheduler,
) -> Callable[[], Awaitable[None]]:
    """Return a zero-argument coroutine useful for framework lifecycle hooks."""

    async def _start() -> None:
        await renewal_scheduler.start()

    return _start


def _job_id(certificate_id: uuid.UUID) -> str:
    """Return the stable APScheduler job ID for a certificate."""
    return f"renew:{certificate_id}"


def _retry_job_id(certificate_id: uuid.UUID) -> str:
    """Return the stable retry job ID for a certificate."""
    return f"renew-retry:{certificate_id}"


def _retry_time(previous_attempts: int) -> dt.datetime:
    """Return the next retry time using exponential backoff."""
    delay_minutes = 2 ** max(previous_attempts, 0)
    return dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay_minutes)


async def _attempt_count(session: AsyncSession, certificate_id: uuid.UUID) -> int:
    """Return the number of previous failed renewal attempts for a certificate."""
    result = await session.execute(
        select(RenewalAttempt).where(
            RenewalAttempt.certificate_id == certificate_id,
            RenewalAttempt.status == "failed",
        )
    )
    return len(result.scalars().all())


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Normalize naive or aware datetimes to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
