"""Domain-based acme.sh certificate revocation lifecycle operations."""

# This orchestration helper intentionally uses lifecycle internals to share its
# configured session, backend, event recording, and webhook dispatch boundary.
# pylint: disable=protected-access
from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.deployer import DeploymentError
from acme_api.models.certificate import Certificate
from acme_api.models.certificate_revocation import CertificateRevocation, CertificateRevocationStatus
from acme_api.services.certificate_contracts import CertificateLifecycleError, CertificateNotFoundError
from acme_api.services.certificate_utilities import account_key_path

if TYPE_CHECKING:
    from acme_api.services.certificates import CertificateLifecycleService

_REVOCATION_LEASE = dt.timedelta(minutes=10)


async def request_certificate_revocation(
    service: CertificateLifecycleService,
    certificate_id: uuid.UUID,
    *,
    reason: int | None,
    idempotency_key: str,
    actor: str | None,
) -> CertificateRevocation:
    """Run one durable, claimed, idempotent acme.sh revocation request."""
    async with service._session_factory() as session:
        certificate = await session.get(Certificate, certificate_id)
        if certificate is None:
            raise CertificateNotFoundError("Certificate not found.")
        if certificate.expiry_date is None:
            raise CertificateLifecycleError("Certificate has not been issued and cannot be revoked.")

        revocation = CertificateRevocation(
            certificate_id=certificate.id,
            domain=certificate.domains[0],
            reason=reason,
            idempotency_key=idempotency_key,
            actor=actor,
        )
        session.add(revocation)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            certificate = await session.get(Certificate, certificate_id)
            if certificate is None:
                raise CertificateNotFoundError("Certificate not found.") from None
            existing = await session.scalar(
                select(CertificateRevocation).where(
                    CertificateRevocation.certificate_id == certificate_id,
                    CertificateRevocation.idempotency_key == idempotency_key,
                )
            )
            if existing is None:
                raise
            if existing.reason != reason:
                raise CertificateLifecycleError(
                    "Idempotency key was already used with another revocation reason."
                ) from None
            if existing.status is not CertificateRevocationStatus.PENDING:
                return existing
            revocation = existing

        if not await _claim_pending_revocation(session, revocation):
            return revocation

        try:
            account = service._acme_account(certificate.acme_account_ref)
            await service._backend.revoke_certificate(
                revocation.domain,
                reason=revocation.reason,
                key_algorithm=certificate.key_algorithm,
                account_key_path=account_key_path(account),
                server_url=account.server_url,
            )
        except (AcmeShError, DeploymentError, OSError) as exc:
            revocation.status = CertificateRevocationStatus.FAILED
            revocation.error_category = "transient" if isinstance(exc, TransientAcmeShError) else "terminal"
            revocation.error_details = str(exc)
            revocation.completed_at = dt.datetime.now(dt.UTC)
            await service._record_event(
                session,
                certificate,
                "certificate.revocation_failed",
                {"domain": revocation.domain, "category": revocation.error_category},
            )
            await session.commit()
            await session.refresh(revocation)
            return revocation

        revocation.status = CertificateRevocationStatus.SUCCEEDED
        revocation.completed_at = dt.datetime.now(dt.UTC)
        await service._record_event(
            session,
            certificate,
            "certificate.revoked_at_ca",
            {"domain": revocation.domain, "reason": revocation.reason, "actor": revocation.actor},
        )
        await session.commit()
        await session.refresh(revocation)
        await service._dispatch_webhook(session, "certificate.revoked_at_ca", certificate)
        return revocation


async def _claim_pending_revocation(session: AsyncSession, revocation: CertificateRevocation) -> bool:
    """Atomically lease a pending request, allowing recovery after a dead worker."""
    now = dt.datetime.now(dt.UTC)
    result = await session.execute(
        update(CertificateRevocation)
        .where(
            CertificateRevocation.id == revocation.id,
            CertificateRevocation.status == CertificateRevocationStatus.PENDING,
            or_(
                CertificateRevocation.attempt_started_at.is_(None),
                CertificateRevocation.attempt_started_at < now - _REVOCATION_LEASE,
            ),
        )
        .values(attempt_started_at=now)
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    if cast(CursorResult[Any], result).rowcount != 1:
        await session.refresh(revocation)
        return False
    await session.refresh(revocation)
    return True
