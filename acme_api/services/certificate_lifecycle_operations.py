# pylint: disable=protected-access
"""Ancillary certificate lifecycle operations."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.services.certificate_contracts import CertificateNotFoundError, CertificateNotRenewableError

if TYPE_CHECKING:
    from acme_api.services.certificates import CertificateLifecycleService


async def revoke_certificate(service: CertificateLifecycleService, certificate_id: uuid.UUID) -> None:
    """Soft-delete a certificate, cancelling held requests before issuance."""
    async with service._session_factory() as session:
        certificate = await session.get(Certificate, certificate_id)
        if certificate is None:
            raise CertificateNotFoundError("Certificate not found.")
        held_statuses = (
            CertificateStatus.HELD,
            CertificateStatus.AUTHORIZATION_READY,
            CertificateStatus.CANCELLED,
        )
        held_request = (
            certificate.status in held_statuses
            or (certificate.status == CertificateStatus.RELEASED and certificate.revision > 0)
            or (certificate.status == CertificateStatus.ISSUING and certificate.release_idempotency_key is not None)
        )
        event_type = "certificate.cancelled" if held_request else "certificate.revoked"
        certificate.status = CertificateStatus.CANCELLED if held_request else CertificateStatus.REVOKED
        await service._record_event(session, certificate, event_type, {"name": certificate.name})
        await session.commit()
        await service._dispatch_webhook(session, event_type, certificate)
    if service._scheduler is not None:
        service._scheduler.remove_certificate(certificate_id)


async def request_manual_renewal(service: CertificateLifecycleService, certificate_id: uuid.UUID) -> Certificate:
    """Record a manual renewal request without doing DNS work inline."""
    async with service._session_factory() as session:
        certificate = await session.get(Certificate, certificate_id)
        if certificate is None:
            raise CertificateNotFoundError("Certificate not found.")
        if certificate.status != CertificateStatus.VALID:
            raise CertificateNotRenewableError("Certificate is not renewable.")
        await service._record_event(session, certificate, "certificate.renewal_requested", {"name": certificate.name})
        await session.commit()
        await session.refresh(certificate)
        return certificate
