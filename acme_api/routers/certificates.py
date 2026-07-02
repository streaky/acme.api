"""Certificate lifecycle API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.rbac import require_operator, require_readonly
from acme_api.db import get_db_session
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.schemas.certificate import CertificateCreate, CertificateRead

router = APIRouter(prefix="/v1/certificates", tags=["Certificates"])


@router.post(
    "",
    response_model=CertificateRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create a certificate request",
)
async def create_certificate(
    payload: CertificateCreate,
    _: object = Depends(require_operator),
    db_session: AsyncSession = Depends(get_db_session),
) -> Certificate:
    """Create a pending certificate record and audit event."""
    certificate = Certificate(
        name=payload.name,
        domains=payload.domains,
        acme_account_ref=payload.acme_account_ref,
        dns_provider_ref=payload.dns_provider_ref,
        key_algorithm=payload.key_algorithm,
        status=CertificateStatus.PENDING,
    )
    db_session.add(certificate)
    try:
        await db_session.flush()
    except IntegrityError as exc:
        await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Certificate name already exists.",
        ) from exc

    db_session.add(
        Event(
            event_type="certificate.created",
            certificate_id=certificate.id,
            details={"name": certificate.name, "domains": certificate.domains},
        )
    )
    await db_session.commit()
    await db_session.refresh(certificate)
    return certificate


@router.get(
    "",
    response_model=list[CertificateRead],
    summary="List certificates",
)
async def list_certificates(
    _: object = Depends(require_readonly),
    db_session: AsyncSession = Depends(get_db_session),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    status_filter: CertificateStatus | None = Query(default=None, alias="status"),
    domain: str | None = Query(default=None, min_length=1),
) -> list[Certificate]:
    """Return certificates with pagination and optional filters."""
    statement = select(Certificate).offset(offset).limit(limit)
    if status_filter is not None:
        statement = statement.where(Certificate.status == status_filter)
    if domain is not None:
        statement = statement.where(Certificate.domains.contains(domain))
    result = await db_session.execute(statement.order_by(Certificate.created_at.desc()))
    return list(result.scalars().all())


@router.get(
    "/{certificate_id}",
    response_model=CertificateRead,
    summary="Get certificate detail",
)
async def get_certificate(
    certificate_id: uuid.UUID,
    _: object = Depends(require_readonly),
    db_session: AsyncSession = Depends(get_db_session),
) -> Certificate:
    """Return a single certificate by ID."""
    certificate = await db_session.get(Certificate, certificate_id)
    if certificate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        )
    return certificate


@router.delete(
    "/{certificate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a certificate record",
)
async def revoke_certificate(
    certificate_id: uuid.UUID,
    _: object = Depends(require_operator),
    db_session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Soft-delete a certificate by marking it revoked."""
    certificate = await db_session.get(Certificate, certificate_id)
    if certificate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        )
    certificate.status = CertificateStatus.REVOKED
    db_session.add(
        Event(
            event_type="certificate.revoked",
            certificate_id=certificate.id,
            details={"name": certificate.name},
        )
    )
    await db_session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{certificate_id}/renew",
    response_model=CertificateRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger certificate renewal",
)
async def renew_certificate(
    certificate_id: uuid.UUID,
    _: object = Depends(require_operator),
    db_session: AsyncSession = Depends(get_db_session),
) -> Certificate:
    """Mark a certificate as renewing and record the manual trigger."""
    certificate = await db_session.get(Certificate, certificate_id)
    if certificate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        )
    certificate.status = CertificateStatus.RENEWING
    db_session.add(
        Event(
            event_type="certificate.renewal_requested",
            certificate_id=certificate.id,
            details={"name": certificate.name},
        )
    )
    await db_session.commit()
    await db_session.refresh(certificate)
    return certificate
