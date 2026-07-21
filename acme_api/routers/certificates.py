"""Certificate lifecycle API routes."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.rbac import require_operator, require_readonly
from acme_api.db import get_db_session
from acme_api.deployer import DeploymentError
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.schemas.certificate import CertificateCreate, CertificateRead
from acme_api.services.certificates import (
    CertificateBackendUnavailableError,
    CertificateConflictError,
    CertificateLifecycleError,
    CertificateLifecycleService,
    CertificateNotFoundError,
    CertificateNotRenewableError,
)

router = APIRouter(prefix="/v1/certificates", tags=["Certificates"])

_NOT_FOUND_RESPONSE: dict[int | str, dict[str, Any]] = {404: {"description": "Certificate not found."}}


@router.post(
    "",
    response_model=CertificateRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create a certificate request",
    responses={
        409: {"description": "Certificate name already exists."},
        422: {"description": "Certificate request cannot be created."},
        503: {"description": "ACME backend is temporarily unavailable."},
    },
)
async def create_certificate(
    payload: CertificateCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    _: object = Depends(require_operator),
) -> Certificate:
    """Create a certificate request, returning DNS instructions when applicable."""
    service = _certificate_service(request)
    try:
        certificate = await service.create_certificate(payload)
    except CertificateConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except CertificateBackendUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except CertificateLifecycleError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except DeploymentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if certificate.status == CertificateStatus.PENDING:
        background_tasks.add_task(service.issue_certificate, certificate.id)
    return certificate


@router.get(
    "",
    response_model=list[CertificateRead],
    summary="List certificates",
    responses={200: {"description": "Certificate list returned."}},
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
    responses=_NOT_FOUND_RESPONSE,
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


@router.post(
    "/{certificate_id}/authorize",
    response_model=CertificateRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Authorize DNS Persist certificate issuance",
    responses={
        **_NOT_FOUND_RESPONSE,
        409: {"description": "Certificate does not use DNS Persist."},
    },
)
async def authorize_dns_persist_certificate(
    certificate_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    _: object = Depends(require_operator),
) -> Certificate:
    """Start issuance after an operator has published the persistent TXT record."""
    service = _certificate_service(request)
    try:
        certificate, starts_issuance = await service.authorize_dns_persist_certificate(certificate_id)
    except CertificateNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except CertificateLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if starts_issuance:
        background_tasks.add_task(service.issue_dns_persist_certificate, certificate.id)
    return certificate


@router.delete(
    "/{certificate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a certificate record",
    responses=_NOT_FOUND_RESPONSE,
)
async def revoke_certificate(
    certificate_id: uuid.UUID,
    request: Request,
    _: object = Depends(require_operator),
) -> Response:
    """Soft-delete a certificate by marking it revoked."""
    try:
        await _certificate_service(request).revoke_certificate(certificate_id)
    except CertificateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        ) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{certificate_id}/renew",
    response_model=CertificateRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger certificate renewal",
    responses={
        **_NOT_FOUND_RESPONSE,
        409: {"description": "Certificate is not renewable."},
        503: {"description": "Renewal scheduler is unavailable."},
    },
)
async def renew_certificate(
    certificate_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    _: object = Depends(require_operator),
) -> Certificate:
    """Queue a manual renewal through the scheduler renewal path."""
    service = _certificate_service(request)
    try:
        certificate = await service.request_manual_renewal(certificate_id)
    except CertificateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        ) from exc
    except CertificateNotRenewableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    scheduler = getattr(request.app.state, "renewal_scheduler", None)
    if scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Renewal scheduler is not available.",
        )
    background_tasks.add_task(scheduler.renew_certificate, certificate.id)
    return certificate


def _certificate_service(request: Request) -> CertificateLifecycleService:
    service = getattr(request.app.state, "certificate_service", None)
    if not isinstance(service, CertificateLifecycleService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate lifecycle service is not available.",
        )
    return service
