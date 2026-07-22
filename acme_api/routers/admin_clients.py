"""Authenticated administration routes for persisted API clients."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.admin_clients import create_client, revoke_client, rotate_client
from acme_api.auth.rbac import require_admin
from acme_api.db import get_db_session
from acme_api.models.api_key import APIKey
from acme_api.schemas.api_client import APIClientCreate, APIClientCredential, APIClientRead

router = APIRouter(prefix="/v1/admin/clients", tags=["Admin clients"])


async def _client_or_404(session: AsyncSession, client_id: uuid.UUID) -> APIKey:
    """Load one API client or return the standard not-found response."""
    client = await session.get(APIKey, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API client not found.")
    return client


def _credential_response(client: APIKey, credential: str) -> APIClientCredential:
    """Build a credential response without persisting raw material."""
    return APIClientCredential(**APIClientRead.model_validate(client).model_dump(), credential=credential)


@router.get("", response_model=list[APIClientRead], summary="List API clients")
async def list_clients(
    _: object = Depends(require_admin),
    db_session: AsyncSession = Depends(get_db_session),
) -> list[APIKey]:
    """List safe metadata for all persisted API clients."""
    result = await db_session.execute(select(APIKey).order_by(APIKey.created_at))
    return list(result.scalars())


@router.post("", response_model=APIClientCredential, status_code=status.HTTP_201_CREATED, summary="Create API client")
async def provision_client(
    payload: APIClientCreate,
    _: object = Depends(require_admin),
    db_session: AsyncSession = Depends(get_db_session),
) -> APIClientCredential:
    """Create a client and return its generated credential exactly once."""
    try:
        provisioned = await create_client(db_session, payload.name, payload.role)
    except IntegrityError as exc:
        await db_session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API client name already exists.") from exc
    return _credential_response(provisioned.client, provisioned.raw_key)


@router.post("/{client_id}/rotate", response_model=APIClientCredential, summary="Rotate API client credential")
async def rotate_client_credential(
    client_id: uuid.UUID,
    _: object = Depends(require_admin),
    db_session: AsyncSession = Depends(get_db_session),
) -> APIClientCredential:
    """Rotate a client credential and return the replacement exactly once."""
    provisioned = await rotate_client(db_session, await _client_or_404(db_session, client_id))
    return _credential_response(provisioned.client, provisioned.raw_key)


@router.post("/{client_id}/revoke", response_model=APIClientRead, summary="Revoke API client")
async def revoke_client_credential(
    client_id: uuid.UUID,
    _: object = Depends(require_admin),
    db_session: AsyncSession = Depends(get_db_session),
) -> APIKey:
    """Revoke a client while retaining the credential record and audit trail."""
    return await revoke_client(db_session, await _client_or_404(db_session, client_id))
