"""Audit event API routes."""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.rbac import require_readonly
from acme_api.db import get_db_session
from acme_api.models.event import Event
from acme_api.schemas.event import EventRead

router = APIRouter(prefix="/v1/events", tags=["Events"])


@router.get("", response_model=list[EventRead], summary="List audit events")
async def list_events(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    _: object = Depends(require_readonly),
    db_session: AsyncSession = Depends(get_db_session),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    event_type: str | None = Query(default=None, min_length=1, max_length=64),
    certificate_id: uuid.UUID | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
) -> list[Event]:
    """Return audit events with pagination and optional filters."""
    statement = select(Event)
    if event_type is not None:
        statement = statement.where(Event.event_type == event_type)
    if certificate_id is not None:
        statement = statement.where(Event.certificate_id == certificate_id)
    if since is not None:
        statement = statement.where(Event.timestamp >= since)
    if until is not None:
        statement = statement.where(Event.timestamp <= until)

    statement = statement.order_by(Event.timestamp.desc()).offset(offset).limit(limit)
    result = await db_session.execute(statement)
    return list(result.scalars().all())
