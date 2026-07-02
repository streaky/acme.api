"""Event audit-log request and response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    """Payload for creating a new event record.

    Attributes:
        event_type: Machine-readable event category (e.g. ``certificate.created``).
        certificate_id: Optional UUID of the certificate this event concerns.
        details: Arbitrary key-value context for the event.
    """

    event_type: str = Field(min_length=1, max_length=64)
    certificate_id: uuid.UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class EventRead(BaseModel):
    """Full event representation returned by GET endpoints.

    Attributes:
        id: Unique identifier.
        timestamp: UTC time at which this event occurred.
        event_type: Machine-readable event category.
        certificate_id: Optional UUID of the associated certificate.
        details: Arbitrary key-value context for the event.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    event_type: str
    certificate_id: uuid.UUID | None = None
    details: dict[str, Any] = {}
