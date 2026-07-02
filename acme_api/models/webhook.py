"""Webhook configuration model."""

from __future__ import annotations

import uuid as _uuid

from sqlalchemy import JSON, Boolean, String, text
from sqlalchemy.orm import Mapped, mapped_column

from acme_api.models.base import Base, TimestampMixin


class WebhookConfig(Base, TimestampMixin):
    """Row describing an outbound webhook subscription."""

    __tablename__ = "webhook_configs"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
        doc="Unique identifier for the webhook subscription.",
    )
    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        doc="Destination URL for webhook deliveries.",
    )
    events: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        doc="Event types this webhook receives. Use ['*'] for all events.",
    )
    secret: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Shared secret used to sign webhook payloads.",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("1"),
        nullable=False,
        doc="Whether this webhook receives deliveries.",
    )
