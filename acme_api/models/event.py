"""Event model — audit-log entries for certificate lifecycle events."""

from __future__ import annotations

import datetime as _dt
import uuid as _uuid

from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from acme_api.models.base import Base


class Event(Base):
    """Row representing a single audit-log event.

    Events are attached to certificates via ``certificate_id`` but may also be
    standalone when no specific certificate is involved (e.g. system-level
    bootstrap events).
    """

    __tablename__ = "events"

    # -- primary key ----------------------------------------------------------

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
        doc="Unique identifier for the event.",
    )

    # -- event metadata -------------------------------------------------------

    timestamp: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="UTC time at which this event occurred.",
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        doc="Machine-readable event category (e.g. 'certificate.created').",
    )

    # -- certificate association ----------------------------------------------

    certificate_id: Mapped[_uuid.UUID | None] = mapped_column(
        ForeignKey("certificates.id"),
        nullable=True,
        doc="Optional link to the certificate this event concerns.",
    )

    # -- payload --------------------------------------------------------------

    details: Mapped[dict[str, object]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="Arbitrary key-value context for the event.",
    )

    # -- relationships --------------------------------------------------------

    certificate = relationship(
        "acme_api.models.certificate.Certificate",
        back_populates="events",
        lazy="selectin",
        doc="Certificate associated with this event, if any.",
    )
