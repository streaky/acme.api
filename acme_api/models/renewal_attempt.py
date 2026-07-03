"""RenewalAttempt model — records each certificate renewal attempt."""

from __future__ import annotations

import datetime as _dt
import uuid as _uuid

from sqlalchemy import JSON, DateTime, ForeignKey, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from acme_api.models.base import Base


class RenewalAttempt(Base):
    """Row representing a single attempt to renew a certificate.

    Each attempt is linked back to its parent certificate and records the
    outcome along with error diagnostics when applicable.
    """

    __tablename__ = "renewal_attempts"

    # -- primary key ----------------------------------------------------------

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
        doc="Unique identifier for the renewal attempt.",
    )

    # -- certificate association ----------------------------------------------

    certificate_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("certificates.id"),
        index=True,
        nullable=False,
        doc="Certificate this attempt was made against.",
    )

    # -- attempt metadata -----------------------------------------------------

    attempted_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        doc="UTC time the renewal attempt was initiated.",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Outcome of the attempt (e.g. 'success', 'failed', 'pending').",
    )

    # -- error diagnostics ----------------------------------------------------

    error_category: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        doc="High-level error classification when applicable.",
    )
    error_details: Mapped[dict[str, object] | None] = mapped_column(
        JSON,
        nullable=True,
        doc="Arbitrary diagnostic details for the error.",
    )

    # -- scheduling -----------------------------------------------------------

    next_retry_at: Mapped[_dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Scheduled UTC time for the next retry, if any.",
    )

    # -- relationships --------------------------------------------------------

    certificate = relationship(
        "acme_api.models.certificate.Certificate",
        back_populates="renewal_attempts",
        lazy="selectin",
        doc="Certificate this attempt belongs to.",
    )
