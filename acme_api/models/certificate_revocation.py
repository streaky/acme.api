"""Durable records for domain-based ACME certificate revocations."""

from __future__ import annotations

import datetime as _dt
import enum
import uuid as _uuid

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from acme_api.models.base import Base


class CertificateRevocationStatus(enum.StrEnum):
    """Terminal and in-flight states for an acme.sh revocation command."""

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CertificateRevocation(Base):
    """One idempotent, domain-based revocation request for a certificate."""

    __tablename__ = "certificate_revocations"
    __table_args__ = (
        UniqueConstraint(
            "certificate_id",
            "idempotency_key",
            name="uq_certificate_revocations_certificate_idempotency_key",
        ),
    )

    id: Mapped[_uuid.UUID] = mapped_column(primary_key=True, default=_uuid.uuid4)
    certificate_id: Mapped[_uuid.UUID] = mapped_column(ForeignKey("certificates.id"), index=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    reason: Mapped[int | None] = mapped_column(Integer, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[CertificateRevocationStatus] = mapped_column(
        Enum(CertificateRevocationStatus),
        default=CertificateRevocationStatus.PENDING,
        nullable=False,
    )
    error_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_details: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )
    attempt_started_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    certificate = relationship(
        "acme_api.models.certificate.Certificate",
        back_populates="revocations",
        lazy="selectin",
    )
