"""Certificate model — the core entity representing an ACME-managed TLS cert."""

from __future__ import annotations

import datetime as _dt
import enum
import uuid as _uuid

from sqlalchemy import JSON, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from acme_api.models.base import Base, TimestampMixin


class CertificateStatus(enum.StrEnum):
    """Lifecycle states a certificate can occupy."""

    PENDING = "pending"
    PENDING_DNS = "pending_dns"
    ISSUING = "issuing"
    VALID = "valid"
    RENEWING = "renewing"
    FAILED = "failed"
    REVOKED = "revoked"


class Certificate(Base, TimestampMixin):
    """Row representing a single ACME-managed TLS certificate.

    Each certificate is linked to an ACME account and DNS provider by config
    alias (``acme_account_ref``, ``dns_provider_ref``) rather than a foreign-key,
    keeping the data layer decoupled from deployment configuration.

    Timestamps (``created_at``, ``updated_at``) are provided by ``TimestampMixin``
    via the model hierarchy — see :class:`base.TimestampMixin`.
    """

    __tablename__ = "certificates"

    # -- primary key ----------------------------------------------------------

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
        doc="Unique identifier for the certificate.",
    )

    # -- identity & target domains --------------------------------------------

    name: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
        doc="Human-readable label / alias for the certificate.",
    )
    domains: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        doc="JSON array of domain strings covered by this certificate.",
    )

    # -- external references (config aliases) ---------------------------------

    acme_account_ref: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Alias referencing the ACME account configuration block.",
    )
    dns_provider_ref: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        doc="Alias referencing the DNS provider configuration block, when required.",
    )

    challenge_method: Mapped[str] = mapped_column(
        String(32),
        default="dns-01",
        nullable=False,
        doc="Durable ACME challenge method used for issuance and renewal.",
    )
    dns_record_type: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        doc="Persistent DNS record type for DNS Persist requests.",
    )
    dns_record_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="Persistent DNS record owner for DNS Persist requests.",
    )
    dns_record_value: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        doc="Account-bound persistent DNS record value for DNS Persist requests.",
    )

    @property
    def challenge(self) -> dict[str, str] | None:
        """Return the stored DNS Persist instruction for authenticated API output."""
        if self.challenge_method != "dns-persist" or self.dns_record_value is None:
            return None
        return {
            "method": "dns-persist",
            "record_type": self.dns_record_type or "TXT",
            "record_name": self.dns_record_name or "",
            "record_value": self.dns_record_value,
        }

    # -- key parameters -------------------------------------------------------

    key_algorithm: Mapped[str] = mapped_column(
        String(32),
        default="ecdsa",
        nullable=False,
        doc="Key algorithm used (e.g. 'ecdsa', 'rsa-2048', 'rsa-4096').",
    )

    # -- expiry & status ------------------------------------------------------

    expiry_date: Mapped[_dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="UTC datetime when the certificate expires. NULL before issuance.",
    )
    status: Mapped[CertificateStatus] = mapped_column(
        Enum(CertificateStatus),
        default=CertificateStatus.PENDING,
        nullable=False,
        doc="Current lifecycle state of the certificate.",
    )

    # -- relationships --------------------------------------------------------

    events = relationship(
        "acme_api.models.event.Event",
        back_populates="certificate",
        lazy="selectin",
        doc="Audit log entries for this certificate.",
    )
    renewal_attempts = relationship(
        "acme_api.models.renewal_attempt.RenewalAttempt",
        back_populates="certificate",
        lazy="selectin",
        doc="Records of each renewal attempt made against this certificate.",
    )
