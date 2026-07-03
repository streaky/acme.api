"""API Key SQLAlchemy model for authentication and authorization."""

from __future__ import annotations

import datetime as _dt
import enum
import uuid as _uuid

from sqlalchemy import Boolean, DateTime, Enum, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from acme_api.models.base import Base, TimestampMixin


class APIKeyRole(enum.StrEnum):
    """Roles for API key access control."""

    ADMIN = "admin"
    OPERATOR = "operator"
    READONLY = "readonly"


class APIKey(Base, TimestampMixin):
    """Row representing an API key used for authentication.

    Keys are stored as PBKDF2 hashes and validated on each request via
    the ``Authorization: Bearer <key>`` header. The role determines which
    endpoints the holder may access.
    """

    __tablename__ = "api_keys"

    # -- primary key ----------------------------------------------------------
    id: Mapped[_uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=_uuid.uuid4,
        doc="Unique identifier for this API key.",
    )

    # -- identity -------------------------------------------------------------
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        doc="Human-readable label (e.g. CI pipeline, operator account).",
    )
    hashed_key: Mapped[str] = mapped_column(
        String(600),
        nullable=False,
        doc="PBKDF2 hash of the raw API key material.",
    )
    key_lookup_hash: Mapped[str | None] = mapped_column(
        String(64),
        unique=True,
        nullable=True,
        index=True,
        doc="SHA-256 digest used to find the candidate key before PBKDF2 verification.",
    )
    role: Mapped[APIKeyRole] = mapped_column(
        Enum(APIKeyRole),
        nullable=False,
        server_default=text("'READONLY'"),
        doc="Access level granted by this key.",
    )

    # -- status & expiry ------------------------------------------------------
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("1"),
        nullable=False,
        doc="Whether this key is currently valid for authentication.",
    )
    expires_at: Mapped[_dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Optional expiration datetime. ``None`` means the key does not expire.",
    )
