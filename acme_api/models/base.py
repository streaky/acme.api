"""Declarative base and timestamp mixin for the data layer."""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import DateTime, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy 2.x declarative base class.

    All model classes inherit from this base to register with the
    SQLAlchemy metadata registry and gain mapper support.
    """


class TimestampMixin:
    """Mixin that adds ``created_at`` and ``updated_at`` audit columns.

    ``created_at`` is set automatically by the database on insert via a
    server-side default. ``updated_at`` is set on every row update by the
    ORM-level ``onupdate`` callback. Both are timezone-aware UTC datetimes.
    """

    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        doc="Timestamp when the row was first inserted.",
    )
    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        onupdate=text("CURRENT_TIMESTAMP"),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        doc="Timestamp of the most recent update to this row.",
    )
