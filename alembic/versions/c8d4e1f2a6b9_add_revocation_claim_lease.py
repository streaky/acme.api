"""Add a lease for resumable certificate revocation requests.

Revision ID: c8d4e1f2a6b9
Revises: a7c3e9d2b4f1
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8d4e1f2a6b9"
down_revision: str | Sequence[str] | None = "a7c3e9d2b4f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the timestamp that leases a pending revocation to one worker."""
    op.add_column("certificate_revocations", sa.Column("attempt_started_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Remove the revocation worker lease timestamp."""
    op.drop_column("certificate_revocations", "attempt_started_at")
