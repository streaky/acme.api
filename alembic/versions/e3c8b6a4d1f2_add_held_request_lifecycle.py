"""Add durable held DNS Persist request lifecycle.

Revision ID: e3c8b6a4d1f2
Revises: d9f4a1c2b7e3
Create Date: 2026-07-23
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "e3c8b6a4d1f2"
down_revision: str | None = "d9f4a1c2b7e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add release concurrency metadata and held lifecycle status values."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.add_column(sa.Column("revision", sa.Integer(), nullable=False, server_default="1"))
        batch_op.add_column(sa.Column("release_idempotency_key", sa.String(length=255), nullable=True))

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in ("HELD", "AUTHORIZATION_READY", "RELEASED", "CANCELLED"):
            op.execute(f"ALTER TYPE certificatestatus ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    """Remove held request concurrency metadata."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_column("release_idempotency_key")
        batch_op.drop_column("revision")
