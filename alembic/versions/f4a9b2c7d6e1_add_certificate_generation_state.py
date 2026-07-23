"""Add durable current-generation selection metadata.

Revision ID: f4a9b2c7d6e1
Revises: e3c8b6a4d1f2
Create Date: 2026-07-23
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "f4a9b2c7d6e1"
down_revision: str | None = "e3c8b6a4d1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Store the selected immutable deployment generation on each certificate."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.add_column(sa.Column("current_generation_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("current_generation_details", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("generation_selection_idempotency_key", sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Remove immutable deployment generation selection metadata."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_column("generation_selection_idempotency_key")
        batch_op.drop_column("current_generation_details")
        batch_op.drop_column("current_generation_id")
