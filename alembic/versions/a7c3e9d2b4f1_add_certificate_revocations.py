"""Add durable acme.sh certificate revocation requests.

Revision ID: a7c3e9d2b4f1
Revises: f4a9b2c7d6e1
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a7c3e9d2b4f1"
down_revision: str | Sequence[str] | None = "f4a9b2c7d6e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the durable certificate-revocation request table."""
    op.create_table(
        "certificate_revocations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("certificate_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("reason", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "SUCCEEDED",
                "FAILED",
                name="certificaterevocationstatus",
            ),
            nullable=False,
        ),
        sa.Column("error_category", sa.String(length=32), nullable=True),
        sa.Column("error_details", sa.String(length=2048), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "certificate_id",
            "idempotency_key",
            name="uq_certificate_revocations_certificate_idempotency_key",
        ),
    )
    op.create_index("ix_certificate_revocations_certificate_id", "certificate_revocations", ["certificate_id"])


def downgrade() -> None:
    """Drop the durable certificate-revocation request table."""
    op.drop_index("ix_certificate_revocations_certificate_id", table_name="certificate_revocations")
    op.drop_table("certificate_revocations")
