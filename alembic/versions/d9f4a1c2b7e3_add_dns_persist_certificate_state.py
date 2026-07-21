"""Add durable DNS Persist certificate state.

Revision ID: d9f4a1c2b7e3
Revises: 1de7e7e68b3d
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = "d9f4a1c2b7e3"
down_revision: str | None = "1de7e7e68b3d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add challenge metadata and permit account-specific request identities."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_index("ix_certificates_name")
        batch_op.alter_column("dns_provider_ref", existing_type=sa.String(length=128), nullable=True)
        batch_op.add_column(
            sa.Column("challenge_method", sa.String(length=32), nullable=False, server_default="dns-01")
        )
        batch_op.add_column(sa.Column("dns_record_type", sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column("dns_record_name", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("dns_record_value", sa.String(length=2048), nullable=True))
        batch_op.create_index("ix_certificates_name", ["name"], unique=False)

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE certificatestatus ADD VALUE IF NOT EXISTS 'PENDING_DNS'")


def downgrade() -> None:
    """Remove DNS Persist state and restore the legacy certificate shape."""
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_index("ix_certificates_name")
        batch_op.drop_column("dns_record_value")
        batch_op.drop_column("dns_record_name")
        batch_op.drop_column("dns_record_type")
        batch_op.drop_column("challenge_method")
        batch_op.alter_column("dns_provider_ref", existing_type=sa.String(length=128), nullable=False)
        batch_op.create_index("ix_certificates_name", ["name"], unique=True)
