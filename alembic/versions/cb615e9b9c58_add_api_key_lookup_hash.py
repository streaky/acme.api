"""add_api_key_lookup_hash

Revision ID: cb615e9b9c58
Revises: 8760d3a7fed0
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "cb615e9b9c58"
down_revision: Union[str, Sequence[str], None] = "8760d3a7fed0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("key_lookup_hash", sa.String(length=64), nullable=True)
        )
        batch_op.create_index(
            batch_op.f("ix_api_keys_key_lookup_hash"),
            ["key_lookup_hash"],
            unique=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_api_keys_key_lookup_hash"))
        batch_op.drop_column("key_lookup_hash")
