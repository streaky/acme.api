"""expand_api_key_lookup_hash.

Revision ID: 1de7e7e68b3d
Revises: cb615e9b9c58
Create Date: 2026-07-20 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1de7e7e68b3d"
down_revision: str | Sequence[str] | None = "cb615e9b9c58"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Expand the work-factor-protected API key lookup digest column."""
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.alter_column(
            "key_lookup_hash",
            existing_type=sa.String(length=64),
            type_=sa.String(length=128),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Restore the legacy API key lookup digest column width."""
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.alter_column(
            "key_lookup_hash",
            existing_type=sa.String(length=128),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
