"""add request ownership token for upload lease fencing

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-23 11:40:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add a fencing token for the request that owns an upload lease."""
    op.add_column(
        "storage_operations",
        sa.Column("lease_token", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    """Refuse to remove request fencing while operations remain unresolved."""
    if context.is_offline_mode():
        raise RuntimeError(
            "Refusing offline downgrade of upload lease fencing; unresolved "
            "operation state cannot be checked without the database."
        )
    unresolved_count = op.get_bind().execute(
        sa.text(
            "SELECT COUNT(*) FROM storage_operations "
            "WHERE status NOT IN ('completed', 'cancelled') "
            "OR lease_token IS NOT NULL"
        )
    ).scalar_one()
    if unresolved_count:
        raise RuntimeError(
            "Refusing to remove upload lease fencing while unresolved storage "
            "operations exist."
        )
    op.drop_column("storage_operations", "lease_token")
