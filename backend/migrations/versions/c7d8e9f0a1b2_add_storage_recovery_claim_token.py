"""add recovery-worker claim fencing

Revision ID: c7d8e9f0a1b2
Revises: b2c3d4e5f6a7
Create Date: 2026-10-23 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision: str = "c7d8e9f0a1b2"
down_revision: str | Sequence[str] | None = "b2c3d4e5f6a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add a distinct fencing token for each recovery-worker claim."""
    op.add_column(
        "storage_operations",
        sa.Column("claim_token", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    """Refuse to remove claim fencing while operations need recovery."""
    if context.is_offline_mode():
        raise RuntimeError(
            "Refusing offline downgrade of recovery claim fencing; unresolved "
            "operation state cannot be checked without the database."
        )
    unresolved_count = op.get_bind().execute(
        sa.text(
            "SELECT COUNT(*) FROM storage_operations "
            "WHERE status NOT IN ('completed', 'cancelled') "
            "OR lease_token IS NOT NULL OR claim_token IS NOT NULL"
        )
    ).scalar_one()
    if unresolved_count:
        raise RuntimeError(
            "Refusing to remove recovery claim fencing while unresolved "
            "storage operations exist."
        )
    op.drop_column("storage_operations", "claim_token")
