"""add storage quota coordination

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-20 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: str | Sequence[str] | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the quota lock row."""
    op.create_table(
        "storage_quota_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name="ck_storage_quota_state_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Remove the Phase 5 quota lock row."""
    op.drop_table("storage_quota_state")
