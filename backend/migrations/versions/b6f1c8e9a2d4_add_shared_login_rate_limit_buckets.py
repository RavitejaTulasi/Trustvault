"""add shared login rate limit buckets and denial-audit marker

Revision ID: b6f1c8e9a2d4
Revises: 74ecdca7750f
Create Date: 2026-10-20 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b6f1c8e9a2d4"
down_revision: str | Sequence[str] | None = "74ecdca7750f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the bounded, expiring shared login rate-limit table."""
    op.create_table(
        "login_rate_limit_buckets",
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column(
            "denial_audit_recorded",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("key_hash"),
    )
    op.create_index(
        "ix_login_rate_limit_buckets_expires_at",
        "login_rate_limit_buckets",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the shared login rate-limit table."""
    op.drop_index(
        "ix_login_rate_limit_buckets_expires_at",
        table_name="login_rate_limit_buckets",
    )
    op.drop_table("login_rate_limit_buckets")
