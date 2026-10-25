"""add password_reset_otps table

Revision ID: c4f5a6b7d8e9
Revises: 1b2bd10ec660
Create Date: 2026-10-25 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4f5a6b7d8e9"
down_revision: str | Sequence[str] | None = "1b2bd10ec660"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the one-time password table used by the login-page reset flow."""
    op.create_table(
        "password_reset_otps",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("otp_code", sa.String(length=10), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "is_used",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_password_reset_otps_email",
        "password_reset_otps",
        ["email"],
        unique=False,
    )
    op.create_index(
        "ix_password_reset_otps_expires_at",
        "password_reset_otps",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the one-time password table."""
    op.drop_index(
        "ix_password_reset_otps_expires_at",
        table_name="password_reset_otps",
    )
    op.drop_index(
        "ix_password_reset_otps_email",
        table_name="password_reset_otps",
    )
    op.drop_table("password_reset_otps")
