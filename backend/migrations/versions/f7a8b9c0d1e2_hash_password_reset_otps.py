"""hash password reset OTP codes at rest

Revision ID: f7a8b9c0d1e2
Revises: d5e6f7a8b9c0
Create Date: 2026-10-25 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a8b9c0d1e2"
down_revision: str | Sequence[str] | None = "d5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Widen the OTP column and invalidate legacy plaintext codes."""
    with op.batch_alter_table("password_reset_otps") as batch_op:
        batch_op.alter_column(
            "otp_code",
            existing_type=sa.String(length=10),
            type_=sa.String(length=64),
            existing_nullable=False,
        )

    # Existing rows contain short-lived plaintext codes. They cannot be safely
    # converted without application configuration, and no reset should survive
    # a deployment that changes the storage format.
    op.execute(
        sa.text(
            "UPDATE password_reset_otps "
            "SET otp_code = :placeholder, is_used = TRUE"
        ).bindparams(placeholder="0" * 64)
    )


def downgrade() -> None:
    """Restore the legacy column shape after invalidating stored digests."""
    op.execute(
        sa.text(
            "UPDATE password_reset_otps "
            "SET otp_code = '000000', is_used = TRUE"
        )
    )
    with op.batch_alter_table("password_reset_otps") as batch_op:
        batch_op.alter_column(
            "otp_code",
            existing_type=sa.String(length=64),
            type_=sa.String(length=10),
            existing_nullable=False,
        )
