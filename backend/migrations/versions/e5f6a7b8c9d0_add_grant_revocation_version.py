"""add grant revocation generation

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-20 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: str | Sequence[str] | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the monotonic revocation generation used for revoke-wins grants."""
    op.add_column(
        "document_grants",
        sa.Column(
            "revocation_version",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Remove the grant revocation generation."""
    with op.batch_alter_table("document_grants") as batch_op:
        batch_op.drop_column("revocation_version")
