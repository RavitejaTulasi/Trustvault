"""add permission_requests table

Revision ID: 1b2bd10ec660
Revises: d8e9f0a1b2c3
Create Date: 2026-10-24 21:53:53.282775

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1b2bd10ec660"
down_revision: str | Sequence[str] | None = "d8e9f0a1b2c3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema: create permission_requests table."""
    op.create_table(
        "permission_requests",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("requester_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("document_id", sa.String(length=36), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("requested_role", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "APPROVED",
                "REJECTED",
                "CANCELED",
                name="permissionrequeststatus",
            ),
            nullable=False,
            server_default="PENDING",
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
            onupdate=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_permission_requests_requester_id",
        "permission_requests",
        ["requester_id"],
    )
    op.create_index(
        "ix_permission_requests_document_id",
        "permission_requests",
        ["document_id"],
    )
    op.create_index(
        "ix_permission_requests_status",
        "permission_requests",
        ["status"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_permission_requests_status", table_name="permission_requests")
    op.drop_index("ix_permission_requests_document_id", table_name="permission_requests")
    op.drop_index("ix_permission_requests_requester_id", table_name="permission_requests")
    op.drop_table("permission_requests")
    # ### end Alembic commands ###
