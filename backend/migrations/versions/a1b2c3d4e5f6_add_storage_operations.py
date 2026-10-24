"""add durable remote storage operations

Revision ID: a1b2c3d4e5f6
Revises: f6a7b8c9d0e1
Create Date: 2026-10-23 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the durable remote storage operation queue."""
    op.create_table(
        "storage_operations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("operation_type", sa.String(length=10), nullable=False),
        sa.Column("storage_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_by_id", sa.String(length=36), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "operation_type IN ('upload', 'delete')",
            name="ck_storage_operations_type",
        ),
        sa.CheckConstraint(
            "status IN ('uploading', 'upload_uncertain', 'upload_committed', "
            "'delete_pending', 'retry_wait', 'completed', 'cancelled', "
            "'needs_review', 'exhausted')",
            name="ck_storage_operations_status",
        ),
        sa.CheckConstraint("retry_count >= 0", name="ck_storage_operations_retry_count"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "operation_type",
            "storage_key",
            name="uq_storage_operations_type_key",
        ),
    )
    op.create_index(
        "ix_storage_operations_due",
        "storage_operations",
        ["status", "next_attempt_at", "lease_until"],
        unique=False,
    )


def downgrade() -> None:
    """Refuse to drop durable storage-operation history."""
    if context.is_offline_mode():
        raise RuntimeError(
            "Refusing offline downgrade of storage operations; unresolved "
            "operation state cannot be checked without the database."
        )
    bind = op.get_bind()
    operation_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM storage_operations")
    ).scalar_one()
    if operation_count:
        raise RuntimeError(
            "Refusing to drop storage_operations while operation records exist. "
            "Resolve and archive the storage-operation history before downgrade."
        )
    op.drop_index("ix_storage_operations_due", table_name="storage_operations")
    op.drop_table("storage_operations")
