"""reconcile permission request indexes and timestamp types

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-10-25 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a8b9c0d1e2f3"
down_revision: str | Sequence[str] | None = "f7a8b9c0d1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Bring databases that applied the earlier revision to schema parity."""
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        for column in ("created_at", "updated_at"):
            data_type = bind.execute(
                sa.text(
                    "SELECT data_type FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = 'permission_requests' "
                    "AND column_name = :column"
                ),
                {"column": column},
            ).scalar_one_or_none()
            if data_type == "timestamp without time zone":
                op.execute(
                    sa.text(
                        f"ALTER TABLE permission_requests "
                        f"ALTER COLUMN {column} TYPE TIMESTAMP WITH TIME ZONE "
                        f"USING {column} AT TIME ZONE 'UTC'"
                    )
                )

    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_permission_requests_requester_id "
        "ON permission_requests (requester_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_permission_requests_document_id "
        "ON permission_requests (document_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_permission_requests_status "
        "ON permission_requests (status)"
    )


def downgrade() -> None:
    """No-op: the indexes may have been created by the original revision."""
    pass
