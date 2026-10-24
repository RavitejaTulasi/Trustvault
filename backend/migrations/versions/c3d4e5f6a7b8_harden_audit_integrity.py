
"""Harden audit hash coverage and actor integrity.

Revision ID: c3d4e5f6a7b8
Revises: b6f1c8e9a2d4
Create Date: 2026-10-20 00:00:00.000000
"""

import hashlib
from collections.abc import Sequence
from datetime import UTC

import sqlalchemy as sa
from alembic import context, op

# Revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: str | Sequence[str] | None = "b6f1c8e9a2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GENESIS_HASH = "0" * 64
ACTOR_FK_NAME = "fk_audit_events_actor_id_users"

SQLITE_FK_NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
}


def _require_online_mode(operation: str) -> None:
    """Prevent audit-integrity changes without a live database connection."""
    if context.is_offline_mode():
        raise RuntimeError(
            f"Refusing to run {operation} for revision {revision} in offline mode. "
            "Audit-chain state and existing audit records must be validated "
            "against a live database connection."
        )


def _validate_legacy_audit_chain() -> tuple[int, str]:
    """Validate every existing version-1 audit record before migration."""
    bind = op.get_bind()

    expected_sequence = 1
    previous_hash = GENESIS_HASH
    last_sequence = 0
    last_hash = GENESIS_HASH

    rows = bind.execute(
        sa.text(
            "SELECT sequence_number, timestamp, actor_id, action, "
            "resource_type, resource_id, outcome, request_id, details, "
            "previous_hash, record_hash "
            "FROM audit_events ORDER BY sequence_number ASC"
        ).columns(timestamp=sa.DateTime(timezone=True))
    ).mappings()

    for row in rows:
        sequence = row["sequence_number"]

        if sequence != expected_sequence:
            raise RuntimeError(
                "Refusing audit migration: sequence gap or invalid sequence; "
                f"expected {expected_sequence}, found {sequence}"
            )

        if row["previous_hash"] != previous_hash:
            raise RuntimeError(
                "Refusing audit migration: previous-hash link mismatch "
                f"at sequence {sequence}"
            )

        timestamp = row["timestamp"]

        # SQLAlchemy should return a datetime because timestamp is typed above.
        # Reject unexpected values instead of silently accepting bad data.
        if not hasattr(timestamp, "tzinfo"):
            raise RuntimeError(
                "Refusing audit migration: invalid timestamp "
                f"at sequence {sequence}"
            )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        else:
            timestamp = timestamp.astimezone(UTC)

        timestamp_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        payload = (
            f"seq:{sequence}|"
            f"ts:{timestamp_str}|"
            f"actor:{row['actor_id'] or ''}|"
            f"action:{row['action']}|"
            f"res_type:{row['resource_type'] or ''}|"
            f"res_id:{row['resource_id'] or ''}|"
            f"outcome:{row['outcome']}|"
            f"req_id:{row['request_id'] or ''}|"
            f"details:{row['details'] or ''}|"
            f"prev:{previous_hash}"
        )

        calculated_hash = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        if row["record_hash"] != calculated_hash:
            raise RuntimeError(
                "Refusing audit migration: record hash mismatch "
                f"at sequence {sequence}"
            )

        previous_hash = row["record_hash"]
        last_sequence = sequence
        last_hash = previous_hash
        expected_sequence += 1

    return last_sequence, last_hash


def _replace_actor_foreign_key(*, ondelete: str) -> None:
    """Change the audit actor FK on SQLite and PostgreSQL."""
    bind = op.get_bind()

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(
            "audit_events",
            naming_convention=SQLITE_FK_NAMING_CONVENTION,
            recreate="always",
        ) as batch_op:
            batch_op.drop_constraint(
                ACTOR_FK_NAME,
                type_="foreignkey",
            )
            batch_op.create_foreign_key(
                ACTOR_FK_NAME,
                "users",
                ["actor_id"],
                ["id"],
                ondelete=ondelete,
                onupdate="RESTRICT",
            )
        return

    inspector = sa.inspect(bind)

    actor_fk_name = next(
        (
            foreign_key["name"]
            for foreign_key in inspector.get_foreign_keys("audit_events")
            if foreign_key["constrained_columns"] == ["actor_id"]
        ),
        None,
    )

    if actor_fk_name is None:
        raise RuntimeError(
            "Refusing audit migration: audit_events actor_id foreign key "
            "was not found"
        )

    op.drop_constraint(
        actor_fk_name,
        "audit_events",
        type_="foreignkey",
    )
    op.create_foreign_key(
        ACTOR_FK_NAME,
        "audit_events",
        "users",
        ["actor_id"],
        ["id"],
        ondelete=ondelete,
        onupdate="RESTRICT",
    )


def upgrade() -> None:
    """Add versioned hashes, serialized chain state, and actor integrity."""
    _require_online_mode("upgrade")

    # Validate existing records before making any schema changes.
    last_sequence, last_hash = _validate_legacy_audit_chain()

    op.add_column(
        "audit_events",
        sa.Column(
            "hash_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "id = 1",
            name="ck_audit_chain_state_singleton",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    bind = op.get_bind()

    bind.execute(
        sa.text(
            "INSERT INTO audit_chain_state "
            "(id, last_sequence, last_hash, updated_at) "
            "VALUES (1, :last_sequence, :last_hash, CURRENT_TIMESTAMP)"
        ),
        {
            "last_sequence": last_sequence,
            "last_hash": last_hash,
        },
    )

    _replace_actor_foreign_key(ondelete="RESTRICT")


def downgrade() -> None:
    """Refuse to remove version metadata while version-2 records exist."""
    _require_online_mode("downgrade")

    bind = op.get_bind()

    v2_records = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM audit_events WHERE hash_version = 2"
        )
    ).scalar_one()

    if v2_records:
        raise RuntimeError(
            f"Refusing to downgrade revision {revision}: "
            f"{v2_records} audit event(s) use hash version 2. The legacy "
            "schema has no hash_version column, so downgrading and re-upgrading "
            "would relabel these records as version 1 and make verification "
            "report a broken chain. Back up the database and keep the current "
            "schema. To return to an older release, restore a database "
            "snapshot taken before version 2 records were written; do not "
            "delete or rewrite audit rows to force the downgrade."
        )

    _replace_actor_foreign_key(ondelete="SET NULL")

    op.drop_table("audit_chain_state")

    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_column("hash_version")
