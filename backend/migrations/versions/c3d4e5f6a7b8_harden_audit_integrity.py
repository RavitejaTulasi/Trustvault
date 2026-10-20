"""harden audit hash coverage and actor integrity

Revision ID: c3d4e5f6a7b8
Revises: b6f1c8e9a2d4
Create Date: 2026-10-20 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: str | Sequence[str] | None = "b6f1c8e9a2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GENESIS_HASH = "0" * 64
ACTOR_FK_NAME = "fk_audit_events_actor_id_users"
SQLITE_FK_NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
}


def _replace_actor_foreign_key(*, ondelete: str) -> None:
    """Change the audit actor FK on both SQLite (batch rebuild) and PostgreSQL."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(
            "audit_events",
            naming_convention=SQLITE_FK_NAMING_CONVENTION,
            recreate="always",
        ) as batch_op:
            batch_op.drop_constraint(ACTOR_FK_NAME, type_="foreignkey")
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
        raise RuntimeError("audit_events actor_id foreign key was not found")

    op.drop_constraint(actor_fk_name, "audit_events", type_="foreignkey")
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
    """Add versioned hashes, serialized chain state, and immutable actor references."""
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
        sa.CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )

    bind = op.get_bind()
    head = bind.execute(
        sa.text(
            "SELECT sequence_number, record_hash "
            "FROM audit_events ORDER BY sequence_number DESC LIMIT 1"
        )
    ).first()
    last_sequence = head[0] if head is not None else 0
    last_hash = head[1] if head is not None else GENESIS_HASH
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
    """Refuse to drop version metadata while version 2 audit records exist."""
    bind = op.get_bind()
    v2_records = bind.execute(
        sa.text("SELECT COUNT(*) FROM audit_events WHERE hash_version = 2")
    ).scalar_one()
    if v2_records:
        raise RuntimeError(
            "Refusing to downgrade revision c3d4e5f6a7b8: "
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
