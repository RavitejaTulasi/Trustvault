"""add canonical storage ownership and upload idempotency

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
Create Date: 2026-10-24 00:00:00.000000

"""
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
import re

import sqlalchemy as sa
from alembic import context, op

revision: str = "d8e9f0a1b2c3"
down_revision: str | Sequence[str] | None = "c7d8e9f0a1b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _preflight_storage_keys(
    bind,
) -> tuple[dict[str, list[tuple[bool, str, str]]], set[str]]:
    orphan_versions = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM document_versions v "
            "LEFT JOIN documents d ON d.id = v.document_id "
            "WHERE d.id IS NULL"
        )
    ).scalar_one()
    if orphan_versions:
        raise RuntimeError(
            "Storage registry backfill refused: document versions without a "
            "parent document were found."
        )
    references: dict[str, list[tuple[bool, str, str]]] = defaultdict(list)
    for row in bind.execute(
        sa.text(
            "SELECT storage_key, is_deleted, 'document' AS owner_type, id AS owner_id "
            "FROM documents "
            "UNION ALL "
            "SELECT v.storage_key, d.is_deleted, 'version' AS owner_type, v.id AS owner_id "
            "FROM document_versions v "
            "LEFT JOIN documents d ON d.id = v.document_id"
        )
    ):
        references[row.storage_key].append(
            (bool(row.is_deleted), row.owner_type, row.owner_id)
        )

    operation_keys = {
        row.storage_key
        for row in bind.execute(
            sa.text("SELECT storage_key FROM storage_operations")
        )
    }
    invalid = [
        key
        for key in set(references) | operation_keys
        if not isinstance(key, str) or _KEY_PATTERN.fullmatch(key) is None
    ]
    duplicates = [key for key, rows in references.items() if len(rows) > 1]
    if invalid or duplicates:
        raise RuntimeError(
            "Storage registry backfill refused: invalid storage keys="
            f"{len(invalid)}, cross-table or duplicate references={len(duplicates)}. "
            "Resolve these records before applying this migration."
        )
    return references, operation_keys


def _create_sqlite_ownership_triggers() -> None:
    op.execute(
        """
        CREATE TRIGGER trg_documents_storage_key_owner_insert
        BEFORE INSERT ON documents
        BEGIN
          UPDATE storage_objects
          SET owner_type = 'document', owner_id = NEW.id
          WHERE storage_key = NEW.storage_key
            AND state = 'active' AND owner_type IS NULL;
          SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'storage object is not active or already owned')
          END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_documents_storage_key_owner_update
        BEFORE UPDATE OF storage_key ON documents
        BEGIN
          SELECT CASE WHEN NEW.storage_key != OLD.storage_key
            THEN RAISE(ABORT, 'storage key ownership is immutable')
          END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_document_versions_storage_key_owner_insert
        BEFORE INSERT ON document_versions
        BEGIN
          UPDATE storage_objects
          SET owner_type = 'version', owner_id = NEW.id
          WHERE storage_key = NEW.storage_key
            AND state = 'active' AND owner_type IS NULL;
          SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'storage object is not active or already owned')
          END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_document_versions_storage_key_owner_update
        BEFORE UPDATE OF storage_key ON document_versions
        BEGIN
          SELECT CASE WHEN NEW.storage_key != OLD.storage_key
            THEN RAISE(ABORT, 'storage key ownership is immutable')
          END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_storage_objects_prevent_delete
        BEFORE DELETE ON storage_objects
        BEGIN
          SELECT CASE WHEN OLD.owner_type IS NOT NULL OR EXISTS (
            SELECT 1 FROM documents WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM document_versions WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM storage_operations WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM upload_requests WHERE storage_key = OLD.storage_key
          ) THEN RAISE(ABORT, 'storage object is still owned') END;
        END
        """
    )


def _create_postgresql_ownership_triggers() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trustvault_guard_storage_key_reference()
        RETURNS trigger AS $$
        DECLARE affected_rows integer;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            IF NEW.storage_key IS DISTINCT FROM OLD.storage_key THEN
              RAISE EXCEPTION 'storage key ownership is immutable';
            END IF;
            RETURN NEW;
          END IF;
          IF TG_TABLE_NAME = 'documents' THEN
            UPDATE storage_objects
            SET owner_type = 'document', owner_id = NEW.id, updated_at = CURRENT_TIMESTAMP
            WHERE storage_key = NEW.storage_key
              AND state = 'active' AND owner_type IS NULL;
          ELSE
            UPDATE storage_objects
            SET owner_type = 'version', owner_id = NEW.id, updated_at = CURRENT_TIMESTAMP
            WHERE storage_key = NEW.storage_key
              AND state = 'active' AND owner_type IS NULL;
          END IF;
          GET DIAGNOSTICS affected_rows = ROW_COUNT;
          IF affected_rows <> 1 THEN
            RAISE EXCEPTION 'storage object is not active or already owned';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    for table in ("documents", "document_versions"):
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_storage_key_owner
            BEFORE INSERT OR UPDATE OF storage_key ON {table}
            FOR EACH ROW EXECUTE FUNCTION trustvault_guard_storage_key_reference()
            """
        )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trustvault_guard_storage_object_delete()
        RETURNS trigger AS $$
        BEGIN
          IF OLD.owner_type IS NOT NULL OR EXISTS (
            SELECT 1 FROM documents WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM document_versions WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM storage_operations WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM upload_requests WHERE storage_key = OLD.storage_key
          ) THEN
            RAISE EXCEPTION 'storage object is still owned';
          END IF;
          RETURN OLD;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_storage_objects_prevent_delete
        BEFORE DELETE ON storage_objects
        FOR EACH ROW EXECUTE FUNCTION trustvault_guard_storage_object_delete()
        """
    )


def _assert_safe_downgrade(bind) -> None:
    object_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM storage_objects")
    ).scalar_one()
    request_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM upload_requests")
    ).scalar_one()
    unresolved_operation_count = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM storage_operations "
            "WHERE status NOT IN ('completed', 'cancelled')"
        )
    ).scalar_one()
    document_reference_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM documents")
    ).scalar_one()
    version_reference_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM document_versions")
    ).scalar_one()
    operation_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM storage_operations")
    ).scalar_one()
    if (
        object_count
        or request_count
        or unresolved_operation_count
        or document_reference_count
        or version_reference_count
        or operation_count
    ):
        raise RuntimeError(
            "Refusing to drop storage ownership or idempotency records while "
            "storage objects, references, upload requests, or storage operations exist."
        )


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "Storage registry backfill requires online validation of existing "
            "storage references; offline SQL generation is not a safety check."
        )

    bind = op.get_bind()

    # Reject unsupported databases before any schema mutations.
    if bind.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            "Unsupported database dialect for storage ownership: "
            f"{bind.dialect.name}"
        )

    # Validate existing data before changing the schema.
    references, operation_keys = _preflight_storage_keys(bind)

    op.create_table(
        "storage_objects",
        sa.Column("storage_key", sa.String(length=64), nullable=False),
        sa.Column("backend", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("owner_type", sa.String(length=16), nullable=True),
        sa.Column("owner_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "backend IN ('local', 'supabase', 'unknown')",
            name="ck_storage_objects_backend",
        ),
        sa.CheckConstraint(
            "state IN ('uploading', 'active', 'deleting', 'deleted', 'needs_review')",
            name="ck_storage_objects_state",
        ),
        sa.CheckConstraint(
            "owner_type IS NULL OR owner_type IN ('document', 'version')",
            name="ck_storage_objects_owner_type",
        ),
        sa.CheckConstraint(
            "(owner_type IS NULL AND owner_id IS NULL) OR "
            "(owner_type IS NOT NULL AND owner_id IS NOT NULL)",
            name="ck_storage_objects_owner_pair",
        ),
        sa.PrimaryKeyConstraint("storage_key"),
        sa.UniqueConstraint("owner_type", "owner_id", name="uq_storage_objects_owner"),
    )
    now = datetime.now(UTC)
    rows = []
    for key in sorted(set(references) | operation_keys):
        deleted_references = references.get(key, [])
        has_pending_delete = bind.execute(
            sa.text(
                "SELECT 1 FROM storage_operations WHERE storage_key = :key "
                "AND operation_type = 'delete' "
                "AND status NOT IN ('completed', 'cancelled') LIMIT 1"
            ),
            {"key": key},
        ).first() is not None
        has_completed_delete = bind.execute(
            sa.text(
                "SELECT 1 FROM storage_operations WHERE storage_key = :key "
                "AND operation_type = 'delete' AND status = 'completed' LIMIT 1"
            ),
            {"key": key},
        ).first() is not None
        if deleted_references and any(not row[0] for row in deleted_references):
            state = "active"
        elif has_pending_delete:
            state = "deleting"
        elif has_completed_delete:
            state = "deleted"
        elif deleted_references:
            state = "active"
        else:
            state = "needs_review"
        rows.append(
            {
                "storage_key": key,
                "backend": "unknown",
                "state": state,
                "owner_type": (
                    deleted_references[0][1] if deleted_references else None
                ),
                "owner_id": (
                    deleted_references[0][2] if deleted_references else None
                ),
            }
        )
    if rows:
        op.bulk_insert(
            sa.table(
                "storage_objects",
                sa.column("storage_key", sa.String()),
                sa.column("backend", sa.String()),
                sa.column("state", sa.String()),
                sa.column("owner_type", sa.String()),
                sa.column("owner_id", sa.String()),
                sa.column("created_at", sa.DateTime()),
                sa.column("updated_at", sa.DateTime()),
            ),
            [
                {**row, "created_at": now, "updated_at": now}
                for row in rows
            ],
        )
    op.create_index(
        "ix_storage_objects_state_updated",
        "storage_objects",
        ["state", "updated_at"],
    )

    op.create_table(
        "upload_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.String(length=64), nullable=False),
        sa.Column("operation_id", sa.String(length=36), nullable=True),
        sa.Column("document_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('in_progress', 'completed', 'needs_review')",
            name="ck_upload_requests_status",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["storage_key"], ["storage_objects.storage_key"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["storage_operations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["document_id"], ["documents.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_id",
            "idempotency_key",
            name="uq_upload_requests_owner_key",
        ),
    )
    op.create_index(
        "ix_upload_requests_document_id", "upload_requests", ["document_id"]
    )

    if bind.dialect.name == "sqlite":
        _create_sqlite_ownership_triggers()
    else:
        _create_postgresql_ownership_triggers()


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "Refusing offline downgrade of storage ownership and idempotency; "
            "live references and unresolved operations cannot be checked."
        )
    bind = op.get_bind()
    _assert_safe_downgrade(bind)

    if bind.dialect.name == "sqlite":
        for trigger in (
            "trg_documents_storage_key_owner_insert",
            "trg_documents_storage_key_owner_update",
            "trg_document_versions_storage_key_owner_insert",
            "trg_document_versions_storage_key_owner_update",
            "trg_storage_objects_prevent_delete",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    elif bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_documents_storage_key_owner ON documents"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_document_versions_storage_key_owner "
            "ON document_versions"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS trustvault_guard_storage_key_reference()"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS trustvault_guard_storage_object_delete()"
        )

    op.drop_index("ix_upload_requests_document_id", table_name="upload_requests")
    op.drop_table("upload_requests")
    op.drop_index("ix_storage_objects_state_updated", table_name="storage_objects")
    op.drop_table("storage_objects")
