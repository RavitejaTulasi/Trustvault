import os
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from backend.tests import postgres_migration_support as migration_support
from backend.tests.postgres_migration_support import (
    MIGRATION_RUN_ENV_VAR,
    migrated_postgres_schema,
)

pytestmark = [
    pytest.mark.postgres_migration_integration,
    pytest.mark.skipif(
        os.environ.get(MIGRATION_RUN_ENV_VAR) != "1",
        reason=(
            "Alembic PostgreSQL migration tests are opt-in. Set "
            f"{MIGRATION_RUN_ENV_VAR}=1 and configure the disposable target."
        ),
    ),
]


def test_all_migrations_reach_head_in_an_isolated_owned_schema():
    with migrated_postgres_schema() as migrated:
        table_names = set(
            migrated.connection.execute(
                text(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = :schema
                    """
                ),
                {"schema": migrated.schema},
            ).scalars()
        )
        trigger_names = set(
            migrated.connection.execute(
                text(
                    """
                    SELECT t.tgname
                    FROM pg_trigger AS t
                    JOIN pg_class AS c ON c.oid = t.tgrelid
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE n.nspname = :schema
                      AND NOT t.tgisinternal
                    """
                ),
                {"schema": migrated.schema},
            ).scalars()
        )
        function_names = set(
            migrated.connection.execute(
                text(
                    """
                    SELECT p.proname
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = :schema
                    """
                ),
                {"schema": migrated.schema},
            ).scalars()
        )

        assert migrated.revision == "d8e9f0a1b2c3"
        assert {
            "alembic_version",
            "audit_chain_state",
            "documents",
            "storage_objects",
            "storage_operations",
            "upload_requests",
            "users",
        }.issubset(table_names)
        assert {
            "trg_documents_storage_key_owner",
            "trg_document_versions_storage_key_owner",
            "trg_storage_objects_prevent_delete",
        }.issubset(trigger_names)
        assert {
            "trustvault_guard_storage_key_reference",
            "trustvault_guard_storage_object_delete",
        }.issubset(function_names)


def test_legacy_document_and_version_keys_are_backfilled():
    with migration_support.migrated_postgres_schema(
        target_revision="c7d8e9f0a1b2"
    ) as migrated:
        connection = migrated.connection
        config = migration_support._create_alembic_config(
            connection,
            migrated.schema,
        )

        now = datetime.now(UTC)
        user_id = "migration-test-user"
        document_id = "migration-test-document"
        version_id = "migration-test-version"
        document_key = "a" * 64
        version_key = "b" * 64

        connection.execute(
            text(
                """
                INSERT INTO users (
                    id, email, hashed_password, full_name, role,
                    is_active, created_at, updated_at, must_change_password
                )
                VALUES (
                    :id, :email, :password, :name, :role,
                    TRUE, :created, :updated, FALSE
                )
                """
            ),
            {
                "id": user_id,
                "email": "migration-test@example.invalid",
                "password": "not-a-real-password-hash",
                "name": "Migration Test",
                "role": "user",
                "created": now,
                "updated": now,
            },
        )

        connection.execute(
            text(
                """
                INSERT INTO documents (
                    id, title, original_filename, storage_key,
                    file_size_bytes, mime_type, category, owner_id,
                    is_deleted, created_at, updated_at
                )
                VALUES (
                    :id, :title, :filename, :key,
                    10, 'text/plain', 'test', :owner,
                    FALSE, :created, :updated
                )
                """
            ),
            {
                "id": document_id,
                "title": "Migration test",
                "filename": "migration-test.txt",
                "key": document_key,
                "owner": user_id,
                "created": now,
                "updated": now,
            },
        )

        connection.execute(
            text(
                """
                INSERT INTO document_versions (
                    id, document_id, version_number, storage_key,
                    file_size_bytes, created_at, created_by_id
                )
                VALUES (
                    :id, :document, 1, :key, 10, :created, :creator
                )
                """
            ),
            {
                "id": version_id,
                "document": document_id,
                "key": version_key,
                "created": now,
                "creator": user_id,
            },
        )
        connection.commit()

        command.upgrade(config, "head")

        rows = connection.execute(
            text(
                """
                SELECT storage_key, backend, state, owner_type, owner_id
                FROM storage_objects
                WHERE storage_key IN (:document_key, :version_key)
                ORDER BY storage_key
                """
            ),
            {
                "document_key": document_key,
                "version_key": version_key,
            },
        ).mappings().all()

        assert len(rows) == 2
        by_key = {row["storage_key"]: row for row in rows}

        assert by_key[document_key]["backend"] == "unknown"
        assert by_key[document_key]["state"] == "active"
        assert by_key[document_key]["owner_type"] == "document"
        assert by_key[document_key]["owner_id"] == document_id

        assert by_key[version_key]["backend"] == "unknown"
        assert by_key[version_key]["state"] == "active"
        assert by_key[version_key]["owner_type"] == "version"
        assert by_key[version_key]["owner_id"] == version_id


def _insert_storage_trigger_fixtures(connection):
    now = datetime.now(UTC)
    user_id = "trigger-test-user"
    document_id = "trigger-test-document"
    version_id = "trigger-test-version"
    document_key = "c" * 64
    version_key = "d" * 64

    connection.execute(
        text(
            """
            INSERT INTO users (
                id, email, hashed_password, full_name, role,
                is_active, created_at, updated_at, must_change_password
            )
            VALUES (
                :id, :email, :password, :name, :role,
                TRUE, :created, :updated, FALSE
            )
            """
        ),
        {
            "id": user_id,
            "email": "trigger-test@example.invalid",
            "password": "not-a-real-password-hash",
            "name": "Trigger Test",
            "role": "user",
            "created": now,
            "updated": now,
        },
    )

    # Create unowned registry entries first; the INSERT triggers
    # should assign each entry to the corresponding record.
    for key in (document_key, version_key):
        connection.execute(
            text(
                """
                INSERT INTO storage_objects (
                    storage_key, backend, state, owner_type, owner_id,
                    created_at, updated_at
                )
                VALUES (
                    :key, 'unknown', 'active', NULL, NULL, :now, :now
                )
                """
            ),
            {"key": key, "now": now},
        )

    connection.execute(
        text(
            """
            INSERT INTO documents (
                id, title, original_filename, storage_key,
                file_size_bytes, mime_type, category, owner_id,
                is_deleted, created_at, updated_at
            )
            VALUES (
                :id, 'Trigger test', 'trigger.txt', :key,
                10, 'text/plain', 'test', :owner,
                FALSE, :created, :updated
            )
            """
        ),
        {
            "id": document_id,
            "key": document_key,
            "owner": user_id,
            "created": now,
            "updated": now,
        },
    )

    connection.execute(
        text(
            """
            INSERT INTO document_versions (
                id, document_id, version_number, storage_key,
                file_size_bytes, created_at, created_by_id
            )
            VALUES (
                :id, :document, 1, :key, 10, :created, :creator
            )
            """
        ),
        {
            "id": version_id,
            "document": document_id,
            "key": version_key,
            "created": now,
            "creator": user_id,
        },
    )

    return document_id, version_id, document_key, version_key


def test_postgres_triggers_reject_storage_key_changes():
    with migrated_postgres_schema() as migrated:
        connection = migrated.connection
        document_id, version_id, document_key, version_key = (
            _insert_storage_trigger_fixtures(connection)
        )
        connection.commit()

        with pytest.raises(
            DBAPIError,
            match="storage key ownership is immutable",
        ):
            connection.execute(
                text(
                    """
                    UPDATE documents
                    SET storage_key = :new_key
                    WHERE id = :id
                    """
                ),
                {"new_key": "e" * 64, "id": document_id},
            )

        connection.rollback()

        with pytest.raises(
            DBAPIError,
            match="storage key ownership is immutable",
        ):
            connection.execute(
                text(
                    """
                    UPDATE document_versions
                    SET storage_key = :new_key
                    WHERE id = :id
                    """
                ),
                {"new_key": "f" * 64, "id": version_id},
            )

        connection.rollback()

        assert connection.execute(
            text("SELECT storage_key FROM documents WHERE id = :id"),
            {"id": document_id},
        ).scalar_one() == document_key

        assert connection.execute(
            text(
                "SELECT storage_key FROM document_versions WHERE id = :id"
            ),
            {"id": version_id},
        ).scalar_one() == version_key


def test_postgres_trigger_rejects_deleting_owned_storage_objects():
    with migrated_postgres_schema() as migrated:
        connection = migrated.connection
        _, _, document_key, version_key = _insert_storage_trigger_fixtures(
            connection
        )
        connection.commit()

        for key in (document_key, version_key):
            with pytest.raises(
                DBAPIError,
                match="storage object is still owned",
            ):
                connection.execute(
                    text(
                        """
                        DELETE FROM storage_objects
                        WHERE storage_key = :key
                        """
                    ),
                    {"key": key},
                )

            connection.rollback()

        remaining = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM storage_objects
                WHERE storage_key IN (:document_key, :version_key)
                """
            ),
            {
                "document_key": document_key,
                "version_key": version_key,
            },
        ).scalar_one()

        assert remaining == 2


def test_postgres_trigger_rejects_duplicate_storage_ownership():
    with migrated_postgres_schema() as migrated:
        connection = migrated.connection
        _, _, document_key, _ = _insert_storage_trigger_fixtures(connection)
        connection.commit()

        now = datetime.now(UTC)
        duplicate_document_id = "trigger-test-document-2"

        # The key already belongs to trigger-test-document.
        with pytest.raises(
            DBAPIError,
            match="storage object is not active or already owned",
        ):
            connection.execute(
                text(
                    """
                    INSERT INTO documents (
                        id, title, original_filename, storage_key,
                        file_size_bytes, mime_type, category, owner_id,
                        is_deleted, created_at, updated_at
                    )
                    VALUES (
                        :id, 'Duplicate', 'duplicate.txt', :key,
                        10, 'text/plain', 'test', :owner,
                        FALSE, :created, :updated
                    )
                    """
                ),
                {
                    "id": duplicate_document_id,
                    "key": document_key,
                    "owner": "trigger-test-user",
                    "created": now,
                    "updated": now,
                },
            )

        connection.rollback()

        owner = connection.execute(
            text(
                """
                SELECT owner_type, owner_id
                FROM storage_objects
                WHERE storage_key = :key
                """
            ),
            {"key": document_key},
        ).mappings().one()

        assert owner["owner_type"] == "document"
        assert owner["owner_id"] == "trigger-test-document"

        duplicate_count = connection.execute(
            text("SELECT COUNT(*) FROM documents WHERE id = :id"),
            {"id": duplicate_document_id},
        ).scalar_one()

        assert duplicate_count == 0


def test_invalid_legacy_storage_key_rejects_migration_without_partial_registry():
    with migrated_postgres_schema(
        target_revision="c7d8e9f0a1b2"
    ) as migrated:
        connection = migrated.connection
        config = migration_support._create_alembic_config(
            connection,
            migrated.schema,
        )

        now = datetime.now(UTC)
        user_id = "migration-invalid-key-user"
        document_id = "migration-invalid-key-document"

        connection.execute(
            text(
                """
                INSERT INTO users (
                    id, email, hashed_password, full_name, role,
                    is_active, created_at, updated_at, must_change_password
                )
                VALUES (
                    :id, :email, :password, :name, :role,
                    TRUE, :created, :updated, FALSE
                )
                """
            ),
            {
                "id": user_id,
                "email": "invalid-key@example.invalid",
                "password": "not-a-real-password-hash",
                "name": "Invalid Key Test",
                "role": "user",
                "created": now,
                "updated": now,
            },
        )

        # Deliberately malformed: the key is not 64 lowercase hex characters.
        connection.execute(
            text(
                """
                INSERT INTO documents (
                    id, title, original_filename, storage_key,
                    file_size_bytes, mime_type, category, owner_id,
                    is_deleted, created_at, updated_at
                )
                VALUES (
                    :id, 'Invalid key', 'invalid.txt', 'not-a-valid-key',
                    10, 'text/plain', 'test', :owner,
                    FALSE, :created, :updated
                )
                """
            ),
            {
                "id": document_id,
                "owner": user_id,
                "created": now,
                "updated": now,
            },
        )
        connection.commit()

        with pytest.raises(RuntimeError, match="invalid storage keys=1"):
            command.upgrade(config, "head")

        # Confirm the failed migration did not advance the version.
        revision = connection.execute(
            text(
                """
                SELECT version_num
                FROM alembic_version
                """
            )
        ).scalar_one()
        assert revision == "c7d8e9f0a1b2"

        # Confirm no registry tables were left behind.
        registry_tables = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = :schema
                  AND table_name IN ('storage_objects', 'upload_requests')
                """
            ),
            {"schema": migrated.schema},
        ).scalar_one()
        assert registry_tables == 0
