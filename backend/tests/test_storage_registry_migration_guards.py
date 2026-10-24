"""Tests only the pure safety guards in the additive storage migration."""

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text


_MIGRATION_PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "d8e9f0a1b2c3_add_storage_registry_and_upload_idempotency.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "storage_registry_migration", _MIGRATION_PATH
)
assert _SPEC is not None and _SPEC.loader is not None
_MIGRATION = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MIGRATION)


def test_backfill_preflight_rejects_cross_table_duplicate_keys():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE documents "
                "(id TEXT, storage_key TEXT, is_deleted BOOLEAN)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE document_versions "
                "(id TEXT, storage_key TEXT, document_id TEXT)"
            )
        )
        connection.execute(
            text("CREATE TABLE storage_operations (storage_key TEXT)")
        )
        connection.execute(
            text("INSERT INTO documents VALUES ('doc', :key, 1)"),
            {"key": "a" * 64},
        )
        connection.execute(
            text("INSERT INTO document_versions VALUES ('version', :key, 'doc')"),
            {"key": "a" * 64},
        )
        with pytest.raises(RuntimeError, match="duplicate references=1"):
            _MIGRATION._preflight_storage_keys(connection)
    engine.dispose()


def test_backfill_preflight_rejects_orphaned_document_versions():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE documents "
                "(id TEXT, storage_key TEXT, is_deleted BOOLEAN)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE document_versions "
                "(id TEXT, storage_key TEXT, document_id TEXT)"
            )
        )
        connection.execute(
            text("CREATE TABLE storage_operations (storage_key TEXT)")
        )
        connection.execute(
            text(
                "INSERT INTO document_versions "
                "VALUES ('version', :key, 'missing-parent')"
            ),
            {"key": "b" * 64},
        )
        with pytest.raises(RuntimeError, match="without a parent document"):
            _MIGRATION._preflight_storage_keys(connection)
    engine.dispose()


def test_downgrade_guard_refuses_objects_requests_and_unresolved_operations():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE storage_objects (storage_key TEXT)")
        )
        connection.execute(
            text("CREATE TABLE upload_requests (id TEXT)")
        )
        connection.execute(
            text("CREATE TABLE storage_operations (status TEXT)")
        )
        connection.execute(text("CREATE TABLE documents (id TEXT)"))
        connection.execute(text("CREATE TABLE document_versions (id TEXT)"))
        connection.execute(
            text("INSERT INTO storage_operations VALUES ('needs_review')")
        )
        with pytest.raises(RuntimeError, match="storage operations exist"):
            _MIGRATION._assert_safe_downgrade(connection)

        connection.execute(text("DELETE FROM storage_operations"))
        connection.execute(
            text("INSERT INTO storage_objects VALUES ('a' || 'a')")
        )
        with pytest.raises(RuntimeError, match="storage objects"):
            _MIGRATION._assert_safe_downgrade(connection)

        connection.execute(text("DELETE FROM storage_objects"))
        connection.execute(text("INSERT INTO documents VALUES ('doc')"))
        with pytest.raises(RuntimeError, match="references"):
            _MIGRATION._assert_safe_downgrade(connection)
    engine.dispose()


@pytest.mark.parametrize(
    "invalid_key",
    [
        "short",
        "g" * 64,
        "A" * 64,
        "",
    ],
)
@pytest.mark.parametrize("source", ["document", "operation"])
def test_backfill_preflight_rejects_malformed_storage_keys(
    invalid_key: str,
    source: str,
):
    engine = create_engine("sqlite://")

    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE documents "
                    "(id TEXT, storage_key TEXT, is_deleted BOOLEAN)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE document_versions "
                    "(id TEXT, storage_key TEXT, document_id TEXT)"
                )
            )
            connection.execute(
                text("CREATE TABLE storage_operations (storage_key TEXT)")
            )

            if source == "document":
                connection.execute(
                    text(
                        "INSERT INTO documents "
                        "VALUES ('doc', :key, 0)"
                    ),
                    {"key": invalid_key},
                )
            else:
                connection.execute(
                    text(
                        "INSERT INTO storage_operations (storage_key) "
                        "VALUES (:key)"
                    ),
                    {"key": invalid_key},
                )

            with pytest.raises(
                RuntimeError,
                match="invalid storage keys=1",
            ):
                _MIGRATION._preflight_storage_keys(connection)
    finally:
        engine.dispose()
