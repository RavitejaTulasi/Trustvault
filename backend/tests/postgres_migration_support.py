"""Fail-closed Alembic harness for explicitly disposable PostgreSQL targets."""

from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import os
import uuid

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool

from backend.tests.postgres_concurrency_support import (
    PostgresTestTarget,
    _verify_connected_target,
    validate_postgres_test_target,
)

MIGRATION_RUN_ENV_VAR = "TRUSTVAULT_POSTGRES_MIGRATION_INTEGRATION"
_MIGRATION_SCHEMA_PREFIX = "trustvault_migration_test_"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_TABLES = {
    "alembic_version",
    "audit_chain_state",
    "documents",
    "document_versions",
    "storage_objects",
    "storage_operations",
    "upload_requests",
    "users",
}
_EXPECTED_TRIGGERS = {
    "trg_documents_storage_key_owner",
    "trg_document_versions_storage_key_owner",
    "trg_storage_objects_prevent_delete",
}
_EXPECTED_FUNCTIONS = {
    "trustvault_guard_storage_key_reference",
    "trustvault_guard_storage_object_delete",
}


@dataclass(frozen=True)
class MigratedPostgresSchema:
    schema: str
    connection: Connection = field(repr=False)
    revision: str


def validate_postgres_migration_target(
    environ: Mapping[str, str] | None = None,
    *,
    application_url: str | None = None,
) -> PostgresTestTarget:
    """Validate migration opt-in and explicit target settings without connecting."""
    values = os.environ if environ is None else environ
    flag = values.get(MIGRATION_RUN_ENV_VAR)
    if flag not in (None, "", "0", "1"):
        raise ValueError(f"{MIGRATION_RUN_ENV_VAR} must be set to 0 or 1.")

    target = validate_postgres_test_target(
        values,
        application_url=application_url,
        required_opt_in=MIGRATION_RUN_ENV_VAR,
    )
    if target.port == 55432:
        raise ValueError(
            "PostgreSQL migration integration cannot target the protected "
            "persistent database port."
        )
    return target


def _schema_is_owned_and_current(
    connection: Connection,
    schema: str,
    expected_role: str,
) -> bool:
    result = connection.execute(
        text(
            """
            SELECT current_schema() = :schema
                   AND current_user = :role
                   AND n.nspowner = r.oid AS is_owned
            FROM pg_namespace AS n
            JOIN pg_roles AS r ON r.rolname = current_user
            WHERE n.nspname = :schema
            """
        ),
        {"schema": schema, "role": expected_role},
    ).scalar_one_or_none()
    return result is True


def _create_schema_bound_engine(
    target: PostgresTestTarget,
    schema: str,
) -> Engine:
    if not _is_generated_migration_schema(schema):
        raise ValueError("Refusing to configure an invalid migration schema.")
    return create_engine(
        target.url,
        poolclass=NullPool,
        connect_args={"options": f"-csearch_path={schema}"},
    )


def _is_generated_migration_schema(schema: str) -> bool:
    prefix = _MIGRATION_SCHEMA_PREFIX
    suffix = schema.removeprefix(prefix) if schema.startswith(prefix) else ""
    return len(suffix) == 32 and all(
        character in "0123456789abcdef" for character in suffix
    )


def _verify_schema_connection(
    connection: Connection,
    schema: str,
    target: PostgresTestTarget,
) -> None:
    if connection.dialect.default_schema_name != schema:
        raise RuntimeError(
            "The PostgreSQL dialect did not initialize with the isolated "
            "migration schema as its default schema."
        )
    _verify_connected_target(connection, target)
    if not _schema_is_owned_and_current(connection, schema, target.role):
        raise RuntimeError(
            "The migration schema is not current and owned by the verified "
            "test role."
        )


def _verify_migration_objects(connection: Connection, schema: str) -> None:
    table_names = set(
        connection.execute(
            text(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = :schema
                """
            ),
            {"schema": schema},
        ).scalars()
    )
    trigger_names = set(
        connection.execute(
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
            {"schema": schema},
        ).scalars()
    )
    function_names = set(
        connection.execute(
            text(
                """
                SELECT p.proname
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema
                """
            ),
            {"schema": schema},
        ).scalars()
    )
    if not _EXPECTED_TABLES.issubset(table_names):
        raise RuntimeError(
            "The isolated migration schema is missing expected tables."
        )
    if not _EXPECTED_TRIGGERS.issubset(trigger_names):
        raise RuntimeError(
            "The isolated migration schema is missing expected triggers."
        )
    if not _EXPECTED_FUNCTIONS.issubset(function_names):
        raise RuntimeError(
            "The isolated migration schema is missing expected functions."
        )


def _cleanup_migration_schema(
    target: PostgresTestTarget,
    schema: str,
) -> None:
    cleanup_engine = _create_schema_bound_engine(target, schema)
    try:
        with cleanup_engine.connect() as cleanup_connection:
            _verify_schema_connection(cleanup_connection, schema, target)
            cleanup_connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            cleanup_connection.commit()
    finally:
        cleanup_engine.dispose()


def _create_alembic_config(
    connection: Connection,
    schema: str,
) -> Config:
    config = Config(str(_REPOSITORY_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["version_table_schema"] = schema
    config.attributes["trustvault_postgres_migration_test"] = True
    return config


@contextmanager
def migrated_postgres_schema(
    target_revision: str = "head",
) -> Generator[
    MigratedPostgresSchema,
    None,
    None,
]:
    """Upgrade an isolated owned schema to a revision, then drop only that schema."""
    target = validate_postgres_migration_target()
    schema = f"{_MIGRATION_SCHEMA_PREFIX}{uuid.uuid4().hex}"
    schema_created = False
    setup_engine = create_engine(target.url, poolclass=NullPool)

    try:
        try:
            with setup_engine.connect() as connection:
                _verify_connected_target(connection, target)
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
                schema_created = True
                connection.commit()
        finally:
            setup_engine.dispose()

        bound_engine = _create_schema_bound_engine(target, schema)
        try:
            with bound_engine.connect() as connection:
                _verify_schema_connection(connection, schema, target)
                relation_count = connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM pg_class
                        WHERE relnamespace = to_regnamespace(:schema)
                        """
                    ),
                    {"schema": schema},
                ).scalar_one()
                if relation_count != 0:
                    raise RuntimeError(
                        "The newly created migration schema was not empty."
                    )
                connection.commit()

                config = _create_alembic_config(connection, schema)
                command.upgrade(config, target_revision)
                script = ScriptDirectory.from_config(config)
                if target_revision == "head":
                    expected_revision = script.get_current_head()
                else:
                    target_script = script.get_revision(target_revision)
                    if target_script is None:
                        raise RuntimeError("Unknown Alembic target revision.")
                    expected_revision = target_script.revision

                _verify_schema_connection(connection, schema, target)
                revision = MigrationContext.configure(
                    connection,
                    opts={"version_table_schema": schema},
                ).get_current_revision()
                if revision is None or revision != expected_revision:
                    raise RuntimeError(
                        "The migration schema did not record the expected "
                        "Alembic revision."
                    )
                if target_revision == "head":
                    _verify_migration_objects(connection, schema)

                yield MigratedPostgresSchema(
                    schema=schema,
                    connection=connection,
                    revision=revision,
                )
        finally:
            bound_engine.dispose()
    finally:
        if schema_created:
            _cleanup_migration_schema(target, schema)
