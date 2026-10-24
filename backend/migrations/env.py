from logging.config import fileConfig
import os
import re

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend.app.models import Base

config = context.config
MIGRATION_INTEGRATION_FLAG = "TRUSTVAULT_POSTGRES_MIGRATION_INTEGRATION"
_MIGRATION_SCHEMA_PATTERN = re.compile(
    r"^trustvault_migration_test_[0-9a-f]{32}$"
)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _migration_test_connection():
    flag = os.environ.get(MIGRATION_INTEGRATION_FLAG)
    if flag not in (None, "", "0", "1"):
        raise RuntimeError(
            f"{MIGRATION_INTEGRATION_FLAG} must be set to 0 or 1."
        )
    opted_in = flag == "1"
    configured_test_mode = (
        config.attributes.get("trustvault_postgres_migration_test") is True
    )
    if not opted_in and not configured_test_mode:
        return None
    if not opted_in or not configured_test_mode:
        raise RuntimeError(
            "PostgreSQL migration integration mode requires both explicit "
            "opt-in and migration-test connection configuration."
        )

    connection = config.attributes.get("connection")
    schema = config.attributes.get("version_table_schema")
    if connection is None:
        raise RuntimeError(
            "PostgreSQL migration integration mode requires an explicitly "
            "supplied SQLAlchemy connection."
        )
    if connection.dialect.name != "postgresql":
        raise RuntimeError(
            "PostgreSQL migration integration mode requires PostgreSQL."
        )
    if not isinstance(schema, str) or not _MIGRATION_SCHEMA_PATTERN.fullmatch(
        schema
    ):
        raise RuntimeError(
            "PostgreSQL migration integration mode requires its generated "
            "isolated schema."
        )
    return connection, schema


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    if _migration_test_connection() is not None:
        raise RuntimeError(
            "PostgreSQL migration integration mode cannot run offline."
        )

    from backend.app.database import db_url

    config.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    migration_test = _migration_test_connection()
    if migration_test is not None:
        connection, schema = migration_test
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            version_table_schema=schema,
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    from backend.app.database import db_url

    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = db_url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
