"""Shared opt-in PostgreSQL schema harness for concurrency tests."""

import os
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
from backend.app.config import _APPLICATION_DATABASE_URL_AT_LOAD
from backend.app.models import audit as audit_models
from backend.app.models import document as document_models
from backend.app.models import grant as grant_models
from backend.app.models import rate_limit as rate_limit_models
from backend.app.models import session as session_models
from backend.app.models import storage_quota as storage_quota_models
from backend.app.models import user as user_models
from backend.app.models.audit import AuditChainState
from backend.app.services.audit_service import GENESIS_HASH

_MODEL_MODULES = (
    audit_models,
    document_models,
    grant_models,
    rate_limit_models,
    session_models,
    storage_quota_models,
    user_models,
)

RUN_ENV_VAR = "TRUSTVAULT_POSTGRES_INTEGRATION"
URL_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_URL"
DATABASE_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_DATABASE"
ROLE_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_ROLE"
HOST_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_HOST"
PORT_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_PORT"
SERVER_ID_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_SERVER_ID"
SERVER_PORT_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_SERVER_PORT"
DISPOSABLE_CONFIRM_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_DISPOSABLE_CONFIRM"
DISPOSABLE_CONFIRMATION = "I_CONFIRM_SCHEMA_CASCADE"
_CONNECTED_TARGET_QUERY = """
    SELECT current_database() AS database_name,
           current_user AS role_name,
           current_setting('cluster_name') AS server_id,
           inet_server_port() AS server_port,
           (SELECT rolsuper FROM pg_roles
            WHERE rolname = current_user) AS is_superuser,
           (SELECT rolcreatedb FROM pg_roles
            WHERE rolname = current_user) AS can_create_database,
           (SELECT rolcreaterole FROM pg_roles
            WHERE rolname = current_user) AS can_create_roles,
           (SELECT datistemplate FROM pg_database
            WHERE datname = current_database()) AS is_template,
           (SELECT datdba = (SELECT oid FROM pg_roles
                             WHERE rolname = current_user)
            FROM pg_database WHERE datname = current_database())
               AS owns_database,
           EXISTS (
               SELECT 1 FROM pg_auth_members
               WHERE member = (SELECT oid FROM pg_roles
                               WHERE rolname = current_user)
           ) AS has_role_memberships,
           has_database_privilege(
               current_user, current_database(), 'CREATE'
           ) AS can_create_schema
"""
_CONNECTED_TARGET_FIELDS = (
    "database_name",
    "role_name",
    "server_id",
    "server_port",
    "is_superuser",
    "can_create_database",
    "can_create_roles",
    "is_template",
    "owns_database",
    "has_role_memberships",
    "can_create_schema",
)

_INTEGRATION_ENABLED = os.environ.get(RUN_ENV_VAR) == "1"

POSTGRES_INTEGRATION_MARKERS = [
    pytest.mark.postgres_integration,
    pytest.mark.skipif(
        not _INTEGRATION_ENABLED,
        reason=(
            "PostgreSQL concurrency tests are opt-in. Set "
            f"{RUN_ENV_VAR}=1 and configure all explicit disposable-target "
            "settings before running."
        ),
    ),
]


@dataclass(frozen=True)
class PostgresTestTarget:
    url: URL = field(repr=False)
    database: str
    role: str
    host: str
    port: int
    server_id: str
    server_port: int


def _parse_postgres_url(raw_url: str) -> URL:
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif raw_url.startswith("postgresql://"):
        raw_url = raw_url.replace("postgresql://", "postgresql+psycopg://", 1)
    try:
        parsed = make_url(raw_url)
    except ArgumentError as exc:
        raise ValueError(f"{URL_ENV_VAR} is not a valid PostgreSQL URL.") from exc
    if parsed.get_backend_name() != "postgresql":
        raise ValueError(f"{URL_ENV_VAR} must point to PostgreSQL.")
    return parsed


def _required_value(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} must be explicitly configured.")
    return value


def validate_postgres_test_target(
    environ: Mapping[str, str] | None = None,
    *,
    application_url: str | None = None,
    required_opt_in: str = RUN_ENV_VAR,
) -> PostgresTestTarget:
    """Validate explicit disposable-target configuration without connecting."""
    values = os.environ if environ is None else environ
    if values.get(required_opt_in) != "1":
        raise ValueError(f"{required_opt_in}=1 is required.")

    raw_url = _required_value(values, URL_ENV_VAR)
    parsed = _parse_postgres_url(raw_url)
    database = _required_value(values, DATABASE_ENV_VAR)
    role = _required_value(values, ROLE_ENV_VAR)
    host = _required_value(values, HOST_ENV_VAR).lower()
    server_id = _required_value(values, SERVER_ID_ENV_VAR)
    if values.get(DISPOSABLE_CONFIRM_ENV_VAR) != DISPOSABLE_CONFIRMATION:
        raise ValueError(
            f"{DISPOSABLE_CONFIRM_ENV_VAR} must explicitly confirm the "
            "disposable database and schema cleanup scope."
        )
    try:
        port = int(_required_value(values, PORT_ENV_VAR))
        server_port = int(_required_value(values, SERVER_PORT_ENV_VAR))
    except ValueError as exc:
        raise ValueError("The configured PostgreSQL ports must be integers.") from exc
    if not 1 <= port <= 65535 or not 1 <= server_port <= 65535:
        raise ValueError("The configured PostgreSQL ports are out of range.")

    if (
        parsed.host is None
        or parsed.host.lower() != host
        or parsed.port != port
        or parsed.database != database
        or parsed.username != role
    ):
        raise ValueError(
            "The PostgreSQL URL does not match the explicitly expected "
            "test host, port, database, and role."
        )

    configured_application_url = (
        _APPLICATION_DATABASE_URL_AT_LOAD
        if application_url is None
        else application_url
    )
    if not configured_application_url or not configured_application_url.strip():
        raise ValueError(
            "The application's original database URL is not configured."
        )
    try:
        application_target = make_url(configured_application_url)
    except ArgumentError as exc:
        raise ValueError(
            "The application's configured database URL cannot be validated."
        ) from exc
    if application_target.get_backend_name() not in {"postgresql", "sqlite"}:
        raise ValueError(
            "The application's configured database URL uses an unsupported backend."
        )
    if (
        application_target.get_backend_name() == "postgresql"
        and not application_target.database
    ):
        raise ValueError(
            "The application's PostgreSQL URL does not identify a database."
        )
    if (
        parsed.get_backend_name() == application_target.get_backend_name()
        and parsed.database == application_target.database
    ):
        raise ValueError(
            "The PostgreSQL integration target matches the application's "
            "configured database name."
        )

    return PostgresTestTarget(
        url=parsed,
        database=database,
        role=role,
        host=host,
        port=port,
        server_id=server_id,
        server_port=server_port,
    )


def _verify_connected_target(connection, target: PostgresTestTarget) -> None:
    identity = connection.execute(text(_CONNECTED_TARGET_QUERY)).mappings().one()
    _verify_identity_values(identity, target)


def _verify_identity_values(identity, target: PostgresTestTarget) -> None:
    if (
        identity["database_name"] != target.database
        or identity["role_name"] != target.role
        or identity["server_id"] != target.server_id
        or identity["server_port"] != target.server_port
        or identity["is_superuser"] is not False
        or identity["can_create_database"] is not False
        or identity["can_create_roles"] is not False
        or identity["is_template"] is not False
        or identity["owns_database"] is not False
        or identity["has_role_memberships"] is not False
        or identity["can_create_schema"] is not True
    ):
        raise RuntimeError(
            "Connected PostgreSQL server identity or isolation checks failed; "
            "no test schema was created."
        )


def _drop_owned_schema(connection, schema: str) -> None:
    is_owned = connection.execute(
        text(
            "SELECT nspowner = (SELECT oid FROM pg_roles "
            "WHERE rolname = current_user) "
            "FROM pg_namespace WHERE nspname = :schema"
        ),
        {"schema": schema},
    ).scalar_one_or_none()
    if is_owned is None:
        return
    if is_owned is not True:
        raise RuntimeError(
            "Refusing to clean up a schema not owned by this test role."
        )
    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


@dataclass(frozen=True)
class PostgresTestSchema:
    schema: str
    engine: Engine
    session_factory: sessionmaker


@contextmanager
def isolated_postgres_schema(
    *, seed_audit_chain: bool = False
) -> Iterator[PostgresTestSchema]:
    target = validate_postgres_test_target()
    schema = f"trustvault_concurrency_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        target.url,
        isolation_level="AUTOCOMMIT",
    )
    engine: Engine | None = None
    schema_created = False
    try:
        with admin_engine.connect() as connection:
            _verify_connected_target(connection, target)
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            schema_created = True

        engine = create_engine(
            target.url,
            connect_args={"options": f"-csearch_path={schema}"},
        )

        @event.listens_for(engine, "connect")
        def _set_search_path(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute(_CONNECTED_TARGET_QUERY)
                row = cursor.fetchone()
                if row is None:
                    raise RuntimeError(
                        "PostgreSQL connection returned no identity information."
                    )
                _verify_identity_values(
                    dict(zip(_CONNECTED_TARGET_FIELDS, row)),
                    target,
                )
                cursor.execute(f'SET search_path TO "{schema}"')
            finally:
                cursor.close()

        Base.metadata.create_all(engine)
        session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
        )
        if seed_audit_chain:
            with session_factory() as seed_session:
                seed_session.add(
                    AuditChainState(
                        id=1,
                        last_sequence=0,
                        last_hash=GENESIS_HASH,
                    )
                )
                seed_session.commit()
        yield PostgresTestSchema(
            schema=schema,
            engine=engine,
            session_factory=session_factory,
        )
    finally:
        if engine is not None:
            engine.dispose()
        try:
            if schema_created:
                with admin_engine.connect() as connection:
                    _verify_connected_target(connection, target)
                    _drop_owned_schema(connection, schema)
        finally:
            admin_engine.dispose()
