"""Shared opt-in PostgreSQL schema harness for concurrency tests."""

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
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

_INTEGRATION_ENABLED = os.environ.get(RUN_ENV_VAR) == "1"

POSTGRES_INTEGRATION_MARKERS = [
    pytest.mark.postgres_integration,
    pytest.mark.skipif(
        not _INTEGRATION_ENABLED,
        reason=(
            "PostgreSQL concurrency tests are opt-in. Set "
            f"{RUN_ENV_VAR}=1 and {URL_ENV_VAR} to an approved test database."
        ),
    ),
]


def normalized_postgres_url() -> str:
    raw_url = os.environ.get(URL_ENV_VAR, "").strip()
    if not raw_url:
        pytest.fail(
            f"{RUN_ENV_VAR}=1 requires {URL_ENV_VAR}; no database URL is configured.",
            pytrace=False,
        )
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif raw_url.startswith("postgresql://"):
        raw_url = raw_url.replace("postgresql://", "postgresql+psycopg://", 1)
    try:
        parsed = make_url(raw_url)
    except ArgumentError:
        pytest.fail(f"{URL_ENV_VAR} is not a valid PostgreSQL URL.", pytrace=False)
    if parsed.get_backend_name() != "postgresql":
        pytest.fail(f"{URL_ENV_VAR} must point to PostgreSQL.", pytrace=False)
    return raw_url


@dataclass(frozen=True)
class PostgresTestSchema:
    schema: str
    engine: Engine
    session_factory: sessionmaker


@contextmanager
def isolated_postgres_schema(
    *, seed_audit_chain: bool = False
) -> Iterator[PostgresTestSchema]:
    schema = f"trustvault_concurrency_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        normalized_postgres_url(),
        isolation_level="AUTOCOMMIT",
    )
    with admin_engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        normalized_postgres_url(),
        connect_args={"options": f"-csearch_path={schema}"},
    )

    @event.listens_for(engine, "connect")
    def _set_search_path(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f'SET search_path TO "{schema}"')
        cursor.close()

    try:
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
        engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
