"""Opt-in PostgreSQL concurrency tests for serialized audit appends.

These tests are skipped unless TRUSTVAULT_POSTGRES_INTEGRATION=1 is set with an
explicitly approved PostgreSQL test-database URL. They create and destroy an
isolated schema and never run against SQLite. The default offline SQLite suite
is a portability check only, not evidence that PostgreSQL concurrency was
verified.
"""

import os
import threading
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
from backend.app.models.audit import AuditChainState, AuditEvent, AuditOutcome
from backend.app.services.audit_service import GENESIS_HASH, AuditService

RUN_ENV_VAR = "TRUSTVAULT_POSTGRES_INTEGRATION"
URL_ENV_VAR = "TRUSTVAULT_TEST_POSTGRES_URL"

_INTEGRATION_ENABLED = os.environ.get(RUN_ENV_VAR) == "1"

pytestmark = [
    pytest.mark.postgres_integration,
    pytest.mark.skipif(
        not _INTEGRATION_ENABLED,
        reason=(
            "PostgreSQL concurrency tests are opt-in. Set "
            f"{RUN_ENV_VAR}=1 and {URL_ENV_VAR} to an approved test database."
        ),
    ),
]


def _normalized_postgres_url() -> str:
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


@pytest.fixture
def postgres_schema() -> Iterator[tuple[sessionmaker, str]]:
    schema = f"trustvault_audit_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        _normalized_postgres_url(),
        isolation_level="AUTOCOMMIT",
    )
    with admin_engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        _normalized_postgres_url(),
        connect_args={"options": f"-csearch_path={schema}"},
    )

    @event.listens_for(engine, "connect")
    def _set_search_path(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f'SET search_path TO "{schema}"')
        cursor.close()

    try:
        Base.metadata.create_all(engine)
        session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        with session_factory() as seed_session:
            seed_session.add(
                AuditChainState(
                    id=1,
                    last_sequence=0,
                    last_hash=GENESIS_HASH,
                )
            )
            seed_session.commit()
        yield session_factory, schema
    finally:
        engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


def test_concurrent_postgres_appends_allocate_unique_contiguous_sequences(
    postgres_schema: tuple[sessionmaker, str],
):
    session_factory, _schema = postgres_schema
    workers = 8
    barrier = threading.Barrier(workers)

    def append_event(index: int) -> int:
        with session_factory() as worker_session:
            barrier.wait(timeout=30)
            event = AuditService.log_event(
                worker_session,
                action=f"test.postgres.concurrent.{index}",
                outcome=AuditOutcome.SUCCESS,
                actor_id=None,
                ip_address="203.0.113.50",
                user_agent="TrustVault-Postgres-Concurrency/1.0",
            )
            worker_session.commit()
            return event.sequence_number

    with ThreadPoolExecutor(max_workers=workers) as executor:
        sequences = list(executor.map(append_event, range(workers)))

    assert sorted(sequences) == list(range(1, workers + 1))

    with session_factory() as verification_session:
        result = AuditService.verify_chain_integrity_bounded(
            verification_session,
            max_records=100,
            batch_size=10,
            timeout_seconds=30,
        )
        assert result.status == "VALID", result.failure_reason
        assert result.records_verified == workers

        state = verification_session.get(AuditChainState, 1)
        tail = verification_session.execute(
            select(AuditEvent).order_by(AuditEvent.sequence_number.desc()).limit(1)
        ).scalar_one()
        assert state is not None
        assert state.last_sequence == workers
        assert state.last_hash == tail.record_hash
