"""Opt-in PostgreSQL concurrency tests for serialized audit appends.

These tests are skipped unless TRUSTVAULT_POSTGRES_INTEGRATION=1 is set with an
explicitly approved PostgreSQL test-database URL. They create and destroy an
isolated schema and never run against SQLite. The default offline SQLite suite
is a portability check only, not evidence that PostgreSQL concurrency was
verified.
"""

import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from backend.app.models.audit import AuditChainState, AuditEvent, AuditOutcome
from backend.app.services.audit_service import AuditService
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    isolated_postgres_schema,
)

pytestmark = POSTGRES_INTEGRATION_MARKERS


@pytest.fixture
def postgres_schema() -> Iterator[tuple[sessionmaker, str]]:
    with isolated_postgres_schema(seed_audit_chain=True) as schema:
        yield schema.session_factory, schema.schema


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
