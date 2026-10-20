"""Opt-in PostgreSQL transaction tests for audit-chain appends and verification."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from backend.app.models.audit import AuditChainState, AuditEvent, AuditOutcome
from backend.app.services.audit_service import AuditService
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    PostgresTestSchema,
    isolated_postgres_schema,
)

pytestmark = POSTGRES_INTEGRATION_MARKERS


@pytest.fixture
def unseeded_schema():
    with isolated_postgres_schema() as schema:
        yield schema


@pytest.fixture
def seeded_schema():
    with isolated_postgres_schema(seed_audit_chain=True) as schema:
        yield schema


def _append(session, action: str) -> AuditEvent:
    return AuditService.log_event(
        session,
        action=action,
        outcome=AuditOutcome.SUCCESS,
    )


def test_concurrent_first_appends_seed_chain_state_once(
    unseeded_schema: PostgresTestSchema,
):
    workers = 8
    barrier = threading.Barrier(workers)

    def append(index: int) -> int:
        with unseeded_schema.session_factory() as session:
            barrier.wait(timeout=30)
            event = _append(session, f"test.postgres.first.{index}")
            session.commit()
            return event.sequence_number

    with ThreadPoolExecutor(max_workers=workers) as executor:
        sequences = list(executor.map(append, range(workers)))

    assert sorted(sequences) == list(range(1, workers + 1))

    with unseeded_schema.session_factory() as session:
        verification = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=10,
            timeout_seconds=30,
        )
        assert verification.status == "VALID", verification.failure_reason
        assert verification.records_verified == workers
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert state.last_sequence == workers


def test_rolled_back_append_does_not_leave_a_sequence_gap(
    seeded_schema: PostgresTestSchema,
):
    with seeded_schema.session_factory() as session:
        rolled_back = _append(session, "test.postgres.rolled_back")
        assert rolled_back.sequence_number == 1
        session.rollback()

    with seeded_schema.session_factory() as session:
        committed = _append(session, "test.postgres.committed")
        session.commit()
        assert committed.sequence_number == 1

    with seeded_schema.session_factory() as session:
        verification = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=10,
            timeout_seconds=30,
        )
        assert verification.status == "VALID", verification.failure_reason
        assert verification.records_verified == 1
        assert session.scalar(select(func.count(AuditEvent.id))) == 1


def test_concurrent_rollback_and_commit_reuse_the_sequence(
    seeded_schema: PostgresTestSchema,
):
    barrier = threading.Barrier(2)

    def append(commit: bool) -> int | None:
        with seeded_schema.session_factory() as session:
            barrier.wait(timeout=30)
            event = _append(
                session,
                "test.postgres.commit" if commit else "test.postgres.rollback",
            )
            sequence_number = event.sequence_number
            if commit:
                session.commit()
                return sequence_number
            session.rollback()
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(append, [True, False]))

    assert results.count(None) == 1
    assert results[0] == 1 or results[1] == 1

    with seeded_schema.session_factory() as session:
        events = session.scalars(
            select(AuditEvent).order_by(AuditEvent.sequence_number)
        ).all()
        assert [event.sequence_number for event in events] == [1]
        state = session.get(AuditChainState, 1)
        assert state is not None
        assert state.last_sequence == 1
        verification = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=10,
            timeout_seconds=30,
        )
        assert verification.status == "VALID", verification.failure_reason


def test_verification_high_water_mark_excludes_concurrent_append(
    seeded_schema: PostgresTestSchema,
):
    with seeded_schema.session_factory() as session:
        for index in range(5):
            _append(session, f"test.postgres.high_water.seed.{index}")
        session.commit()

    appended = False
    clock_calls = 0

    def clock() -> float:
        nonlocal appended, clock_calls
        clock_calls += 1
        if clock_calls == 2 and not appended:
            with seeded_schema.session_factory() as writer:
                _append(writer, "test.postgres.high_water.concurrent")
                writer.commit()
            appended = True
        return time.monotonic()

    with seeded_schema.session_factory() as session:
        result = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=2,
            timeout_seconds=30,
            clock=clock,
        )
        assert result.status == "VALID", result.failure_reason
        assert result.records_verified == 5
        assert session.scalar(select(func.max(AuditEvent.sequence_number))) == 6

    with seeded_schema.session_factory() as session:
        result = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=2,
            timeout_seconds=30,
        )
        assert result.status == "VALID", result.failure_reason
        assert result.records_verified == 6
