"""Phase 4 audit-integrity hardening tests.

Covers versioned hash coverage, serialized sequence allocation, and immutable
actor references. SQLite concurrency here is a portability check only; it is
not evidence that PostgreSQL concurrency has been verified.
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, event, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.database import Base
from backend.app.models.audit import (
    AUDIT_HASH_VERSION_CURRENT,
    AUDIT_HASH_VERSION_LEGACY,
    AuditChainState,
    AuditEvent,
    AuditOutcome,
)
from backend.app.models.base import generate_uuid
from backend.app.models.user import User
from backend.app.services.audit_service import GENESIS_HASH, AuditService
from backend.tests.test_auth import VALID_PASSWORD, make_user


@pytest.fixture
def isolated_session():
    """Provide a committed-transaction SQLite session independent of the shared fixture."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _verify(db: Session):
    return AuditService.verify_chain_integrity_bounded(
        db,
        max_records=1000,
        batch_size=100,
        timeout_seconds=30,
    )


def test_hash_version_2_binds_event_identity_ip_and_user_agent(db_session: Session):
    event = AuditService.log_event(
        db_session,
        action="test.hash.v2",
        outcome=AuditOutcome.SUCCESS,
        actor_id=None,
        ip_address="203.0.113.25",
        user_agent="TrustVault-Test/1.0",
        details={"changed_fields": ["full_name"]},
    )
    db_session.commit()

    assert event.hash_version == AUDIT_HASH_VERSION_CURRENT
    assert event.id
    assert _verify(db_session).status == "VALID"

    expected_hash = AuditService.calculate_hash(
        sequence_number=event.sequence_number,
        timestamp=event.timestamp,
        actor_id=event.actor_id,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        outcome=event.outcome,
        request_id=event.request_id,
        details_str=event.details,
        previous_hash=event.previous_hash,
        event_id=event.id,
        ip_address=event.ip_address,
        user_agent=event.user_agent,
        hash_version=AUDIT_HASH_VERSION_CURRENT,
    )
    assert expected_hash == event.record_hash


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", "tampered-event-identity"),
        ("ip_address", "198.51.100.99"),
        ("user_agent", "Tampered-Agent/9.9"),
        ("hash_version", 99),
    ],
)
def test_verification_detects_v2_identity_and_metadata_tampering(
    db_session: Session, field: str, replacement: object
):
    event = AuditService.log_event(
        db_session,
        action="test.hash.tamper",
        outcome=AuditOutcome.SUCCESS,
        actor_id=None,
        ip_address="203.0.113.25",
        user_agent="TrustVault-Test/1.0",
    )
    db_session.commit()

    db_session.execute(
        update(AuditEvent)
        .where(AuditEvent.sequence_number == event.sequence_number)
        .values({field: replacement})
    )
    db_session.commit()

    result = _verify(db_session)
    assert result.status == "INVALID"
    assert result.records_verified == 0
    if field == "hash_version":
        assert "Unsupported audit hash version" in (result.failure_reason or "")
    else:
        assert "Record tampering detected" in (result.failure_reason or "")


def test_legacy_version_1_record_still_verifies_and_new_appends_use_version_2(
    db_session: Session,
):
    timestamp = datetime(2026, 10, 20, 12, 0, 0, 123456, tzinfo=UTC)
    event_id = generate_uuid()
    details = '{"reason":"legacy"}'
    legacy_hash = AuditService.calculate_hash(
        sequence_number=1,
        timestamp=timestamp,
        actor_id=None,
        action="test.hash.legacy",
        resource_type="test_resource",
        resource_id="legacy-1",
        outcome=AuditOutcome.SUCCESS,
        request_id=None,
        details_str=details,
        previous_hash=GENESIS_HASH,
        hash_version=AUDIT_HASH_VERSION_LEGACY,
    )
    db_session.add(
        AuditEvent(
            id=event_id,
            sequence_number=1,
            timestamp=timestamp,
            actor_id=None,
            action="test.hash.legacy",
            resource_type="test_resource",
            resource_id="legacy-1",
            outcome=AuditOutcome.SUCCESS,
            request_id=None,
            ip_address=None,
            user_agent=None,
            details=details,
            hash_version=AUDIT_HASH_VERSION_LEGACY,
            previous_hash=GENESIS_HASH,
            record_hash=legacy_hash,
        )
    )
    db_session.commit()

    assert _verify(db_session).status == "VALID"

    new_event = AuditService.log_event(
        db_session,
        action="test.hash.after_legacy",
        outcome=AuditOutcome.SUCCESS,
        actor_id=None,
        ip_address="203.0.113.25",
        user_agent="TrustVault-Test/1.0",
    )
    assert new_event.sequence_number == 2
    assert new_event.previous_hash == legacy_hash
    assert new_event.hash_version == AUDIT_HASH_VERSION_CURRENT
    db_session.commit()

    result = _verify(db_session)
    assert result.status == "VALID"
    assert result.records_verified == 2


def test_referenced_actor_cannot_be_deleted(isolated_session: Session):
    actor = make_user(
        isolated_session,
        email="audit-actor-delete@example.com",
        password=VALID_PASSWORD,
    )
    isolated_session.commit()
    event = AuditService.log_event(
        isolated_session,
        action="test.actor.delete",
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor.id,
    )
    isolated_session.commit()
    actor_id = actor.id
    event_id = event.id

    isolated_session.delete(actor)
    with pytest.raises(IntegrityError):
        isolated_session.commit()
    isolated_session.rollback()

    assert isolated_session.get(User, actor_id) is not None
    stored_event = isolated_session.get(AuditEvent, event_id)
    assert stored_event is not None
    assert stored_event.actor_id == actor_id
    assert _verify(isolated_session).status == "VALID"


def test_direct_actor_delete_is_rejected_by_database_constraint(
    isolated_session: Session,
):
    actor = make_user(
        isolated_session,
        email="audit-actor-direct-delete@example.com",
        password=VALID_PASSWORD,
    )
    isolated_session.commit()
    event = AuditService.log_event(
        isolated_session,
        action="test.actor.direct_delete",
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor.id,
    )
    isolated_session.commit()
    actor_id = actor.id
    event_id = event.id

    with pytest.raises(IntegrityError):
        isolated_session.execute(
            text("DELETE FROM users WHERE id = :actor_id"),
            {"actor_id": actor_id},
        )
    isolated_session.rollback()

    stored_event = isolated_session.get(AuditEvent, event_id)
    assert stored_event is not None
    assert stored_event.actor_id == actor_id
    assert _verify(isolated_session).status == "VALID"


def test_actor_deactivation_preserves_identity_and_hash_chain(db_session: Session):
    actor = make_user(
        db_session,
        email="audit-actor-deactivate@example.com",
        password=VALID_PASSWORD,
    )
    db_session.commit()
    event = AuditService.log_event(
        db_session,
        action="test.actor.deactivate",
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor.id,
    )
    db_session.commit()

    actor.is_active = False
    db_session.commit()

    db_session.expire_all()
    stored_event = db_session.get(AuditEvent, event.id)
    assert stored_event is not None
    assert stored_event.actor_id == actor.id
    assert db_session.get(User, actor.id).is_active is False
    assert _verify(db_session).status == "VALID"


def test_sqlite_file_sessions_serialize_sequence_allocation(tmp_path):
    db_path = tmp_path / "audit-concurrency.sqlite"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 15},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.close()

    Base.metadata.create_all(engine)
    with Session(engine) as seed_session:
        seed_session.add(
            AuditChainState(
                id=1,
                last_sequence=0,
                last_hash=GENESIS_HASH,
            )
        )
        seed_session.commit()

    workers = 4
    barrier = threading.Barrier(workers)

    def append_event(index: int) -> int:
        with Session(engine) as worker_session:
            barrier.wait(timeout=10)
            event = AuditService.log_event(
                worker_session,
                action=f"test.concurrent.{index}",
                outcome=AuditOutcome.SUCCESS,
                actor_id=None,
                ip_address="203.0.113.50",
                user_agent="TrustVault-Concurrency/1.0",
            )
            worker_session.commit()
            return event.sequence_number

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            sequences = list(executor.map(append_event, range(workers)))

        assert sorted(sequences) == list(range(1, workers + 1))

        with Session(engine) as verify_session:
            result = _verify(verify_session)
            assert result.status == "VALID", result.failure_reason
            assert result.records_verified == workers

            state = verify_session.get(AuditChainState, 1)
            tail = verify_session.execute(
                select(AuditEvent).order_by(AuditEvent.sequence_number.desc()).limit(1)
            ).scalar_one()
            assert state.last_sequence == workers
            assert state.last_hash == tail.record_hash
    finally:
        engine.dispose()
