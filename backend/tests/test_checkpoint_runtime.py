"""Tests for scheduled audit checkpoint creation and runtime observability."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

import backend.app.main as main_module
import backend.app.services.checkpoint_runtime as runtime_module
import backend.app.services.checkpoint_store as checkpoint_store_module
import backend.app.services.checkpoint_store_factory as checkpoint_store_factory
from backend.app.config import Settings
from backend.app.database import Base
from backend.app.models.audit import AuditEvent
from backend.app.services.audit_service import AuditService
from backend.app.services.checkpoint_runtime import (
    CheckpointScheduler,
    CheckpointSchedulerSnapshot,
    build_audit_anchor_health,
    validate_checkpoint_runtime,
)
from backend.app.services.checkpoint_store import (
    CheckpointStoreUnavailableError,
    LocalFileCheckpointStore,
    UnavailableCheckpointStore,
)
from backend.tests.test_audit_checkpoints import _add_event

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
TEST_CA_FILE = Path(__file__).resolve()
PRODUCTION_DATABASE_URL = (
    "postgresql+psycopg://trustvault_app:unique-test-password@db:5432/trustvault"
)


_TLS_QUERY = (
    "?sslmode=verify-full&sslrootcert="
    f"{quote(str(TEST_CA_FILE), safe='/')}"
)
PRODUCTION_DATABASE_URL = f"{PRODUCTION_DATABASE_URL}{_TLS_QUERY}"


def make_config(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "AUDIT_ANCHOR_MODE": "local_file",
        "AUDIT_ANCHOR_HMAC_KEY": "k" * 64,
        "AUDIT_ANCHOR_DATABASE_URL": (
            "postgresql+psycopg://anchor:test-only-anchor-password"
            f"@audit-db:5432/trustvault_anchor{_TLS_QUERY}"
        ),
        "AUDIT_CHECKPOINT_INTERVAL_SECONDS": 60,
        "AUDIT_CHECKPOINT_MAX_AGE_SECONDS": 120,
    }
    values.update(overrides)
    return Settings(**values)


def make_production_config(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "ENVIRONMENT": "production",
        "SESSION_COOKIE_SECURE": True,
        "DATABASE_URL": PRODUCTION_DATABASE_URL,
        "AUDIT_ANCHOR_MODE": "postgresql",
        "AUDIT_ANCHOR_HMAC_KEY": "k" * 64,
        "AUDIT_ANCHOR_DATABASE_URL": (
            "postgresql+psycopg://anchor:test-only-anchor-password"
            f"@audit-db:5432/trustvault_anchor{_TLS_QUERY}"
        ),
        "AUDIT_CHECKPOINT_INTERVAL_SECONDS": 60,
        "AUDIT_CHECKPOINT_MAX_AGE_SECONDS": 120,
    }
    values.update(overrides)
    return Settings(**values)


class FakeScheduler:
    def __init__(self, snapshot: CheckpointSchedulerSnapshot) -> None:
        self._snapshot = snapshot

    def snapshot(self) -> CheckpointSchedulerSnapshot:
        return self._snapshot


def snapshot(
    *,
    running: bool = True,
    last_attempt_at: datetime | None = NOW,
    last_success_at: datetime | None = NOW,
    last_failure_at: datetime | None = None,
    last_failure_reason: str | None = None,
    last_result: str | None = None,
    last_checkpoint_sequence: int | None = 3,
    last_checkpoint_at: datetime | None = NOW,
) -> CheckpointSchedulerSnapshot:
    return CheckpointSchedulerSnapshot(
        running=running,
        interval_seconds=60,
        max_age_seconds=120,
        last_attempt_at=last_attempt_at,
        last_success_at=last_success_at,
        last_failure_at=last_failure_at,
        last_failure_reason=last_failure_reason,
        last_result=last_result,
        last_checkpoint_sequence=last_checkpoint_sequence,
        last_checkpoint_at=last_checkpoint_at,
        next_run_at=NOW + timedelta(seconds=60),
    )


def test_scheduler_creates_checkpoint_and_updates_observable_state(
    db_session: Session, tmp_path
):
    checkpoint_store = LocalFileCheckpointStore(
        tmp_path / "audit_checkpoints", b"k" * 64
    )
    _add_event(db_session, action="test.scheduler.event")
    scheduler = CheckpointScheduler(
        config=make_config(),
        store_factory=lambda: checkpoint_store,
        clock=lambda: NOW,
    )

    result = scheduler.run_once(db_session)

    assert result is not None
    assert result.already_present is False
    assert checkpoint_store.read_latest().sequence_number == 1
    state = scheduler.snapshot()
    assert state.last_attempt_at == NOW
    assert state.last_success_at == NOW
    assert state.last_failure_at is None
    assert state.last_failure_reason is None
    assert state.last_result == "created"
    assert state.last_checkpoint_sequence == 1
    assert state.last_checkpoint_at == NOW

    db_session.expire_all()
    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.checkpoint_scheduled")
        .one()
    )
    assert json.loads(event.details) == {
        "already_present": False,
        "checkpoint_sequence": 1,
    }


def test_scheduler_keeps_checkpoint_when_audit_event_cannot_be_persisted(
    db_session: Session, tmp_path, monkeypatch: pytest.MonkeyPatch
):
    checkpoint_store = LocalFileCheckpointStore(
        tmp_path / "audit_checkpoints", b"k" * 64
    )
    _add_event(db_session, action="test.scheduler.audit-failure")

    def failing_log_event(*args, **kwargs):
        raise SQLAlchemyError("audit write failed")

    monkeypatch.setattr(
        AuditService, "log_event", staticmethod(failing_log_event)
    )
    scheduler = CheckpointScheduler(
        config=make_config(),
        store_factory=lambda: checkpoint_store,
        clock=lambda: NOW,
    )

    result = scheduler.run_once(db_session)

    assert result is not None
    assert checkpoint_store.read_latest().sequence_number == 1
    assert scheduler.snapshot().last_result == "created"
    assert scheduler.snapshot().last_success_at == NOW


def test_scheduler_failure_is_fail_closed_and_observable(
    db_session: Session,
):
    _add_event(db_session, action="test.scheduler.failure")
    scheduler = CheckpointScheduler(
        config=make_config(),
        store_factory=UnavailableCheckpointStore,
        clock=lambda: NOW,
    )

    result = scheduler.run_once(db_session)

    assert result is None
    state = scheduler.snapshot()
    assert state.last_result == "failed"
    assert state.last_failure_at == NOW
    assert state.last_failure_reason == "anchor_unavailable"
    assert state.last_success_at is None

    db_session.expire_all()
    assert (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.checkpoint_scheduled")
        .count()
        == 0
    )

    health = build_audit_anchor_health(
        make_config(), FakeScheduler(state), now=NOW
    )
    assert health.status == "unavailable"
    assert health.healthy is False
    assert health.details["failure_reason"] == "anchor_unavailable"


def test_scheduler_records_database_failure_when_session_cannot_open():
    def failing_session_factory():
        raise SQLAlchemyError("database unavailable")

    scheduler = CheckpointScheduler(
        config=make_config(),
        session_factory=failing_session_factory,
        store_factory=UnavailableCheckpointStore,
        clock=lambda: NOW,
    )

    result = scheduler.run_once()

    assert result is None
    state = scheduler.snapshot()
    assert state.last_result == "failed"
    assert state.last_failure_reason == "database_unavailable"
    assert state.last_failure_at == NOW


def test_health_reports_overdue_checkpoint():
    stale = NOW - timedelta(seconds=300)
    state = snapshot(
        last_attempt_at=stale,
        last_success_at=stale,
        last_checkpoint_at=stale,
        last_result="already_present",
    )

    health = build_audit_anchor_health(
        make_config(AUDIT_ANCHOR_MODE="local_file"),
        FakeScheduler(state),
        now=NOW,
    )

    assert health.status == "overdue"
    assert health.healthy is False
    assert health.details["overdue"] is True
    assert health.details["checkpoint_age_seconds"] == 300


def test_health_reports_store_unavailability_from_scheduler_evidence():
    state = snapshot(
        last_success_at=None,
        last_checkpoint_at=None,
        last_checkpoint_sequence=None,
        last_failure_at=NOW,
        last_failure_reason="anchor_unavailable",
        last_result="failed",
    )

    health = build_audit_anchor_health(
        make_config(AUDIT_ANCHOR_MODE="local_file"),
        FakeScheduler(state),
        now=NOW,
    )

    assert health.status == "unavailable"
    assert health.healthy is False
    assert health.details["available"] is False
    assert health.details["overdue"] is False


def test_local_file_health_never_claims_independence():
    local = build_audit_anchor_health(
        make_config(AUDIT_ANCHOR_MODE="local_file"),
        FakeScheduler(snapshot()),
        now=NOW,
    )

    assert local.details["independent"] is False
    assert local.details["external_adapter"] is False
    assert local.details["independence_verified"] is False


def test_postgresql_health_reports_external_adapter_but_not_operator_verification():
    health = build_audit_anchor_health(
        make_config(AUDIT_ANCHOR_MODE="postgresql"),
        FakeScheduler(snapshot()),
        now=NOW,
    )

    assert health.status == "ok"
    assert health.healthy is True
    assert health.details["independent"] is True
    assert health.details["external_adapter"] is True
    assert health.details["independence_verified"] is False


def test_production_local_file_anchor_health_is_degraded():
    config = make_production_config().model_copy(
        update={"AUDIT_ANCHOR_MODE": "local_file"}
    )
    health = build_audit_anchor_health(
        config,
        FakeScheduler(snapshot()),
        now=NOW,
    )

    assert health.status == "local_only"
    assert health.healthy is False
    assert health.details["available"] is True
    assert health.details["independent"] is False


def test_disabled_anchor_is_healthy_outside_production():
    health = build_audit_anchor_health(
        make_config(AUDIT_ANCHOR_MODE="disabled"),
        FakeScheduler(snapshot(running=False, last_success_at=None, last_checkpoint_at=None)),
        now=NOW,
    )

    assert health.status == "not_configured"
    assert health.healthy is True


def test_runtime_validation_rejects_disabled_production_anchor():
    config = make_production_config().model_copy(
        update={"AUDIT_ANCHOR_MODE": "disabled"}
    )

    with pytest.raises(RuntimeError, match="independently administered PostgreSQL"):
        validate_checkpoint_runtime(config)


def test_runtime_validation_accepts_local_file_production_adapter(tmp_path):
    config = make_production_config().model_copy(
        update={
            "AUDIT_ANCHOR_MODE": "local_file",
            "AUDIT_ANCHOR_DIR": str(tmp_path / "audit_checkpoints"),
        }
    )

    with pytest.raises(RuntimeError, match="independently administered"):
        validate_checkpoint_runtime(config)


def test_runtime_validation_fails_when_production_adapter_cannot_initialize(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "backend.app.services.checkpoint_runtime.create_checkpoint_store",
        lambda config: UnavailableCheckpointStore(),
    )

    with pytest.raises(RuntimeError, match="could not be initialized"):
        validate_checkpoint_runtime(make_production_config())


def test_checkpoint_store_factory_closes_postgres_store_after_probe_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    class FailingStore:
        closed = False

        def __init__(self, *_args, **_kwargs):
            pass

        def read_latest(self):
            raise CheckpointStoreUnavailableError("test failure")

        def close(self):
            type(self).closed = True

    monkeypatch.setattr(
        checkpoint_store_factory, "PostgresCheckpointStore", FailingStore
    )

    configured = checkpoint_store_factory.create_checkpoint_store(
        make_config(AUDIT_ANCHOR_MODE="postgresql")
    )

    assert isinstance(configured, UnavailableCheckpointStore)
    assert FailingStore.closed is True


def test_postgres_checkpoint_store_bounds_connections_and_statements(
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict[str, object] = {}

    class FakeEngine:
        def dispose(self):
            pass

    def fake_create_engine(url, **options):
        captured["url"] = url
        captured.update(options)
        return FakeEngine()

    monkeypatch.setattr(
        checkpoint_store_module, "create_engine", fake_create_engine
    )

    store = checkpoint_store_module.PostgresCheckpointStore(
        "postgresql+psycopg://anchor:synthetic-password@anchor-db:5432/anchor",
        b"k" * 64,
    )

    assert captured["pool_pre_ping"] is True
    assert captured["pool_size"] == 1
    assert captured["max_overflow"] == 0
    assert captured["pool_timeout"] == 5
    assert captured["connect_args"] == {
        "connect_timeout": 5,
        "options": "-c statement_timeout=10000",
    }
    store.close()


@pytest.mark.asyncio
async def test_scheduler_loop_creates_checkpoint_and_stops(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'scheduler-loop.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    test_session_factory = sessionmaker(bind=engine)
    with test_session_factory() as session:
        _add_event(session, action="test.scheduler.loop")

    checkpoint_store = LocalFileCheckpointStore(
        tmp_path / "audit_checkpoints", b"k" * 64
    )
    monkeypatch.setattr(
        runtime_module,
        "validate_checkpoint_runtime",
        lambda config: True,
    )
    scheduler = CheckpointScheduler(
        config=make_config(),
        session_factory=test_session_factory,
        store_factory=lambda: checkpoint_store,
    )

    scheduler.start()
    try:
        assert scheduler.snapshot().running is True
        for _ in range(200):
            if scheduler.snapshot().last_success_at is not None:
                break
            await asyncio.sleep(0.01)

        state = scheduler.snapshot()
        assert state.last_success_at is not None
        assert state.last_failure_reason is None
        assert checkpoint_store.read_latest().sequence_number == 1
    finally:
        await scheduler.stop()
        engine.dispose()

    assert scheduler.snapshot().running is False


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_checkpoint_scheduler(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    monkeypatch.setattr(main_module.settings, "STORAGE_DIR", str(tmp_path))
    started: list[bool] = []
    stopped: list[bool] = []

    monkeypatch.setattr(
        main_module.checkpoint_scheduler, "start", lambda: started.append(True)
    )

    async def fake_stop() -> None:
        stopped.append(True)

    monkeypatch.setattr(main_module.checkpoint_scheduler, "stop", fake_stop)

    async with main_module.lifespan(main_module.app):
        assert started == [True]

    assert stopped == [True]


@pytest.mark.asyncio
async def test_scheduler_does_not_start_when_anchor_is_disabled():
    scheduler = CheckpointScheduler(
        config=make_config(AUDIT_ANCHOR_MODE="disabled"),
    )

    scheduler.start()

    assert scheduler.snapshot().running is False
    await scheduler.stop()
