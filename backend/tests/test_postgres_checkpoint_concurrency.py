"""Opt-in PostgreSQL concurrency tests for scheduled checkpoint writers."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from starlette.responses import Response

from backend.app.api.audit import create_audit_checkpoint
from backend.app.config import Settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import UserRole
from backend.app.services.audit_service import AuditService
from backend.app.services.checkpoint_runtime import CheckpointScheduler
from backend.app.services.checkpoint_store import LocalFileCheckpointStore
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    PostgresTestSchema,
    isolated_postgres_schema,
)
from backend.tests.test_auth import make_user

pytestmark = POSTGRES_INTEGRATION_MARKERS


@pytest.fixture
def pg_schema():
    with isolated_postgres_schema(seed_audit_chain=True) as schema:
        yield schema


class BlockingCheckpointStore(LocalFileCheckpointStore):
    def __init__(self, directory, hmac_key) -> None:
        super().__init__(directory, hmac_key)
        self._state_lock = threading.Lock()
        self._active_writes = 0
        self.max_active_writes = 0

    def write_checkpoint(self, checkpoint):
        with self._state_lock:
            self._active_writes += 1
            self.max_active_writes = max(
                self.max_active_writes,
                self._active_writes,
            )
            should_block = self._active_writes == 1
        try:
            if should_block:
                time.sleep(0.5)
            return super().write_checkpoint(checkpoint)
        finally:
            with self._state_lock:
                self._active_writes -= 1


class OverlapCheckpointStore(LocalFileCheckpointStore):
    def __init__(self, directory, hmac_key) -> None:
        super().__init__(directory, hmac_key)
        self._state_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._active_writes = 0
        self._write_count = 0
        self.max_active_writes = 0
        self.second_writer_entered = threading.Event()

    def write_checkpoint(self, checkpoint):
        with self._state_lock:
            self._active_writes += 1
            self.max_active_writes = max(
                self.max_active_writes,
                self._active_writes,
            )
            self._write_count += 1
            should_wait = self._write_count == 1
            if self._write_count > 1:
                self.second_writer_entered.set()
        try:
            if should_wait:
                self.second_writer_entered.wait(timeout=2)
            with self._write_lock:
                return super().write_checkpoint(checkpoint)
        finally:
            with self._state_lock:
                self._active_writes -= 1


def _config() -> Settings:
    return Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        AUDIT_ANCHOR_MODE="local_file",
        AUDIT_ANCHOR_HMAC_KEY="k" * 64,
        AUDIT_CHECKPOINT_INTERVAL_SECONDS=60,
        AUDIT_CHECKPOINT_MAX_AGE_SECONDS=120,
    )


def test_scheduler_advisory_lock_serializes_postgres_writers(
    pg_schema: PostgresTestSchema,
    tmp_path,
):
    store = BlockingCheckpointStore(
        tmp_path / "checkpoints",
        b"k" * 64,
    )
    config = _config()

    with pg_schema.session_factory() as session:
        seed = AuditService.log_event(
            session,
            action="test.postgres.checkpoint.seed",
            outcome=AuditOutcome.SUCCESS,
        )
        session.commit()
        assert seed.sequence_number == 1

    schedulers = [
        CheckpointScheduler(
            config=config,
            store_factory=lambda: store,
        )
        for _ in range(2)
    ]
    barrier = threading.Barrier(2)

    def run_scheduler(index: int):
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            return schedulers[index].run_once(session)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run_scheduler, range(2)))

    assert all(result is not None for result in results)
    assert store.max_active_writes == 1

    latest = store.read_latest()
    assert latest is not None
    assert latest.sequence_number == 2

    with pg_schema.session_factory() as session:
        scheduled_events = session.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "audit.checkpoint_scheduled"
            )
        )
        assert scheduled_events == 2
        verification = AuditService.verify_chain_integrity_bounded(
            session,
            max_records=100,
            batch_size=10,
            timeout_seconds=30,
        )
        assert verification.status == "VALID", verification.failure_reason
        assert verification.records_verified == 3


def test_admin_checkpoint_creation_shares_scheduler_writer_lock(
    pg_schema: PostgresTestSchema,
    tmp_path,
):
    store = OverlapCheckpointStore(
        tmp_path / "admin-checkpoints",
        b"k" * 64,
    )
    config = _config()

    with pg_schema.session_factory() as session:
        admin = make_user(
            session,
            email="checkpoint-admin@example.com",
            password="Passw0rd!SecureX",
            role=UserRole.ADMIN,
        )
        admin_id = admin.id
        seed = AuditService.log_event(
            session,
            action="test.postgres.checkpoint.admin_seed",
            outcome=AuditOutcome.SUCCESS,
            actor_id=admin_id,
        )
        session.commit()
        assert seed.sequence_number == 1

    scheduler = CheckpointScheduler(
        config=config,
        store_factory=lambda: store,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            client_ip="203.0.113.70",
            user_agent="pytest",
            request_id="req-admin-checkpoint-race",
        )
    )
    barrier = threading.Barrier(2)

    def run_scheduler():
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            return scheduler.run_once(session)

    def run_admin():
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            return create_audit_checkpoint(
                request,
                Response(),
                current_user=SimpleNamespace(id=admin_id),
                db=session,
                store=store,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        scheduler_future = executor.submit(run_scheduler)
        admin_future = executor.submit(run_admin)
        scheduler_result = scheduler_future.result(timeout=30)
        admin_result = admin_future.result(timeout=30)

    assert scheduler_result is not None
    assert admin_result is not None
    assert store.second_writer_entered.is_set()
    assert store.max_active_writes == 1
