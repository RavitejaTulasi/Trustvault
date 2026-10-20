"""
Scheduled Audit-Checkpoint Creation and Runtime Health

The scheduler runs inside the application process, creates a checkpoint over the
verified committed audit prefix at a fixed interval, and exposes its last
attempt/success/failure state for health monitoring. Checkpoint writes retain
their existing compare-and-swap and HMAC protections; multiple workers may race,
and the store resolves identical writes idempotently.
"""

import asyncio
import logging
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import Settings, settings
from backend.app.database import SessionLocal
from backend.app.models.audit import AuditOutcome
from backend.app.services.audit_service import AuditService
from backend.app.services.checkpoint_service import (
    CheckpointCreationError,
    CheckpointCreationResult,
    CheckpointService,
)
from backend.app.services.checkpoint_store import (
    CheckpointStore,
    UnavailableCheckpointStore,
)
from backend.app.services.checkpoint_store_factory import create_checkpoint_store

logger = logging.getLogger(__name__)

CHECKPOINT_SCHEDULER_LOCK_KEY = 0x54565253


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    return _utc(value).isoformat() if value is not None else None


@dataclass(frozen=True)
class CheckpointSchedulerSnapshot:
    """Thread-safe copy of the scheduler's observable state."""

    running: bool
    interval_seconds: int
    max_age_seconds: int
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_failure_reason: str | None
    last_result: str | None
    last_checkpoint_sequence: int | None
    last_checkpoint_at: datetime | None
    next_run_at: datetime | None

    def to_health_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "interval_seconds": self.interval_seconds,
            "max_age_seconds": self.max_age_seconds,
            "last_attempt_at": _iso(self.last_attempt_at),
            "last_success_at": _iso(self.last_success_at),
            "last_failure_at": _iso(self.last_failure_at),
            "last_failure_reason": self.last_failure_reason,
            "last_result": self.last_result,
            "last_checkpoint_sequence": self.last_checkpoint_sequence,
            "last_checkpoint_at": _iso(self.last_checkpoint_at),
            "next_run_at": _iso(self.next_run_at),
        }


@dataclass(frozen=True)
class AuditAnchorHealth:
    """Health status for the audit anchoring component."""

    status: str
    healthy: bool
    details: dict[str, Any]


def _failure_status(reason: str) -> str:
    if reason in {
        "chain_invalid",
        "anchor_integrity_failure",
        "anchor_format_unsupported",
        "anchor_stream_mismatch",
        "anchor_chain_mismatch",
        "anchor_ahead_of_chain",
    }:
        return "invalid"
    if reason == "chain_incomplete":
        return "incomplete"
    if reason in {
        "anchor_unavailable",
        "anchor_access_denied",
        "database_unavailable",
    }:
        return "unavailable"
    return "error"


class CheckpointScheduler:
    """Create audit checkpoints on a fixed interval and expose runtime state."""

    def __init__(
        self,
        *,
        config: Settings = settings,
        session_factory: Callable[[], Session] = SessionLocal,
        store_factory: Callable[[], CheckpointStore] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._session_factory = session_factory
        self._store_factory = store_factory or (
            lambda: create_checkpoint_store(self._config)
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._state_lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self._last_attempt_at: datetime | None = None
        self._last_success_at: datetime | None = None
        self._last_failure_at: datetime | None = None
        self._last_failure_reason: str | None = None
        self._last_result: str | None = None
        self._last_checkpoint_sequence: int | None = None
        self._last_checkpoint_at: datetime | None = None
        self._next_run_at: datetime | None = None

    def _now(self) -> datetime:
        return _utc(self._clock())

    def snapshot(self) -> CheckpointSchedulerSnapshot:
        with self._state_lock:
            running = self._task is not None and not self._task.done()
            return CheckpointSchedulerSnapshot(
                running=running,
                interval_seconds=self._config.AUDIT_CHECKPOINT_INTERVAL_SECONDS,
                max_age_seconds=self._config.AUDIT_CHECKPOINT_MAX_AGE_SECONDS,
                last_attempt_at=self._last_attempt_at,
                last_success_at=self._last_success_at,
                last_failure_at=self._last_failure_at,
                last_failure_reason=self._last_failure_reason,
                last_result=self._last_result,
                last_checkpoint_sequence=self._last_checkpoint_sequence,
                last_checkpoint_at=self._last_checkpoint_at,
                next_run_at=self._next_run_at,
            )

    def reset_state(self) -> None:
        """Clear observable state; intended for tests and local tooling."""
        with self._state_lock:
            self._last_attempt_at = None
            self._last_success_at = None
            self._last_failure_at = None
            self._last_failure_reason = None
            self._last_result = None
            self._last_checkpoint_sequence = None
            self._last_checkpoint_at = None
            self._next_run_at = None

    def start(self) -> None:
        """Start the background loop when anchoring is configured."""
        if self._task is not None and not self._task.done():
            return
        if not validate_checkpoint_runtime(self._config):
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(
            self._run_loop(), name="trustvault-audit-checkpoint-scheduler"
        )

    async def stop(self) -> None:
        task = self._task
        if task is None:
            return
        if self._stop_event is not None:
            self._stop_event.set()
        try:
            await asyncio.wait_for(task, timeout=5)
        except TimeoutError:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        except Exception:
            logger.exception("Audit checkpoint scheduler stopped unexpectedly")
        finally:
            self._task = None
            self._stop_event = None
            self._set_next_run(None)

    async def run_once_async(self) -> CheckpointCreationResult | None:
        return await asyncio.to_thread(self.run_once)

    def _acquire_writer_lock(self, db: Session) -> None:
        """Serialize scheduled writers across PostgreSQL workers."""
        if db.get_bind().dialect.name == "postgresql":
            db.execute(select(func.pg_advisory_xact_lock(CHECKPOINT_SCHEDULER_LOCK_KEY)))

    def run_once(self, db: Session | None = None) -> CheckpointCreationResult | None:
        """Run one scheduled checkpoint attempt and update health state."""
        with self._run_lock:
            attempt_at = self._now()
            self._set_attempt(attempt_at)

            owns_session = db is None
            try:
                session = db or self._session_factory()
            except SQLAlchemyError:
                self._set_failure("database_unavailable", self._now())
                logger.error("Scheduled audit checkpoint failed: database unavailable")
                return None
            except Exception:  # noqa: BLE001 - keep the scheduler alive and fail closed
                self._set_failure("internal_error", self._now())
                logger.error("Scheduled audit checkpoint failed unexpectedly")
                return None

            try:
                self._acquire_writer_lock(session)
                store = self._store_factory()
                if isinstance(store, UnavailableCheckpointStore):
                    raise CheckpointCreationError("anchor_unavailable")

                result = CheckpointService.create_checkpoint(
                    session,
                    store,
                    max_records=self._config.AUDIT_VERIFY_MAX_RECORDS,
                    batch_size=self._config.AUDIT_VERIFY_BATCH_SIZE,
                    timeout_seconds=self._config.AUDIT_VERIFY_TIMEOUT_SECONDS,
                    now=self._clock,
                )

                if not result.already_present:
                    try:
                        AuditService.log_event(
                            session,
                            action="audit.checkpoint_scheduled",
                            outcome=AuditOutcome.SUCCESS,
                            actor_id=None,
                            resource_type="audit",
                            details={
                                "checkpoint_sequence": result.checkpoint.sequence_number,
                                "already_present": False,
                            },
                        )
                        session.commit()
                    except Exception:  # noqa: BLE001 - checkpoint is already durable
                        session.rollback()
                        logger.warning(
                            "Scheduled checkpoint was stored but its audit event "
                            "could not be persisted"
                        )
                else:
                    session.commit()

                completed_at = self._now()
                self._set_success(result, completed_at)
                return result
            except CheckpointCreationError as exc:
                session.rollback()
                self._set_failure(exc.reason, self._now())
                logger.error("Scheduled audit checkpoint failed: %s", exc.reason)
                return None
            except SQLAlchemyError:
                session.rollback()
                self._set_failure("database_unavailable", self._now())
                logger.error("Scheduled audit checkpoint failed: database unavailable")
                return None
            except Exception:  # noqa: BLE001 - keep the scheduler alive and fail closed
                session.rollback()
                self._set_failure("internal_error", self._now())
                logger.error("Scheduled audit checkpoint failed unexpectedly")
                return None
            finally:
                if owns_session:
                    session.close()

    async def _run_loop(self) -> None:
        stop_event = self._stop_event
        if stop_event is None:
            return
        while not stop_event.is_set():
            await self.run_once_async()
            interval = self._config.AUDIT_CHECKPOINT_INTERVAL_SECONDS
            self._set_next_run(self._now() + timedelta(seconds=interval))
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except TimeoutError:
                pass
            finally:
                self._set_next_run(None)

    def _set_attempt(self, value: datetime) -> None:
        with self._state_lock:
            self._last_attempt_at = value
            self._last_result = None

    def _set_success(self, result: CheckpointCreationResult, at: datetime) -> None:
        with self._state_lock:
            self._last_success_at = at
            self._last_result = (
                "already_present" if result.already_present else "created"
            )
            self._last_checkpoint_sequence = result.checkpoint.sequence_number
            self._last_checkpoint_at = _utc(result.checkpoint.created_at)

    def _set_failure(self, reason: str, at: datetime) -> None:
        with self._state_lock:
            self._last_failure_at = at
            self._last_failure_reason = reason
            self._last_result = "failed"

    def _set_next_run(self, value: datetime | None) -> None:
        with self._state_lock:
            self._next_run_at = value


def validate_checkpoint_runtime(config: Settings = settings) -> bool:
    """
    Validate that scheduled anchoring can start.

    Production must use an external adapter and must not start with a missing
    SDK/configuration. A provider being unreachable is not a startup failure; the
    scheduler records that as an observable runtime failure instead.
    """
    if config.AUDIT_ANCHOR_MODE == "disabled":
        if config.ENVIRONMENT == "production":
            raise RuntimeError(
                "Audit checkpoint anchoring must be enabled in production."
            )
        return False

    if config.ENVIRONMENT == "production" and config.AUDIT_ANCHOR_MODE != "s3":
        raise RuntimeError(
            "Production audit checkpoint anchoring requires the external s3 adapter."
        )

    store = create_checkpoint_store(config)
    if isinstance(store, UnavailableCheckpointStore):
        if config.ENVIRONMENT == "production":
            raise RuntimeError(
                "Audit checkpoint anchoring is configured but its adapter could "
                "not be initialized."
            )
        logger.warning(
            "Audit checkpoint scheduler is not starting because the configured "
            "adapter is unavailable"
        )
        return False
    return True


def build_audit_anchor_health(
    config: Settings = settings,
    scheduler: CheckpointScheduler | None = None,
    *,
    now: datetime | None = None,
) -> AuditAnchorHealth:
    """Build the anchor health component from scheduler evidence, not config alone."""
    scheduler = scheduler or checkpoint_scheduler
    snapshot = scheduler.snapshot()
    mode = config.AUDIT_ANCHOR_MODE
    now = _utc(now or datetime.now(UTC))

    age_seconds: int | None = None
    if snapshot.last_success_at is not None:
        age_seconds = max(0, int((now - snapshot.last_success_at).total_seconds()))
    overdue = bool(
        age_seconds is not None
        and age_seconds > config.AUDIT_CHECKPOINT_MAX_AGE_SECONDS
    )

    active_failure = snapshot.last_failure_at is not None and (
        snapshot.last_success_at is None
        or snapshot.last_failure_at > snapshot.last_success_at
    )

    if mode == "disabled":
        status = "not_configured"
        healthy = config.ENVIRONMENT != "production"
    elif active_failure:
        status = _failure_status(snapshot.last_failure_reason or "internal_error")
        healthy = False
    elif mode == "local_file":
        status = "local_development_only"
        healthy = config.ENVIRONMENT != "production" and not overdue
    elif not snapshot.running:
        status = "scheduler_stopped"
        healthy = False
    elif snapshot.last_success_at is None:
        status = "starting"
        healthy = False
    elif overdue:
        status = "overdue"
        healthy = False
    else:
        status = "ok"
        healthy = True

    details = {
        "status": status,
        "mode": mode,
        "independent": mode == "s3",
        "available": snapshot.last_checkpoint_at is not None,
        "last_checkpoint_at": _iso(snapshot.last_checkpoint_at),
        "checkpoint_sequence": snapshot.last_checkpoint_sequence,
        "checkpoint_age_seconds": age_seconds,
        "max_age_seconds": config.AUDIT_CHECKPOINT_MAX_AGE_SECONDS,
        "overdue": overdue,
        "failure_reason": (
            snapshot.last_failure_reason if active_failure else None
        ),
        "scheduler": snapshot.to_health_dict(),
    }
    return AuditAnchorHealth(status=status, healthy=healthy, details=details)


checkpoint_scheduler = CheckpointScheduler()
