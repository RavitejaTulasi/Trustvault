"""Durable retry and reconciliation for remote storage operations."""

import asyncio
import logging
from collections.abc import Callable
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from typing import Iterator

from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database import SessionLocal
from backend.app.models.base import generate_uuid
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.storage_object import StorageObject, UploadRequest
from backend.app.services.storage_objects import transition_storage_object
from backend.app.services.storage_service import (
    StorageService,
    _get_supabase_bucket,
    is_storage_object_not_found,
    is_valid_storage_key,
)

logger = logging.getLogger(__name__)

UPLOAD_IN_PROGRESS = "uploading"
UPLOAD_UNCERTAIN = "upload_uncertain"
UPLOAD_COMMITTED = "upload_committed"
DELETE_PENDING = "delete_pending"
RETRY_WAIT = "retry_wait"
COMPLETED = "completed"
CANCELLED = "cancelled"
NEEDS_REVIEW = "needs_review"
EXHAUSTED = "exhausted"

MAX_STORAGE_OPERATION_ATTEMPTS = 8
STORAGE_OPERATION_BATCH_SIZE = 25
STORAGE_OPERATION_LEASE = timedelta(minutes=15)
UPLOAD_LEASE_HEARTBEAT_SECONDS = 30
STORAGE_RECOVERY_INTERVAL_SECONDS = 30
STORAGE_RETRY_BASE_SECONDS = 15
STORAGE_RETRY_MAX_SECONDS = 3600

_TERMINAL_STATUSES = {COMPLETED, CANCELLED, NEEDS_REVIEW, EXHAUSTED}


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _retry_delay(attempt: int) -> timedelta:
    seconds = min(
        STORAGE_RETRY_BASE_SECONDS * (2 ** max(0, attempt - 1)),
        STORAGE_RETRY_MAX_SECONDS,
    )
    return timedelta(seconds=seconds)


class StorageRecoveryService:
    """Persist upload/delete intent and recover operations at least once."""

    @staticmethod
    def create_upload_intent(
        db: Session,
        *,
        storage_key: str,
        content_sha256: str,
        actor_id: str,
        upload_request: UploadRequest | None = None,
    ) -> StorageOperation:
        if not is_valid_storage_key(storage_key):
            raise ValueError("Invalid storage key for upload operation")
        if len(content_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in content_sha256
        ):
            raise ValueError("Invalid content digest for upload operation")

        operation = StorageOperation(
            id=generate_uuid(),
            operation_type="upload",
            storage_key=storage_key,
            status=UPLOAD_IN_PROGRESS,
            content_sha256=content_sha256,
            retry_count=0,
            next_attempt_at=_now(),
            lease_until=_now() + STORAGE_OPERATION_LEASE,
            lease_token=generate_uuid(),
            last_error=None,
            created_by_id=actor_id,
        )
        db.add(
            StorageObject(
                storage_key=storage_key,
                backend="supabase",
                state="uploading",
            )
        )
        if upload_request is not None:
            upload_request.operation_id = operation.id
        db.add(operation)
        db.flush()
        if upload_request is not None:
            db.add(upload_request)
        db.commit()
        return operation

    @staticmethod
    def _renew_upload_lease(
        session_factory: Callable[[], Session],
        operation_id: str,
        lease_token: str,
    ) -> bool:
        now = _now()
        with session_factory() as lease_db:
            result = lease_db.execute(
                update(StorageOperation)
                .where(
                    StorageOperation.id == operation_id,
                    StorageOperation.operation_type == "upload",
                    StorageOperation.status == UPLOAD_IN_PROGRESS,
                    StorageOperation.lease_token == lease_token,
                    StorageOperation.claim_token.is_(None),
                )
                .execution_options(synchronize_session=False)
                .values(
                    lease_until=now + STORAGE_OPERATION_LEASE,
                    updated_at=now,
                )
            )
            lease_db.commit()
            return result.rowcount == 1

    @classmethod
    @contextmanager
    def maintain_upload_lease(
        cls,
        db: Session,
        operation_id: str,
    ) -> Iterator[str]:
        """Renew an upload lease until its fenced database commit or failure."""
        operation = db.get(StorageOperation, operation_id)
        if (
            operation is None
            or operation.operation_type != "upload"
            or operation.status != UPLOAD_IN_PROGRESS
            or operation.lease_token is None
            or operation.lease_until is None
            or _as_utc(operation.lease_until) <= _now()
        ):
            raise RuntimeError("Upload lease is no longer owned by this request")

        lease_token = operation.lease_token
        bind = db.get_bind()
        session_factory = sessionmaker(bind=bind, expire_on_commit=False)

        stop_event = Event()

        def renew_until_stopped() -> None:
            while not stop_event.wait(UPLOAD_LEASE_HEARTBEAT_SECONDS):
                try:
                    renewed = cls._renew_upload_lease(
                        session_factory,
                        operation_id,
                        lease_token,
                    )
                except SQLAlchemyError as exc:
                    logger.warning(
                        "Upload lease heartbeat failed: operation_id=%s "
                        "error_type=%s",
                        operation_id,
                        type(exc).__name__,
                    )
                    continue
                if not renewed:
                    logger.warning(
                        "Upload lease ownership was lost: operation_id=%s",
                        operation_id,
                    )
                    return

        heartbeat = Thread(
            target=renew_until_stopped,
            name=f"storage-upload-lease-{operation_id}",
            daemon=True,
        )
        heartbeat.start()
        try:
            yield lease_token
        finally:
            stop_event.set()
            heartbeat.join(timeout=UPLOAD_LEASE_HEARTBEAT_SECONDS + 1)

    @staticmethod
    def mark_upload_committed(
        db: Session,
        operation_id: str,
        lease_token: str,
    ) -> None:
        """Fence the document transaction against recovery claiming its lease."""
        result = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.operation_type == "upload",
                StorageOperation.status == UPLOAD_IN_PROGRESS,
                StorageOperation.lease_token == lease_token,
                StorageOperation.claim_token.is_(None),
                StorageOperation.lease_until > _now(),
            )
            .execution_options(synchronize_session="fetch")
            .values(
                status=UPLOAD_COMMITTED,
                lease_until=None,
                lease_token=None,
                last_error=None,
            )
        )
        if result.rowcount != 1:
            raise RuntimeError("Upload lease was lost before database commit")

    @staticmethod
    def create_delete_intent(
        db: Session,
        *,
        storage_key: str,
        actor_id: str,
    ) -> StorageOperation:
        if not is_valid_storage_key(storage_key):
            raise ValueError("Invalid storage key for delete operation")

        existing = db.scalar(
            select(StorageOperation).where(
                StorageOperation.operation_type == "delete",
                StorageOperation.storage_key == storage_key,
            )
        )
        if existing is not None:
            return existing

        operation = StorageOperation(
            id=generate_uuid(),
            operation_type="delete",
            storage_key=storage_key,
            status=DELETE_PENDING,
            content_sha256=None,
            retry_count=0,
            next_attempt_at=_now(),
            lease_until=None,
            last_error=None,
            created_by_id=actor_id,
        )
        db.add(operation)
        return operation

    @staticmethod
    def mark_upload_uncertain(
        db: Session,
        operation_id: str,
        error_type: str,
    ) -> None:
        now = _now()
        retry_count = db.scalar(
            select(StorageOperation.retry_count).where(
                StorageOperation.id == operation_id,
                StorageOperation.status == UPLOAD_IN_PROGRESS,
                StorageOperation.claim_token.is_(None),
            )
        )
        if retry_count is None:
            return
        retry_count = max(1, retry_count)
        result = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.operation_type == "upload",
                StorageOperation.status == UPLOAD_IN_PROGRESS,
                StorageOperation.claim_token.is_(None),
            )
            .execution_options(synchronize_session=False)
            .values(
                status=UPLOAD_UNCERTAIN,
                retry_count=retry_count,
                last_attempt_at=now,
                next_attempt_at=now + _retry_delay(retry_count),
                lease_until=None,
                lease_token=None,
                last_error=error_type[:100],
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            return
        transition_storage_object(
            db,
            db.scalar(
                select(StorageOperation.storage_key).where(
                    StorageOperation.id == operation_id
                )
            ),
            "uploading",
            "needs_review",
        )
        db.execute(
            update(UploadRequest)
            .where(
                UploadRequest.operation_id == operation_id,
                UploadRequest.status == "in_progress",
            )
            .values(status="needs_review", updated_at=now)
        )
        db.commit()

    @staticmethod
    def cancel_unattempted_upload(db: Session, operation_id: str) -> None:
        result = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.status == UPLOAD_IN_PROGRESS,
                StorageOperation.claim_token.is_(None),
            )
            .execution_options(synchronize_session=False)
            .values(
                status=CANCELLED,
                lease_until=None,
                lease_token=None,
                last_error=None,
                updated_at=_now(),
            )
        )
        if result.rowcount == 1:
            storage_key = db.scalar(
                select(StorageOperation.storage_key).where(
                    StorageOperation.id == operation_id
                )
            )
            if storage_key is not None:
                transition_storage_object(
                    db, storage_key, "uploading", "deleted"
                )
            return

    @staticmethod
    def complete_committed_upload(
        db: Session,
        operation_id: str,
        *,
        remove_staging: Callable[[], bool],
    ) -> None:
        try:
            cleaned = remove_staging()
        except Exception as exc:
            logger.error(
                "Unable to remove staging file for committed storage operation: "
                "operation_id=%s error_type=%s",
                operation_id,
                type(exc).__name__,
            )
            cleaned = False
        if not cleaned:
            return
        try:
            result = db.execute(
                update(StorageOperation)
                .where(
                    StorageOperation.id == operation_id,
                    StorageOperation.status == UPLOAD_COMMITTED,
                    StorageOperation.claim_token.is_(None),
                )
                .execution_options(synchronize_session=False)
                .values(
                    status=COMPLETED,
                    lease_until=None,
                    lease_token=None,
                    last_error=None,
                    updated_at=_now(),
                )
            )
            if result.rowcount != 1:
                return
            db.commit()
        except SQLAlchemyError as exc:
            try:
                db.rollback()
            except SQLAlchemyError as rollback_error:
                logger.error(
                    "Unable to roll back storage cleanup bookkeeping: "
                    "operation_id=%s error_type=%s",
                    operation_id,
                    type(rollback_error).__name__,
                )
            logger.error(
                "Unable to persist completion of storage staging cleanup: "
                "operation_id=%s error_type=%s",
                operation_id,
                type(exc).__name__,
            )

    @classmethod
    def process_operation(cls, db: Session, operation_id: str) -> bool:
        """Claim and perform one due operation with a fenced worker token."""
        now = _now()
        operation = db.get(StorageOperation, operation_id)
        if (
            operation is None
            or operation.status in _TERMINAL_STATUSES
            or _as_utc(operation.next_attempt_at) > now
            or (
                operation.lease_until is not None
                and _as_utc(operation.lease_until) > now
            )
            or (
                operation.claim_token is not None
                and (
                    operation.lease_until is None
                    or _as_utc(operation.lease_until) > now
                )
            )
        ):
            return False

        observed_status = operation.status
        if operation.retry_count >= MAX_STORAGE_OPERATION_ATTEMPTS:
            result = db.execute(
                update(StorageOperation)
                .where(
                    StorageOperation.id == operation_id,
                    StorageOperation.status == observed_status,
                    StorageOperation.retry_count
                    >= MAX_STORAGE_OPERATION_ATTEMPTS,
                    or_(
                        StorageOperation.claim_token.is_(None),
                        StorageOperation.lease_until <= now,
                    ),
                    or_(
                        StorageOperation.lease_until.is_(None),
                        StorageOperation.lease_until <= now,
                    ),
                )
                .values(
                    status=EXHAUSTED,
                    lease_until=None,
                    lease_token=None,
                    claim_token=None,
                    updated_at=now,
                )
            )
            if result.rowcount == 1:
                db.commit()
            else:
                db.rollback()
            return False

        claim_token = generate_uuid()
        lease_predicate = (
            StorageOperation.lease_until.is_(None)
            | (StorageOperation.lease_until <= now)
        )
        claim = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.status == observed_status,
                StorageOperation.status.not_in(_TERMINAL_STATUSES),
                StorageOperation.next_attempt_at <= now,
                lease_predicate,
                or_(
                    StorageOperation.claim_token.is_(None),
                    StorageOperation.lease_until <= now,
                ),
            )
            .execution_options(synchronize_session=False)
            .values(
                claim_token=claim_token,
                lease_until=now + STORAGE_OPERATION_LEASE,
                retry_count=StorageOperation.retry_count + 1,
                last_attempt_at=now,
                updated_at=now,
            )
        )
        if claim.rowcount != 1:
            db.rollback()
            return False

        db.commit()
        db.expire_all()
        operation = db.get(StorageOperation, operation_id)
        if operation is None:
            return False
        claimed_status = operation.status
        try:
            if (
                operation.operation_type == "upload"
                and (
                    operation.status == UPLOAD_COMMITTED
                    or (
                        operation.status == RETRY_WAIT
                        and operation.last_error == "LocalCleanupError"
                    )
                )
            ):
                if not cls._remove_staging_file(operation.storage_key):
                    cls._schedule_retry(
                        db,
                        operation_id,
                        claim_token,
                        claimed_status,
                        "LocalCleanupError",
                        _now(),
                    )
                    return False
                return cls._transition_claimed(
                    db,
                    operation_id,
                    claim_token,
                    claimed_status,
                    COMPLETED,
                )
            if (
                operation.operation_type == "upload"
                and operation.status
                in {UPLOAD_IN_PROGRESS, UPLOAD_UNCERTAIN, RETRY_WAIT}
            ):
                reason = (
                    "UploadRequestMayStillBeActive"
                    if operation.status == UPLOAD_IN_PROGRESS
                    else "RemoteUploadOutcomeUncertain"
                )
                return cls._transition_claimed(
                    db,
                    operation_id,
                    claim_token,
                    claimed_status,
                    NEEDS_REVIEW,
                    last_error=reason,
                )
            if operation.operation_type == "delete":
                return cls._process_delete(db, operation_id, claim_token)
            else:
                return cls._transition_claimed(
                    db,
                    operation_id,
                    claim_token,
                    claimed_status,
                    NEEDS_REVIEW,
                    last_error="UnsupportedOperation",
                )
        except Exception as exc:
            db.rollback()
            cls._schedule_retry(
                db,
                operation_id,
                claim_token,
                claimed_status,
                type(exc).__name__,
                _now(),
            )
            logger.warning(
                "Storage recovery attempt failed: operation_id=%s type=%s "
                "error_type=%s",
                operation_id,
                operation.operation_type,
                type(exc).__name__,
            )
            return False

    @classmethod
    def _process_delete(
        cls,
        db: Session,
        operation_id: str,
        claim_token: str,
    ) -> bool:
        operation = db.get(StorageOperation, operation_id)
        if operation is None or not cls._owns_claim(
            db, operation_id, claim_token
        ):
            db.rollback()
            return False
        operation = db.scalar(
            select(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.lease_until > _now(),
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if operation is None:
            db.rollback()
            return False

        active_reference = db.scalar(
            select(Document.id)
            .where(
                Document.is_deleted.is_(False),
                or_(
                    Document.storage_key == operation.storage_key,
                    Document.id.in_(
                        select(DocumentVersion.document_id).where(
                            DocumentVersion.storage_key == operation.storage_key
                        )
                    ),
                ),
            )
            .limit(1)
        )
        if active_reference is not None:
            return cls._transition_claimed(
                db,
                operation_id,
                claim_token,
                operation.status,
                NEEDS_REVIEW,
                last_error="document_still_active",
            )

        storage_object = db.get(StorageObject, operation.storage_key)
        if (
            not is_valid_storage_key(operation.storage_key)
            or storage_object is None
            or storage_object.state != "deleting"
        ):
            return cls._transition_claimed(
                db,
                operation_id,
                claim_token,
                operation.status,
                NEEDS_REVIEW,
                last_error="invalid_storage_key",
            )
        if not cls._owns_claim(db, operation_id, claim_token):
            db.rollback()
            return False
        # Release all database locks before waiting on the storage provider.
        db.commit()
        try:
            _get_supabase_bucket().remove([operation.storage_key])
        except Exception as exc:
            if not is_storage_object_not_found(exc):
                raise

        completion = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.status == operation.status,
                StorageOperation.lease_until > _now(),
            )
            .values(
                status=COMPLETED,
                lease_until=None,
                lease_token=None,
                claim_token=None,
                last_error=None,
                updated_at=_now(),
            )
            .execution_options(synchronize_session=False)
        )
        object_completion = db.execute(
            update(StorageObject)
            .where(
                StorageObject.storage_key == operation.storage_key,
                StorageObject.state == "deleting",
            )
            .values(state="deleted", updated_at=_now())
            .execution_options(synchronize_session=False)
        )
        if completion.rowcount != 1 or object_completion.rowcount != 1:
            db.rollback()
            return False
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception(
                "Remote storage deletion succeeded but completion could not be "
                "persisted: operation_id=%s",
                operation_id,
            )
            return False
        return True

    @staticmethod
    def _remove_staging_file(storage_key: str) -> bool:
        if not is_valid_storage_key(storage_key):
            return False
        staging_path = StorageService.get_staging_path() / f"{storage_key}.part"
        try:
            staging_path.unlink(missing_ok=True)
        except OSError:
            return False
        return True

    @staticmethod
    def _owns_claim(db: Session, operation_id: str, claim_token: str) -> bool:
        return (
            db.scalar(
                select(StorageOperation.id).where(
                    StorageOperation.id == operation_id,
                    StorageOperation.claim_token == claim_token,
                    StorageOperation.lease_until > _now(),
                )
            )
            is not None
        )

    @staticmethod
    def _transition_claimed(
        db: Session,
        operation_id: str,
        claim_token: str,
        expected_status: str,
        status_value: str,
        *,
        last_error: str | None = None,
    ) -> bool:
        operation_storage_key = db.scalar(
            select(StorageOperation.storage_key).where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.status == expected_status,
                StorageOperation.lease_until > _now(),
            )
        )
        if operation_storage_key is None:
            db.rollback()
            return False
        if status_value == NEEDS_REVIEW:
            storage_state = db.scalar(
                select(StorageObject.state).where(
                    StorageObject.storage_key == operation_storage_key
                )
            )
            if storage_state not in {"deleted", "needs_review"}:
                db.execute(
                    update(StorageObject)
                    .where(
                        StorageObject.storage_key == operation_storage_key,
                        StorageObject.state == storage_state,
                    )
                    .values(state="needs_review", updated_at=_now())
                )
        result = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.status == expected_status,
                StorageOperation.lease_until > _now(),
            )
            .execution_options(synchronize_session=False)
            .values(
                status=status_value,
                lease_until=None,
                lease_token=None,
                claim_token=None,
                last_error=last_error,
                updated_at=_now(),
            )
        )
        if result.rowcount != 1:
            db.rollback()
            return False
        if status_value == NEEDS_REVIEW:
            db.execute(
                update(UploadRequest)
                .where(
                    UploadRequest.operation_id == operation_id,
                    UploadRequest.status == "in_progress",
                )
                .values(status="needs_review", updated_at=_now())
            )
        db.commit()
        return True

    @staticmethod
    def _schedule_retry(
        db: Session,
        operation_id: str,
        claim_token: str,
        expected_status: str,
        error_type: str,
        now: datetime,
    ) -> bool:
        retry_count = db.scalar(
            select(StorageOperation.retry_count).where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.status == expected_status,
                StorageOperation.lease_until > now,
            )
        )
        if retry_count is None:
            db.rollback()
            return False
        exhausted = retry_count >= MAX_STORAGE_OPERATION_ATTEMPTS
        result = db.execute(
            update(StorageOperation)
            .where(
                StorageOperation.id == operation_id,
                StorageOperation.claim_token == claim_token,
                StorageOperation.status == expected_status,
                StorageOperation.lease_until > now,
            )
            .execution_options(synchronize_session=False)
            .values(
                status=EXHAUSTED if exhausted else RETRY_WAIT,
                next_attempt_at=(
                    now if exhausted else now + _retry_delay(retry_count)
                ),
                last_error=error_type[:100],
                lease_until=None,
                lease_token=None,
                claim_token=None,
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            db.rollback()
            return False
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception(
                "Unable to persist storage operation retry state"
            )
            return False
        return True

    @classmethod
    def run_once(
        cls,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> int:
        now = _now()
        with session_factory() as db:
            operation_ids = list(
                db.scalars(
                    select(StorageOperation.id)
                    .where(
                        StorageOperation.status.not_in(_TERMINAL_STATUSES),
                        StorageOperation.next_attempt_at <= now,
                        or_(
                            StorageOperation.lease_until.is_(None),
                            StorageOperation.lease_until <= now,
                        ),
                    )
                    .order_by(StorageOperation.next_attempt_at, StorageOperation.created_at)
                    .limit(STORAGE_OPERATION_BATCH_SIZE)
                ).all()
            )

        attempted = 0
        for operation_id in operation_ids:
            with session_factory() as db:
                if cls.process_operation(db, operation_id):
                    attempted += 1
        return attempted


class StorageRecoveryScheduler:
    """Periodically recover due remote storage operations."""

    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self._session_factory = session_factory
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(
            self._run_loop(),
            name="trustvault-storage-recovery",
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
        finally:
            self._task = None
            self._stop_event = None

    async def run_once_async(self) -> int:
        return await asyncio.to_thread(
            StorageRecoveryService.run_once,
            self._session_factory,
        )

    async def _run_loop(self) -> None:
        stop_event = self._stop_event
        if stop_event is None:
            return
        while not stop_event.is_set():
            try:
                await self.run_once_async()
            except Exception:
                logger.exception("Storage recovery cycle failed")
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=STORAGE_RECOVERY_INTERVAL_SECONDS,
                )
            except TimeoutError:
                pass


storage_recovery_scheduler = StorageRecoveryScheduler()
