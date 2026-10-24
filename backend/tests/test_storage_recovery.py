import importlib
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from storage3.exceptions import StorageApiError

from backend.app.config import settings
from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.audit import AuditEvent
from backend.app.models.base import generate_uuid
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.storage_object import StorageObject
from backend.app.models.user import UserRole
from backend.app.services import storage_recovery
from backend.app.services.storage_recovery import (
    COMPLETED,
    DELETE_PENDING,
    EXHAUSTED,
    MAX_STORAGE_OPERATION_ATTEMPTS,
    NEEDS_REVIEW,
    RETRY_WAIT,
    UPLOAD_COMMITTED,
    UPLOAD_UNCERTAIN,
    UPLOAD_IN_PROGRESS,
    StorageRecoveryService,
)
from backend.app.services.storage_service import StagedUpload, StorageService
from backend.tests.test_auth import VALID_PASSWORD, make_user
from backend.tests.test_supabase_storage import _install_mock_bucket
from backend.tests.conftest import (
    _inject_csrf_header_hook,
    _inject_upload_idempotency_header_hook,
)


@contextmanager
def _isolated_database(tmp_path: Path):
    database_path = tmp_path / "storage-recovery.sqlite"
    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(connection, _connection_record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        engine.dispose()


@asynccontextmanager
async def _isolated_client(tmp_path: Path):
    with _isolated_database(tmp_path) as factory:

        def override_get_db():
            with factory() as db:
                yield db

        app.dependency_overrides[get_db] = override_get_db
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://testserver",
                event_hooks={
                    "request": [
                        _inject_csrf_header_hook,
                        _inject_upload_idempotency_header_hook,
                    ]
                },
            ) as client:
                yield client, factory
        finally:
            app.dependency_overrides.clear()


def _new_upload_operation(
    db: Session,
    storage_key: str,
    *,
    status_value: str = UPLOAD_UNCERTAIN,
    content_sha256: str = "a" * 64,
) -> StorageOperation:
    operation = StorageOperation(
        operation_type="upload",
        storage_key=storage_key,
        status=status_value,
        content_sha256=content_sha256,
        lease_token=generate_uuid(),
        retry_count=0,
        lease_until=(
            datetime.now(UTC) + timedelta(minutes=15)
            if status_value == UPLOAD_IN_PROGRESS
            else None
        ),
        next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db.add(operation)
    db.commit()
    return operation


def _new_deleted_document_and_operation(
    db: Session,
    storage_key: str,
) -> StorageOperation:
    owner = make_user(
        db,
        email=f"storage-recovery-{storage_key[:8]}@example.com",
        role=UserRole.OWNER,
    )
    document = Document(
        title="Deleted object",
        original_filename="deleted.pdf",
        storage_key=storage_key,
        file_size_bytes=10,
        mime_type="application/pdf",
        category="General",
        owner_id=owner.id,
        is_deleted=True,
    )
    db.add(document)
    db.flush()
    storage_object = db.get(StorageObject, storage_key)
    assert storage_object is not None
    storage_object.state = "deleting"
    operation = StorageOperation(
        operation_type="delete",
        storage_key=storage_key,
        status=DELETE_PENDING,
        retry_count=0,
        next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db.add(operation)
    db.commit()
    return operation


def test_complete_does_not_remove_local_final_file_or_remote_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "local")
    staged = StagedUpload(
        storage_key="a" * 64,
        staging_path=tmp_path / "staged.part",
        final_path=tmp_path / ("a" * 64),
        size_bytes=4,
        content_sha256="b" * 64,
    )
    staged.final_path.write_bytes(b"final")
    staged.staging_path.write_bytes(b"stage")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)

    assert staged.complete() is True

    assert staged.final_path.read_bytes() == b"final"
    assert staged.staging_path.read_bytes() == b"stage"
    bucket.remove.assert_not_called()


def test_local_staged_upload_still_finalizes_with_atomic_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "local")
    staged = StagedUpload(
        storage_key="c" * 64,
        staging_path=tmp_path / "staged.part",
        final_path=tmp_path / ("c" * 64),
        size_bytes=5,
        content_sha256="d" * 64,
    )
    staged.staging_path.write_bytes(b"local")

    staged.finalize()

    assert staged.final_path.read_bytes() == b"local"
    assert not staged.staging_path.exists()
    assert staged.complete() is True


def test_confirmed_supabase_complete_only_removes_staging_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    staged = StagedUpload(
        storage_key="a" * 64,
        staging_path=tmp_path / "staged.part",
        final_path=tmp_path / ("a" * 64),
        size_bytes=4,
        content_sha256="b" * 64,
    )
    staged.staging_path.write_bytes(b"stage")
    staged.final_path.write_bytes(b"remote-key-placeholder")
    staged._remote_uploaded = True
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)

    assert staged.complete() is True

    assert not staged.staging_path.exists()
    assert staged.final_path.read_bytes() == b"remote-key-placeholder"
    bucket.remove.assert_not_called()


def test_recovery_retries_failed_remote_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.remove.side_effect = [RuntimeError("provider failure"), []]
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "c" * 64)
            operation_id = operation.id

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is False
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == RETRY_WAIT
            assert operation.retry_count == 1
            assert operation.last_error == "RuntimeError"
            assert (
                operation.next_attempt_at.replace(tzinfo=UTC)
                > datetime.now(UTC)
            )
            operation.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            operation.lease_until = None
            db.commit()

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == COMPLETED
            assert operation.retry_count == 2
    assert bucket.remove.call_count == 2


def test_recovery_treats_already_absent_delete_as_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.remove.side_effect = StorageApiError("Object not found", "NotFound", 404)
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "a" * 64)
            operation_id = operation.id
        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == COMPLETED

    bucket.remove.assert_called_once_with(["a" * 64])


def test_recovery_does_not_treat_other_provider_404_as_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.remove.side_effect = StorageApiError(
        "Access denied", "Unauthorized", 404
    )
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "9" * 64)
            operation_id = operation.id

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is False

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == RETRY_WAIT
            assert operation.last_error == "StorageApiError"

    bucket.remove.assert_called_once_with(["9" * 64])


def test_recovery_does_not_delete_an_active_document_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            owner = make_user(
                db,
                email="active-version-recovery@example.com",
                role=UserRole.OWNER,
            )
            document = Document(
                title="Active document",
                original_filename="active.pdf",
                storage_key="b" * 64,
                file_size_bytes=10,
                mime_type="application/pdf",
                category="General",
                owner_id=owner.id,
                is_deleted=False,
            )
            db.add(document)
            db.flush()
            version = DocumentVersion(
                document_id=document.id,
                version_number=1,
                storage_key="c" * 64,
                file_size_bytes=10,
            )
            operation = StorageOperation(
                operation_type="delete",
                storage_key=version.storage_key,
                status=DELETE_PENDING,
                retry_count=0,
                next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
            )
            db.add_all([document, version, operation])
            db.commit()
            operation_id = operation.id

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == NEEDS_REVIEW
            assert operation.last_error == "document_still_active"

    bucket.remove.assert_not_called()


def test_uncertain_upload_with_active_document_version_requires_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            owner = make_user(
                db,
                email="active-version-upload-recovery@example.com",
                role=UserRole.OWNER,
            )
            document = Document(
                title="Active document",
                original_filename="active.pdf",
                storage_key="f" * 64,
                file_size_bytes=10,
                mime_type="application/pdf",
                category="General",
                owner_id=owner.id,
                is_deleted=False,
            )
            db.add(document)
            db.flush()
            version = DocumentVersion(
                document_id=document.id,
                version_number=1,
                storage_key="a" * 64,
                file_size_bytes=10,
            )
            operation = _new_upload_operation(db, version.storage_key)
            operation_id = operation.id
            storage_object = db.get(StorageObject, version.storage_key)
            assert storage_object is not None
            storage_object.state = "active"
            db.flush()
            db.add(version)
            db.commit()

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == NEEDS_REVIEW
            assert operation.last_error == "RemoteUploadOutcomeUncertain"

    bucket.info.assert_not_called()
    bucket.remove.assert_not_called()


def test_recovery_stops_retrying_after_attempt_limit(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    operation = _new_deleted_document_and_operation(db_session, "d" * 64)
    operation.retry_count = MAX_STORAGE_OPERATION_ATTEMPTS
    db_session.commit()
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    assert StorageRecoveryService.process_operation(db_session, operation.id) is False
    db_session.refresh(operation)

    assert operation.status == EXHAUSTED
    bucket.remove.assert_not_called()


def test_last_permitted_retry_is_attempted_before_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.remove.side_effect = RuntimeError("provider unavailable")
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "2" * 64)
            operation.retry_count = MAX_STORAGE_OPERATION_ATTEMPTS - 1
            db.commit()
            operation_id = operation.id

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is False

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.retry_count == MAX_STORAGE_OPERATION_ATTEMPTS
            assert operation.status == EXHAUSTED

    bucket.remove.assert_called_once_with(["2" * 64])


def test_restart_recovery_processes_due_delete_operation(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    operation = _new_deleted_document_and_operation(db_session, "e" * 64)
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    @contextmanager
    def reuse_test_session():
        yield db_session

    assert StorageRecoveryService.run_once(reuse_test_session) == 1
    db_session.refresh(operation)

    assert operation.status == COMPLETED
    bucket.remove.assert_called_once_with(["e" * 64])


def test_uncertain_upload_is_preserved_for_manual_review(
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    storage_key = "f" * 64
    operation = _new_upload_operation(db_session, storage_key)
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)
    staging_path = StorageService.get_staging_path() / f"{storage_key}.part"
    staging_path.write_bytes(b"staged")

    assert StorageRecoveryService.process_operation(db_session, operation.id) is True
    db_session.refresh(operation)

    assert operation.status == NEEDS_REVIEW
    assert operation.last_error == "RemoteUploadOutcomeUncertain"
    bucket.info.assert_not_called()
    bucket.remove.assert_not_called()
    assert staging_path.read_bytes() == b"staged"


def test_uncertain_upload_cleanup_is_not_attempted_automatically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    storage_key = "0" * 64
    staging_path = StorageService.get_staging_path() / f"{storage_key}.part"
    staging_path.write_bytes(b"recoverable staged bytes")
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_upload_operation(db, storage_key)
            operation_id = operation.id
            bucket.info.return_value = {
                "metadata": {
                    "trustvault_operation_id": operation_id,
                    "sha256": operation.content_sha256,
                }
            }

        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == NEEDS_REVIEW
            assert operation.last_error == "RemoteUploadOutcomeUncertain"
    assert staging_path.read_bytes() == b"recoverable staged bytes"
    bucket.info.assert_not_called()
    bucket.remove.assert_not_called()


def test_upload_timeout_with_possible_remote_write_requires_manual_review(
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    storage_key = "1" * 64
    operation = _new_upload_operation(
        db_session,
        storage_key,
        status_value=UPLOAD_IN_PROGRESS,
    )
    staged_path = StorageService.get_staging_path() / f"{storage_key}.part"
    staged_path.write_bytes(b"staged")
    staged = StagedUpload(
        storage_key=storage_key,
        staging_path=staged_path,
        final_path=tmp_path / storage_key,
        size_bytes=6,
        content_sha256=operation.content_sha256 or "",
        operation_id=operation.id,
    )
    bucket = Mock()
    bucket.upload.side_effect = TimeoutError("response lost after remote write")
    _install_mock_bucket(monkeypatch, bucket)
    with pytest.raises(TimeoutError):
        staged.finalize()
    staged.discard()
    StorageRecoveryService.mark_upload_uncertain(
        db_session,
        operation.id,
        "TimeoutError",
    )

    remote_bucket = Mock()
    monkeypatch.setattr(
        storage_recovery,
        "_get_supabase_bucket",
        lambda: remote_bucket,
    )
    operation.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    assert StorageRecoveryService.process_operation(db_session, operation.id) is True
    db_session.refresh(operation)
    assert operation.status == NEEDS_REVIEW
    assert operation.last_error == "RemoteUploadOutcomeUncertain"
    remote_bucket.info.assert_not_called()
    remote_bucket.remove.assert_not_called()
    assert staged_path.read_bytes() == b"staged"


def test_unverified_remote_upload_is_never_deleted(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    operation = _new_upload_operation(db_session, "2" * 64)
    bucket = Mock()
    bucket.info.return_value = {"metadata": {"sha256": operation.content_sha256}}
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    assert StorageRecoveryService.process_operation(db_session, operation.id) is True
    db_session.refresh(operation)

    assert operation.status == NEEDS_REVIEW
    bucket.remove.assert_not_called()


@pytest.mark.asyncio
async def test_upload_commit_failure_leaves_durable_recovery_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    bucket = Mock()
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)
    _install_mock_bucket(monkeypatch, bucket)
    original_commit = Session.commit
    commit_failed = False

    def fail_commit_after_upload(db: Session):
        nonlocal commit_failed
        if bucket.upload.called and not commit_failed:
            commit_failed = True
            raise SQLAlchemyError("simulated commit failure")
        original_commit(db)

    monkeypatch.setattr(Session, "commit", fail_commit_after_upload)
    async with _isolated_client(tmp_path) as (client, factory):
        with factory() as db:
            owner = make_user(
                db,
                email="upload-commit-failure@example.com",
                password=VALID_PASSWORD,
                role=UserRole.OWNER,
            )
            db.commit()

        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "upload-commit-failure@example.com",
                "password": VALID_PASSWORD,
            },
        )
        response = await client.post(
            "/api/v1/documents",
            files={
                "file": (
                    "commit.pdf",
                    b"%PDF-1.4 commit failure",
                    "application/pdf",
                )
            },
            data={"title": "Commit failure"},
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        with factory() as db:
            operation = (
                db.query(StorageOperation)
                .filter(StorageOperation.operation_type == "upload")
                .one()
            )
            assert operation.status == UPLOAD_UNCERTAIN
            assert (
                db.query(Document)
                .filter_by(storage_key=operation.storage_key)
                .count()
                == 0
            )
        bucket.remove.assert_not_called()
        uploaded_metadata = bucket.upload.call_args.kwargs["file_options"]["metadata"]
        assert uploaded_metadata["trustvault_operation_id"] == operation.id
        bucket.info.return_value = {
            "metadata": {
                "trustvault_operation_id": operation.id,
                "sha256": operation.content_sha256,
            }
        }
        with factory() as db:
            operation = db.get(StorageOperation, operation.id)
            operation.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()
        with factory() as db:
            assert (
                StorageRecoveryService.process_operation(db, operation.id) is True
            )
        with factory() as db:
            operation = db.get(StorageOperation, operation.id)
            assert operation.status == NEEDS_REVIEW
            staging_path = (
                StorageService.get_staging_path()
                / f"{operation.storage_key}.part"
            )
        bucket.info.assert_not_called()
        bucket.remove.assert_not_called()
        assert staging_path.exists()


@pytest.mark.asyncio
async def test_ambiguous_database_commit_preserves_committed_document_and_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    original_commit = Session.commit
    commit_reported_failure = False

    def commit_then_raise_after_upload(db: Session):
        nonlocal commit_reported_failure
        if bucket.upload.called and not commit_reported_failure:
            commit_reported_failure = True
            original_commit(db)
            raise SQLAlchemyError("simulated lost commit response")
        original_commit(db)

    monkeypatch.setattr(Session, "commit", commit_then_raise_after_upload)
    async with _isolated_client(tmp_path) as (client, factory):
        with factory() as db:
            make_user(
                db,
                email="ambiguous-upload-commit@example.com",
                password=VALID_PASSWORD,
                role=UserRole.OWNER,
            )
            db.commit()

        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "ambiguous-upload-commit@example.com",
                "password": VALID_PASSWORD,
            },
        )
        response = await client.post(
            "/api/v1/documents",
            files={
                "file": (
                    "ambiguous.pdf",
                    b"%PDF-1.4 ambiguous commit",
                    "application/pdf",
                )
            },
            data={"title": "Ambiguous commit"},
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        with factory() as db:
            operation = (
                db.query(StorageOperation)
                .filter(StorageOperation.operation_type == "upload")
                .one()
            )
            document = (
                db.query(Document)
                .filter_by(storage_key=operation.storage_key)
                .one()
            )
            assert operation.status == UPLOAD_COMMITTED
            assert document.is_deleted is False
            operation_id = operation.id
        bucket.remove.assert_not_called()
        with factory() as db:
            assert StorageRecoveryService.process_operation(db, operation_id) is True
        with factory() as db:
            assert db.get(StorageOperation, operation_id).status == COMPLETED
        bucket.remove.assert_not_called()


@pytest.mark.asyncio
async def test_local_ambiguous_database_commit_preserves_final_file_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    storage_dir = tmp_path / "private"
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "local")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(storage_dir))
    original_commit = Session.commit
    commit_reported_failure = False

    def commit_then_raise_after_local_finalize(db: Session):
        nonlocal commit_reported_failure
        finalized_files = (
            [
                path
                for path in storage_dir.iterdir()
                if path.is_file()
            ]
            if storage_dir.exists()
            else []
        )
        if finalized_files and not commit_reported_failure:
            commit_reported_failure = True
            original_commit(db)
            raise SQLAlchemyError("simulated lost commit response")
        original_commit(db)

    monkeypatch.setattr(Session, "commit", commit_then_raise_after_local_finalize)
    async with _isolated_client(tmp_path) as (client, factory):
        with factory() as db:
            make_user(
                db,
                email="ambiguous-local-upload-commit@example.com",
                password=VALID_PASSWORD,
                role=UserRole.OWNER,
            )
            db.commit()

        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "ambiguous-local-upload-commit@example.com",
                "password": VALID_PASSWORD,
            },
        )
        response = await client.post(
            "/api/v1/documents",
            files={
                "file": (
                    "ambiguous-local.pdf",
                    b"%PDF-1.4 ambiguous local commit",
                    "application/pdf",
                )
            },
            data={"title": "Ambiguous local commit"},
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert commit_reported_failure
        with factory() as db:
            document = (
                db.query(Document)
                .filter_by(title="Ambiguous local commit")
                .one()
            )
            assert document.is_deleted is False
            assert (
                db.query(AuditEvent)
                .filter_by(
                    action="document.upload",
                    resource_id=document.id,
                )
                .one()
                is not None
            )
            assert (storage_dir / document.storage_key).read_bytes() == (
                b"%PDF-1.4 ambiguous local commit"
            )
            assert not (
                StorageService.get_staging_path()
                / f"{document.storage_key}.part"
            ).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_type",
    ["database_update", "database_commit", "staging_cleanup"],
)
async def test_post_commit_bookkeeping_failure_does_not_fail_or_reupload_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: str,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    complete_upload = StorageRecoveryService.complete_committed_upload

    def fail_completion_update(
        db: Session,
        operation_id: str,
        *,
        remove_staging,
    ) -> None:
        if failure_type == "staging_cleanup":
            complete_upload(
                db,
                operation_id,
                remove_staging=lambda: False,
            )
            return

        if failure_type == "database_commit":
            original_commit = db.commit

            def fail_commit():
                raise SQLAlchemyError("simulated post-commit commit failure")

            db.commit = fail_commit
            try:
                complete_upload(
                    db,
                    operation_id,
                    remove_staging=remove_staging,
                )
            finally:
                db.commit = original_commit
            return

        original_execute = db.execute

        def fail_execute(*args, **kwargs):
            raise SQLAlchemyError("simulated post-commit bookkeeping failure")

        db.execute = fail_execute
        try:
            complete_upload(
                db,
                operation_id,
                remove_staging=remove_staging,
            )
        finally:
            db.execute = original_execute

    monkeypatch.setattr(
        StorageRecoveryService,
        "complete_committed_upload",
        staticmethod(fail_completion_update),
    )
    async with _isolated_client(tmp_path) as (client, factory):
        with factory() as db:
            make_user(
                db,
                email="post-commit-bookkeeping@example.com",
                password=VALID_PASSWORD,
                role=UserRole.OWNER,
            )
            db.commit()

        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "post-commit-bookkeeping@example.com",
                "password": VALID_PASSWORD,
            },
        )
        response = await client.post(
            "/api/v1/documents",
            files={
                "file": (
                    "post-commit.pdf",
                    b"%PDF-1.4 durable upload",
                    "application/pdf",
                )
            },
            data={"title": "Post-commit bookkeeping"},
        )

        assert response.status_code == status.HTTP_201_CREATED, response.text
        with factory() as db:
            document = db.get(Document, response.json()["id"])
            assert document is not None
            operation = (
                db.query(StorageOperation)
                .filter_by(storage_key=document.storage_key)
                .one()
            )
            assert operation.status == UPLOAD_COMMITTED
            storage_operation_id = operation.id
            storage_key = document.storage_key
            staging_path = (
                StorageService.get_staging_path()
                / f"{storage_key}.part"
            )

        assert staging_path.exists() is (failure_type == "staging_cleanup")
        assert bucket.upload.call_count == 1
        with factory() as db:
            assert StorageRecoveryService.process_operation(
                db,
                storage_operation_id,
            ) is True
        with factory() as db:
            assert db.get(StorageOperation, storage_operation_id).status == COMPLETED

        assert bucket.upload.call_count == 1
        with factory() as db:
            assert db.query(Document).filter_by(storage_key=storage_key).count() == 1


@pytest.mark.asyncio
async def test_supabase_document_delete_queues_current_and_version_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)
    async with _isolated_client(tmp_path) as (client, factory):
        with factory() as db:
            owner = make_user(
                db,
                email="version-delete-owner@example.com",
                password=VALID_PASSWORD,
                role=UserRole.OWNER,
            )
            document = Document(
                title="Versioned document",
                original_filename="versioned.pdf",
                storage_key="d" * 64,
                file_size_bytes=10,
                mime_type="application/pdf",
                category="General",
                owner_id=owner.id,
                is_deleted=False,
            )
            db.add(document)
            db.flush()
            version = DocumentVersion(
                document_id=document.id,
                version_number=1,
                storage_key="e" * 64,
                file_size_bytes=8,
            )
            db.add_all([document, version])
            db.commit()
            document_id = document.id

        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "version-delete-owner@example.com",
                "password": VALID_PASSWORD,
            },
        )
        response = await client.delete(f"/api/v1/documents/{document_id}")

        assert response.status_code == 204
        assert bucket.remove.call_args_list[0].args == (["d" * 64],)
        assert bucket.remove.call_args_list[1].args == (["e" * 64],)
        with factory() as db:
            operations = (
                db.query(StorageOperation)
                .filter(StorageOperation.operation_type == "delete")
                .order_by(StorageOperation.storage_key)
                .all()
            )
            assert {item.storage_key for item in operations} == {
                "d" * 64,
                "e" * 64,
            }
            assert {item.status for item in operations} == {COMPLETED}


def test_recovery_does_not_interfere_with_upload_past_expired_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    monkeypatch.setattr(storage_recovery, "UPLOAD_LEASE_HEARTBEAT_SECONDS", 0.01)

    upload_started = threading.Event()
    allow_upload_to_finish = threading.Event()
    renewal_started = threading.Event()
    allow_renewal = threading.Event()
    renewal_succeeded = threading.Event()
    bucket = Mock()

    def slow_upload(*args, **kwargs):
        upload_started.set()
        if not allow_upload_to_finish.wait(timeout=10):
            raise TimeoutError("test upload timed out")

    bucket.upload.side_effect = slow_upload
    _install_mock_bucket(monkeypatch, bucket)
    renew_upload_lease = StorageRecoveryService._renew_upload_lease

    def controlled_renewal(session_factory, operation_id, lease_token):
        renewal_started.set()
        if not allow_renewal.wait(timeout=5):
            raise TimeoutError("test did not release heartbeat renewal")
        renewed = renew_upload_lease(session_factory, operation_id, lease_token)
        renewal_succeeded.set()
        return renewed

    monkeypatch.setattr(
        StorageRecoveryService,
        "_renew_upload_lease",
        staticmethod(controlled_renewal),
    )

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_upload_operation(
                db,
                "f" * 64,
                status_value=UPLOAD_IN_PROGRESS,
            )
            operation_id = operation.id
            db.commit()
            content_sha256 = operation.content_sha256 or ""

        staged_path = StorageService.get_staging_path() / f"{'f' * 64}.part"
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        staged_path.write_bytes(b"slow staged upload")

        staged = StagedUpload(
            storage_key="f" * 64,
            staging_path=staged_path,
            final_path=tmp_path / ("f" * 64),
            size_bytes=len(b"slow staged upload"),
            content_sha256=content_sha256,
            operation_id=operation_id,
        )

        remote_bucket = Mock()
        remote_bucket.info.side_effect = StorageApiError(
            "Object not found",
            "NotFound",
            404,
        )
        monkeypatch.setattr(
            storage_recovery,
            "_get_supabase_bucket",
            lambda: remote_bucket,
        )

        with factory() as request_db:
            with StorageRecoveryService.maintain_upload_lease(
                request_db,
                operation_id,
            ) as lease_token:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    upload_future = pool.submit(staged.finalize)
                    try:
                        assert upload_started.wait(timeout=5), "upload did not start"
                        assert renewal_started.wait(timeout=5), (
                            "heartbeat did not start"
                        )

                        with factory() as expired_db:
                            operation = expired_db.get(
                                StorageOperation,
                                operation_id,
                            )
                            operation.lease_until = datetime.now(UTC) - timedelta(
                                seconds=1
                            )
                            expired_db.commit()

                        allow_renewal.set()
                        assert renewal_succeeded.wait(timeout=5), (
                            "upload heartbeat did not renew the expired lease"
                        )

                        with factory() as recovery_db:
                            assert StorageRecoveryService.process_operation(
                                recovery_db,
                                operation_id,
                            ) is False
                            live_operation = recovery_db.get(
                                StorageOperation,
                                operation_id,
                            )
                            assert live_operation.status == UPLOAD_IN_PROGRESS
                            assert live_operation.lease_until is not None
                            assert (
                                live_operation.lease_until.replace(tzinfo=UTC)
                                > datetime.now(UTC)
                            )

                        assert staged_path.exists(), (
                            "recovery removed staging while the upload was in flight"
                        )
                        remote_bucket.info.assert_not_called()
                        remote_bucket.remove.assert_not_called()
                    finally:
                        allow_upload_to_finish.set()

                    upload_future.result(timeout=5)

                StorageRecoveryService.mark_upload_committed(
                    request_db,
                    operation_id,
                    lease_token,
                )
                request_db.commit()
                assert staged.complete() is True
                assert not staged_path.exists()

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == UPLOAD_COMMITTED

        bucket.upload.assert_called_once()
        remote_bucket.info.assert_not_called()
        remote_bucket.remove.assert_not_called()


def test_heartbeat_failure_and_upload_past_grace_are_preserved_for_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    monkeypatch.setattr(storage_recovery, "UPLOAD_LEASE_HEARTBEAT_SECONDS", 0.01)
    upload_started = threading.Event()
    allow_upload_to_finish = threading.Event()
    heartbeat_failed = threading.Event()
    bucket = Mock()
    remote_bucket = Mock()

    def slow_upload(*args, **kwargs):
        upload_started.set()
        if not allow_upload_to_finish.wait(timeout=10):
            raise TimeoutError("test upload timed out")

    def failed_heartbeat(*args, **kwargs):
        heartbeat_failed.set()
        raise SQLAlchemyError("simulated heartbeat database failure")

    bucket.upload.side_effect = slow_upload
    _install_mock_bucket(monkeypatch, bucket)
    monkeypatch.setattr(
        StorageRecoveryService,
        "_renew_upload_lease",
        staticmethod(failed_heartbeat),
    )
    monkeypatch.setattr(
        storage_recovery,
        "_get_supabase_bucket",
        lambda: remote_bucket,
    )

    storage_key = "9" * 64
    staging_path = StorageService.get_staging_path() / f"{storage_key}.part"
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    staged_bytes = b"blocked upload beyond former grace"
    staging_path.write_bytes(staged_bytes)
    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_upload_operation(
                db,
                storage_key,
                status_value=UPLOAD_IN_PROGRESS,
            )
            operation_id = operation.id
            stale_lease_token = operation.lease_token
            assert stale_lease_token is not None
            content_sha256 = operation.content_sha256 or ""

        staged = StagedUpload(
            storage_key=storage_key,
            staging_path=staging_path,
            final_path=tmp_path / storage_key,
            size_bytes=len(staged_bytes),
            content_sha256=content_sha256,
            operation_id=operation_id,
        )

        with factory() as request_db:
            with StorageRecoveryService.maintain_upload_lease(
                request_db,
                operation_id,
            ):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    upload_future = pool.submit(staged.finalize)
                    try:
                        assert upload_started.wait(timeout=5), (
                            "provider upload did not start"
                        )
                        assert heartbeat_failed.wait(timeout=5), (
                            "heartbeat failure was not exercised"
                        )
                        with factory() as expired_db:
                            operation = expired_db.get(
                                StorageOperation,
                                operation_id,
                            )
                            operation.lease_until = datetime.now(UTC) - timedelta(
                                minutes=16
                            )
                            expired_db.commit()

                        with factory() as recovery_db:
                            assert StorageRecoveryService.process_operation(
                                recovery_db,
                                operation_id,
                            ) is True
                            operation = recovery_db.get(
                                StorageOperation,
                                operation_id,
                            )
                            assert operation.status == NEEDS_REVIEW
                            assert (
                                operation.last_error
                                == "UploadRequestMayStillBeActive"
                            )
                        assert staging_path.read_bytes() == staged_bytes
                        remote_bucket.info.assert_not_called()
                        remote_bucket.remove.assert_not_called()
                    finally:
                        allow_upload_to_finish.set()

                    upload_future.result(timeout=5)

                with pytest.raises(RuntimeError, match="lease was lost"):
                    StorageRecoveryService.mark_upload_committed(
                        request_db,
                        operation_id,
                        stale_lease_token,
                    )
                request_db.rollback()
                staged.discard()

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == NEEDS_REVIEW
        assert staging_path.read_bytes() == staged_bytes
        bucket.upload.assert_called_once()
        remote_bucket.info.assert_not_called()
        remote_bucket.remove.assert_not_called()


def test_expired_upload_after_restart_is_preserved_for_manual_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    remote_bucket = Mock()
    monkeypatch.setattr(
        storage_recovery,
        "_get_supabase_bucket",
        lambda: remote_bucket,
    )
    storage_key = "8" * 64
    staging_path = StorageService.get_staging_path() / f"{storage_key}.part"
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path.write_bytes(b"abandoned staged upload")

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_upload_operation(
                db,
                storage_key,
                status_value=UPLOAD_IN_PROGRESS,
            )
            operation_id = operation.id
            stale_lease_token = operation.lease_token
            operation.lease_until = datetime.now(UTC) - timedelta(minutes=16)
            db.commit()

        with factory() as restarted_worker_db:
            assert StorageRecoveryService.process_operation(
                restarted_worker_db,
                operation_id,
            ) is True

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == NEEDS_REVIEW
            assert operation.last_error == "UploadRequestMayStillBeActive"
            assert operation.lease_token is None
            with pytest.raises(RuntimeError, match="lease was lost"):
                StorageRecoveryService.mark_upload_committed(
                    db,
                    operation_id,
                    stale_lease_token,
                )
            db.rollback()

    assert staging_path.read_bytes() == b"abandoned staged upload"
    remote_bucket.info.assert_not_called()
    remote_bucket.remove.assert_not_called()


def test_two_recovery_workers_cannot_claim_the_same_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    provider_started = threading.Event()
    allow_provider_to_finish = threading.Event()
    bucket = Mock()

    def blocked_remove(*args, **kwargs):
        provider_started.set()
        if not allow_provider_to_finish.wait(timeout=10):
            raise TimeoutError("test delete timed out")

    bucket.remove.side_effect = blocked_remove
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "7" * 64)
            operation_id = operation.id

        def run_first_worker() -> bool:
            with factory() as db:
                return StorageRecoveryService.process_operation(db, operation_id)

        with ThreadPoolExecutor(max_workers=1) as pool:
            first_worker = pool.submit(run_first_worker)
            try:
                assert provider_started.wait(timeout=5), (
                    "first worker did not reach the provider"
                )
                with factory() as competing_worker_db:
                    assert StorageRecoveryService.process_operation(
                        competing_worker_db,
                        operation_id,
                    ) is False
            finally:
                allow_provider_to_finish.set()
            assert first_worker.result(timeout=5) is True

        with factory() as db:
            operation = db.get(StorageOperation, operation_id)
            assert operation.status == COMPLETED
            assert operation.claim_token is None
        bucket.remove.assert_called_once_with(["7" * 64])


def test_stale_recovery_worker_cannot_update_after_claim_takeover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    provider_started = threading.Event()
    allow_provider_to_finish = threading.Event()
    bucket = Mock()

    def blocked_remove(*args, **kwargs):
        provider_started.set()
        if not allow_provider_to_finish.wait(timeout=10):
            raise TimeoutError("test delete timed out")

    bucket.remove.side_effect = blocked_remove
    monkeypatch.setattr(storage_recovery, "_get_supabase_bucket", lambda: bucket)

    with _isolated_database(tmp_path) as factory:
        with factory() as db:
            operation = _new_deleted_document_and_operation(db, "6" * 64)
            operation_id = operation.id
            stale_claim_token = generate_uuid()
            operation.claim_token = stale_claim_token
            operation.lease_until = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()

        def run_recovery() -> bool:
            with factory() as worker_db:
                return StorageRecoveryService.process_operation(
                    worker_db, operation_id
                )

        with ThreadPoolExecutor(max_workers=1) as pool:
            worker = pool.submit(run_recovery)
            try:
                assert provider_started.wait(timeout=5)
                with factory() as db:
                    operation = db.get(StorageOperation, operation_id)
                    winning_claim_token = operation.claim_token
                    assert winning_claim_token != stale_claim_token

                with factory() as stale_worker_db:
                    assert (
                        StorageRecoveryService._transition_claimed(
                            stale_worker_db,
                            operation_id,
                            stale_claim_token,
                            DELETE_PENDING,
                            COMPLETED,
                        )
                        is False
                    )

                with factory() as db:
                    operation = db.get(StorageOperation, operation_id)
                    assert operation.status == DELETE_PENDING
                    assert operation.claim_token == winning_claim_token
            finally:
                allow_provider_to_finish.set()
            assert worker.result(timeout=5) is True


@pytest.mark.parametrize(
    "migration_name",
    [
        "a1b2c3d4e5f6_add_storage_operations",
        "b2c3d4e5f6a7_add_upload_lease_fencing",
        "c7d8e9f0a1b2_add_storage_recovery_claim_token",
    ],
)
def test_storage_migration_downgrade_refuses_unresolved_operations(
    migration_name: str,
    monkeypatch: pytest.MonkeyPatch,
):
    migration = importlib.import_module(
        f"backend.migrations.versions.{migration_name}"
    )
    result = SimpleNamespace(scalar_one=lambda: 1)
    bind = Mock()
    bind.execute.return_value = result
    monkeypatch.setattr(
        migration.context,
        "is_offline_mode",
        lambda: False,
    )
    monkeypatch.setattr(migration.op, "get_bind", lambda: bind)

    with pytest.raises(RuntimeError, match="Refusing"):
        migration.downgrade()
