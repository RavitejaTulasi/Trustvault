from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.orm import Session
from storage3.exceptions import StorageApiError

from backend.app.config import settings
from backend.app.models.document import Document
from backend.app.models.storage_object import StorageObject, UploadRequest
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.user import UserRole
from backend.app.services import storage_service
from backend.app.services.storage_service import StagedUpload, StorageService
from backend.tests.test_auth import VALID_PASSWORD, make_user


def _install_mock_bucket(monkeypatch: pytest.MonkeyPatch, bucket: Mock) -> Mock:
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "test-only-key")
    storage = SimpleNamespace(from_=Mock(return_value=bucket))
    client = SimpleNamespace(storage=storage)
    create_client = Mock(return_value=client)
    monkeypatch.setattr(storage_service, "create_client", create_client)
    return create_client


def _staged_upload(tmp_path: Path, key: str = "a" * 64) -> StagedUpload:
    staging_path = tmp_path / f"{key}.part"
    final_path = tmp_path / key
    staging_path.write_bytes(b"staged document")
    return StagedUpload(
        storage_key=key,
        staging_path=staging_path,
        final_path=final_path,
        size_bytes=15,
        content_sha256="0" * 64,
        operation_id="b" * 32,
    )


def test_supabase_upload_uses_sdk_options_and_keeps_staging_until_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    create_client = _install_mock_bucket(monkeypatch, bucket)
    staged = _staged_upload(tmp_path)

    staged.finalize()

    bucket.upload.assert_called_once_with(
        staged.storage_key,
        str(staged.staging_path),
        file_options={
            "content-type": "application/octet-stream",
            "upsert": "false",
            "metadata": {
                "trustvault_operation_id": staged.operation_id,
                "sha256": staged.content_sha256,
            },
        },
    )
    assert staged._finalized is True
    assert staged.staging_path.read_bytes() == b"staged document"
    create_client.assert_called_once()
    staged.complete()
    assert staged.staging_path.exists() is False


def test_legacy_save_file_rejects_supabase_before_staging_or_provider_access(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    create_client = Mock()
    monkeypatch.setattr(storage_service, "create_client", create_client)
    stage_file = Mock()
    monkeypatch.setattr(StorageService, "stage_file", stage_file)

    with pytest.raises(RuntimeError, match="durable storage-operation workflow"):
        StorageService.save_file(BytesIO(b"%PDF-1.4 legacy upload"), "legacy.pdf")

    stage_file.assert_not_called()
    create_client.assert_not_called()


def test_save_file_preserves_local_storage_return_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "local")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private"))
    content = b"%PDF-1.4 local compatibility upload"

    storage_key, size_bytes = StorageService.save_file(
        BytesIO(content),
        "local.pdf",
    )

    assert len(storage_key) == 64
    assert size_bytes == len(content)
    assert (tmp_path / "private" / storage_key).read_bytes() == content
    assert not (
        tmp_path / "private" / ".staging" / f"{storage_key}.part"
    ).exists()


def test_supabase_upload_discard_defers_remote_cleanup_to_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    staged = _staged_upload(tmp_path)

    staged.finalize()
    staged.discard()

    bucket.remove.assert_not_called()
    assert staged.staging_path.read_bytes() == b"staged document"


def test_supabase_upload_discard_preserves_staging_after_confirmed_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    staged = _staged_upload(tmp_path)

    staged.finalize()
    staged.discard()

    bucket.remove.assert_not_called()
    assert staged.staging_path.read_bytes() == b"staged document"


def test_supabase_provider_upload_exception_preserves_staging_without_remote_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.upload.side_effect = TimeoutError("simulated ambiguous provider timeout")
    _install_mock_bucket(monkeypatch, bucket)
    staged = _staged_upload(tmp_path)

    with pytest.raises(TimeoutError):
        staged.finalize()
    staged.discard()

    bucket.remove.assert_not_called()
    assert staged.staging_path.read_bytes() == b"staged document"


def test_supabase_upload_staging_cleanup_failure_preserves_staged_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    staged = _staged_upload(tmp_path)
    path_unlink = Path.unlink

    def fail_staging_unlink(path: Path, *, missing_ok: bool = False) -> None:
        if path == staged.staging_path:
            raise OSError("simulated staging cleanup failure")
        path_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_staging_unlink)

    staged.finalize()
    staged.complete()

    bucket.upload.assert_called_once()
    assert staged.staging_path.read_bytes() == b"staged document"
    assert "Unable to remove staged file" in caplog.text


def test_supabase_download_returns_bytes(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.download.return_value = b"remote document"
    _install_mock_bucket(monkeypatch, bucket)

    result = StorageService.get_file_bytes("b" * 64)

    assert result == b"remote document"
    bucket.download.assert_called_once_with("b" * 64)


def test_supabase_download_rejects_invalid_key_without_provider_call(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    create_client = Mock()
    monkeypatch.setattr(storage_service, "create_client", create_client)

    with pytest.raises(HTTPException) as error:
        StorageService.get_file_bytes("../document")

    assert error.value.status_code == 400
    create_client.assert_not_called()


def test_supabase_download_maps_provider_failure_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.download.side_effect = RuntimeError("provider detail")
    _install_mock_bucket(monkeypatch, bucket)

    with pytest.raises(HTTPException) as error:
        StorageService.get_file_bytes("c" * 64)

    assert error.value.status_code == 503
    assert error.value.detail == "Document storage is temporarily unavailable"
    assert "provider detail" not in caplog.text
    assert "error_type=RuntimeError" in caplog.text


@pytest.mark.parametrize(
    ("provider_error", "expected_status"),
    [
        (StorageApiError("Object not found", "NotFound", 404), 404),
        (StorageApiError("Access denied", "Unauthorized", 404), 503),
        (StorageApiError("Provider unavailable", "InternalError", 500), 503),
    ],
)
def test_supabase_download_classifies_provider_errors_safely(
    monkeypatch: pytest.MonkeyPatch,
    provider_error: Exception,
    expected_status: int,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.download.side_effect = provider_error
    _install_mock_bucket(monkeypatch, bucket)

    with pytest.raises(HTTPException) as error:
        StorageService.get_file_bytes("c" * 64)

    assert error.value.status_code == expected_status
    assert "Access denied" not in str(error.value.detail)
    assert "Provider unavailable" not in str(error.value.detail)


def test_supabase_delete_removes_object(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)

    assert StorageService.delete_file("d" * 64) is True

    bucket.remove.assert_called_once_with(["d" * 64])


def test_supabase_delete_rejects_invalid_key_without_provider_call(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    create_client = Mock()
    monkeypatch.setattr(storage_service, "create_client", create_client)

    assert StorageService.delete_file("not-a-storage-key") is False

    create_client.assert_not_called()


def test_supabase_delete_reports_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    bucket = Mock()
    bucket.remove.side_effect = RuntimeError("provider detail")
    _install_mock_bucket(monkeypatch, bucket)

    assert StorageService.delete_file("e" * 64) is False
    assert "provider detail" not in caplog.text
    assert "error_type=RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_authorized_supabase_download_returns_bytes_after_authorization(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    owner = make_user(
        db_session,
        email="supabase_download_owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    document = Document(
        title="Remote document",
        original_filename="private report.pdf",
        storage_key="f" * 64,
        file_size_bytes=19,
        mime_type="application/pdf",
        category="General",
        owner_id=owner.id,
        is_deleted=False,
    )
    db_session.add(document)
    db_session.commit()
    remote_download = Mock(return_value=b"%PDF-1.4 remote bytes")
    monkeypatch.setattr(StorageService, "get_file_bytes", remote_download)

    await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "supabase_download_owner@example.com",
            "password": VALID_PASSWORD,
        },
    )
    response = await async_client.get(
        f"/api/v1/documents/{document.id}/download"
    )

    assert response.status_code == 200
    assert response.content == b"%PDF-1.4 remote bytes"
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["cache-control"] == (
        "no-store, no-cache, must-revalidate, private"
    )
    assert response.headers["pragma"] == "no-cache"
    assert "attachment" in response.headers["content-disposition"]
    assert "private%20report.pdf" in response.headers["content-disposition"]
    remote_download.assert_called_once_with(document.storage_key)


@pytest.mark.asyncio
async def test_missing_document_download_returns_not_found(
    async_client: AsyncClient,
    db_session: Session,
):
    owner = make_user(
        db_session,
        email="missing_download_owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": VALID_PASSWORD},
    )

    response = await async_client.get(
        f"/api/v1/documents/{'0' * 32}/download"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Document not found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("storage_error", "expected_status", "expected_detail"),
    [
        (
            HTTPException(
                status_code=503,
                detail="Document storage is temporarily unavailable",
            ),
            503,
            "Document storage is temporarily unavailable",
        ),
        (
            HTTPException(
                status_code=404,
                detail="Document file not found in storage",
            ),
            404,
            "Document file not found in storage",
        ),
        (
            HTTPException(status_code=400, detail="Invalid storage key format"),
            400,
            "Invalid storage key format",
        ),
    ],
)
async def test_authorized_supabase_download_preserves_expected_storage_errors(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    storage_error: HTTPException,
    expected_status: int,
    expected_detail: str,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    owner = make_user(
        db_session,
        email=f"download_error_{expected_status}@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    document = Document(
        title="Storage error document",
        original_filename="storage-error.pdf",
        storage_key="a" * 64,
        file_size_bytes=10,
        mime_type="application/pdf",
        category="General",
        owner_id=owner.id,
        is_deleted=False,
    )
    db_session.add(document)
    db_session.commit()
    remote_download = Mock(side_effect=storage_error)
    monkeypatch.setattr(StorageService, "get_file_bytes", remote_download)
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": VALID_PASSWORD},
    )

    response = await async_client.get(
        f"/api/v1/documents/{document.id}/download"
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == expected_detail
    remote_download.assert_called_once_with(document.storage_key)


@pytest.mark.asyncio
async def test_supabase_upload_endpoint_uses_mocked_provider(
    async_client: AsyncClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private-storage"))
    bucket = Mock()
    _install_mock_bucket(monkeypatch, bucket)
    make_user(
        db_session,
        email="supabase_upload_owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "supabase_upload_owner@example.com",
            "password": VALID_PASSWORD,
        },
    )
    response = await async_client.post(
        "/api/v1/documents",
        files={
            "file": (
                "remote.pdf",
                b"%PDF-1.4 mocked remote upload",
                "application/pdf",
            )
        },
        data={"title": "Remote upload"},
    )

    assert response.status_code == 201
    bucket.upload.assert_called_once()
    uploaded_key, staging_path = bucket.upload.call_args.args
    assert len(uploaded_key) == 64
    assert Path(staging_path).exists() is False
    document = db_session.query(Document).filter_by(id=response.json()["id"]).one()
    operation = (
        db_session.query(StorageOperation)
        .filter_by(operation_type="upload", storage_key=uploaded_key)
        .one()
    )
    storage_object = db_session.get(StorageObject, uploaded_key)
    upload_request = (
        db_session.query(UploadRequest)
        .filter_by(operation_id=operation.id)
        .one()
    )

    assert (
        bucket.upload.call_args.kwargs["file_options"]["metadata"][
            "trustvault_operation_id"
        ]
        == operation.id
    )
    assert operation.status == "completed"
    assert storage_object is not None
    assert storage_object.state == "active"
    assert (storage_object.owner_type, storage_object.owner_id) == (
        "document",
        document.id,
    )
    assert upload_request.status == "completed"
    assert upload_request.document_id == document.id


@pytest.mark.asyncio
async def test_supabase_upload_failure_logs_only_sanitized_error_type(
    async_client: AsyncClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "private-storage"))
    bucket = Mock()
    bucket.upload.side_effect = RuntimeError("signed-url-and-key-must-not-be-logged")
    _install_mock_bucket(monkeypatch, bucket)
    make_user(
        db_session,
        email="supabase_failed_upload_owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "supabase_failed_upload_owner@example.com",
            "password": VALID_PASSWORD,
        },
    )
    response = await async_client.post(
        "/api/v1/documents",
        files={
            "file": (
                "remote-failure.pdf",
                b"%PDF-1.4 failed remote upload",
                "application/pdf",
            )
        },
        data={"title": "Failed remote upload"},
    )

    assert response.status_code == 503
    assert "signed-url-and-key-must-not-be-logged" not in caplog.text
    assert "error_type=RuntimeError" in caplog.text
    bucket.remove.assert_not_called()
    staged_files = list((tmp_path / "private-storage" / ".staging").glob("*.part"))
    assert len(staged_files) == 1
    assert staged_files[0].read_bytes() == b"%PDF-1.4 failed remote upload"


@pytest.mark.asyncio
async def test_denied_supabase_download_does_not_call_remote_storage(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    owner = make_user(
        db_session,
        email="supabase_private_owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    make_user(
        db_session,
        email="supabase_private_viewer@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    document = Document(
        title="Private remote document",
        original_filename="private.pdf",
        storage_key="0" * 64,
        file_size_bytes=10,
        mime_type="application/pdf",
        category="General",
        owner_id=owner.id,
        is_deleted=False,
    )
    db_session.add(document)
    db_session.commit()
    remote_download = Mock(return_value=b"must not be returned")
    monkeypatch.setattr(StorageService, "get_file_bytes", remote_download)

    await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "supabase_private_viewer@example.com",
            "password": VALID_PASSWORD,
        },
    )
    response = await async_client.get(
        f"/api/v1/documents/{document.id}/download"
    )

    assert response.status_code == 404
    remote_download.assert_not_called()
    assert db_session.query(Document).filter_by(id=document.id).one().owner_id == owner.id
