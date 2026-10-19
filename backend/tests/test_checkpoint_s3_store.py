"""
Day 8 Tests for the External S3 Checkpoint Adapter

The adapter is exercised through a deterministic fake S3 client. No boto3,
cloud credentials, network access, or real bucket is required. Tests cover
configuration validation, successful writes and reads, idempotency, conflicts,
rollback, provider failure mapping, tampered objects, pagination, conditional
writes, encryption/object-lock parameters, fail-closed service/API behavior,
and secret-leakage checks.
"""

import builtins
import json
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.app.api.audit import get_checkpoint_store
from backend.app.config import Settings, settings
from backend.app.main import app
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.services.checkpoint_service import CheckpointCreationError
from backend.app.services.checkpoint_store import (
    AUDIT_STREAM_ID,
    CHECKPOINT_FORMAT_VERSION,
    AuditCheckpoint,
    CheckpointConflictError,
    CheckpointIntegrityError,
    CheckpointRollbackError,
    CheckpointStoreAccessDeniedError,
    CheckpointStoreUnavailableError,
    S3CheckpointStore,
    UnavailableCheckpointStore,
    compute_checkpoint_tag,
    create_s3_client,
    serialize_checkpoint,
)
from backend.tests.test_audit_checkpoints import (
    CHECKPOINT_KEY,
    _add_event,
    _create_checkpoint,
    _login_admin,
    _rewrite_chain,
    _verify_checkpoint,
)

S3_BUCKET = "trustvault-test-audit-bucket"
S3_PREFIX = "anchors"
CHECKPOINT_ENDPOINTS = (
    "/api/v1/admin/audit/checkpoints",
    "/api/v1/admin/audit/checkpoints/verify",
)


class FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._data
        return self._data[:size]


class FakeS3Error(Exception):
    """ClientError-like exception with an AWS error code."""

    def __init__(self, code: str, message: str = "fake s3 error") -> None:
        super().__init__(message)
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }


class EndpointConnectionError(Exception):
    """Duck-typed transport failure matched by class name."""


class NoCredentialsError(Exception):
    """Duck-typed botocore credential failure matched by class name."""


class SSLError(Exception):
    """Duck-typed TLS failure matched by class name."""


class ProxyConnectionError(Exception):
    """Duck-typed proxy failure matched by class name."""


class BotoCoreError(Exception):
    """Duck-typed botocore base error."""


class ParamValidationError(BotoCoreError):
    """Duck-typed SDK validation failure (e.g. old client without IfNoneMatch)."""


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_requests: list[dict] = []
        self.list_requests: list[dict] = []
        self.page_size: int | None = None
        self.fail_list: Exception | None = None
        self.fail_get: Exception | None = None
        self.fail_put: Exception | None = None
        self.put_status_code = 200
        self.repeat_list_token = False

    def list_objects_v2(self, **request):
        self.list_requests.append(dict(request))
        if self.fail_list is not None:
            raise self.fail_list
        prefix = request.get("Prefix", "")
        keys = sorted(key for key in self.objects if key.startswith(prefix))
        token = request.get("ContinuationToken")
        if token == "repeated-token":
            start = 0
        else:
            start = int(token) if token else 0
        page_size = self.page_size or len(keys) or 1
        page = keys[start : start + page_size]
        truncated = start + page_size < len(keys)
        response = {
            "Contents": [{"Key": key} for key in page],
            "IsTruncated": truncated,
        }
        if truncated:
            response["NextContinuationToken"] = (
                "repeated-token" if self.repeat_list_token else str(start + page_size)
            )
        return response

    def get_object(self, **request):
        if self.fail_get is not None:
            raise self.fail_get
        key = request["Key"]
        if key not in self.objects:
            raise FakeS3Error("NoSuchKey")
        return {
            "Body": FakeBody(self.objects[key]),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def put_object(self, **request):
        self.put_requests.append(dict(request))
        if self.fail_put is not None:
            raise self.fail_put
        key = request["Key"]
        if request.get("IfNoneMatch") == "*" and key in self.objects:
            raise FakeS3Error("PreconditionFailed")
        self.objects[key] = request["Body"]
        return {
            "ETag": '"fake-etag"',
            "ResponseMetadata": {"HTTPStatusCode": self.put_status_code},
        }


def _checkpoint(
    sequence_number: int,
    *,
    record_hash: str = "a" * 64,
    previous_checkpoint_hmac: str | None = None,
    created_at: datetime | None = None,
) -> AuditCheckpoint:
    return AuditCheckpoint(
        format_version=CHECKPOINT_FORMAT_VERSION,
        stream_id=AUDIT_STREAM_ID,
        sequence_number=sequence_number,
        record_hash=record_hash,
        created_at=created_at or datetime.now(UTC),
        previous_checkpoint_hmac=previous_checkpoint_hmac,
    )


@pytest.fixture
def fake_s3_client() -> FakeS3Client:
    return FakeS3Client()


@pytest.fixture
def s3_store(fake_s3_client: FakeS3Client) -> S3CheckpointStore:
    return S3CheckpointStore(
        S3_BUCKET,
        hmac_key=CHECKPOINT_KEY,
        client=fake_s3_client,
        prefix=S3_PREFIX,
    )


@pytest_asyncio.fixture
async def api_s3_store(
    async_client: AsyncClient,
    s3_store: S3CheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
) -> S3CheckpointStore:
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")
    app.dependency_overrides[get_checkpoint_store] = lambda: s3_store
    yield s3_store
    app.dependency_overrides.pop(get_checkpoint_store, None)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


def test_s3_settings_require_bucket_region_and_hmac_key():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            AUDIT_ANCHOR_MODE="s3",
            AUDIT_ANCHOR_HMAC_KEY="k" * 64,
            AUDIT_ANCHOR_S3_REGION="us-east-1",
        )

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            AUDIT_ANCHOR_MODE="s3",
            AUDIT_ANCHOR_HMAC_KEY="k" * 64,
            AUDIT_ANCHOR_S3_BUCKET="audit-bucket",
        )

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            AUDIT_ANCHOR_MODE="s3",
            AUDIT_ANCHOR_HMAC_KEY="short",
            AUDIT_ANCHOR_S3_BUCKET="audit-bucket",
            AUDIT_ANCHOR_S3_REGION="us-east-1",
        )


def test_s3_settings_reject_plaintext_endpoint_in_production():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            AUDIT_ANCHOR_MODE="s3",
            AUDIT_ANCHOR_HMAC_KEY="k" * 64,
            AUDIT_ANCHOR_S3_BUCKET="audit-bucket",
            AUDIT_ANCHOR_S3_REGION="us-east-1",
            AUDIT_ANCHOR_S3_ENDPOINT_URL="http://minio.internal:9000",
        )


def test_s3_settings_accept_explicit_provider_configuration():
    configured = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        AUDIT_ANCHOR_MODE="s3",
        AUDIT_ANCHOR_HMAC_KEY="k" * 64,
        AUDIT_ANCHOR_S3_BUCKET="audit-bucket",
        AUDIT_ANCHOR_S3_REGION="us-east-1",
        AUDIT_ANCHOR_S3_ENDPOINT_URL="https://objects.example.invalid",
        AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE="COMPLIANCE",
    )
    assert configured.AUDIT_ANCHOR_MODE == "s3"
    assert configured.AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE == "COMPLIANCE"


def test_create_s3_client_returns_none_without_boto3(monkeypatch: pytest.MonkeyPatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3" or name.startswith("botocore"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert create_s3_client(region="us-east-1") is None


def test_api_factory_fails_closed_without_provider_client(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_BUCKET", S3_BUCKET)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_HMAC_KEY", "k" * 64)
    monkeypatch.setattr(
        "backend.app.api.audit.create_s3_client", lambda **kwargs: None
    )

    store = get_checkpoint_store()
    assert isinstance(store, UnavailableCheckpointStore)
    with pytest.raises(CheckpointStoreUnavailableError):
        store.read_latest()


def test_api_factory_fails_closed_when_client_creation_raises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_BUCKET", S3_BUCKET)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_HMAC_KEY", "k" * 64)

    def explode(**kwargs):
        raise ValueError(f"invalid endpoint for {S3_BUCKET}")

    monkeypatch.setattr("backend.app.api.audit.create_s3_client", explode)

    store = get_checkpoint_store()
    assert isinstance(store, UnavailableCheckpointStore)
    with pytest.raises(CheckpointStoreUnavailableError):
        store.read_latest()
    assert S3_BUCKET not in caplog.text
    assert "invalid endpoint" not in caplog.text


def test_api_factory_builds_s3_store_from_settings(
    fake_s3_client: FakeS3Client, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_BUCKET", S3_BUCKET)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_REGION", "eu-west-1")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_PREFIX", S3_PREFIX)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_HMAC_KEY", "k" * 64)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_ENDPOINT_URL", "")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE", "")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_KMS_KEY_ID", "")
    monkeypatch.setattr(
        "backend.app.api.audit.create_s3_client", lambda **kwargs: fake_s3_client
    )

    store = get_checkpoint_store()
    assert isinstance(store, S3CheckpointStore)
    checkpoint = _checkpoint(1)
    stored, created = store.write_checkpoint(checkpoint)
    assert created is True
    assert store.read_latest() == stored


# ─────────────────────────────────────────────────────────────────────────────
# Store: happy path, idempotency, progression
# ─────────────────────────────────────────────────────────────────────────────


def test_s3_store_write_read_roundtrip(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    checkpoint = _checkpoint(3)
    stored, created = s3_store.write_checkpoint(checkpoint)

    assert created is True
    assert stored.integrity_tag is not None
    assert s3_store.read_latest() == stored
    request = fake_s3_client.put_requests[0]
    assert request["Bucket"] == S3_BUCKET
    assert request["Key"] == f"{S3_PREFIX}/checkpoint-00000000000000000003.json"
    assert request["IfNoneMatch"] == "*"
    assert request["ContentType"] == "application/json"


def test_s3_store_idempotent_retry(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    first, created = s3_store.write_checkpoint(_checkpoint(2))
    assert created is True

    second, created_again = s3_store.write_checkpoint(_checkpoint(2))
    assert created_again is False
    assert second.integrity_tag == first.integrity_tag
    assert len(fake_s3_client.objects) == 1


def test_s3_store_rejects_conflict_rollback_and_broken_link(
    s3_store: S3CheckpointStore,
):
    stored, _ = s3_store.write_checkpoint(_checkpoint(3, record_hash="d" * 64))

    with pytest.raises(CheckpointRollbackError):
        s3_store.write_checkpoint(_checkpoint(2))

    with pytest.raises(CheckpointConflictError):
        s3_store.write_checkpoint(_checkpoint(3, record_hash="e" * 64))

    advanced, created = s3_store.write_checkpoint(
        _checkpoint(
            4,
            record_hash="f" * 64,
            previous_checkpoint_hmac=stored.integrity_tag,
        )
    )
    assert created is True
    assert advanced.sequence_number == 4

    with pytest.raises(CheckpointConflictError):
        s3_store.write_checkpoint(
            _checkpoint(5, record_hash="9" * 64, previous_checkpoint_hmac="0" * 64)
        )

    fresh_store = S3CheckpointStore(
        "another-bucket",
        hmac_key=CHECKPOINT_KEY,
        client=FakeS3Client(),
    )
    with pytest.raises(CheckpointConflictError):
        fresh_store.write_checkpoint(_checkpoint(1, previous_checkpoint_hmac="0" * 64))


def test_s3_store_handles_lost_conditional_write_race(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client, monkeypatch: pytest.MonkeyPatch
):
    stored, _ = s3_store.write_checkpoint(_checkpoint(1, record_hash="a" * 64))

    monkeypatch.setattr(s3_store, "read_latest", lambda: None)
    idempotent, created = s3_store.write_checkpoint(_checkpoint(1, record_hash="a" * 64))
    assert created is False
    assert idempotent.integrity_tag == stored.integrity_tag

    with pytest.raises(CheckpointConflictError):
        s3_store.write_checkpoint(_checkpoint(1, record_hash="b" * 64))

    fake_s3_client.fail_get = FakeS3Error("AccessDenied")
    with pytest.raises(CheckpointStoreAccessDeniedError):
        s3_store.write_checkpoint(_checkpoint(1, record_hash="b" * 64))
    fake_s3_client.fail_get = None

    assert len(fake_s3_client.objects) == 1


def test_s3_store_applies_encryption_and_object_lock(fake_s3_client: FakeS3Client):
    store = S3CheckpointStore(
        S3_BUCKET,
        hmac_key=CHECKPOINT_KEY,
        client=fake_s3_client,
        prefix=S3_PREFIX,
        object_lock_mode="COMPLIANCE",
        object_lock_retain_days=7,
        kms_key_id="alias/trustvault-audit",
    )
    before = datetime.now(UTC)
    store.write_checkpoint(_checkpoint(1))

    request = fake_s3_client.put_requests[0]
    assert request["ServerSideEncryption"] == "aws:kms"
    assert request["SSEKMSKeyId"] == "alias/trustvault-audit"
    assert request["ObjectLockMode"] == "COMPLIANCE"
    assert request["ObjectLockRetainUntilDate"].tzinfo is not None
    assert request["ObjectLockRetainUntilDate"] > before


def test_s3_store_rejects_invalid_construction(tmp_path):
    with pytest.raises(ValueError):
        S3CheckpointStore("", hmac_key=CHECKPOINT_KEY, client=FakeS3Client())
    with pytest.raises(ValueError):
        S3CheckpointStore(S3_BUCKET, hmac_key=b"short", client=FakeS3Client())
    with pytest.raises(ValueError):
        S3CheckpointStore(
            S3_BUCKET,
            hmac_key=CHECKPOINT_KEY,
            client=FakeS3Client(),
            object_lock_mode="NOT_A_MODE",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Store: provider failures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "error",
    [
        FakeS3Error("NoSuchBucket"),
        FakeS3Error("SlowDown"),
        FakeS3Error("InternalError"),
        FakeS3Error("RequestTimeout"),
        FakeS3Error("ConditionalRequestConflict"),
        EndpointConnectionError("connection failed"),
        SSLError("tls handshake failed"),
        ProxyConnectionError("proxy refused connection"),
        NoCredentialsError("no credentials"),
        ParamValidationError("unknown parameter IfNoneMatch"),
    ],
)
def test_s3_store_maps_unavailable_errors(
    s3_store: S3CheckpointStore,
    fake_s3_client: FakeS3Client,
    error: Exception,
):
    fake_s3_client.fail_list = error
    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.read_latest()


def test_s3_store_maps_get_and_put_failures(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    stored, _ = s3_store.write_checkpoint(_checkpoint(1, record_hash="b" * 64))
    fake_s3_client.fail_get = EndpointConnectionError("connection failed")
    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.read_latest()

    fake_s3_client.fail_get = None
    fake_s3_client.fail_put = FakeS3Error("SlowDown")
    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.write_checkpoint(
            _checkpoint(
                2,
                record_hash="c" * 64,
                previous_checkpoint_hmac=stored.integrity_tag,
            )
        )

    fake_s3_client.fail_put = NoCredentialsError("no credentials")
    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.write_checkpoint(
            _checkpoint(
                2,
                record_hash="c" * 64,
                previous_checkpoint_hmac=stored.integrity_tag,
            )
        )


def test_s3_store_maps_access_denied_for_read_and_write(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    fake_s3_client.fail_list = FakeS3Error("AccessDenied")
    with pytest.raises(CheckpointStoreAccessDeniedError):
        s3_store.read_latest()

    fake_s3_client.fail_list = None
    fake_s3_client.fail_put = FakeS3Error("AccessDenied")
    with pytest.raises(CheckpointStoreAccessDeniedError):
        s3_store.write_checkpoint(_checkpoint(1))

    fake_s3_client.fail_put = None
    s3_store.write_checkpoint(_checkpoint(1))
    fake_s3_client.fail_get = FakeS3Error("403")
    with pytest.raises(CheckpointStoreAccessDeniedError):
        s3_store.read_latest()


def test_s3_store_maps_non_200_put_response(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    fake_s3_client.put_status_code = 500
    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.write_checkpoint(_checkpoint(1))


# ─────────────────────────────────────────────────────────────────────────────
# Store: malformed and tampered objects
# ─────────────────────────────────────────────────────────────────────────────


def test_s3_store_detects_tampered_checkpoint(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    valid = serialize_checkpoint(CHECKPOINT_KEY, _checkpoint(1))
    document = json.loads(valid)
    document["payload"]["record_hash"] = "f" * 64
    key = s3_store._object_key(1)
    fake_s3_client.objects[key] = json.dumps(document).encode("utf-8")

    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()


def test_s3_store_detects_malformed_oversized_and_incomplete_objects(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    key = s3_store._object_key(1)
    fake_s3_client.objects[key] = b"{not-json"
    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()

    fake_s3_client.objects[key] = b"x" * (65 * 1024)
    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()

    payload = {"format_version": CHECKPOINT_FORMAT_VERSION}
    document = {
        "payload": payload,
        "hmac": compute_checkpoint_tag(CHECKPOINT_KEY, payload),
    }
    fake_s3_client.objects[key] = json.dumps(document).encode("utf-8")
    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()


def test_s3_store_rejects_object_key_payload_mismatch(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    fake_s3_client.objects[s3_store._object_key(5)] = serialize_checkpoint(
        CHECKPOINT_KEY, _checkpoint(4)
    ).encode("utf-8")

    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()


def test_s3_store_missing_object_after_listing_is_integrity_failure(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    fake_s3_client.objects[s3_store._object_key(1)] = serialize_checkpoint(
        CHECKPOINT_KEY, _checkpoint(1)
    ).encode("utf-8")
    fake_s3_client.fail_get = FakeS3Error("NoSuchKey")

    with pytest.raises(CheckpointIntegrityError):
        s3_store.read_latest()


def test_s3_store_paginates_and_ignores_unrelated_objects(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    for sequence in (1, 2, 5):
        store = s3_store
        client_checkpoint = _checkpoint(sequence, record_hash=f"{sequence:064x}")
        fake_s3_client.objects[store._object_key(sequence)] = serialize_checkpoint(
            CHECKPOINT_KEY, client_checkpoint
        ).encode("utf-8")
    fake_s3_client.objects[f"{S3_PREFIX}/notes.txt"] = b"ignore me"
    fake_s3_client.objects[
        f"{S3_PREFIX}/nested/checkpoint-00000000000000000009.json"
    ] = serialize_checkpoint(
        CHECKPOINT_KEY, _checkpoint(9, record_hash="9" * 64)
    ).encode("utf-8")
    fake_s3_client.objects["other-prefix/checkpoint-00000000000000000009.json"] = b"{}"
    fake_s3_client.page_size = 1

    latest = s3_store.read_latest()
    assert latest is not None
    assert latest.sequence_number == 5
    assert len(fake_s3_client.list_requests) >= 2


def test_s3_store_rejects_repeated_listing_token(
    s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    fake_s3_client.objects[s3_store._object_key(1)] = serialize_checkpoint(
        CHECKPOINT_KEY, _checkpoint(1)
    ).encode("utf-8")
    fake_s3_client.objects[s3_store._object_key(2)] = serialize_checkpoint(
        CHECKPOINT_KEY, _checkpoint(2)
    ).encode("utf-8")
    fake_s3_client.page_size = 1
    fake_s3_client.repeat_list_token = True

    with pytest.raises(CheckpointStoreUnavailableError):
        s3_store.read_latest()


# ─────────────────────────────────────────────────────────────────────────────
# Service: chain integration and fail-closed behavior
# ─────────────────────────────────────────────────────────────────────────────


def test_s3_service_create_and_verify_valid_chain(
    db_session: Session, s3_store: S3CheckpointStore
):
    for index in range(3):
        _add_event(db_session, action=f"test.s3.valid.{index}")

    created = _create_checkpoint(db_session, s3_store)
    assert created.already_present is False

    result = _verify_checkpoint(db_session, s3_store)
    assert result.status == "VALID"
    assert result.checkpoint_sequence == 3
    assert result.chain_head_sequence == 3


def test_s3_service_detects_rewrite_at_checkpoint(
    db_session: Session, s3_store: S3CheckpointStore
):
    for index in range(3):
        _add_event(db_session, action=f"test.s3.rewrite.{index}")
    _create_checkpoint(db_session, s3_store)

    _rewrite_chain(db_session, start_sequence=2, action="test.s3.rewritten")

    result = _verify_checkpoint(db_session, s3_store)
    assert result.status == "INVALID"
    assert "does not match the checkpoint" in (result.failure_reason or "")


def test_s3_service_access_denied_never_returns_valid(
    db_session: Session, s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    _add_event(db_session, action="test.s3.denied")
    fake_s3_client.fail_list = FakeS3Error("AccessDenied")

    result = _verify_checkpoint(db_session, s3_store)
    assert result.status == "INCOMPLETE"
    assert result.status != "VALID"
    assert "denied" in (result.failure_reason or "").lower()

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, s3_store)
    assert exc.value.reason == "anchor_access_denied"


def test_s3_service_unavailable_reports_incomplete(
    db_session: Session, s3_store: S3CheckpointStore, fake_s3_client: FakeS3Client
):
    _add_event(db_session, action="test.s3.unavailable")
    fake_s3_client.fail_list = EndpointConnectionError("connection failed")

    result = _verify_checkpoint(db_session, s3_store)
    assert result.status == "INCOMPLETE"
    assert result.status != "VALID"

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, s3_store)
    assert exc.value.reason == "anchor_unavailable"


# ─────────────────────────────────────────────────────────────────────────────
# API: external adapter behavior, no leakage, health
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_s3_api_create_inspect_verify(
    async_client: AsyncClient,
    db_session: Session,
    api_s3_store: S3CheckpointStore,
):
    await _login_admin(async_client, db_session, email="admin_s3@example.com")

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 201, create.text
    assert create.json()["anchor_mode"] == "s3"

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 200, info.text
    info_data = info.json()
    assert info_data["available"] is True
    assert info_data["anchor_mode"] == "s3"

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    verify_data = verify.json()
    assert verify_data["status"] == "VALID"
    assert verify_data["anchor_mode"] == "s3"

    serialized = json.dumps([create.json(), info_data, verify_data])
    assert S3_BUCKET not in serialized
    assert S3_PREFIX not in serialized
    assert "record_hash" not in serialized
    assert "hmac" not in serialized


@pytest.mark.asyncio
async def test_s3_info_reports_unavailable_when_configured_but_empty(
    async_client: AsyncClient,
    db_session: Session,
    api_s3_store: S3CheckpointStore,
):
    await _login_admin(async_client, db_session, email="admin_s3_empty@example.com")

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 200, info.text
    data = info.json()
    assert data["available"] is False
    assert data["anchor_mode"] == "s3"
    assert data["stream_id"] is None
    assert data["sequence_number"] is None
    assert data["created_at"] is None
    assert data["format_version"] is None


@pytest.mark.asyncio
async def test_s3_api_access_denied_fails_closed_without_leaking_provider_details(
    async_client: AsyncClient,
    db_session: Session,
    api_s3_store: S3CheckpointStore,
    fake_s3_client: FakeS3Client,
    caplog: pytest.LogCaptureFixture,
):
    await _login_admin(async_client, db_session, email="admin_s3_denied@example.com")
    fake_s3_client.fail_put = FakeS3Error("AccessDenied")

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 503
    assert create.headers["cache-control"] == "no-store"
    detail = create.json()["detail"]
    assert detail == "Checkpoint creation refused: checkpoint store access was denied"
    assert S3_BUCKET not in detail
    assert S3_PREFIX not in detail

    db_session.expire_all()
    failure = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "audit.checkpoint_created",
            AuditEvent.outcome == AuditOutcome.FAILURE,
        )
        .one()
    )
    assert json.loads(failure.details) == {"reason": "anchor_access_denied"}

    fake_s3_client.fail_list = FakeS3Error("AccessDenied")
    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    verify_data = verify.json()
    assert verify_data["status"] == "INCOMPLETE"
    assert verify_data["is_valid"] is False
    assert "denied" in (verify_data["failure_reason"] or "").lower()

    assert S3_BUCKET not in caplog.text
    assert S3_PREFIX not in caplog.text


@pytest.mark.asyncio
async def test_s3_api_unavailable_returns_generic_503(
    async_client: AsyncClient,
    db_session: Session,
    api_s3_store: S3CheckpointStore,
    fake_s3_client: FakeS3Client,
):
    await _login_admin(async_client, db_session, email="admin_s3_unavailable@example.com")
    fake_s3_client.fail_list = EndpointConnectionError("connection failed")

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 503
    assert create.json()["detail"] == "Checkpoint anchoring is not configured or unavailable"

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 503
    assert info.json()["detail"] == "Checkpoint store unavailable"

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200
    assert verify.json()["status"] == "INCOMPLETE"


@pytest.mark.asyncio
async def test_health_reports_external_provider_configuration_only(
    async_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")

    response = await async_client.get("/health")
    assert response.status_code == 200
    anchor = response.json()["components"]["audit_anchor"]
    assert anchor == {
        "status": "external_provider_configured",
        "mode": "s3",
        "independent": True,
    }


@pytest.mark.asyncio
async def test_s3_checkpoint_endpoints_still_require_admin(
    async_client: AsyncClient, api_s3_store: S3CheckpointStore
):
    for path in CHECKPOINT_ENDPOINTS:
        response = await async_client.get(path)
        assert response.status_code == 401, path

    assert api_s3_store.read_latest() is None
