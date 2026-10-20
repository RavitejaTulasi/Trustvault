"""
Opt-In Real AWS S3 Integration Tests for the External Checkpoint Adapter

These tests use real boto3 clients, real AWS S3 requests, and an explicitly
approved test bucket. They never run by default: the module is skipped unless
TRUSTVAULT_AWS_INTEGRATION=1 is set together with the documented variables, and
there is no fake-client fallback. When the opt-in gate is enabled but the
environment is not ready, the tests fail with a sanitized readiness message
instead of silently passing. See docs/AWS_INTEGRATION_TESTING.md for
prerequisites, least-privilege permissions, exact commands, cleanup, and the
honest limits of what these tests prove.

No AWS credentials, bucket names, or account identifiers are stored in this
repository. Everything is read from the operator's environment at run time.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import UserRole
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
    create_s3_client,
)
from backend.tests.test_audit_checkpoints import (
    CHECKPOINT_KEY,
    _add_event,
    _head_sequence,
    _login_admin,
    _rewrite_chain,
)
from backend.tests.test_auth import VALID_PASSWORD, make_user

logger = logging.getLogger(__name__)

RUN_ENV_VAR = "TRUSTVAULT_AWS_INTEGRATION"
BUCKET_ENV_VAR = "TRUSTVAULT_AWS_TEST_BUCKET"
APPROVAL_ENV_VAR = "TRUSTVAULT_AWS_TEST_BUCKET_APPROVAL"
REGION_ENV_VAR = "TRUSTVAULT_AWS_TEST_REGION"
PREFIX_ENV_VAR = "TRUSTVAULT_AWS_TEST_PREFIX"
DEFAULT_RUN_PREFIX = "trustvault-integration-tests"

PROHIBITED_BUCKET_MARKERS = ("prod", "production")
CHECKPOINT_ENDPOINTS = (
    "/api/v1/admin/audit/checkpoints",
    "/api/v1/admin/audit/checkpoints/verify",
)
REPO_ROOT = Path(__file__).resolve().parents[2]

_INTEGRATION_ENABLED = os.environ.get(RUN_ENV_VAR) == "1"

pytestmark = [
    pytest.mark.aws_integration,
    pytest.mark.skipif(
        not _INTEGRATION_ENABLED,
        reason=(
            "Real AWS S3 integration tests are opt-in. Set "
            f"{RUN_ENV_VAR}=1 with {BUCKET_ENV_VAR}, {APPROVAL_ENV_VAR}, and "
            f"{REGION_ENV_VAR}; see docs/AWS_INTEGRATION_TESTING.md."
        ),
    ),
]


@dataclass(frozen=True)
class AwsTestContext:
    bucket: str
    region: str
    run_prefix: str
    client: Any


def _require_boto3() -> Any:
    try:
        import boto3
    except ImportError:
        pytest.fail(
            "boto3>=1.36.0 is required when the AWS integration gate is enabled; "
            "install backend/requirements.txt in the selected environment.",
            pytrace=False,
        )
    return boto3


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str):
                return code
    return None


def _verify_bucket_ready(context: AwsTestContext) -> None:
    try:
        context.client.list_objects_v2(
            Bucket=context.bucket,
            Prefix=f"{context.run_prefix}/",
            MaxKeys=1,
        )
    except Exception as exc:  # noqa: BLE001 - any readiness failure is reported sanitized
        pytest.fail(
            "AWS test bucket readiness check failed "
            f"({type(exc).__name__}); verify the configured credentials, region, "
            "and bucket permissions before rerunning. See "
            "docs/AWS_INTEGRATION_TESTING.md.",
            pytrace=False,
        )


def _cleanup_run_prefix(context: AwsTestContext) -> None:
    list_prefix = f"{context.run_prefix}/"
    try:
        paginator = context.client.get_paginator("list_objects_v2")
        keys = [
            item["Key"]
            for page in paginator.paginate(Bucket=context.bucket, Prefix=list_prefix)
            for item in page.get("Contents", [])
        ]
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask test results
        logger.warning(
            "AWS integration cleanup could not list its run prefix (%s); "
            "objects may remain in the test bucket",
            type(exc).__name__,
        )
        return

    removed = 0
    leftovers = 0
    for key in keys:
        if not isinstance(key, str) or not key.startswith(list_prefix):
            continue
        try:
            context.client.delete_object(Bucket=context.bucket, Key=key)
            removed += 1
        except Exception:  # noqa: BLE001 - count leftovers instead of failing teardown
            leftovers += 1
    if leftovers:
        logger.warning(
            "AWS integration cleanup left %d object(s) under its run prefix; "
            "delete them manually or wait for Object Lock retention to expire",
            leftovers,
        )
    logger.info("AWS integration cleanup removed %d test object(s)", removed)


@pytest.fixture(scope="module")
def aws_context() -> Iterator[AwsTestContext]:
    _require_boto3()

    bucket = os.environ.get(BUCKET_ENV_VAR, "").strip()
    approval = os.environ.get(APPROVAL_ENV_VAR, "").strip()
    region = os.environ.get(REGION_ENV_VAR, "").strip()
    if not bucket or not region:
        pytest.fail(
            f"{BUCKET_ENV_VAR} and {REGION_ENV_VAR} must both be set when "
            f"{RUN_ENV_VAR}=1; see docs/AWS_INTEGRATION_TESTING.md.",
            pytrace=False,
        )
    if approval != bucket:
        pytest.fail(
            f"{APPROVAL_ENV_VAR} must exactly match {BUCKET_ENV_VAR}; refusing to "
            "run and clean up against an unapproved bucket.",
            pytrace=False,
        )
    lowered = bucket.lower()
    if any(marker in lowered for marker in PROHIBITED_BUCKET_MARKERS):
        pytest.fail(
            "Refusing to run integration tests against a production-looking "
            "bucket name; use a dedicated test bucket.",
            pytrace=False,
        )
    configured_bucket = settings.AUDIT_ANCHOR_S3_BUCKET.strip()
    if configured_bucket and configured_bucket == bucket:
        pytest.fail(
            "Refusing to run integration tests against the bucket configured for "
            "application anchoring; use a dedicated test bucket.",
            pytrace=False,
        )

    prefix_root = (
        os.environ.get(PREFIX_ENV_VAR, DEFAULT_RUN_PREFIX).strip().strip("/")
        or DEFAULT_RUN_PREFIX
    )
    run_prefix = (
        f"{prefix_root}/{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:12]}"
    )

    client = create_s3_client(region=region)
    if client is None:
        pytest.fail(
            "The application factory could not import boto3 even though the "
            "integration gate is enabled; install backend/requirements.txt.",
            pytrace=False,
        )

    context = AwsTestContext(
        bucket=bucket,
        region=region,
        run_prefix=run_prefix,
        client=client,
    )
    _verify_bucket_ready(context)
    yield context
    _cleanup_run_prefix(context)


def _scoped_prefix(context: AwsTestContext, name: str) -> str:
    return f"{context.run_prefix}/{name}"


def _use_test_bucket_settings(
    monkeypatch: pytest.MonkeyPatch,
    context: AwsTestContext,
    prefix: str,
    *,
    endpoint_url: str = "",
) -> None:
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "s3")
    monkeypatch.setattr(
        settings, "AUDIT_ANCHOR_HMAC_KEY", CHECKPOINT_KEY.decode("utf-8")
    )
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_BUCKET", context.bucket)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_REGION", context.region)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_PREFIX", prefix)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_ENDPOINT_URL", endpoint_url)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_KMS_KEY_ID", "")
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE", "")


def _real_store(context: AwsTestContext, prefix: str) -> S3CheckpointStore:
    return S3CheckpointStore(
        context.bucket,
        hmac_key=CHECKPOINT_KEY,
        client=context.client,
        prefix=prefix,
    )


def _checkpoint(
    sequence_number: int,
    record_hash: str,
    *,
    previous_checkpoint_hmac: str | None = None,
) -> AuditCheckpoint:
    return AuditCheckpoint(
        format_version=CHECKPOINT_FORMAT_VERSION,
        stream_id=AUDIT_STREAM_ID,
        sequence_number=sequence_number,
        record_hash=record_hash,
        created_at=datetime.now(UTC),
        previous_checkpoint_hmac=previous_checkpoint_hmac,
    )


def _assert_prefix_is_empty(context: AwsTestContext, prefix: str) -> None:
    response = context.client.list_objects_v2(
        Bucket=context.bucket, Prefix=f"{prefix}/"
    )
    assert response.get("Contents", []) == []


def test_conditional_put_object_duplicate_is_rejected(aws_context: AwsTestContext):
    """Prove the installed SDK performs S3 conditional writes (documented pin)."""
    from botocore.exceptions import ClientError

    key = f"{aws_context.run_prefix}/conditional-write-probe.json"
    body = b'{"probe": "conditional-write"}'
    aws_context.client.put_object(
        Bucket=aws_context.bucket, Key=key, Body=body, IfNoneMatch="*"
    )

    with pytest.raises(ClientError) as excinfo:
        aws_context.client.put_object(
            Bucket=aws_context.bucket, Key=key, Body=body, IfNoneMatch="*"
        )

    assert _error_code(excinfo.value) == "PreconditionFailed"


def test_real_store_write_read_idempotency_and_refusals(aws_context: AwsTestContext):
    prefix = _scoped_prefix(aws_context, "adapter-roundtrip")
    store = _real_store(aws_context, prefix)

    first = _checkpoint(1, "a" * 64)
    stored, created = store.write_checkpoint(first)
    assert created is True
    assert stored.integrity_tag is not None
    assert store.read_latest() == stored

    duplicate, duplicate_created = store.write_checkpoint(first)
    assert duplicate_created is False
    assert duplicate == stored

    second = _checkpoint(
        2, "b" * 64, previous_checkpoint_hmac=stored.integrity_tag
    )
    _, second_created = store.write_checkpoint(second)
    assert second_created is True

    with pytest.raises(CheckpointRollbackError):
        store.write_checkpoint(_checkpoint(1, "c" * 64))

    with pytest.raises(CheckpointConflictError):
        store.write_checkpoint(
            _checkpoint(2, "d" * 64, previous_checkpoint_hmac=stored.integrity_tag)
        )

    latest = store.read_latest()
    assert latest is not None
    assert latest.sequence_number == 2
    assert latest.record_hash == "b" * 64


def test_real_store_detects_tampered_object(aws_context: AwsTestContext):
    prefix = _scoped_prefix(aws_context, "adapter-tamper")
    store = _real_store(aws_context, prefix)
    store.write_checkpoint(_checkpoint(1, "a" * 64))

    key = f"{prefix}/checkpoint-{1:020d}.json"
    aws_context.client.put_object(
        Bucket=aws_context.bucket,
        Key=key,
        Body=b'{"payload": {"format_version": 1}, "hmac": "' + b"0" * 64 + b'"}',
    )

    with pytest.raises(CheckpointIntegrityError):
        store.read_latest()


@pytest.mark.asyncio
async def test_api_checkpoint_lifecycle_against_real_bucket(
    async_client: AsyncClient,
    db_session: Session,
    aws_context: AwsTestContext,
    monkeypatch: pytest.MonkeyPatch,
):
    prefix = _scoped_prefix(aws_context, "api-lifecycle")
    _use_test_bucket_settings(monkeypatch, aws_context, prefix)
    await _login_admin(async_client, db_session, email="admin_aws_integration@example.com")

    info_before = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info_before.status_code == 200, info_before.text
    assert info_before.json()["available"] is False

    for index in range(3):
        _add_event(db_session, action=f"test.aws.integration.{index}")
    head_sequence = _head_sequence(db_session)

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 201, create.text
    created = create.json()
    assert created["status"] == "CREATED"
    assert created["anchor_mode"] == "s3"
    assert created["sequence_number"] == head_sequence

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 200, info.text
    info_data = info.json()
    assert info_data["available"] is True
    assert info_data["anchor_mode"] == "s3"

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    verify_data = verify.json()
    assert verify_data["status"] == "VALID"
    assert verify_data["is_valid"] is True
    assert verify_data["anchor_mode"] == "s3"

    serialized = json.dumps([created, info_data, verify_data])
    assert aws_context.bucket not in serialized
    assert prefix not in serialized
    assert "record_hash" not in serialized
    assert "hmac" not in serialized

    _rewrite_chain(db_session, start_sequence=2, action="test.aws.integration.rewritten")
    invalid = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert invalid.status_code == 200, invalid.text
    assert invalid.json()["status"] == "INVALID"


@pytest.mark.asyncio
async def test_api_checkpoint_endpoints_require_admin_against_real_bucket(
    async_client: AsyncClient,
    db_session: Session,
    aws_context: AwsTestContext,
    monkeypatch: pytest.MonkeyPatch,
):
    prefix = _scoped_prefix(aws_context, "api-rbac")
    _use_test_bucket_settings(monkeypatch, aws_context, prefix)

    anonymous_post = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert anonymous_post.status_code == 401

    for path in CHECKPOINT_ENDPOINTS:
        anonymous = await async_client.get(path)
        assert anonymous.status_code == 401, path

    viewer = make_user(
        db_session,
        email="viewer_aws_integration@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": viewer.email, "password": VALID_PASSWORD},
    )
    assert login.status_code == 200, login.text

    for path in CHECKPOINT_ENDPOINTS:
        denied = await async_client.get(path)
        assert denied.status_code == 403, path

    denied_create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert denied_create.status_code == 403

    _assert_prefix_is_empty(aws_context, prefix)
    db_session.expire_all()
    assert (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action.like("audit.checkpoint%"))
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_api_reports_unreachable_provider_as_unavailable(
    async_client: AsyncClient,
    db_session: Session,
    aws_context: AwsTestContext,
    monkeypatch: pytest.MonkeyPatch,
):
    prefix = _scoped_prefix(aws_context, "api-unreachable")
    _use_test_bucket_settings(
        monkeypatch, aws_context, prefix, endpoint_url="https://127.0.0.1:1"
    )
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_CONNECT_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_READ_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_S3_MAX_ATTEMPTS", 1)
    await _login_admin(
        async_client, db_session, email="admin_aws_unreachable@example.com"
    )

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 503
    assert create.json()["detail"] == (
        "Checkpoint anchoring is not configured or unavailable"
    )

    db_session.expire_all()
    failure = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "audit.checkpoint_created",
            AuditEvent.outcome == AuditOutcome.FAILURE,
        )
        .one()
    )
    assert json.loads(failure.details) == {"reason": "anchor_unavailable"}

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 503
    assert info.json()["detail"] == "Checkpoint store unavailable"

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    assert verify.json()["status"] == "UNAVAILABLE"
    assert verify.json()["is_valid"] is False


def test_access_denied_is_classified_against_aws(aws_context: AwsTestContext):
    boto3 = _require_boto3()
    client = boto3.Session(
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region_name=aws_context.region,
    ).client("s3")
    store = S3CheckpointStore(
        aws_context.bucket,
        hmac_key=CHECKPOINT_KEY,
        client=client,
        prefix=_scoped_prefix(aws_context, "adapter-denied"),
    )

    try:
        store.read_latest()
    except CheckpointStoreAccessDeniedError:
        pass
    except CheckpointStoreUnavailableError:
        pytest.skip(
            "AWS S3 endpoint is not reachable from this environment; "
            "access-denied classification could not be exercised"
        )
    else:
        pytest.fail("dummy AWS example credentials unexpectedly reached the provider")


_MISSING_CREDENTIALS_SCRIPT = """
from backend.app.services.checkpoint_store import (
    CheckpointStoreUnavailableError,
    S3CheckpointStore,
    create_s3_client,
)

client = create_s3_client(
    region="us-east-1",
    connect_timeout_seconds=1,
    read_timeout_seconds=1,
    max_attempts=1,
)
assert client is not None, "boto3 is not importable"
store = S3CheckpointStore(
    "trustvault-credential-probe-not-a-real-bucket",
    hmac_key=b"k" * 64,
    client=client,
    prefix="trustvault-credential-probe",
)
try:
    store.read_latest()
except CheckpointStoreUnavailableError:
    print("MISSING_CREDENTIALS_FAIL_CLOSED")
else:
    raise SystemExit("expected CheckpointStoreUnavailableError")
"""


def _credential_free_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("AWS_")
    }
    missing_file = os.path.join(
        tempfile.gettempdir(), "trustvault-aws-integration-missing-credentials"
    )
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["AWS_SHARED_CREDENTIALS_FILE"] = missing_file
    env["AWS_CONFIG_FILE"] = missing_file
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def test_missing_credentials_fail_closed_in_clean_subprocess():
    completed = subprocess.run(
        [sys.executable, "-c", _MISSING_CREDENTIALS_SCRIPT],
        cwd=REPO_ROOT,
        env=_credential_free_env(),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, (
        "credential-free subprocess failed; stderr tail: "
        f"{completed.stderr.strip()[-300:]}"
    )
    assert "MISSING_CREDENTIALS_FAIL_CLOSED" in completed.stdout
