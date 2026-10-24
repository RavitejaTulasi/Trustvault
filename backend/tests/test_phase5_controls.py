"""Storage lifecycle, quota, body-limit, and audit-bounding coverage."""

import json
import os
import secrets
from datetime import UTC, datetime

import pytest
from alembic import command
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config import Settings, settings
from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.audit import (
    AuditChainState,
    AuditEvent,
    AuditOutcome,
)
from backend.app.models.document import Document
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.models.user import UserRole
from backend.app.security.body_limit import RequestBodyLimitMiddleware
from backend.app.security.rate_limiter import (
    LoginRateLimitDecision,
    LoginRateLimiter,
    LoginRateLimitUnavailable,
    login_rate_limiter,
)
from backend.app.services.audit_service import GENESIS_HASH, AuditService
from backend.app.services.storage_lifecycle import StorageLifecycleService
from backend.app.services.storage_quota import (
    StorageQuotaExceeded,
    StorageQuotaService,
)
from backend.app.services.storage_service import StagedUpload, StorageService
from backend.tests.test_audit_migration import _alembic_config
from backend.tests.test_auth import VALID_PASSWORD, make_user
from backend.tests.test_rate_limiter_shared import MutableClock


def _make_document(
    db: Session,
    owner_id: str,
    storage_key: str,
    *,
    title: str,
    is_deleted: bool = False,
) -> Document:
    document = Document(
        title=title,
        original_filename=f"{title}.pdf",
        storage_key=storage_key,
        file_size_bytes=16,
        mime_type="application/pdf",
        category="General",
        owner_id=owner_id,
        is_deleted=is_deleted,
    )
    db.add(document)
    return document


def _storage_files(directory) -> list[str]:
    return [
        path.name
        for path in directory.iterdir()
        if path.is_file() and path.name != ".staging"
    ]


@pytest.mark.asyncio
async def test_request_metadata_limits_are_enforced(async_client: AsyncClient):
    invalid_request_id = await async_client.get(
        "/health",
        headers={"X-Request-ID": "contains spaces"},
    )
    assert invalid_request_id.status_code == 400
    assert invalid_request_id.headers["X-Request-ID"]

    oversized_agent = await async_client.get(
        "/health",
        headers={"User-Agent": "a" * 501},
    )
    assert oversized_agent.status_code == 431


@pytest.mark.asyncio
async def test_declared_json_body_over_limit_is_rejected_before_parsing(
    async_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "MAX_JSON_BODY_BYTES", 32)

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "person@example.com", "password": "x" * 64},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"
    assert response.headers["connection"] == "close"


@pytest.mark.asyncio
async def test_chunked_body_limit_counts_actual_bytes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "MAX_JSON_BODY_BYTES", 10)
    inner_called = False
    sent: list[dict] = []
    messages = [
        {"type": "http.request", "body": b"12345", "more_body": True},
        {"type": "http.request", "body": b"123456", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": False},
    ]

    async def inner(scope, receive, send):
        nonlocal inner_called
        inner_called = True
        while (await receive()).get("more_body"):
            pass

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(inner)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
        send,
    )

    assert inner_called is True
    assert sent[0]["status"] == 413
    assert sent[0]["headers"][-1] == (b"connection", b"close")


@pytest.mark.asyncio
async def test_upload_count_quota_rejects_and_cleans_staged_file(
    async_client: AsyncClient,
    db_session: Session,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setattr(settings, "MAX_UPLOADS_PER_USER", 1)
    make_user(
        db_session,
        email="quota-owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "quota-owner@example.com", "password": VALID_PASSWORD},
    )

    first = await async_client.post(
        "/api/v1/documents",
        files={"file": ("first.pdf", b"%PDF-1.4 first", "application/pdf")},
        data={"title": "First"},
    )
    assert first.status_code == 201

    second = await async_client.post(
        "/api/v1/documents",
        files={"file": ("second.pdf", b"%PDF-1.4 second", "application/pdf")},
        data={"title": "Second"},
    )
    assert second.status_code == 409

    db_session.expire_all()
    assert (
        db_session.scalar(
            select(func.count(Document.id)).where(Document.title == "Second")
        )
        == 0
    )
    assert len(_storage_files(StorageService.get_storage_path())) == 1

    denial = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "document.upload",
            AuditEvent.outcome == AuditOutcome.DENIED,
        )
    )
    assert denial is not None
    assert json.loads(denial.details)["reason"] == "upload_count_quota"


def test_storage_quota_rejects_user_and_global_byte_limits(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    user = make_user(
        db_session,
        email="byte-quota-owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    owner_id = user.id
    existing = _make_document(
        db_session,
        owner_id,
        secrets.token_hex(32),
        title="existing",
    )
    existing.file_size_bytes = 90
    db_session.commit()

    monkeypatch.setattr(settings, "MAX_USER_STORAGE_BYTES", 100)
    monkeypatch.setattr(settings, "MAX_GLOBAL_STORAGE_BYTES", 1000)
    with pytest.raises(StorageQuotaExceeded) as user_error:
        StorageQuotaService.acquire_upload_slot(db_session, owner_id, 11)
    assert user_error.value.reason == "user_storage_quota"
    assert user_error.value.status_code == 413

    monkeypatch.setattr(settings, "MAX_USER_STORAGE_BYTES", 1000)
    monkeypatch.setattr(settings, "MAX_GLOBAL_STORAGE_BYTES", 95)
    with pytest.raises(StorageQuotaExceeded) as global_error:
        StorageQuotaService.acquire_upload_slot(db_session, user.id, 6)
    assert global_error.value.reason == "global_storage_quota"
    assert global_error.value.status_code == 413


@pytest.mark.asyncio
async def test_upload_cleanup_when_finalize_fails(
    async_client: AsyncClient,
    db_session: Session,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "storage"))
    make_user(
        db_session,
        email="finalize-owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "finalize-owner@example.com", "password": VALID_PASSWORD},
    )

    def fail_finalize(self):
        raise OSError("simulated finalize failure")

    monkeypatch.setattr(StagedUpload, "finalize", fail_finalize)

    response = await async_client.post(
        "/api/v1/documents",
        files={"file": ("fail.pdf", b"%PDF-1.4 failure", "application/pdf")},
        data={"title": "Failure"},
    )

    assert response.status_code == 503
    db_session.expire_all()
    assert (
        db_session.scalar(
            select(func.count(Document.id)).where(Document.title == "Failure")
        )
        == 0
    )
    assert _storage_files(StorageService.get_storage_path()) == []
    staging = StorageService.get_staging_path()
    assert list(staging.iterdir()) == []


def test_storage_reconciliation_preserves_active_and_recent_files(
    db_session: Session,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setattr(settings, "STORAGE_ORPHAN_GRACE_SECONDS", 60)
    user = make_user(
        db_session,
        email="reconcile-owner@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    now = datetime.now(UTC).timestamp()
    storage_dir = StorageService.get_storage_path()
    staging_dir = StorageService.get_staging_path()

    active_key = secrets.token_hex(32)
    deleted_key = secrets.token_hex(32)
    old_orphan_key = secrets.token_hex(32)
    recent_orphan_key = secrets.token_hex(32)
    missing_key = secrets.token_hex(32)
    old_staging_key = secrets.token_hex(32)

    _make_document(db_session, user.id, active_key, title="active")
    _make_document(
        db_session,
        user.id,
        deleted_key,
        title="deleted",
        is_deleted=True,
    )
    _make_document(db_session, user.id, missing_key, title="missing")
    db_session.commit()

    for key in (active_key, deleted_key, old_orphan_key, recent_orphan_key):
        (storage_dir / key).write_bytes(b"x" * 16)
    old_orphan = storage_dir / old_orphan_key
    old_orphan.touch()
    os.utime(old_orphan, (now - 3600, now - 3600))

    staging_file = staging_dir / f"{old_staging_key}.part"
    staging_file.write_bytes(b"partial")
    os.utime(staging_file, (now - 3600, now - 3600))

    report = StorageLifecycleService.reconcile(db_session)

    assert report.removed_deleted_files == 1
    assert report.removed_orphaned_files == 0
    assert report.removed_staging_files == 0
    assert report.missing_active_files == 1
    assert (storage_dir / active_key).is_file()
    assert (storage_dir / recent_orphan_key).is_file()
    assert not (storage_dir / deleted_key).exists()
    assert old_orphan.is_file()
    assert old_orphan.read_bytes() == b"x" * 16
    assert staging_file.read_bytes() == b"partial"


def test_denial_audit_is_claimed_once_per_ip_window():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine)
    clock = MutableClock(1_000_000)
    limiter = LoginRateLimiter(
        max_attempts=1,
        window_seconds=60,
        max_buckets=100,
        time_func=clock,
    )

    try:
        assert limiter.reserve(session, "203.0.113.10", "first@example.com").allowed
        assert not limiter.reserve(
            session, "203.0.113.10", "first@example.com"
        ).allowed

        assert limiter.claim_denial_audit(
            session,
            "203.0.113.10",
            "first@example.com",
        )
        session.commit()
        assert not limiter.claim_denial_audit(
            session,
            "203.0.113.10",
            "first@example.com",
        )

        assert not limiter.reserve(
            session, "203.0.113.10", "second@example.com"
        ).allowed
        assert not limiter.claim_denial_audit(
            session,
            "203.0.113.10",
            "second@example.com",
        )

        clock.value += 61
        assert limiter.reserve(session, "203.0.113.10", "first@example.com").allowed
        assert not limiter.reserve(
            session, "203.0.113.10", "first@example.com"
        ).allowed
        assert limiter.claim_denial_audit(
            session,
            "203.0.113.10",
            "first@example.com",
        )
        session.commit()
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_rate_limit_denials_emit_one_aggregated_audit_event(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    email = "aggregate-limit@example.com"
    now = int(login_rate_limiter.time_func())
    ip_key = login_rate_limiter._build_keys("127.0.0.1", email)[1][0]
    db_session.add(
        LoginRateLimitBucket(
            key_hash=ip_key,
            scope="ip",
            attempt_count=5,
            window_started_at=now,
            expires_at=now + 300,
            denial_audit_recorded=False,
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        login_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False,
            retry_after=60,
        ),
    )

    for _ in range(2):
        response = await async_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert response.status_code == 429

    db_session.expire_all()
    denials = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "user.login_rate_limited")
    ).all()
    assert len(denials) == 1
    assert json.loads(denials[0].details)["aggregated"] is True


@pytest.mark.asyncio
async def test_denial_audit_claim_failure_fails_closed(
    async_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        login_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False,
            retry_after=60,
        ),
    )

    def failed_claim(*args, **kwargs):
        raise LoginRateLimitUnavailable("simulated claim failure")

    monkeypatch.setattr(login_rate_limiter, "claim_denial_audit", failed_claim)

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "claim-failure@example.com", "password": "WrongPassword123!"},
    )

    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"


@pytest.mark.asyncio
async def test_denial_audit_claim_and_event_commit_atomically(
    async_client: AsyncClient,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'denial-audit.sqlite').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 15},
    )
    Base.metadata.create_all(engine)
    request_sessions = sessionmaker(bind=engine)

    def override_get_db():
        session = request_sessions()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    email = "atomic-limit@example.com"
    now = int(login_rate_limiter.time_func())
    ip_key = login_rate_limiter._build_keys("127.0.0.1", email)[1][0]
    with request_sessions() as seed:
        seed.add(
            LoginRateLimitBucket(
                key_hash=ip_key,
                scope="ip",
                attempt_count=5,
                window_started_at=now,
                expires_at=now + 300,
                denial_audit_recorded=False,
            )
        )
        seed.commit()

    monkeypatch.setattr(
        login_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False,
            retry_after=60,
        ),
    )

    original_log_event = AuditService.log_event
    fail_once = {"pending": True}

    def fail_after_partial_write(db, **kwargs):
        if fail_once["pending"]:
            fail_once["pending"] = False
            original_log_event(db, **kwargs)
            raise SQLAlchemyError("simulated commit failure")
        return original_log_event(db, **kwargs)

    monkeypatch.setattr(AuditService, "log_event", fail_after_partial_write)

    try:
        failed = await async_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert failed.status_code == 503
        assert failed.headers["retry-after"] == "5"

        with request_sessions() as check:
            assert check.scalar(select(func.count(AuditEvent.id))) == 0
            bucket = check.get(LoginRateLimitBucket, ip_key)
            assert bucket is not None
            assert bucket.denial_audit_recorded is False
            assert check.get(AuditChainState, 1) is None

        retried = await async_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert retried.status_code == 429
        repeated = await async_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert repeated.status_code == 429

        with request_sessions() as check:
            events = check.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "user.login_rate_limited"
                )
            ).all()
            assert len(events) == 1
            assert json.loads(events[0].details)["aggregated"] is True
            bucket = check.get(LoginRateLimitBucket, ip_key)
            assert bucket is not None
            assert bucket.denial_audit_recorded is True
            state = check.get(AuditChainState, 1)
            assert state is not None
            assert state.last_sequence == 1
            assert state.last_hash != GENESIS_HASH
    finally:
        engine.dispose()


def test_audit_retention_auto_delete_is_rejected():
    with pytest.raises(ValidationError, match="AUDIT_RETENTION_AUTO_DELETE"):
        Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            DATABASE_URL="sqlite:///:memory:",
            SESSION_COOKIE_SECURE=False,
            AUDIT_ANCHOR_MODE="disabled",
            AUDIT_RETENTION_AUTO_DELETE=True,
        )


def test_phase5_migration_upgrades_and_downgrades(tmp_path, monkeypatch):
    config = _alembic_config(monkeypatch, tmp_path / "phase5.sqlite")
    command.upgrade(config, "head")

    db_url = config.get_main_option("sqlalchemy.url")
    engine = create_engine(db_url)
    inspector = inspect(engine)

    assert "storage_quota_state" in inspector.get_table_names()
    bucket_columns = {
        column["name"] for column in inspector.get_columns("login_rate_limit_buckets")
    }
    assert "denial_audit_recorded" in bucket_columns
    engine.dispose()

    command.downgrade(config, "c3d4e5f6a7b8")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "storage_quota_state" not in inspector.get_table_names()
    bucket_columns = {
        column["name"] for column in inspector.get_columns("login_rate_limit_buckets")
    }
    assert "denial_audit_recorded" in bucket_columns
    engine.dispose()
