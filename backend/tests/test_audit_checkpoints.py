"""
Day 7 Tests for Independently Stored Audit-Chain Checkpoints

Covers checkpoint creation over verified prefixes, refusal on invalid or
incomplete chains, checkpoint/chain comparison, rewrite and truncation
detection, monotonicity and conflict handling, unavailable anchors and entities, retries,
administrative authorization, no-cache/no-hash responses, preserved Day 6.1
bounds and rate limiting, configuration validation, and historical-record
immutability.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.api.audit import get_checkpoint_store
from backend.app.config import Settings, settings
from backend.app.main import app
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import User, UserRole
from backend.app.security.rate_limiter import audit_checkpoint_rate_limiter
from backend.app.services.audit_service import GENESIS_HASH, AuditService
from backend.app.services.checkpoint_service import (
    CheckpointCreationError,
    CheckpointService,
)
from backend.app.services.checkpoint_store import (
    AUDIT_STREAM_ID,
    CHECKPOINT_FORMAT_VERSION,
    AuditCheckpoint,
    CheckpointConflictError,
    CheckpointIntegrityError,
    CheckpointRollbackError,
    LocalFileCheckpointStore,
    UnavailableCheckpointStore,
)
from backend.tests.test_auth import VALID_PASSWORD, make_user

CHECKPOINT_KEY = b"k" * 64
CHECKPOINT_ENDPOINTS = (
    "/api/v1/admin/audit/checkpoints",
    "/api/v1/admin/audit/checkpoints/verify",
)


@pytest.fixture
def checkpoint_store(tmp_path: Path) -> LocalFileCheckpointStore:
    return LocalFileCheckpointStore(tmp_path / "audit_checkpoints", CHECKPOINT_KEY)


@pytest_asyncio.fixture
async def api_checkpoint_store(
    async_client: AsyncClient,
    checkpoint_store: LocalFileCheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
) -> LocalFileCheckpointStore:
    """Expose a real local file store to API requests without touching global config."""
    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "local_file")
    app.dependency_overrides[get_checkpoint_store] = lambda: checkpoint_store
    yield checkpoint_store
    app.dependency_overrides.pop(get_checkpoint_store, None)


def _add_event(
    db: Session,
    *,
    action: str = "test.checkpoint.event",
    actor_id: str | None = None,
) -> AuditEvent:
    event = AuditService.log_event(
        db,
        action=action,
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor_id,
        resource_type="test_resource",
    )
    db.commit()
    return event


def _create_checkpoint(
    db: Session,
    store,
    *,
    max_records: int = 1000,
):
    return CheckpointService.create_checkpoint(
        db,
        store,
        max_records=max_records,
        batch_size=100,
        timeout_seconds=30,
    )


def _verify_checkpoint(
    db: Session,
    store,
    *,
    max_records: int = 1000,
):
    return CheckpointService.verify_checkpoint(
        db,
        store,
        max_records=max_records,
        batch_size=100,
        timeout_seconds=30,
    )


def _head_sequence(db: Session) -> int:
    return db.query(func.max(AuditEvent.sequence_number)).scalar() or 0


def _tail_event(db: Session) -> AuditEvent:
    return (
        db.query(AuditEvent)
        .order_by(AuditEvent.sequence_number.desc())
        .first()
    )


def _rewrite_chain(db: Session, *, start_sequence: int, action: str) -> None:
    """Rewrite a record and recompute subsequent hashes so the chain stays self-consistent."""
    events = db.query(AuditEvent).order_by(AuditEvent.sequence_number.asc()).all()
    previous_hash = GENESIS_HASH
    for event in events:
        if event.sequence_number == start_sequence:
            event.action = action
        event.previous_hash = previous_hash
        event.record_hash = AuditService.calculate_hash(
            sequence_number=event.sequence_number,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome,
            request_id=event.request_id,
            details_str=event.details,
            previous_hash=previous_hash,
            event_id=event.id,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            hash_version=event.hash_version,
        )
        previous_hash = event.record_hash
    db.commit()


async def _login_admin(
    client: AsyncClient, db: Session, email: str = "admin_checkpoints@example.com"
) -> User:
    admin = make_user(db, email=email, password=VALID_PASSWORD, role=UserRole.ADMIN)
    db.commit()
    await client.post("/api/v1/auth/logout")
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return admin


# ─────────────────────────────────────────────────────────────────────────────
# Service: creation
# ─────────────────────────────────────────────────────────────────────────────


def test_create_checkpoint_from_verified_chain(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    events = [
        _add_event(db_session, action=f"test.checkpoint.create.{index}")
        for index in range(3)
    ]

    result = _create_checkpoint(db_session, checkpoint_store)

    assert result.already_present is False
    assert result.checkpoint.format_version == CHECKPOINT_FORMAT_VERSION
    assert result.checkpoint.stream_id == AUDIT_STREAM_ID
    assert result.checkpoint.sequence_number == 3
    assert result.checkpoint.record_hash == events[-1].record_hash
    assert result.checkpoint.previous_checkpoint_hmac is None
    assert checkpoint_store.read_latest() == result.checkpoint

    db_session.expire_all()
    stored = db_session.query(AuditEvent).order_by(AuditEvent.sequence_number).all()
    assert [event.record_hash for event in stored] == [
        event.record_hash for event in events
    ]


def test_create_checkpoint_refuses_invalid_chain(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    event = _add_event(db_session, action="test.checkpoint.invalid")
    event.action = "test.checkpoint.tampered"
    db_session.commit()

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, checkpoint_store)

    assert exc.value.reason == "chain_invalid"
    assert checkpoint_store.read_latest() is None


def test_create_checkpoint_refuses_incomplete_chain(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    for index in range(3):
        _add_event(db_session, action=f"test.checkpoint.incomplete.{index}")

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, checkpoint_store, max_records=2)

    assert exc.value.reason == "chain_incomplete"
    assert checkpoint_store.read_latest() is None


def test_create_checkpoint_retry_is_idempotent(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore, tmp_path: Path
):
    _add_event(db_session, action="test.checkpoint.idempotent.one")
    _add_event(db_session, action="test.checkpoint.idempotent.two")

    first = _create_checkpoint(db_session, checkpoint_store)
    second = _create_checkpoint(db_session, checkpoint_store)

    assert first.already_present is False
    assert second.already_present is True
    assert second.checkpoint.sequence_number == first.checkpoint.sequence_number
    assert second.checkpoint.record_hash == first.checkpoint.record_hash
    assert len(list((tmp_path / "audit_checkpoints").glob("checkpoint-*.json"))) == 1


def test_empty_chain_without_checkpoint_is_incomplete(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    verification = _verify_checkpoint(db_session, checkpoint_store)

    assert verification.status == "INCOMPLETE"
    assert verification.records_verified == 0
    assert verification.checkpoint_sequence is None
    assert verification.chain_head_sequence is None
    assert "no checkpoint" in (verification.failure_reason or "").lower()


def test_genesis_checkpoint_does_not_make_empty_or_extended_chain_valid(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    result = _create_checkpoint(db_session, checkpoint_store)
    assert result.checkpoint.sequence_number == 0
    assert result.checkpoint.record_hash == GENESIS_HASH

    verification = _verify_checkpoint(db_session, checkpoint_store)
    assert verification.status == "INCOMPLETE"
    assert verification.records_verified == 0
    assert verification.checkpoint_sequence == 0
    assert verification.chain_head_sequence == 0
    assert "genesis checkpoint" in (verification.failure_reason or "").lower()

    _add_event(db_session, action="test.checkpoint.empty.extended")
    extended = _verify_checkpoint(db_session, checkpoint_store)
    assert extended.status == "INCOMPLETE"
    assert extended.checkpoint_sequence == 0
    assert extended.chain_head_sequence == 1

    anchored = _create_checkpoint(db_session, checkpoint_store)
    assert anchored.checkpoint.sequence_number == 1
    non_genesis = _verify_checkpoint(db_session, checkpoint_store)
    assert non_genesis.status == "VALID"
    assert non_genesis.checkpoint_sequence == 1
    assert non_genesis.chain_head_sequence == 1


def test_create_checkpoint_detects_anchor_ahead_of_chain(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    _add_event(db_session, action="test.checkpoint.ahead.one")
    _add_event(db_session, action="test.checkpoint.ahead.two")
    checkpoint_store.write_checkpoint(
        AuditCheckpoint(
            format_version=CHECKPOINT_FORMAT_VERSION,
            stream_id=AUDIT_STREAM_ID,
            sequence_number=5,
            record_hash="a" * 64,
            created_at=datetime.now(UTC),
            previous_checkpoint_hmac=None,
        )
    )

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, checkpoint_store)

    assert exc.value.reason == "anchor_ahead_of_chain"


def test_store_rejects_rollback_and_conflicting_checkpoints(
    checkpoint_store: LocalFileCheckpointStore,
):
    created_at = datetime.now(UTC)
    sequence_three = AuditCheckpoint(
        format_version=CHECKPOINT_FORMAT_VERSION,
        stream_id=AUDIT_STREAM_ID,
        sequence_number=3,
        record_hash="a" * 64,
        created_at=created_at,
        previous_checkpoint_hmac=None,
    )
    stored, created = checkpoint_store.write_checkpoint(sequence_three)
    assert created is True
    assert stored.integrity_tag is not None

    with pytest.raises(CheckpointRollbackError):
        checkpoint_store.write_checkpoint(
            AuditCheckpoint(
                format_version=CHECKPOINT_FORMAT_VERSION,
                stream_id=AUDIT_STREAM_ID,
                sequence_number=2,
                record_hash="b" * 64,
                created_at=created_at,
                previous_checkpoint_hmac=None,
            )
        )

    with pytest.raises(CheckpointConflictError):
        checkpoint_store.write_checkpoint(
            AuditCheckpoint(
                format_version=CHECKPOINT_FORMAT_VERSION,
                stream_id=AUDIT_STREAM_ID,
                sequence_number=3,
                record_hash="c" * 64,
                created_at=created_at,
                previous_checkpoint_hmac=None,
            )
        )

    duplicate, duplicate_created = checkpoint_store.write_checkpoint(
        AuditCheckpoint(
            format_version=CHECKPOINT_FORMAT_VERSION,
            stream_id=AUDIT_STREAM_ID,
            sequence_number=3,
            record_hash="a" * 64,
            created_at=datetime.now(UTC),
            previous_checkpoint_hmac=None,
        )
    )
    assert duplicate_created is False
    assert duplicate.record_hash == "a" * 64


def test_local_store_requires_strong_hmac_key(tmp_path: Path):
    with pytest.raises(ValueError):
        LocalFileCheckpointStore(tmp_path, b"too-short")


# ─────────────────────────────────────────────────────────────────────────────
# Service: verification
# ─────────────────────────────────────────────────────────────────────────────


def test_verify_matching_checkpoint_and_chain_extension(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    for index in range(3):
        _add_event(db_session, action=f"test.checkpoint.verify.valid.{index}")
    created = _create_checkpoint(db_session, checkpoint_store)

    for index in range(2):
        _add_event(db_session, action=f"test.checkpoint.verify.extension.{index}")

    result = _verify_checkpoint(db_session, checkpoint_store)

    assert result.status == "VALID"
    assert result.checkpoint_sequence == created.checkpoint.sequence_number
    assert result.records_verified == 5
    assert result.chain_head_sequence == 5
    assert result.failure_reason is None


def test_verify_detects_rewritten_history_at_checkpoint(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    for index in range(3):
        _add_event(db_session, action=f"test.checkpoint.rewrite.{index}")
    _create_checkpoint(db_session, checkpoint_store)

    _rewrite_chain(db_session, start_sequence=2, action="test.checkpoint.rewritten")

    chain = AuditService.verify_chain_integrity_bounded(
        db_session, max_records=1000, batch_size=100, timeout_seconds=30
    )
    assert chain.status == "VALID"

    result = _verify_checkpoint(db_session, checkpoint_store)
    assert result.status == "INVALID"
    assert "does not match the checkpoint" in (result.failure_reason or "")


def test_verify_detects_missing_checkpointed_sequence(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore
):
    for index in range(4):
        _add_event(db_session, action=f"test.checkpoint.truncate.{index}")
    _create_checkpoint(db_session, checkpoint_store)

    db_session.query(AuditEvent).filter(AuditEvent.sequence_number >= 4).delete(
        synchronize_session=False
    )
    db_session.commit()

    chain = AuditService.verify_chain_integrity_bounded(
        db_session, max_records=1000, batch_size=100, timeout_seconds=30
    )
    assert chain.status == "VALID"

    result = _verify_checkpoint(db_session, checkpoint_store)
    assert result.status == "INVALID"
    assert result.checkpoint_sequence == 4
    assert result.chain_head_sequence == 3
    assert "no longer exists" in (result.failure_reason or "")


def test_verify_returns_unavailable_when_anchor_unavailable(
    db_session: Session,
):
    _add_event(db_session, action="test.checkpoint.unavailable")

    result = _verify_checkpoint(db_session, UnavailableCheckpointStore())

    assert result.status == "UNAVAILABLE"
    assert result.records_verified == 1
    assert result.checkpoint_sequence is None
    assert "unavailable" in (result.failure_reason or "").lower()

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, UnavailableCheckpointStore())
    assert exc.value.reason == "anchor_unavailable"


def test_local_store_detects_tampered_checkpoint(
    db_session: Session, checkpoint_store: LocalFileCheckpointStore, tmp_path: Path
):
    _add_event(db_session, action="test.checkpoint.tamper.anchor.one")
    _add_event(db_session, action="test.checkpoint.tamper.anchor.two")
    _create_checkpoint(db_session, checkpoint_store)

    path = next((tmp_path / "audit_checkpoints").glob("checkpoint-*.json"))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["payload"]["record_hash"] = "f" * 64
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CheckpointIntegrityError):
        checkpoint_store.read_latest()

    result = _verify_checkpoint(db_session, checkpoint_store)
    assert result.status == "INVALID"
    assert "integrity" in (result.failure_reason or "").lower()

    with pytest.raises(CheckpointCreationError) as exc:
        _create_checkpoint(db_session, checkpoint_store)
    assert exc.value.reason == "anchor_integrity_failure"


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


def test_production_rejects_local_anchor():
    with pytest.raises(ValidationError, match="independent"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            SESSION_COOKIE_SECURE=True,
            DATABASE_URL=(
                "postgresql+psycopg://trustvault_app:test-only-db-password"
                "@db:5432/trustvault"
            ),
            AUDIT_ANCHOR_MODE="local_file",
            AUDIT_ANCHOR_HMAC_KEY="k" * 64,
        )


def test_local_anchor_requires_strong_hmac_key():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            AUDIT_ANCHOR_MODE="local_file",
            AUDIT_ANCHOR_HMAC_KEY="short",
        )


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_checkpoint_api_create_inspect_and_verify(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
):
    admin = await _login_admin(async_client, db_session)
    head_sequence = _head_sequence(db_session)

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 201, create.text
    assert create.headers["cache-control"] == "no-store"
    assert create.headers["pragma"] == "no-cache"
    created = create.json()
    assert created["status"] == "CREATED"
    assert created["anchor_mode"] == "local_file"
    assert created["stream_id"] == AUDIT_STREAM_ID
    assert created["sequence_number"] == head_sequence

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 200, info.text
    assert info.headers["cache-control"] == "no-store"
    info_data = info.json()
    assert info_data["available"] is True
    assert info_data["anchor_mode"] == "local_file"
    assert info_data["sequence_number"] == head_sequence

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    assert verify.headers["cache-control"] == "no-store"
    verify_data = verify.json()
    assert verify_data["status"] == "VALID"
    assert verify_data["is_valid"] is True
    assert verify_data["checkpoint_sequence"] == head_sequence
    assert verify_data["chain_head_sequence"] >= head_sequence

    for payload in (created, info_data, verify_data):
        serialized = json.dumps(payload)
        assert "record_hash" not in serialized
        assert "previous_checkpoint_hmac" not in serialized
        assert "hmac" not in serialized
        assert re.search(r"\b[0-9a-f]{64}\b", serialized) is None

    events = await async_client.get(
        "/api/v1/admin/audit", params={"action": "audit.checkpoint_created"}
    )
    assert events.status_code == 200, events.text
    checkpoint_events = events.json()["events"]
    assert len(checkpoint_events) == 1
    assert checkpoint_events[0]["actor_id"] == admin.id
    assert checkpoint_events[0]["outcome"] == AuditOutcome.SUCCESS
    assert checkpoint_events[0]["details"] == {
        "already_present": False,
        "checkpoint_sequence": head_sequence,
    }


@pytest.mark.asyncio
async def test_checkpoint_endpoints_require_admin(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
):
    anonymous_post = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert anonymous_post.status_code == 401

    for path in CHECKPOINT_ENDPOINTS:
        anonymous = await async_client.get(path)
        assert anonymous.status_code == 401, path

    viewer = make_user(
        db_session,
        email="viewer_checkpoints@example.com",
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

    assert api_checkpoint_store.read_latest() is None
    db_session.expire_all()
    assert (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action.like("audit.checkpoint%"))
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_checkpoint_api_refuses_invalid_chain(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_invalid@example.com")
    event = _tail_event(db_session)
    event.action = "test.checkpoint.api.tampered"
    db_session.commit()

    response = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store"
    assert "verification failed" in response.json()["detail"].lower()
    assert api_checkpoint_store.read_latest() is None

    db_session.expire_all()
    failure = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "audit.checkpoint_created",
            AuditEvent.outcome == AuditOutcome.FAILURE,
        )
        .one()
    )
    assert json.loads(failure.details) == {"reason": "chain_invalid"}


@pytest.mark.asyncio
async def test_checkpoint_api_fails_closed_when_anchor_unavailable(
    async_client: AsyncClient, db_session: Session
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_unavailable@example.com")

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 503
    assert create.headers["cache-control"] == "no-store"
    assert "not configured" in create.json()["detail"].lower()

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

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200, verify.text
    data = verify.json()
    assert data["status"] == "UNAVAILABLE"
    assert data["is_valid"] is False
    assert data["anchor_mode"] == "disabled"
    assert "unavailable" in (data["failure_reason"] or "").lower()

    info = await async_client.get("/api/v1/admin/audit/checkpoints")
    assert info.status_code == 200
    info_data = info.json()
    assert info_data["available"] is False
    assert info_data["sequence_number"] is None


@pytest.mark.asyncio
async def test_checkpoint_creation_survives_audit_write_failure(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_audit_fail@example.com")

    def exploding_log_event(*args, **kwargs):
        raise SQLAlchemyError("audit store unavailable")

    monkeypatch.setattr(AuditService, "log_event", exploding_log_event)

    response = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert response.status_code == 503
    assert response.json()["detail"] == "Audit trail unavailable"
    assert api_checkpoint_store.read_latest() is not None


@pytest.mark.asyncio
async def test_checkpoint_api_duplicate_returns_already_present(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
    tmp_path: Path,
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_duplicate@example.com")
    head_sequence = _head_sequence(db_session)
    tail = _tail_event(db_session)
    api_checkpoint_store.write_checkpoint(
        AuditCheckpoint(
            format_version=CHECKPOINT_FORMAT_VERSION,
            stream_id=AUDIT_STREAM_ID,
            sequence_number=head_sequence,
            record_hash=tail.record_hash,
            created_at=datetime.now(UTC),
            previous_checkpoint_hmac=None,
        )
    )

    response = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "ALREADY_PRESENT"
    assert data["sequence_number"] == head_sequence
    assert len(list((tmp_path / "audit_checkpoints").glob("checkpoint-*.json"))) == 1


@pytest.mark.asyncio
async def test_checkpoint_verify_is_rate_limited_and_separate(
    async_client: AsyncClient, db_session: Session
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_rate@example.com")
    limit = audit_checkpoint_rate_limiter.max_requests

    for _ in range(limit):
        response = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "UNAVAILABLE"

    blocked = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"].isdigit()
    assert blocked.headers["cache-control"] == "no-store"
    assert "rate limit" in blocked.json()["detail"].lower()

    db_session.expire_all()
    recorded = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.checkpoint_verify")
        .count()
    )
    assert recorded == limit

    day_six_verify = await async_client.get("/api/v1/admin/audit/verify")
    assert day_six_verify.status_code == 200


@pytest.mark.asyncio
async def test_checkpoint_creation_respects_verification_bounds(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_bounds@example.com")
    for index in range(3):
        _add_event(db_session, action=f"test.checkpoint.bounds.{index}")
    monkeypatch.setattr(settings, "AUDIT_VERIFY_MAX_RECORDS", 2)

    create = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert create.status_code == 409
    assert "incomplete" in create.json()["detail"].lower()
    assert api_checkpoint_store.read_latest() is None

    verify = await async_client.get("/api/v1/admin/audit/checkpoints/verify")
    assert verify.status_code == 200
    data = verify.json()
    assert data["status"] == "INCOMPLETE"
    assert data["is_valid"] is False


@pytest.mark.asyncio
async def test_checkpoint_creation_preserves_historical_records(
    async_client: AsyncClient,
    db_session: Session,
    api_checkpoint_store: LocalFileCheckpointStore,
):
    await _login_admin(async_client, db_session, email="admin_checkpoint_history@example.com")
    for index in range(2):
        _add_event(db_session, action=f"test.checkpoint.history.{index}")

    db_session.expire_all()
    before = [
        (event.sequence_number, event.record_hash, event.previous_hash)
        for event in db_session.query(AuditEvent)
        .order_by(AuditEvent.sequence_number.asc())
        .all()
    ]
    head_sequence = before[-1][0]

    response = await async_client.post("/api/v1/admin/audit/checkpoints")
    assert response.status_code == 201, response.text

    db_session.expire_all()
    after = [
        (event.sequence_number, event.record_hash, event.previous_hash)
        for event in db_session.query(AuditEvent)
        .order_by(AuditEvent.sequence_number.asc())
        .all()
    ]
    assert after[: len(before)] == before
    assert len(after) == len(before) + 1

    checkpoint_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.checkpoint_created")
        .one()
    )
    assert checkpoint_event.sequence_number == head_sequence + 1

    latest = api_checkpoint_store.read_latest()
    assert latest is not None
    assert latest.sequence_number == head_sequence
    assert latest.record_hash == before[-1][1]
    assert latest.record_hash != checkpoint_event.record_hash


@pytest.mark.asyncio
async def test_health_reports_anchor_mode(
    async_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    response = await async_client.get("/health")
    assert response.status_code == 200
    anchor = response.json()["components"]["audit_anchor"]
    assert anchor["status"] == "not_configured"
    assert anchor["mode"] == "disabled"
    assert anchor["independent"] is False
    assert anchor["available"] is False
    assert anchor["overdue"] is False
    assert anchor["scheduler"]["running"] is False

    monkeypatch.setattr(settings, "AUDIT_ANCHOR_MODE", "local_file")
    local_response = await async_client.get("/health")
    assert local_response.status_code == 200
    local_anchor = local_response.json()["components"]["audit_anchor"]
    assert local_anchor["status"] == "local_only"
    assert local_anchor["external_adapter"] is False
    assert local_anchor["independent"] is False
    assert local_anchor["independence_verified"] is False
