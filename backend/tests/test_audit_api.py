"""
Day 6 Integration Tests for Administrative Audit and Activity APIs

Verifies admin-only authorization, safe response shaping, filtering, pagination,
document activity correlation, hash-chain verification, tamper detection, and
separation from document-content authorization.
"""

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.document import Document
from backend.app.models.user import User, UserRole
from backend.app.security.rate_limiter import audit_verification_rate_limiter
from backend.app.services.audit_service import AuditService
from backend.tests.test_auth import VALID_PASSWORD, make_user

AUDIT_ENDPOINTS = (
    "/api/v1/admin/audit",
    "/api/v1/admin/audit/verify",
    "/api/v1/admin/documents/activity",
)


async def _login(client: AsyncClient, email: str) -> None:
    await client.post("/api/v1/auth/logout")
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text


async def _login_admin(
    client: AsyncClient, db: Session, email: str = "admin_audit_api@example.com"
) -> User:
    admin = make_user(
        db,
        email=email,
        password=VALID_PASSWORD,
        full_name="Audit Admin",
        role=UserRole.ADMIN,
    )
    db.commit()
    await _login(client, email)
    return admin


def _add_event(
    db: Session,
    *,
    action: str,
    actor_id: str | None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str = AuditOutcome.SUCCESS,
    details: dict | None = None,
) -> AuditEvent:
    event = AuditService.log_event(
        db,
        action=action,
        outcome=outcome,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    db.commit()
    return event


@pytest.mark.asyncio
@pytest.mark.parametrize("path", AUDIT_ENDPOINTS)
async def test_audit_endpoints_require_authentication(
    async_client: AsyncClient, path: str
):
    response = await async_client.get(path)
    assert response.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.OWNER])
async def test_audit_endpoints_deny_non_admin_roles(
    async_client: AsyncClient, db_session: Session, role: str
):
    make_user(
        db_session,
        email=f"{role}_audit_api@example.com",
        password=VALID_PASSWORD,
        role=role,
    )
    db_session.commit()
    await _login(async_client, f"{role}_audit_api@example.com")

    for path in AUDIT_ENDPOINTS:
        response = await async_client.get(path)
        assert response.status_code == 403, path

    assert (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action.in_(
                ("audit.read", "audit.verify", "audit.activity_read")
            )
        )
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_admin_lists_audit_events_with_safe_fields_and_pagination(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    events = [
        _add_event(
            db_session,
            action="test.audit.pagination",
            actor_id=admin.id,
            resource_type="test_resource",
            resource_id=f"resource-{index}",
            details={"changed_fields": [f"field-{index}"], "permission": "read"},
        )
        for index in range(3)
    ]

    response = await async_client.get(
        "/api/v1/admin/audit",
        params={"action": "test.audit.pagination", "page": 1, "page_size": 2},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    data = response.json()
    assert data["total"] == 3
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert [event["sequence_number"] for event in data["events"]] == [
        events[2].sequence_number,
        events[1].sequence_number,
    ]
    assert data["events"][0]["details"] == {
        "changed_fields": ["field-2"],
        "permission": "read",
    }

    for event in data["events"]:
        assert "record_hash" not in event
        assert "previous_hash" not in event
        assert "hashed_password" not in event

    second_page = await async_client.get(
        "/api/v1/admin/audit",
        params={"action": "test.audit.pagination", "page": 2, "page_size": 2},
    )
    assert second_page.status_code == 200
    assert [event["sequence_number"] for event in second_page.json()["events"]] == [
        events[0].sequence_number
    ]


@pytest.mark.asyncio
async def test_audit_filters_combine_and_invalid_parameters_are_rejected(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    other = make_user(
        db_session,
        email="other_audit_filter@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()

    matching = _add_event(
        db_session,
        action="test.filter.matching",
        actor_id=admin.id,
        resource_type="test_filter",
        resource_id="resource-matching",
        details={"reason": "matching"},
    )
    _add_event(
        db_session,
        action="test.filter.other",
        actor_id=other.id,
        resource_type="other_filter",
        resource_id="resource-other",
        outcome=AuditOutcome.DENIED,
    )

    now = datetime.now(UTC)
    response = await async_client.get(
        "/api/v1/admin/audit",
        params={
            "actor_id": admin.id,
            "action": "test.filter.matching",
            "resource_type": "test_filter",
            "resource_id": "resource-matching",
            "outcome": AuditOutcome.SUCCESS,
            "timestamp_from": (now - timedelta(minutes=5)).isoformat(),
            "timestamp_to": (now + timedelta(minutes=5)).isoformat(),
            "page": 1,
            "page_size": 25,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 1
    assert [event["id"] for event in data["events"]] == [matching.id]
    assert data["events"][0]["details"] == {"reason": "matching"}

    denied = await async_client.get(
        "/api/v1/admin/audit", params={"outcome": AuditOutcome.DENIED}
    )
    assert denied.status_code == 200
    assert all(
        event["outcome"] == AuditOutcome.DENIED for event in denied.json()["events"]
    )

    outside_range = await async_client.get(
        "/api/v1/admin/audit",
        params={"timestamp_from": (now + timedelta(hours=1)).isoformat()},
    )
    assert outside_range.status_code == 200
    assert outside_range.json()["total"] == 0

    injection = await async_client.get(
        "/api/v1/admin/audit", params={"action": "' OR 1=1--"}
    )
    assert injection.status_code == 200
    assert injection.json()["total"] == 0

    invalid_requests = [
        {"page": 0},
        {"page_size": 101},
        {"action": "   "},
        {"action": "a" * 101},
        {"actor_id": "   "},
        {"outcome": "UNKNOWN"},
        {"timestamp_from": "not-a-date"},
        {
            "timestamp_from": "2026-03-01T00:00:00Z",
            "timestamp_to": "2026-02-01T00:00:00Z",
        },
    ]
    for params in invalid_requests:
        invalid = await async_client.get("/api/v1/admin/audit", params=params)
        assert invalid.status_code == 422, params


@pytest.mark.asyncio
async def test_document_activity_correlates_document_and_grant_events(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    document_id = "doc_activity_target"
    grant_id = "grant_activity_target"
    unrelated_document_id = "doc_activity_unrelated"

    document_read = _add_event(
        db_session,
        action="document.read",
        actor_id=admin.id,
        resource_type="document",
        resource_id=document_id,
    )
    document_denied = _add_event(
        db_session,
        action="document.download",
        actor_id=admin.id,
        resource_type="document",
        resource_id=document_id,
        outcome=AuditOutcome.DENIED,
    )
    grant_event = _add_event(
        db_session,
        action="permission.grant",
        actor_id=admin.id,
        resource_type="document_grant",
        resource_id=grant_id,
        details={
            "document_id": document_id,
            "recipient_id": "recipient-audit",
            "permission": "read",
        },
    )
    revoke_event = _add_event(
        db_session,
        action="permission.revoke",
        actor_id=admin.id,
        resource_type="document_grant",
        resource_id="grant_activity_revoked",
        details={"document_id": document_id, "target_user_id": "recipient-audit"},
    )
    _add_event(
        db_session,
        action="document.read",
        actor_id=admin.id,
        resource_type="document",
        resource_id=unrelated_document_id,
    )
    _add_event(
        db_session,
        action="permission.grant",
        actor_id=admin.id,
        resource_type="document_grant",
        resource_id="grant_activity_unrelated",
        details={
            "document_id": unrelated_document_id,
            "recipient_id": "recipient-unrelated",
            "permission": "read",
        },
    )

    response = await async_client.get(
        "/api/v1/admin/documents/activity",
        params={"document_id": document_id, "page_size": 100},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["total"] == 4
    assert [event["id"] for event in data["events"]] == [
        revoke_event.id,
        grant_event.id,
        document_denied.id,
        document_read.id,
    ]
    assert all(
        event["resource_type"] in {"document", "document_grant"}
        for event in data["events"]
    )
    assert grant_event.details is not None
    assert data["events"][1]["details"]["document_id"] == document_id

    grants_only = await async_client.get(
        "/api/v1/admin/documents/activity",
        params={"document_id": document_id, "action": "permission.grant"},
    )
    assert grants_only.status_code == 200
    assert grants_only.json()["total"] == 1
    assert grants_only.json()["events"][0]["id"] == grant_event.id

    denied_only = await async_client.get(
        "/api/v1/admin/documents/activity",
        params={"document_id": document_id, "outcome": AuditOutcome.DENIED},
    )
    assert denied_only.status_code == 200
    assert denied_only.json()["total"] == 1
    assert denied_only.json()["events"][0]["id"] == document_denied.id

    wildcard = await async_client.get(
        "/api/v1/admin/documents/activity", params={"document_id": "%"}
    )
    assert wildcard.status_code == 200
    assert wildcard.json()["total"] == 0

    blank = await async_client.get(
        "/api/v1/admin/documents/activity", params={"document_id": "   "}
    )
    assert blank.status_code == 422

    for params in ({"page": 0}, {"page_size": 101}, {"outcome": "UNKNOWN"}):
        invalid = await async_client.get(
            "/api/v1/admin/documents/activity", params=params
        )
        assert invalid.status_code == 422, params


@pytest.mark.asyncio
async def test_audit_verification_returns_valid_chain_metadata(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    _add_event(
        db_session,
        action="test.verify.valid",
        actor_id=admin.id,
        resource_type="test_resource",
        resource_id="verify-valid",
    )
    total = db_session.query(AuditEvent).count()

    response = await async_client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    data = response.json()
    assert data["is_valid"] is True
    assert data["records_verified"] == total
    assert data["failure_reason"] is None


@pytest.mark.asyncio
async def test_audit_verification_detects_tampering_without_repairing_it(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    event = _add_event(
        db_session,
        action="test.verify.tamper",
        actor_id=admin.id,
        resource_type="test_resource",
        resource_id="verify-tamper",
    )
    total = db_session.query(AuditEvent).count()

    event.action = "test.verify.tampered"
    db_session.commit()

    response = await async_client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["is_valid"] is False
    assert data["records_verified"] < total
    assert "tampering" in data["failure_reason"].lower()
    assert "[redacted]" in data["failure_reason"]
    assert re.search(r"\b[0-9a-f]{64}\b", data["failure_reason"]) is None

    assert db_session.query(AuditEvent).count() == total + 1
    db_session.refresh(event)
    assert event.action == "test.verify.tampered"

    read_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.verify")
        .order_by(AuditEvent.sequence_number.desc())
        .first()
    )
    assert read_event is not None
    assert read_event.actor_id == admin.id
    assert read_event.outcome == AuditOutcome.SUCCESS
    assert read_event.resource_type == "audit"
    assert json.loads(read_event.details) == {"verification_status": "INVALID"}


@pytest.mark.asyncio
async def test_audit_list_safely_ignores_malformed_details(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    event = _add_event(
        db_session,
        action="test.details.malformed",
        actor_id=admin.id,
        resource_type="test_resource",
        resource_id="details-malformed",
    )
    event.details = "{not-valid-json"
    db_session.commit()

    response = await async_client.get(
        "/api/v1/admin/audit", params={"action": "test.details.malformed"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["events"][0]["details"] is None


@pytest.mark.asyncio
async def test_audit_response_redacts_document_metadata_and_secret_values(
    async_client: AsyncClient, db_session: Session
):
    admin = await _login_admin(async_client, db_session)
    document_id = "doc_redaction_target"
    _add_event(
        db_session,
        action="test.details.redaction",
        actor_id=admin.id,
        resource_type="document",
        resource_id=document_id,
        details={
            "title": "Secret Title",
            "filename": "secret.pdf",
            "size": 123,
            "category": "Private",
            "mime_type": "application/pdf",
            "storage_key": "a" * 64,
            "path": "/private/secret.pdf",
            "password": "SecretPassword1!",
            "session_token": "session-token-value",
            "document_id": document_id,
            "recipient_id": "recipient-redaction",
            "permission": "read",
            "changed_fields": ["title"],
            "nested": {"title": "Nested Secret"},
        },
    )

    response = await async_client.get(
        "/api/v1/admin/audit", params={"action": "test.details.redaction"}
    )
    assert response.status_code == 200, response.text
    details = response.json()["events"][0]["details"]
    assert details["title"] == "[redacted]"
    assert details["filename"] == "[redacted]"
    assert details["size"] == "[redacted]"
    assert details["category"] == "[redacted]"
    assert details["mime_type"] == "[redacted]"
    assert details["storage_key"] == "[redacted]"
    assert details["path"] == "[redacted]"
    assert details["password"] == "[redacted]"
    assert details["session_token"] == "[redacted]"
    assert details["nested"] == "[redacted]"
    assert details["document_id"] == document_id
    assert details["recipient_id"] == "recipient-redaction"
    assert details["permission"] == "read"
    assert details["changed_fields"] == ["title"]

    db_session.expire_all()
    stored = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "test.details.redaction")
        .one()
    )
    assert json.loads(stored.details)["title"] == "Secret Title"


def test_verification_detects_altered_record_hash(db_session: Session):
    _add_event(
        db_session,
        action="test.verify.hash.one",
        actor_id=None,
        resource_type="test_resource",
    )
    second = _add_event(
        db_session,
        action="test.verify.hash.two",
        actor_id=None,
        resource_type="test_resource",
    )
    second.record_hash = "f" * 64
    db_session.commit()

    is_valid, reason, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is False
    assert count == 1
    assert "Record tampering detected at sequence 2" in reason


def test_verification_detects_broken_previous_hash_link(db_session: Session):
    _add_event(
        db_session,
        action="test.verify.link.one",
        actor_id=None,
        resource_type="test_resource",
    )
    second = _add_event(
        db_session,
        action="test.verify.link.two",
        actor_id=None,
        resource_type="test_resource",
    )
    second.previous_hash = "f" * 64
    db_session.commit()

    is_valid, reason, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is False
    assert count == 1
    assert "Hash link broken at sequence 2" in reason


def test_verification_detects_sequence_gap(db_session: Session):
    _add_event(
        db_session,
        action="test.verify.gap.one",
        actor_id=None,
        resource_type="test_resource",
    )
    second = _add_event(
        db_session,
        action="test.verify.gap.two",
        actor_id=None,
        resource_type="test_resource",
    )
    _add_event(
        db_session,
        action="test.verify.gap.three",
        actor_id=None,
        resource_type="test_resource",
    )
    db_session.delete(second)
    db_session.commit()

    is_valid, reason, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is False
    assert count == 1
    assert "Sequence gap detected" in reason


def test_verification_detects_out_of_range_low_sequence(db_session: Session):
    event = _add_event(
        db_session,
        action="test.verify.out_of_range",
        actor_id=None,
        resource_type="test_resource",
    )
    event.sequence_number = 0
    db_session.commit()

    result = AuditService.verify_chain_integrity_bounded(
        db_session,
        max_records=10,
        batch_size=2,
        timeout_seconds=5,
    )

    assert result.status == "INVALID"
    assert result.records_verified == 0
    assert result.failure_reason is not None
    assert "Sequence gap detected" in result.failure_reason


def test_verification_accepts_empty_chain(db_session: Session):
    result = AuditService.verify_chain_integrity_bounded(
        db_session,
        max_records=10,
        batch_size=2,
        timeout_seconds=5,
    )

    assert result.status == "VALID"
    assert result.records_verified == 0
    assert result.failure_reason is None


def test_verification_processes_large_chain_in_bounded_batches(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    for index in range(7):
        _add_event(
            db_session,
            action=f"test.verify.batch.{index}",
            actor_id=None,
            resource_type="test_resource",
        )

    batch_sizes: list[int] = []
    original_loader = AuditService._load_verification_batch

    def spy_loader(
        cls, db, after_sequence, high_water_mark, batch_size
    ):
        rows = original_loader(db, after_sequence, high_water_mark, batch_size)
        batch_sizes.append(len(rows))
        return rows

    monkeypatch.setattr(
        AuditService,
        "_load_verification_batch",
        classmethod(spy_loader),
    )

    result = AuditService.verify_chain_integrity_bounded(
        db_session,
        max_records=100,
        batch_size=3,
        timeout_seconds=5,
    )

    assert result.status == "VALID"
    assert result.records_verified == 7
    assert batch_sizes == [3, 3, 1]


def test_verification_timeout_returns_incomplete_not_valid(db_session: Session):
    for index in range(3):
        _add_event(
            db_session,
            action=f"test.verify.timeout.{index}",
            actor_id=None,
            resource_type="test_resource",
        )

    ticks = iter([0.0, 0.0, 100.0])

    def fake_clock() -> float:
        return next(ticks, 100.0)

    result = AuditService.verify_chain_integrity_bounded(
        db_session,
        max_records=10,
        batch_size=1,
        timeout_seconds=5,
        clock=fake_clock,
    )

    assert result.status == "INCOMPLETE"
    assert result.records_verified == 1
    assert result.failure_reason is not None
    assert "incomplete" in result.failure_reason.lower()
    assert "time limit" in result.failure_reason.lower()


@pytest.mark.asyncio
async def test_audit_verification_reports_incomplete_without_full_success(
    async_client: AsyncClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    admin = await _login_admin(
        async_client, db_session, email="admin_verify_limit@example.com"
    )
    for index in range(3):
        _add_event(
            db_session,
            action=f"test.verify.limit.{index}",
            actor_id=admin.id,
            resource_type="test_resource",
        )
    total = db_session.query(AuditEvent).count()
    monkeypatch.setattr(settings, "AUDIT_VERIFY_MAX_RECORDS", max(total - 1, 1))

    response = await async_client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "INCOMPLETE"
    assert data["is_valid"] is False
    assert data["records_verified"] == 0
    assert "incomplete" in data["failure_reason"].lower()
    assert re.search(r"\b[0-9a-f]{64}\b", data["failure_reason"]) is None

    db_session.expire_all()
    read_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.verify")
        .order_by(AuditEvent.sequence_number.desc())
        .first()
    )
    assert read_event is not None
    assert json.loads(read_event.details) == {"verification_status": "INCOMPLETE"}


@pytest.mark.asyncio
async def test_audit_verification_is_rate_limited(
    async_client: AsyncClient, db_session: Session
):
    await _login_admin(
        async_client, db_session, email="admin_verify_rate_limit@example.com"
    )
    limit = audit_verification_rate_limiter.max_requests

    for _ in range(limit):
        allowed = await async_client.get("/api/v1/admin/audit/verify")
        assert allowed.status_code == 200, allowed.text

    blocked = await async_client.get("/api/v1/admin/audit/verify")
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"].isdigit()
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.headers["cache-control"] == "no-store"
    assert blocked.headers["pragma"] == "no-cache"
    assert "rate limit" in blocked.json()["detail"].lower()

    repeated = await async_client.get(
        "/api/v1/admin/audit/verify",
        params={"max_records": "999999", "batch_size": "1"},
    )
    assert repeated.status_code == 429

    db_session.expire_all()
    recorded = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.verify")
        .count()
    )
    assert recorded == limit


@pytest.mark.asyncio
async def test_audit_access_does_not_expand_document_visibility(
    async_client: AsyncClient, db_session: Session
):
    owner = make_user(
        db_session,
        email="owner_audit_boundary@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    document = Document(
        title="Audit Boundary Document",
        original_filename="audit_boundary.pdf",
        storage_key="a" * 64,
        file_size_bytes=16,
        mime_type="application/pdf",
        category="Private",
        owner_id=owner.id,
        is_deleted=False,
    )
    db_session.add(document)
    db_session.commit()

    await _login_admin(async_client, db_session, email="admin_audit_boundary@example.com")

    assert (await async_client.get("/api/v1/admin/audit")).status_code == 200
    assert (
        await async_client.get("/api/v1/admin/documents/activity")
    ).status_code == 200
    assert (
        await async_client.get(f"/api/v1/documents/{document.id}")
    ).status_code == 404


@pytest.mark.asyncio
async def test_admin_audit_reads_are_audited_once(
    async_client: AsyncClient, db_session: Session
):
    """Each successful admin read records exactly one matching audit event."""
    admin = await _login_admin(
        async_client, db_session, email="admin_audit_reads@example.com"
    )

    expected_actions = {
        "/api/v1/admin/audit": "audit.read",
        "/api/v1/admin/audit/verify": "audit.verify",
        "/api/v1/admin/documents/activity": "audit.activity_read",
    }
    for path, action in expected_actions.items():
        response = await async_client.get(path)
        assert response.status_code == 200, response.text

    db_session.expire_all()
    for action in expected_actions.values():
        events = (
            db_session.query(AuditEvent)
            .filter(AuditEvent.action == action)
            .all()
        )
        assert len(events) == 1, action
        assert events[0].actor_id == admin.id
        assert events[0].outcome == AuditOutcome.SUCCESS
        assert events[0].resource_type == "audit"
        assert events[0].resource_id is None

    verify_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.verify")
        .one()
    )
    assert json.loads(verify_event.details) == {"verification_status": "VALID"}


@pytest.mark.asyncio
async def test_admin_read_event_details_expose_only_allowlisted_fields(
    async_client: AsyncClient, db_session: Session
):
    """The recorded verification status is allowlisted and returned to admins."""
    await _login_admin(
        async_client, db_session, email="admin_audit_details@example.com"
    )
    verify = await async_client.get("/api/v1/admin/audit/verify")
    assert verify.status_code == 200, verify.text

    response = await async_client.get(
        "/api/v1/admin/audit", params={"action": "audit.verify"}
    )
    assert response.status_code == 200, response.text
    events = response.json()["events"]
    assert len(events) == 1
    assert events[0]["details"] == {"verification_status": "VALID"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", AUDIT_ENDPOINTS)
async def test_admin_audit_reads_fail_closed_when_audit_write_fails(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
):
    """A successful read is refused if its audit event cannot be persisted."""
    await _login_admin(
        async_client,
        db_session,
        email=f"admin_fail_closed_{path.rsplit('/', 1)[-1]}@example.com",
    )

    def exploding_log_event(*args, **kwargs):
        raise SQLAlchemyError("audit store unavailable")

    monkeypatch.setattr(AuditService, "log_event", exploding_log_event)

    response = await async_client.get(path)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["detail"] == "Audit trail unavailable"


@pytest.mark.asyncio
async def test_failed_audit_write_rolls_back_partial_event_and_session_recovers(
    async_client: AsyncClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    """A flushed-but-uncommitted read event is rolled back and the session stays usable."""
    await _login_admin(
        async_client, db_session, email="admin_partial_audit_write@example.com"
    )

    original_log_event = AuditService.log_event

    def log_then_fail(*args, **kwargs):
        original_log_event(*args, **kwargs)
        raise SQLAlchemyError("simulated audit commit failure")

    monkeypatch.setattr(AuditService, "log_event", log_then_fail)
    response = await async_client.get("/api/v1/admin/audit")
    assert response.status_code == 503

    monkeypatch.setattr(AuditService, "log_event", original_log_event)
    db_session.expire_all()
    assert (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.read")
        .count()
        == 0
    )

    recovered = AuditService.log_event(
        db_session,
        action="audit.read",
        outcome=AuditOutcome.SUCCESS,
        actor_id=None,
        resource_type="audit",
    )
    assert recovered.sequence_number == 1
    is_valid, failure_reason, verified = AuditService.verify_chain_integrity(db_session)
    assert is_valid is True, failure_reason
    assert verified == 1
    db_session.rollback()
