from datetime import UTC, datetime, timedelta
import json

import pytest
from httpx import AsyncClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.user import UserRole
from backend.app.services.audit_service import AuditService
from backend.tests.test_auth import VALID_PASSWORD, make_user


async def _login(client: AsyncClient, email: str) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text


def _review_operation(
    db: Session,
    storage_key: str,
    *,
    operation_type: str = "upload",
) -> StorageOperation:
    operation = StorageOperation(
        operation_type=operation_type,
        storage_key=storage_key,
        status="needs_review",
        content_sha256="a" * 64 if operation_type == "upload" else None,
        retry_count=1,
        next_attempt_at=datetime.now(UTC),
    )
    db.add(operation)
    db.flush()
    return operation


@pytest.mark.asyncio
async def test_storage_operation_review_requires_admin(
    async_client: AsyncClient,
    db_session: Session,
):
    make_user(
        db_session,
        email="storage-review-viewer@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    await _login(async_client, "storage-review-viewer@example.com")

    response = await async_client.get(
        "/api/v1/admin/storage-operations/review"
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_non_admin_cannot_retry_storage_operation(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    make_user(
        db_session,
        email="storage-retry-viewer@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    operation = _review_operation(
        db_session,
        "d" * 64,
        operation_type="delete",
    )
    db_session.commit()
    await _login(async_client, "storage-retry-viewer@example.com")

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation.id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "provider_issue_resolved",
        },
    )

    assert response.status_code == 403
    db_session.refresh(operation)
    assert operation.status == "needs_review"
    assert (
        db_session.query(AuditEvent)
        .filter_by(action="storage_operation.resolve")
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_admin_review_list_does_not_expose_storage_keys(
    async_client: AsyncClient,
    db_session: Session,
):
    admin = make_user(
        db_session,
        email="storage-review-list-admin@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    _review_operation(db_session, "c" * 64)
    db_session.commit()
    await _login(async_client, admin.email)

    response = await async_client.get(
        "/api/v1/admin/storage-operations/review"
    )

    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    operation_data = response.json()["operations"][0]
    assert operation_data["operation_type"] == "upload"
    assert "storage_key" not in operation_data
    review_event = (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operations.review_read",
            actor_id=admin.id,
            outcome=AuditOutcome.SUCCESS,
        )
        .one()
    )
    assert review_event.timestamp is not None


@pytest.mark.asyncio
async def test_admin_review_list_fails_closed_when_audit_write_fails(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    admin = make_user(
        db_session,
        email="storage-review-audit-failure@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    db_session.commit()
    await _login(async_client, admin.email)

    def fail_audit(*args, **kwargs):
        raise SQLAlchemyError("audit write failed")

    monkeypatch.setattr(AuditService, "log_event", fail_audit)

    response = await async_client.get(
        "/api/v1/admin/storage-operations/review"
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Audit trail unavailable"


@pytest.mark.asyncio
async def test_admin_cannot_resolve_ambiguous_upload_without_lifetime_proof(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-review-admin@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(db_session, "b" * 64)
    db_session.commit()
    await _login(async_client, admin.email)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation.id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "operator_verified_cleanup",
        },
    )

    assert response.status_code == 409
    assert "provider-lifetime" in response.json()["detail"]
    db_session.refresh(operation)
    assert operation.status == "needs_review"
    assert operation.claim_token is None
    assert (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operation.resolve",
            resource_id=operation.id,
            outcome=AuditOutcome.SUCCESS,
        )
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_admin_retry_delete_records_audited_retry_intent(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-delete-admin@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(
        db_session,
        "f" * 64,
        operation_type="delete",
    )
    db_session.commit()
    await _login(async_client, admin.email)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation.id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "provider_issue_resolved",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "retry_wait"
    db_session.refresh(operation)
    assert operation.status == "retry_wait"
    assert operation.claim_token is None
    audit_event = (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operation.resolve",
            resource_id=operation.id,
            outcome=AuditOutcome.SUCCESS,
        )
        .one()
    )
    assert audit_event.actor_id == admin.id
    assert audit_event.timestamp is not None
    assert json.loads(audit_event.details or "") == {
        "action": "retry_delete",
        "previous_state": "needs_review",
        "reason": "provider_issue_resolved",
    }
    assert audit_event.resource_id == operation.id

    duplicate_response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation.id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "provider_issue_resolved",
        },
    )
    assert duplicate_response.status_code == 409
    rejected_event = (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operation.resolve",
            resource_id=operation.id,
            outcome=AuditOutcome.DENIED,
        )
        .one()
    )
    assert rejected_event.actor_id == admin.id
    assert rejected_event.timestamp is not None
    assert json.loads(rejected_event.details or "") == {
        "action": "retry_delete",
        "previous_state": "retry_wait",
        "reason": "operation_not_awaiting_review",
    }
    assert (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operation.resolve",
            resource_id=operation.id,
            outcome=AuditOutcome.SUCCESS,
        )
        .count()
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"action": "retry_delete"},
        {"action": "retry_delete", "reason": "try it"},
    ],
)
async def test_retry_requires_a_supported_operator_reason(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, str],
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-retry-invalid-reason@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(
        db_session,
        "e" * 64,
        operation_type="delete",
    )
    db_session.commit()
    await _login(async_client, admin.email)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation.id}/resolve",
        json=payload,
    )

    assert response.status_code == 422
    db_session.refresh(operation)
    assert operation.status == "needs_review"
    assert (
        db_session.query(AuditEvent)
        .filter_by(action="storage_operation.resolve")
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_retry_rejects_stale_claim_and_audits_actual_observed_state(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-retry-stale-claim@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(
        db_session,
        "f" * 64,
        operation_type="delete",
    )
    operation.claim_token = "a" * 36
    operation.lease_until = datetime.now(UTC) + timedelta(minutes=5)
    operation_id = operation.id
    db_session.commit()
    await _login(async_client, admin.email)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation_id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "document_marked_deleted",
        },
    )

    assert response.status_code == 409
    rejection = (
        db_session.query(AuditEvent)
        .filter_by(
            action="storage_operation.resolve",
            resource_id=operation_id,
            outcome=AuditOutcome.DENIED,
        )
        .one()
    )
    assert rejection.actor_id == admin.id
    assert rejection.timestamp is not None
    assert json.loads(rejection.details or "") == {
        "action": "retry_delete",
        "previous_state": "needs_review",
        "reason": "operation_changed_or_claimed",
    }


@pytest.mark.asyncio
async def test_retry_audit_failure_rolls_back_operation_transition(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-retry-audit-failure@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(
        db_session,
        "1" * 64,
        operation_type="delete",
    )
    operation_id = operation.id
    db_session.commit()
    await _login(async_client, admin.email)

    original_log_event = AuditService.log_event
    original_commit = db_session.commit
    original_rollback = db_session.rollback
    observations = {}
    commits_after_failure = 0

    def log_then_fail(*args, **kwargs):
        original_log_event(*args, **kwargs)
        raise SQLAlchemyError("simulated audit commit failure")

    def record_commit():
        nonlocal commits_after_failure
        commits_after_failure += 1
        original_commit()

    def observe_then_rollback():
        observations["status"] = db_session.query(StorageOperation.status).filter_by(
            id=operation_id
        ).scalar()
        observations["audit_count"] = db_session.query(AuditEvent).filter_by(
            action="storage_operation.resolve",
            resource_id=operation_id,
            outcome=AuditOutcome.SUCCESS,
        ).count()
        original_rollback()

    monkeypatch.setattr(AuditService, "log_event", log_then_fail)
    monkeypatch.setattr(db_session, "commit", record_commit)
    monkeypatch.setattr(db_session, "rollback", observe_then_rollback)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation_id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "provider_issue_resolved",
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Audit trail unavailable"
    assert observations == {"status": "retry_wait", "audit_count": 1}
    assert commits_after_failure == 0


@pytest.mark.asyncio
async def test_retry_rejection_audit_failure_returns_service_unavailable(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "supabase")
    admin = make_user(
        db_session,
        email="storage-retry-rejection-audit-failure@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    operation = _review_operation(
        db_session,
        "2" * 64,
        operation_type="delete",
    )
    operation.claim_token = "b" * 36
    operation.lease_until = datetime.now(UTC) + timedelta(minutes=5)
    operation_id = operation.id
    db_session.commit()
    await _login(async_client, admin.email)

    def fail_audit(*args, **kwargs):
        raise SQLAlchemyError("simulated rejection audit failure")

    monkeypatch.setattr(AuditService, "log_event", fail_audit)

    response = await async_client.post(
        f"/api/v1/admin/storage-operations/{operation_id}/resolve",
        json={
            "action": "retry_delete",
            "reason": "provider_issue_resolved",
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Audit trail unavailable"
