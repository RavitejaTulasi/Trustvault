"""Tests for permission request lifecycle and document activity export."""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.document import Document
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.security.rate_limiter import (
    LoginRateLimitDecision,
    activity_export_rate_limiter,
    permission_request_rate_limiter,
)
from backend.app.services.audit_service import AuditService
from backend.tests.test_auth import VALID_PASSWORD, make_user


async def _login(client: AsyncClient, email: str) -> None:
    await client.post("/api/v1/auth/logout")
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_permission_request_and_activity_export_flow(
    async_client: AsyncClient,
    db_session: Session,
) -> None:
    # 1. Setup Admin, Owner, and Viewer users
    admin = make_user(db_session, email="admin_pr_test@example.com", password=VALID_PASSWORD, role="admin")
    owner = make_user(db_session, email="owner_pr_test@example.com", password=VALID_PASSWORD, role="owner")
    viewer = make_user(db_session, email="viewer_pr_test@example.com", password=VALID_PASSWORD, role="viewer")
    db_session.commit()

    # Create a document owned by owner
    doc = Document(
        title="Financial Report 2026",
        original_filename="report.pdf",
        storage_key="test-storage-key-report-2026",
        file_size_bytes=1024,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(doc)
    db_session.commit()
    db_session.refresh(doc)

    # Grant read access to viewer
    grant = DocumentGrant(
        document_id=doc.id,
        user_id=viewer.id,
        permission=PermissionLevel.READ,
    )
    db_session.add(grant)

    # Log some audit events for this document
    AuditService.log_event(
        db_session,
        action="document.create",
        outcome=AuditOutcome.SUCCESS,
        actor_id=owner.id,
        resource_type="document",
        resource_id=doc.id,
    )
    AuditService.log_event(
        db_session,
        action="document.read",
        outcome=AuditOutcome.SUCCESS,
        actor_id=viewer.id,
        resource_type="document",
        resource_id=doc.id,
        ip_address="203.0.113.10",
        user_agent="pytest-viewer",
        request_id="req-viewer-activity",
    )
    db_session.commit()

    # 2. Viewer logs in and can view document activity, but sensitive request
    # metadata is redacted for non-admin readers.
    await _login(async_client, viewer.email)
    activity_res = await async_client.get(f"/api/v1/documents/{doc.id}/activity")
    assert activity_res.status_code == 200
    activity_events = activity_res.json()["events"]
    assert activity_res.json()["total"] >= 2
    viewer_read_event = next(e for e in activity_events if e["action"] == "document.read")
    assert viewer_read_event["ip_address"] is None
    assert viewer_read_event["user_agent"] is None
    assert viewer_read_event["request_id"] is None

    # 3. Viewer attempts to export activity without permission -> 403 Forbidden
    export_fail = await async_client.get(f"/api/v1/documents/{doc.id}/activity/export?format=csv")
    assert export_fail.status_code == 403
    assert "Download permission required" in export_fail.json()["detail"]
    denial = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "audit.activity_export",
            AuditEvent.outcome == AuditOutcome.DENIED,
            AuditEvent.resource_id == doc.id,
        )
        .one_or_none()
    )
    assert denial is not None

    # 4. Check initial request status -> None
    status_res = await async_client.get(f"/api/v1/permission-requests/status?document_id={doc.id}")
    assert status_res.status_code == 200
    assert status_res.json() is None

    # 5. Viewer submits a request to download activity
    req_res = await async_client.post(
        "/api/v1/permission-requests/",
        json={"document_id": doc.id, "requested_role": "download_activity"},
    )
    assert req_res.status_code == 201
    req_data = req_res.json()
    assert req_data["status"] == "pending"
    assert req_data["document_id"] == doc.id
    assert req_data["document_title"] is None
    assert req_data["requester_email"] is None
    request_id = req_data["id"]

    # 6. Status check now returns pending without leaking document metadata
    status_res2 = await async_client.get(f"/api/v1/permission-requests/status?document_id={doc.id}")
    assert status_res2.status_code == 200
    assert status_res2.json()["status"] == "pending"
    assert status_res2.json()["document_title"] is None
    assert status_res2.json()["requester_email"] is None

    # 7. Admin logs in and checks pending requests
    await _login(async_client, admin.email)
    pending_res = await async_client.get("/api/v1/permission-requests/pending")
    assert pending_res.status_code == 200
    pending_list = pending_res.json()
    pending_item = next(p for p in pending_list if p["id"] == request_id)
    assert pending_item["document_title"] == doc.title
    assert pending_item["requester_email"] == viewer.email

    # Admin approves the request
    approve_res = await async_client.patch(
        f"/api/v1/permission-requests/{request_id}",
        json={"status": "approved"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "approved"
    assert approve_res.json()["document_title"] == doc.title
    assert approve_res.json()["requester_email"] == viewer.email

    # A request cannot be moved back to pending, and a completed request is immutable.
    reset_to_pending = await async_client.patch(
        f"/api/v1/permission-requests/{request_id}",
        json={"status": "pending"},
    )
    assert reset_to_pending.status_code == 400
    update_approved = await async_client.patch(
        f"/api/v1/permission-requests/{request_id}",
        json={"status": "rejected"},
    )
    assert update_approved.status_code == 409

    # 8. Viewer logs in again: status is now approved and export works!
    await _login(async_client, viewer.email)
    status_res3 = await async_client.get(f"/api/v1/permission-requests/status?document_id={doc.id}")
    assert status_res3.status_code == 200
    assert status_res3.json()["status"] == "approved"
    assert status_res3.json()["document_title"] is None
    assert status_res3.json()["requester_email"] is None

    # Viewer exports CSV without sensitive request metadata
    export_csv = await async_client.get(f"/api/v1/documents/{doc.id}/activity/export?format=csv")
    assert export_csv.status_code == 200
    assert "text/csv" in export_csv.headers["content-type"]
    assert export_csv.headers["cache-control"] == "no-store, no-cache, must-revalidate"
    csv_text = export_csv.text
    assert "Sequence" in csv_text
    assert "document.create" in csv_text
    assert "203.0.113.10" not in csv_text

    # Viewer exports Excel
    export_excel = await async_client.get(f"/api/v1/documents/{doc.id}/activity/export?format=excel")
    assert export_excel.status_code == 200
    assert "application/vnd.ms-excel" in export_excel.headers["content-type"]
    assert "document.create" in export_excel.text

    # 9. Admin can always export directly and sees sensitive request metadata
    await _login(async_client, admin.email)
    admin_activity = await async_client.get(f"/api/v1/documents/{doc.id}/activity")
    assert admin_activity.status_code == 200
    admin_read_event = next(
        e for e in admin_activity.json()["events"] if e["action"] == "document.read"
    )
    assert admin_read_event["ip_address"] == "203.0.113.10"
    assert admin_read_event["user_agent"] == "pytest-viewer"
    assert admin_read_event["request_id"] == "req-viewer-activity"

    admin_export = await async_client.get(f"/api/v1/documents/{doc.id}/activity/export?format=csv")
    assert admin_export.status_code == 200
    assert admin_export.headers["cache-control"] == "no-store, no-cache, must-revalidate"
    assert "203.0.113.10" in admin_export.text

    # 10. The document owner can export without an approved request
    await _login(async_client, owner.email)
    owner_export = await async_client.get(f"/api/v1/documents/{doc.id}/activity/export?format=csv")
    assert owner_export.status_code == 200

@pytest.mark.asyncio
async def test_permission_request_creation_is_rate_limited(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = make_user(
        db_session,
        email="owner_pr_limit@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    viewer = make_user(
        db_session,
        email="viewer_pr_limit@example.com",
        password=VALID_PASSWORD,
        role="viewer",
    )
    document = Document(
        title="Rate limited request",
        original_filename="rate.pdf",
        storage_key="test-storage-key-pr-limit",
        file_size_bytes=128,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)

    monkeypatch.setattr(permission_request_rate_limiter, "max_attempts", 1)
    await _login(async_client, viewer.email)

    first = await async_client.post(
        "/api/v1/permission-requests/",
        json={"document_id": document.id, "requested_role": "download_activity"},
    )
    assert first.status_code == 201, first.text

    second = await async_client.post(
        "/api/v1/permission-requests/",
        json={"document_id": document.id, "requested_role": "download_activity"},
    )
    assert second.status_code == 429
    assert second.json()["detail"] == (
        "Too many permission requests. Please try again later."
    )
    assert int(second.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_activity_export_rejects_rows_above_the_configured_limit(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = make_user(
        db_session,
        email="admin_export_limit@example.com",
        password=VALID_PASSWORD,
        role="admin",
    )
    owner = make_user(
        db_session,
        email="owner_export_limit@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    document = Document(
        title="Large activity export",
        original_filename="large.pdf",
        storage_key="test-storage-key-export-limit",
        file_size_bytes=256,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)

    for index in range(2):
        AuditService.log_event(
            db_session,
            action=f"document.export_test_{index}",
            outcome=AuditOutcome.SUCCESS,
            actor_id=owner.id,
            resource_type="document",
            resource_id=document.id,
        )
    db_session.commit()

    monkeypatch.setattr(settings, "DOCUMENT_ACTIVITY_EXPORT_MAX_ROWS", 1)
    await _login(async_client, admin.email)

    response = await async_client.get(
        f"/api/v1/documents/{document.id}/activity/export?format=csv"
    )
    assert response.status_code == 413
    assert "row limit" in response.json()["detail"]

    db_session.expire_all()
    denial = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "audit.activity_export",
            AuditEvent.outcome == AuditOutcome.DENIED,
            AuditEvent.details.like("%export_row_limit_exceeded%"),
        )
        .one_or_none()
    )
    assert denial is not None


@pytest.mark.asyncio
async def test_activity_export_is_rate_limited(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = make_user(
        db_session,
        email="admin_export_rate@example.com",
        password=VALID_PASSWORD,
        role="admin",
    )
    owner = make_user(
        db_session,
        email="owner_export_rate@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    document = Document(
        title="Rate limited export",
        original_filename="rate-export.pdf",
        storage_key="test-storage-key-export-rate",
        file_size_bytes=256,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)

    AuditService.log_event(
        db_session,
        action="document.create",
        outcome=AuditOutcome.SUCCESS,
        actor_id=owner.id,
        resource_type="document",
        resource_id=document.id,
    )
    db_session.commit()

    monkeypatch.setattr(activity_export_rate_limiter, "max_attempts", 1)
    await _login(async_client, admin.email)

    first = await async_client.get(
        f"/api/v1/documents/{document.id}/activity/export?format=csv"
    )
    assert first.status_code == 200, first.text

    second = await async_client.get(
        f"/api/v1/documents/{document.id}/activity/export?format=csv"
    )
    assert second.status_code == 429
    assert second.json()["detail"] == (
        "Too many activity exports. Please try again later."
    )
    assert int(second.headers["Retry-After"]) > 0

@pytest.mark.asyncio
async def test_permission_request_rate_limit_denial_is_audited(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = make_user(
        db_session,
        email="owner_pr_audit@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    viewer = make_user(
        db_session,
        email="viewer_pr_audit@example.com",
        password=VALID_PASSWORD,
        role="viewer",
    )
    document = Document(
        title="Audited request denial",
        original_filename="audit.pdf",
        storage_key="test-storage-key-pr-audit",
        file_size_bytes=128,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)
    await _login(async_client, viewer.email)

    now = int(permission_request_rate_limiter.time_func())
    ip_key = permission_request_rate_limiter._build_keys(
        "127.0.0.1", viewer.email
    )[1][0]
    db_session.add(
        LoginRateLimitBucket(
            key_hash=ip_key,
            scope="ip",
            attempt_count=permission_request_rate_limiter.max_attempts,
            window_started_at=now,
            expires_at=now + permission_request_rate_limiter.window_seconds,
            denial_audit_recorded=False,
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        permission_request_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False, retry_after=60
        ),
    )

    denied = await async_client.post(
        "/api/v1/permission-requests/",
        json={"document_id": document.id, "requested_role": "download_activity"},
    )
    assert denied.status_code == 429

    db_session.expire_all()
    denial = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "permission_request.rate_limited")
        .one_or_none()
    )
    assert denial is not None
    assert denial.actor_id == viewer.id
    assert denial.outcome == AuditOutcome.DENIED


@pytest.mark.asyncio
async def test_activity_export_rate_limit_denial_is_audited(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = make_user(
        db_session,
        email="admin_export_audit@example.com",
        password=VALID_PASSWORD,
        role="admin",
    )
    owner = make_user(
        db_session,
        email="owner_export_audit@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    document = Document(
        title="Audited export denial",
        original_filename="audit-export.pdf",
        storage_key="test-storage-key-export-audit",
        file_size_bytes=256,
        mime_type="application/pdf",
        category="Finance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)
    AuditService.log_event(
        db_session,
        action="document.create",
        outcome=AuditOutcome.SUCCESS,
        actor_id=owner.id,
        resource_type="document",
        resource_id=document.id,
    )
    db_session.commit()
    await _login(async_client, admin.email)

    now = int(activity_export_rate_limiter.time_func())
    ip_key = activity_export_rate_limiter._build_keys(
        "127.0.0.1", admin.email
    )[1][0]
    db_session.add(
        LoginRateLimitBucket(
            key_hash=ip_key,
            scope="ip",
            attempt_count=activity_export_rate_limiter.max_attempts,
            window_started_at=now,
            expires_at=now + activity_export_rate_limiter.window_seconds,
            denial_audit_recorded=False,
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        activity_export_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False, retry_after=60
        ),
    )

    denied = await async_client.get(
        f"/api/v1/documents/{document.id}/activity/export?format=csv"
    )
    assert denied.status_code == 429

    db_session.expire_all()
    denial = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "audit.activity_export_rate_limited")
        .one_or_none()
    )
    assert denial is not None
    assert denial.actor_id == admin.id
    assert denial.outcome == AuditOutcome.DENIED
