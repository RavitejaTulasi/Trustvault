"""Tests for the notification inbox and permission-request notifications."""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.document import Document
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.tests.test_auth import VALID_PASSWORD, make_user


async def _login(client: AsyncClient, email: str) -> None:
    await client.post("/api/v1/auth/logout")
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_permission_requests_feed_the_notification_inbox(
    async_client: AsyncClient,
    db_session: Session,
) -> None:
    admin = make_user(
        db_session,
        email="notify.admin@example.com",
        password=VALID_PASSWORD,
        role="admin",
    )
    owner = make_user(
        db_session,
        email="notify.owner@example.com",
        password=VALID_PASSWORD,
        role="owner",
    )
    viewer = make_user(
        db_session,
        email="notify.viewer@example.com",
        password=VALID_PASSWORD,
        role="viewer",
    )
    db_session.commit()

    document = Document(
        title="Board minutes",
        original_filename="minutes.pdf",
        storage_key="test-storage-key-notifications",
        file_size_bytes=512,
        mime_type="application/pdf",
        category="Governance",
        owner_id=owner.id,
    )
    db_session.add(document)
    db_session.commit()
    db_session.refresh(document)
    db_session.add(
        DocumentGrant(
            document_id=document.id,
            user_id=viewer.id,
            permission=PermissionLevel.READ,
        )
    )
    db_session.commit()

    await _login(async_client, viewer.email)
    created = await async_client.post(
        "/api/v1/permission-requests/",
        json={"document_id": document.id, "requested_role": "download_activity"},
    )
    assert created.status_code == 201, created.text
    request_id = created.json()["id"]

    await _login(async_client, admin.email)
    inbox = await async_client.get("/api/v1/notifications")
    assert inbox.status_code == 200
    payload = inbox.json()
    assert payload["unread_count"] == 1
    assert len(payload["notifications"]) == 1
    admin_notification = payload["notifications"][0]
    assert admin_notification["title"] == "New permission request"
    assert admin_notification["link"] == "/dashboard"
    assert admin_notification["is_read"] is False
    assert "Board minutes" in admin_notification["message"]

    marked = await async_client.post(
        f"/api/v1/notifications/{admin_notification['id']}/read"
    )
    assert marked.status_code == 200
    assert marked.json()["is_read"] is True

    db_session.expire_all()
    read_event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "notification.read",
            AuditEvent.resource_id == admin_notification["id"],
        )
        .one_or_none()
    )
    assert read_event is not None
    assert read_event.actor_id == admin.id
    assert read_event.outcome == AuditOutcome.SUCCESS

    refreshed = await async_client.get("/api/v1/notifications")
    assert refreshed.json()["unread_count"] == 0

    approved = await async_client.patch(
        f"/api/v1/permission-requests/{request_id}",
        json={"status": "approved"},
    )
    assert approved.status_code == 200

    await _login(async_client, viewer.email)
    viewer_inbox = await async_client.get("/api/v1/notifications")
    assert viewer_inbox.status_code == 200
    viewer_payload = viewer_inbox.json()
    assert viewer_payload["unread_count"] == 1
    requester_notification = viewer_payload["notifications"][0]
    assert requester_notification["title"] == "Permission request approved"
    assert requester_notification["link"] == f"/documents/{document.id}"
    assert "was approved" in requester_notification["message"]

    await _login(async_client, admin.email)
    forbidden = await async_client.post(
        f"/api/v1/notifications/{requester_notification['id']}/read"
    )
    assert forbidden.status_code == 404

    await _login(async_client, viewer.email)
    marked_all = await async_client.post("/api/v1/notifications/read-all")
    assert marked_all.status_code == 200
    assert marked_all.json() == {"updated": 1}
    assert (await async_client.get("/api/v1/notifications")).json()["unread_count"] == 0

    db_session.expire_all()
    read_all_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "notification.read_all")
        .one_or_none()
    )
    assert read_all_event is not None
    assert read_all_event.actor_id == viewer.id
    assert read_all_event.outcome == AuditOutcome.SUCCESS
    assert read_all_event.details is not None
    assert '"updated": 1' in read_all_event.details


@pytest.mark.asyncio
async def test_notification_inbox_requires_authentication(
    async_client: AsyncClient,
) -> None:
    response = await async_client.get("/api/v1/notifications")
    assert response.status_code == 401
