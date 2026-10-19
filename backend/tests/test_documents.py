"""
Day 3 Integration Tests for Private Document Management & Storage
Verifies authentication, RBAC, owner authorization, magic byte validation,
size limits, cross-user isolation, audit events, and deliberate 404 responses.
"""

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import UserRole
from backend.tests.test_auth import VALID_PASSWORD, make_user


@pytest.mark.asyncio
async def test_owner_can_upload_valid_pdf(async_client: AsyncClient, db_session: Session):
    """Authenticated document owner can upload a valid PDF file with magic bytes."""
    make_user(db_session, email="owner_up@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_up@example.com", "password": VALID_PASSWORD},
    )

    pdf_content = b"%PDF-1.4 mock pdf document content for testing storage and security"
    files = {"file": ("test_doc.pdf", pdf_content, "application/pdf")}
    data = {"title": "Q3 Financial Report", "category": "Financial"}

    resp = await async_client.post("/api/v1/documents", files=files, data=data)
    assert resp.status_code == 201
    res_json = resp.json()
    assert res_json["title"] == "Q3 Financial Report"
    assert res_json["original_filename"] == "test_doc.pdf"
    assert res_json["file_size_bytes"] == len(pdf_content)
    assert "id" in res_json


@pytest.mark.asyncio
async def test_unauthenticated_document_requests_rejected(async_client: AsyncClient):
    """Unauthenticated requests to document endpoints return 401 Unauthorized."""
    # List
    assert (await async_client.get("/api/v1/documents")).status_code == 401
    # Detail
    assert (await async_client.get("/api/v1/documents/doc_fake123")).status_code == 401
    # Download
    assert (await async_client.get("/api/v1/documents/doc_fake123/download")).status_code == 401
    # Upload
    assert (await async_client.post("/api/v1/documents")).status_code == 401
    # Update
    assert (await async_client.patch("/api/v1/documents/doc_fake123", json={"title": "Hacked"})).status_code == 401
    # Delete
    assert (await async_client.delete("/api/v1/documents/doc_fake123")).status_code == 401


@pytest.mark.asyncio
async def test_owner_lifecycle_operations(async_client: AsyncClient, db_session: Session):
    """Owner can list, retrieve, download, update, and delete their own document."""
    make_user(db_session, email="owner_life@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_life@example.com", "password": VALID_PASSWORD},
    )

    # 1. Upload
    pdf_content = b"%PDF-1.4 Lifecycle Test Document"
    upload_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("lifecycle.pdf", pdf_content, "application/pdf")},
        data={"title": "Original Title", "category": "Legal"},
    )
    assert upload_resp.status_code == 201
    doc_id = upload_resp.json()["id"]

    # 2. List
    list_resp = await async_client.get("/api/v1/documents")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # 3. Retrieve Metadata
    get_resp = await async_client.get(f"/api/v1/documents/{doc_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == "Original Title"

    # 4. Download Bytes
    down_resp = await async_client.get(f"/api/v1/documents/{doc_id}/download")
    assert down_resp.status_code == 200
    assert down_resp.content == pdf_content
    assert "attachment" in down_resp.headers.get("Content-Disposition", "")

    # 5. Update Metadata
    patch_resp = await async_client.patch(
        f"/api/v1/documents/{doc_id}",
        json={"title": "Updated Title", "category": "Confidential"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["title"] == "Updated Title"
    assert patch_resp.json()["category"] == "Confidential"

    # 6. Delete
    del_resp = await async_client.delete(f"/api/v1/documents/{doc_id}")
    assert del_resp.status_code == 204

    # Post-delete retrieval returns 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404


@pytest.mark.asyncio
async def test_cross_user_document_isolation(async_client: AsyncClient, db_session: Session):
    """User A cannot retrieve, download, update, or delete User B's document (returns deliberate 404)."""
    make_user(db_session, email="owner_b@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    make_user(db_session, email="owner_a@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    # Login as Owner B and upload a confidential document
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_b@example.com", "password": VALID_PASSWORD},
    )
    pdf_content = b"%PDF-1.4 Secret Confidential Information belonging to B"
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("secret_b.pdf", pdf_content, "application/pdf")},
        data={"title": "Secret B Document"},
    )
    assert up_resp.status_code == 201
    doc_id = up_resp.json()["id"]

    # Log out B and log in as Owner A
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_a@example.com", "password": VALID_PASSWORD},
    )

    # Owner A attempts to access User B's document -> must receive 404 (deliberate existence shielding)
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 404
    assert (await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "Takeover"})).status_code == 404
    assert (await async_client.delete(f"/api/v1/documents/{doc_id}")).status_code == 404


@pytest.mark.asyncio
async def test_admin_cannot_access_document_contents(async_client: AsyncClient, db_session: Session):
    """Admin role alone does not bypass document-content authorization (returns 404)."""
    make_user(db_session, email="docowner@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    make_user(db_session, email="platformadmin@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    db_session.commit()

    # Owner uploads doc
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "docowner@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("private.pdf", b"%PDF-1.4 Private owner data", "application/pdf")},
        data={"title": "Private Memo"},
    )
    doc_id = up_resp.json()["id"]

    # Login as Admin
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "platformadmin@example.com", "password": VALID_PASSWORD},
    )

    # Admin cannot read metadata or download bytes of unshared document
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 404


@pytest.mark.asyncio
async def test_invalid_file_type_and_magic_bytes_rejected(async_client: AsyncClient, db_session: Session):
    """Invalid extensions and malicious magic bytes (e.g. executable header) are rejected with 400."""
    make_user(db_session, email="malicious@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "malicious@example.com", "password": VALID_PASSWORD},
    )

    # 1. Disallowed extension (.exe)
    resp_ext = await async_client.post(
        "/api/v1/documents",
        files={"file": ("malware.exe", b"MZ mock executable binary", "application/x-msdownload")},
        data={"title": "Fake PDF"},
    )
    assert resp_ext.status_code == 400

    # 2. Disguised executable (.pdf extension but MZ executable magic bytes)
    resp_magic = await async_client.post(
        "/api/v1/documents",
        files={"file": ("disguised.pdf", b"MZ999 malicious payload", "application/pdf")},
        data={"title": "Disguised Malware"},
    )
    assert resp_magic.status_code == 400

    db_session.expire_all()
    denied_events = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "document.upload",
            AuditEvent.outcome == AuditOutcome.DENIED,
        )
        .order_by(AuditEvent.sequence_number.asc())
        .all()
    )
    assert len(denied_events) == 2
    assert [json.loads(event.details)["reason"] for event in denied_events] == [
        "invalid_upload",
        "invalid_upload",
    ]
    assert (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "document.upload",
            AuditEvent.outcome == AuditOutcome.SUCCESS,
        )
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_empty_upload_rejected(async_client: AsyncClient, db_session: Session):
    """Empty file upload returns 400 Bad Request."""
    make_user(db_session, email="emptyup@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "emptyup@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("empty.pdf", b"", "application/pdf")},
        data={"title": "Empty Doc"},
    )
    assert resp.status_code == 400

    db_session.expire_all()
    denied_event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "document.upload",
            AuditEvent.outcome == AuditOutcome.DENIED,
        )
        .one()
    )
    assert json.loads(denied_event.details) == {"reason": "invalid_upload"}


@pytest.mark.asyncio
async def test_viewer_upload_denial_is_audited(async_client: AsyncClient, db_session: Session):
    """A viewer upload attempt is denied and recorded without a false success event."""
    viewer = make_user(
        db_session,
        email="viewer_up_denied@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "viewer_up_denied@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("denied.pdf", b"%PDF-1.4 viewer upload attempt", "application/pdf")},
        data={"title": "Denied Upload"},
    )
    assert resp.status_code == 403

    db_session.expire_all()
    upload_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "document.upload")
        .all()
    )
    assert len(upload_events) == 1
    assert upload_events[0].outcome == AuditOutcome.DENIED
    assert upload_events[0].actor_id == viewer.id
    assert json.loads(upload_events[0].details) == {"reason": "insufficient_role"}


@pytest.mark.asyncio
async def test_document_audit_events_created(async_client: AsyncClient, db_session: Session):
    """Successful upload, download, and denied access create corresponding audit events."""
    make_user(db_session, email="auditdoc@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    make_user(db_session, email="auditother@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    # Upload as owner
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "auditdoc@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("audited.pdf", b"%PDF-1.4 Audited file bytes", "application/pdf")},
        data={"title": "Audited Document"},
    )
    doc_id = up_resp.json()["id"]

    # Download as owner (success audit)
    await async_client.get(f"/api/v1/documents/{doc_id}/download")

    # Attempt access as other user (denied audit)
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "auditother@example.com", "password": VALID_PASSWORD},
    )
    await async_client.get(f"/api/v1/documents/{doc_id}")

    # Verify audit events in database
    db_session.expire_all()
    upload_event = db_session.query(AuditEvent).filter(AuditEvent.action == "document.upload", AuditEvent.outcome == AuditOutcome.SUCCESS).first()
    assert upload_event is not None

    download_event = db_session.query(AuditEvent).filter(AuditEvent.action == "document.download", AuditEvent.outcome == AuditOutcome.SUCCESS).first()
    assert download_event is not None

    denied_event = db_session.query(AuditEvent).filter(AuditEvent.action == "document.read", AuditEvent.outcome == AuditOutcome.DENIED).first()
    assert denied_event is not None
