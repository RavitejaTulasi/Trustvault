"""
Day 4 Integration Tests for Document Sharing, Access Grants & Immediate Revocation
Verifies grant management, least-privilege permission levels (read vs edit),
immediate revocation, cross-user isolation, and sharing audit events.
"""

import json
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

import backend.app.api.documents as documents_api
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.grant import DocumentGrant
from backend.app.models.user import UserRole
from backend.tests.test_auth import VALID_PASSWORD, make_user


async def _login(client: AsyncClient, email: str) -> None:
    await client.post("/api/v1/auth/logout")
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert resp.status_code == 200


async def _upload(client: AsyncClient, title: str, filename: str = "document.pdf") -> str:
    resp = await client.post(
        "/api/v1/documents",
        files={"file": (filename, b"%PDF-1.4 Test document bytes", "application/pdf")},
        data={"title": title},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_owner_can_grant_read_and_edit(async_client: AsyncClient, db_session: Session):
    """Owner can grant read and edit permissions to named users."""
    make_user(db_session, email="owner_share@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient_read = make_user(db_session, email="recip_read@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    recipient_edit = make_user(db_session, email="recip_edit@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    # Owner uploads a document
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_share@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("shared.pdf", b"%PDF-1.4 Shared doc content", "application/pdf")},
        data={"title": "Shared Contract"},
    )
    assert up_resp.status_code == 201
    doc_id = up_resp.json()["id"]

    # 1. Grant read access to recipient_read
    grant_read_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient_read.id, "permission": "read"},
    )
    assert grant_read_resp.status_code == 201
    assert grant_read_resp.json()["permission"] == "read"

    # 2. Grant edit access to recipient_edit
    grant_edit_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient_edit.id, "permission": "edit"},
    )
    assert grant_edit_resp.status_code == 201
    assert grant_edit_resp.json()["permission"] == "edit"

    # 3. List permissions
    list_perm_resp = await async_client.get(f"/api/v1/documents/{doc_id}/permissions")
    assert list_perm_resp.status_code == 200
    assert len(list_perm_resp.json()["grants"]) == 2


@pytest.mark.asyncio
async def test_read_grant_permissions_enforced(async_client: AsyncClient, db_session: Session):
    """Read grant permits metadata access and download, but blocks edit and delete."""
    make_user(db_session, email="owner_r@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    reader = make_user(db_session, email="reader@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    # Owner uploads document and grants read access
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_r@example.com", "password": VALID_PASSWORD},
    )
    pdf_bytes = b"%PDF-1.4 Reader test bytes"
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("readtest.pdf", pdf_bytes, "application/pdf")},
        data={"title": "Read-Only Doc"},
    )
    doc_id = up_resp.json()["id"]

    await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": reader.id, "permission": "read"},
    )

    # Login as reader
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "reader@example.com", "password": VALID_PASSWORD},
    )

    # Reader can list document
    list_resp = await async_client.get("/api/v1/documents")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 1

    # Reader can retrieve metadata
    get_resp = await async_client.get(f"/api/v1/documents/{doc_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == "Read-Only Doc"

    # Reader can download bytes
    down_resp = await async_client.get(f"/api/v1/documents/{doc_id}/download")
    assert down_resp.status_code == 200
    assert down_resp.content == pdf_bytes

    # Reader CANNOT edit metadata -> returns 404
    patch_resp = await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "Reader Hack"})
    assert patch_resp.status_code == 404

    # Reader CANNOT delete document -> returns 404
    del_resp = await async_client.delete(f"/api/v1/documents/{doc_id}")
    assert del_resp.status_code == 404

    # Reader CANNOT view permissions -> returns 404
    perm_resp = await async_client.get(f"/api/v1/documents/{doc_id}/permissions")
    assert perm_resp.status_code == 404


@pytest.mark.asyncio
async def test_edit_grant_permissions_enforced(async_client: AsyncClient, db_session: Session):
    """Edit grant permits metadata updates, read, and download, but blocks deletion and sharing."""
    make_user(db_session, email="owner_e@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    editor = make_user(db_session, email="editor@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    other = make_user(db_session, email="other@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_e@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("edittest.pdf", b"%PDF-1.4 Editor bytes", "application/pdf")},
        data={"title": "Editable Doc"},
    )
    doc_id = up_resp.json()["id"]

    await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": editor.id, "permission": "edit"},
    )

    # Login as editor
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "editor@example.com", "password": VALID_PASSWORD},
    )

    # Editor can read and download
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 200
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 200

    # Editor can update metadata
    patch_resp = await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "Editor Updated Title"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["title"] == "Editor Updated Title"

    # Editor CANNOT delete document -> returns 404
    assert (await async_client.delete(f"/api/v1/documents/{doc_id}")).status_code == 404

    # Editor CANNOT share/grant permissions -> returns 404
    share_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": other.id, "permission": "read"},
    )
    assert share_resp.status_code == 404


@pytest.mark.asyncio
async def test_immediate_revocation_sequence(async_client: AsyncClient, db_session: Session):
    """Revoking a grant immediately blocks subsequent metadata, download, and edit requests."""
    make_user(db_session, email="owner_rev@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient = make_user(db_session, email="recipient_rev@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    # 1. Owner uploads document
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_rev@example.com", "password": VALID_PASSWORD},
    )
    pdf_bytes = b"%PDF-1.4 Revocation test bytes"
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("revokeme.pdf", pdf_bytes, "application/pdf")},
        data={"title": "Revocation Doc"},
    )
    doc_id = up_resp.json()["id"]

    # 2. Owner grants edit access
    await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "edit"},
    )

    # 3. Recipient successfully accesses document
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "recipient_rev@example.com", "password": VALID_PASSWORD},
    )
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 200
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 200
    assert (await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "Before Revoke"})).status_code == 200

    # 4. Owner revokes access
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_rev@example.com", "password": VALID_PASSWORD},
    )
    revoke_resp = await async_client.delete(f"/api/v1/documents/{doc_id}/permissions/{recipient.id}")
    assert revoke_resp.status_code == 200

    # 5. Recipient immediately blocked on very next request (deliberate 404)
    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "recipient_rev@example.com", "password": VALID_PASSWORD},
    )
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 404
    assert (await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "After Revoke"})).status_code == 404


@pytest.mark.asyncio
async def test_non_owner_cannot_manage_grants(async_client: AsyncClient, db_session: Session):
    """Non-owners (readers, editors, random viewers) cannot list, create, or revoke grants."""
    make_user(db_session, email="owner_ng@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    make_user(db_session, email="viewer_ng@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    other = make_user(db_session, email="other_ng@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_ng@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("ng.pdf", b"%PDF-1.4", "application/pdf")},
        data={"title": "NG Doc"},
    )
    doc_id = up_resp.json()["id"]

    await async_client.post("/api/v1/auth/logout")
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "viewer_ng@example.com", "password": VALID_PASSWORD},
    )

    # Viewer attempts grant management -> 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/permissions")).status_code == 404
    assert (await async_client.post(f"/api/v1/documents/{doc_id}/permissions", json={"user_id": other.id, "permission": "read"})).status_code == 404
    assert (await async_client.delete(f"/api/v1/documents/{doc_id}/permissions/{other.id}")).status_code == 404


@pytest.mark.asyncio
async def test_sharing_audit_events_logged(async_client: AsyncClient, db_session: Session):
    """Grant creation and revocation generate audit events."""
    make_user(db_session, email="owner_aud@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recip = make_user(db_session, email="recip_aud@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner_aud@example.com", "password": VALID_PASSWORD},
    )
    up_resp = await async_client.post(
        "/api/v1/documents",
        files={"file": ("auditshare.pdf", b"%PDF-1.4", "application/pdf")},
        data={"title": "Audit Share Doc"},
    )
    doc_id = up_resp.json()["id"]

    # Grant
    await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recip.id, "permission": "read"},
    )

    # Revoke
    await async_client.delete(f"/api/v1/documents/{doc_id}/permissions/{recip.id}")

    db_session.expire_all()
    grant_event = db_session.query(AuditEvent).filter(AuditEvent.action == "permission.grant", AuditEvent.outcome == AuditOutcome.SUCCESS).first()
    assert grant_event is not None

    revoke_event = db_session.query(AuditEvent).filter(AuditEvent.action == "permission.revoke", AuditEvent.outcome == AuditOutcome.SUCCESS).first()
    assert revoke_event is not None


@pytest.mark.asyncio
async def test_regrant_after_revocation_restores_requested_permission(
    async_client: AsyncClient, db_session: Session
):
    """A revoked user can be re-granted with the newly selected permission only."""
    owner = make_user(db_session, email="owner_regrant@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient = make_user(db_session, email="recipient_regrant@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Regrant Doc", "regrant.pdf")

    grant_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "edit"},
    )
    assert grant_resp.status_code == 201
    assert grant_resp.json()["permission"] == "edit"

    revoke_resp = await async_client.delete(f"/api/v1/documents/{doc_id}/permissions/{recipient.id}")
    assert revoke_resp.status_code == 200

    db_session.expire_all()
    revoked_grant = (
        db_session.query(DocumentGrant)
        .filter(DocumentGrant.document_id == doc_id, DocumentGrant.user_id == recipient.id)
        .one()
    )
    assert revoked_grant.is_revoked is True
    assert revoked_grant.revocation_version == 1

    regrant_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "read"},
    )
    assert regrant_resp.status_code == 201
    assert regrant_resp.json()["permission"] == "read"
    assert regrant_resp.json()["is_revoked"] is False

    db_session.expire_all()
    grants = (
        db_session.query(DocumentGrant)
        .filter(DocumentGrant.document_id == doc_id, DocumentGrant.user_id == recipient.id)
        .all()
    )
    assert len(grants) == 1
    assert grants[0].permission == "read"
    assert grants[0].is_revoked is False
    assert grants[0].granted_by_id == owner.id
    assert grants[0].revocation_version == 1

    await _login(async_client, recipient.email)
    list_resp = await async_client.get("/api/v1/documents")
    assert list_resp.status_code == 200
    assert doc_id in {doc["id"] for doc in list_resp.json()["documents"]}
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 200
    assert (await async_client.patch(f"/api/v1/documents/{doc_id}", json={"title": "No longer editable"})).status_code == 404


@pytest.mark.asyncio
async def test_owner_cannot_grant_access_to_themselves(async_client: AsyncClient, db_session: Session):
    """Granting to the document owner is rejected and does not create a grant row."""
    owner = make_user(db_session, email="owner_self@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Self Grant Doc", "selfgrant.pdf")

    resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": owner.id, "permission": "read"},
    )
    assert resp.status_code == 400

    db_session.expire_all()
    count = db_session.query(DocumentGrant).filter(DocumentGrant.document_id == doc_id).count()
    assert count == 0


@pytest.mark.asyncio
async def test_cannot_grant_access_to_inactive_recipient(async_client: AsyncClient, db_session: Session):
    """Inactive recipients cannot receive grants."""
    owner = make_user(db_session, email="owner_inactive@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    inactive = make_user(
        db_session,
        email="inactive_recipient@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
        is_active=False,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Inactive Grant Doc", "inactive.pdf")

    resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": inactive.id, "permission": "read"},
    )
    assert resp.status_code == 404

    db_session.expire_all()
    count = db_session.query(DocumentGrant).filter(DocumentGrant.document_id == doc_id).count()
    assert count == 0


@pytest.mark.asyncio
async def test_invalid_permission_value_rejected(async_client: AsyncClient, db_session: Session):
    """Privilege-escalation permission values are rejected with 422 and no grant row."""
    owner = make_user(db_session, email="owner_invalid@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient = make_user(db_session, email="recipient_invalid@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Invalid Permission Doc", "invalidperm.pdf")

    resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "admin"},
    )
    assert resp.status_code == 422

    db_session.expire_all()
    count = db_session.query(DocumentGrant).filter(DocumentGrant.document_id == doc_id).count()
    assert count == 0


@pytest.mark.asyncio
async def test_document_list_excludes_revoked_grant(async_client: AsyncClient, db_session: Session):
    """A revoked document disappears from the recipient's document list."""
    owner = make_user(db_session, email="owner_revlist@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient = make_user(db_session, email="recipient_revlist@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Revoked List Doc", "revokedlist.pdf")
    assert (
        await async_client.post(
            f"/api/v1/documents/{doc_id}/permissions",
            json={"user_id": recipient.id, "permission": "read"},
        )
    ).status_code == 201

    await _login(async_client, recipient.email)
    before = await async_client.get("/api/v1/documents")
    assert before.status_code == 200
    assert before.json()["total"] == 1
    assert doc_id in {doc["id"] for doc in before.json()["documents"]}

    await _login(async_client, owner.email)
    assert (await async_client.delete(f"/api/v1/documents/{doc_id}/permissions/{recipient.id}")).status_code == 200

    await _login(async_client, recipient.email)
    after = await async_client.get("/api/v1/documents")
    assert after.status_code == 200
    assert after.json()["total"] == 0
    assert doc_id not in {doc["id"] for doc in after.json()["documents"]}

    db_session.expire_all()
    grant = (
        db_session.query(DocumentGrant)
        .filter(DocumentGrant.document_id == doc_id, DocumentGrant.user_id == recipient.id)
        .one()
    )
    assert grant.is_revoked is True


@pytest.mark.asyncio
async def test_duplicate_grant_requests_keep_single_record(async_client: AsyncClient, db_session: Session):
    """Duplicate grant requests upsert one row and apply the latest permission."""
    owner = make_user(db_session, email="owner_dup@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    recipient = make_user(db_session, email="recipient_dup@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Duplicate Grant Doc", "duplicate.pdf")

    first = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "read"},
    )
    assert first.status_code == 201
    second = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "edit"},
    )
    assert second.status_code == 201
    assert second.json()["permission"] == "edit"

    db_session.expire_all()
    grants = (
        db_session.query(DocumentGrant)
        .filter(DocumentGrant.document_id == doc_id, DocumentGrant.user_id == recipient.id)
        .all()
    )
    assert len(grants) == 1
    assert grants[0].permission == "edit"
    assert grants[0].is_revoked is False

    list_resp = await async_client.get(f"/api/v1/documents/{doc_id}/permissions")
    assert list_resp.status_code == 200
    assert len(list_resp.json()["grants"]) == 1


@pytest.mark.asyncio
async def test_admin_cannot_list_unshared_document_metadata(async_client: AsyncClient, db_session: Session):
    """Administrator role alone does not expose another user's document metadata."""
    make_user(db_session, email="owner_adminlist@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    make_user(db_session, email="admin_adminlist@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    db_session.commit()

    await _login(async_client, "owner_adminlist@example.com")
    doc_id = await _upload(async_client, "Admin Must Not See", "adminmustnotsee.pdf")

    await _login(async_client, "admin_adminlist@example.com")
    list_resp = await async_client.get("/api/v1/documents")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 0
    assert doc_id not in {doc["id"] for doc in list_resp.json()["documents"]}
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/download")).status_code == 404
    assert (await async_client.get(f"/api/v1/documents/{doc_id}/permissions")).status_code == 404


@pytest.mark.asyncio
async def test_admin_list_includes_owned_and_explicitly_granted_documents(
    async_client: AsyncClient, db_session: Session
):
    """Administrators see documents they own or are explicitly granted, nothing else."""
    admin = make_user(db_session, email="admin_scoped@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    owner = make_user(db_session, email="owner_scoped@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    outsider = make_user(db_session, email="outsider_scoped@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await _login(async_client, admin.email)
    admin_doc_id = await _upload(async_client, "Admin Owned", "adminowned.pdf")

    await _login(async_client, owner.email)
    shared_doc_id = await _upload(async_client, "Shared With Admin", "sharedadmin.pdf")
    assert (
        await async_client.post(
            f"/api/v1/documents/{shared_doc_id}/permissions",
            json={"user_id": admin.id, "permission": "read"},
        )
    ).status_code == 201

    await _login(async_client, outsider.email)
    outsider_doc_id = await _upload(async_client, "Outsider Private", "outsiderprivate.pdf")

    await _login(async_client, admin.email)
    list_resp = await async_client.get("/api/v1/documents")
    assert list_resp.status_code == 200
    visible_ids = {doc["id"] for doc in list_resp.json()["documents"]}
    assert list_resp.json()["total"] == 2
    assert admin_doc_id in visible_ids
    assert shared_doc_id in visible_ids
    assert outsider_doc_id not in visible_ids

    assert (await async_client.get(f"/api/v1/documents/{admin_doc_id}")).status_code == 200
    assert (await async_client.get(f"/api/v1/documents/{shared_doc_id}")).status_code == 200
    assert (await async_client.get(f"/api/v1/documents/{shared_doc_id}/download")).status_code == 200
    assert (await async_client.get(f"/api/v1/documents/{outsider_doc_id}")).status_code == 404
    assert (await async_client.patch(f"/api/v1/documents/{shared_doc_id}", json={"title": "No edit"})).status_code == 404


@pytest.mark.asyncio
async def test_grant_returns_conflict_when_revoke_wins(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
):
    """A grant whose write was refused by the revocation generation returns 409."""
    owner = make_user(
        db_session,
        email="owner_conflict@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    recipient = make_user(
        db_session,
        email="recipient_conflict@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Conflict Doc", "conflict.pdf")

    def stale_upsert(*args, **kwargs):
        return documents_api.GrantUpsertOutcome(
            grant=SimpleNamespace(id="stale-grant-id"),
            applied=False,
        )

    monkeypatch.setattr(documents_api, "_upsert_grant", stale_upsert)

    response = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "read"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Permission grant was revoked concurrently"

    db_session.expire_all()
    events = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "permission.grant",
            AuditEvent.outcome == AuditOutcome.FAILURE,
        )
        .all()
    )
    assert len(events) == 1
    assert json.loads(events[0].details)["reason"] == "revoked_concurrently"
    assert (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "permission.grant",
            AuditEvent.outcome == AuditOutcome.SUCCESS,
        )
        .count()
        == 0
    )


@pytest.mark.asyncio
async def test_sqlite_conditional_upsert_refuses_stale_revoked_generation(
    async_client: AsyncClient,
    db_session: Session,
):
    """The SQLite conditional upsert cannot reactivate a concurrently revoked grant."""
    owner = make_user(
        db_session,
        email="owner_generation@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    recipient = make_user(
        db_session,
        email="recipient_generation@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(async_client, "Generation Doc", "generation.pdf")

    grant_resp = await async_client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        json={"user_id": recipient.id, "permission": "edit"},
    )
    assert grant_resp.status_code == 201

    grant = (
        db_session.query(DocumentGrant)
        .filter(
            DocumentGrant.document_id == doc_id,
            DocumentGrant.user_id == recipient.id,
        )
        .one()
    )
    captured_generation = grant.revocation_version

    revoke_resp = await async_client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{recipient.id}"
    )
    assert revoke_resp.status_code == 200

    stale = documents_api._upsert_grant(
        db_session,
        doc_id,
        recipient.id,
        "read",
        owner.id,
        expected_revocation_version=captured_generation,
    )
    assert stale.applied is False
    assert stale.grant.is_revoked is True
    assert stale.grant.permission == "edit"

    current = (
        db_session.query(DocumentGrant)
        .filter(
            DocumentGrant.document_id == doc_id,
            DocumentGrant.user_id == recipient.id,
        )
        .one()
    )
    assert current.is_revoked is True
    assert current.revocation_version == captured_generation + 1

    regrant = documents_api._upsert_grant(
        db_session,
        doc_id,
        recipient.id,
        "read",
        owner.id,
        expected_revocation_version=current.revocation_version,
    )
    assert regrant.applied is True
    assert regrant.grant.is_revoked is False
    assert regrant.grant.permission == "read"
