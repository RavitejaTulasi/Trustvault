"""Mandatory first-login password-change tests."""

import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.main import app
from backend.app.models.audit import AuditEvent
from backend.app.models.user import User, UserRole
from backend.app.security.passwords import hash_password, verify_password

ADMIN_PASSWORD = "Admin!Secure#Pass1"
INITIAL_PASSWORD = "Initial!Secure#Pass2"
NEW_PASSWORD = "Changed!Secure#Pass3"


def make_user(
    db: Session,
    email: str,
    *,
    password: str = ADMIN_PASSWORD,
    role: str = UserRole.ADMIN,
    must_change_password: bool = False,
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name="Test User",
        role=role,
        is_active=True,
        must_change_password=must_change_password,
    )
    db.add(user)
    db.flush()
    return user


async def login(client: AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return response.json()


@pytest.mark.asyncio
async def test_admin_created_account_must_change_password_before_workspace_access(
    async_client: AsyncClient,
    db_session: Session,
):
    admin = make_user(db_session, "password.admin@example.com")
    db_session.commit()
    await login(async_client, admin.email, ADMIN_PASSWORD)

    created_response = await async_client.post(
        "/api/v1/admin/users",
        json={
            "email": "password.target@example.com",
            "password": INITIAL_PASSWORD,
            "full_name": "Password Target",
            "role": UserRole.VIEWER,
            "is_active": True,
        },
    )
    assert created_response.status_code == 201

    login_data = await login(
        async_client, "password.target@example.com", INITIAL_PASSWORD
    )
    assert login_data["must_change_password"] is True

    me = await async_client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True

    blocked = await async_client.get("/api/v1/documents")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Password change required"
    assert blocked.headers["X-Password-Change-Required"] == "true"

    profile_update = await async_client.patch(
        "/api/v1/auth/me",
        json={"full_name": "Renamed Before Change"},
    )
    assert profile_update.status_code == 403

    old_token = async_client.cookies.get(settings.SESSION_COOKIE_NAME)
    assert old_token is not None

    wrong_current = await async_client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "Wrong!Secure#Pass0",
            "new_password": NEW_PASSWORD,
        },
    )
    assert wrong_current.status_code == 400
    assert wrong_current.json()["detail"] == "Current password is incorrect"

    reused = await async_client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": INITIAL_PASSWORD,
            "new_password": INITIAL_PASSWORD,
        },
    )
    assert reused.status_code == 400

    changed = await async_client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": INITIAL_PASSWORD,
            "new_password": NEW_PASSWORD,
        },
    )
    assert changed.status_code == 200
    changed_data = changed.json()
    assert changed_data["must_change_password"] is False
    assert changed_data["email"] == "password.target@example.com"
    assert "password" not in changed_data
    assert "hash" not in json.dumps(changed_data)

    new_token = async_client.cookies.get(settings.SESSION_COOKIE_NAME)
    assert new_token is not None
    assert new_token != old_token

    old_client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
        cookies={settings.SESSION_COOKIE_NAME: old_token},
    )
    try:
        assert (await old_client.get("/api/v1/auth/me")).status_code == 401
    finally:
        await old_client.aclose()

    assert (await async_client.get("/api/v1/documents")).status_code == 200

    db_session.expire_all()
    target = (
        db_session.query(User)
        .filter(User.email == "password.target@example.com")
        .one()
    )
    assert target.must_change_password is False
    assert verify_password(NEW_PASSWORD, target.hashed_password)
    assert not verify_password(INITIAL_PASSWORD, target.hashed_password)

    success_event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.password_change",
            AuditEvent.resource_id == target.id,
            AuditEvent.outcome == "SUCCESS",
        )
        .one()
    )
    assert success_event.actor_id == target.id
    assert success_event.details is not None
    details = json.loads(success_event.details)
    assert details["session_rotated"] is True
    assert "password" not in success_event.details
    assert "hash" not in success_event.details

    denied_event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.password_change",
            AuditEvent.resource_id == target.id,
            AuditEvent.outcome == "DENIED",
        )
        .one()
    )
    assert json.loads(denied_event.details) == {
        "reason": "current_password_invalid"
    }


@pytest.mark.asyncio
async def test_admin_reset_forces_password_change_on_next_login(
    async_client: AsyncClient,
    db_session: Session,
):
    admin = make_user(db_session, "reset.flag.admin@example.com")
    target = make_user(
        db_session,
        "reset.flag.target@example.com",
        password=INITIAL_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    await login(async_client, admin.email, ADMIN_PASSWORD)

    response = await async_client.post(
        f"/api/v1/admin/users/{target.id}/reset-password",
        json={"password": NEW_PASSWORD},
    )
    assert response.status_code == 200

    login_data = await login(
        async_client, "reset.flag.target@example.com", NEW_PASSWORD
    )
    assert login_data["must_change_password"] is True
    assert (await async_client.get("/api/v1/documents")).status_code == 403


@pytest.mark.asyncio
async def test_self_registration_does_not_require_password_change(
    async_client: AsyncClient,
):
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "self.registered@example.com",
            "password": INITIAL_PASSWORD,
            "full_name": "Self Registered",
        },
    )
    assert response.status_code == 201
    assert response.json()["must_change_password"] is False
    assert (await async_client.get("/api/v1/documents")).status_code == 200
