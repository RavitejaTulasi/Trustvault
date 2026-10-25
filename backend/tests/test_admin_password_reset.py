"""Administrator-assisted password-reset security tests."""

import json
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.main import app
from backend.app.models.audit import AuditEvent
from backend.app.models.user import User, UserRole
from backend.app.security.passwords import hash_password, verify_password
from backend.app.security.sessions import create_session

ADMIN_PASSWORD = "Admin!Secure#Pass1"
OLD_PASSWORD = "Initial!Secure#Pass2"
NEW_PASSWORD = "Reset!Secure#Pass3"


def make_user(
    db: Session,
    email: str,
    password: str = ADMIN_PASSWORD,
    role: str = UserRole.ADMIN,
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name="Test User",
        role=role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


async def login(client: AsyncClient, email: str, password: str = ADMIN_PASSWORD) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200


@pytest_asyncio.fixture
async def target_client(db_session: Session, target_user: User) -> AsyncIterator[AsyncClient]:
    raw_token, _ = create_session(db_session, target_user)
    db_session.commit()
    client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
        cookies={settings.SESSION_COOKIE_NAME: raw_token},
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def target_user(db_session: Session) -> User:
    user = make_user(
        db_session,
        "reset.target@example.com",
        password=OLD_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    return user


@pytest.mark.asyncio
async def test_admin_resets_password_and_revokes_target_sessions(
    async_client: AsyncClient,
    db_session: Session,
    target_user: User,
    target_client: AsyncClient,
):
    admin = make_user(db_session, "reset.admin@example.com")
    db_session.commit()
    await login(async_client, admin.email)
    assert (await target_client.get("/api/v1/auth/me")).status_code == 200

    response = await async_client.post(
        f"/api/v1/admin/users/{target_user.id}/reset-password",
        json={"password": NEW_PASSWORD},
    )

    assert response.status_code == 200
    data = response.json()
    assert data == {"user_id": target_user.id, "sessions_revoked": 1}
    assert "password" not in data
    assert "hash" not in json.dumps(data)

    db_session.expire_all()
    updated = db_session.get(User, target_user.id)
    assert updated is not None
    assert verify_password(NEW_PASSWORD, updated.hashed_password)
    assert not verify_password(OLD_PASSWORD, updated.hashed_password)
    assert updated.role == UserRole.VIEWER
    assert updated.must_change_password is True

    assert (await target_client.get("/api/v1/auth/me")).status_code == 401

    event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.password_reset",
            AuditEvent.resource_id == target_user.id,
            AuditEvent.outcome == "SUCCESS",
        )
        .one()
    )
    assert event.actor_id == admin.id
    details = json.loads(event.details)
    assert details == {"sessions_revoked": 1}
    assert "password" not in event.details
    assert "hash" not in event.details


@pytest.mark.asyncio
async def test_non_admin_cannot_reset_another_password(
    async_client: AsyncClient,
    db_session: Session,
    target_user: User,
):
    viewer = make_user(
        db_session,
        "reset.viewer@example.com",
        password=ADMIN_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    await login(async_client, viewer.email)

    response = await async_client.post(
        f"/api/v1/admin/users/{target_user.id}/reset-password",
        json={"password": NEW_PASSWORD},
    )

    assert response.status_code == 403
    db_session.expire_all()
    unchanged = db_session.get(User, target_user.id)
    assert unchanged is not None
    assert verify_password(OLD_PASSWORD, unchanged.hashed_password)
    assert not verify_password(NEW_PASSWORD, unchanged.hashed_password)


@pytest.mark.asyncio
async def test_admin_must_use_account_settings_for_own_password(
    async_client: AsyncClient,
    db_session: Session,
):
    admin = make_user(db_session, "reset.self@example.com")
    db_session.commit()
    await login(async_client, admin.email)

    response = await async_client.post(
        f"/api/v1/admin/users/{admin.id}/reset-password",
        json={"password": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Use account settings to change your own password"
    db_session.expire_all()
    unchanged = db_session.get(User, admin.id)
    assert unchanged is not None
    assert verify_password(ADMIN_PASSWORD, unchanged.hashed_password)

    event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.password_reset",
            AuditEvent.outcome == "DENIED",
            AuditEvent.resource_id == admin.id,
        )
        .one()
    )
    assert json.loads(event.details) == {"reason": "self_reset_not_allowed"}


@pytest.mark.asyncio
async def test_unknown_target_and_weak_password_are_rejected(
    async_client: AsyncClient,
    db_session: Session,
):
    admin = make_user(db_session, "reset.validation@example.com")
    db_session.commit()
    await login(async_client, admin.email)

    missing = await async_client.post(
        "/api/v1/admin/users/not-a-real-user/reset-password",
        json={"password": NEW_PASSWORD},
    )
    weak = await async_client.post(
        f"/api/v1/admin/users/{admin.id}/reset-password",
        json={"password": "short"},
    )

    assert missing.status_code == 404
    assert weak.status_code == 422


@pytest.mark.asyncio
async def test_unauthenticated_password_reset_is_rejected(
    async_client: AsyncClient,
    db_session: Session,
    target_user: User,
):
    response = await async_client.post(
        f"/api/v1/admin/users/{target_user.id}/reset-password",
        json={"password": NEW_PASSWORD},
    )

    assert response.status_code == 401
    db_session.expire_all()
    unchanged = db_session.get(User, target_user.id)
    assert unchanged is not None
    assert verify_password(OLD_PASSWORD, unchanged.hashed_password)
