"""Administrator account-creation tests."""

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent
from backend.app.models.user import User, UserRole
from backend.app.security.passwords import hash_password, verify_password

ADMIN_PASSWORD = "Admin!Secure#Pass1"
INITIAL_PASSWORD = "Initial!Secure#Pass2"


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


def create_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "email": "new.owner@example.com",
        "password": INITIAL_PASSWORD,
        "full_name": "New Owner",
        "role": UserRole.OWNER,
        "is_active": True,
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_admin_creates_account_with_role_without_starting_a_session(
    async_client: AsyncClient, db_session: Session
):
    admin = make_user(db_session, "creator@example.com")
    db_session.commit()
    await login(async_client, admin.email)

    response = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(email="NEW.OWNER@example.com"),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new.owner@example.com"
    assert data["role"] == UserRole.OWNER
    assert data["is_active"] is True
    assert data["must_change_password"] is True
    assert "password" not in data
    assert "hashed_password" not in data
    assert settings.SESSION_COOKIE_NAME not in response.cookies

    db_session.expire_all()
    created = db_session.query(User).filter(User.email == "new.owner@example.com").one()
    assert created.hashed_password != INITIAL_PASSWORD
    assert verify_password(INITIAL_PASSWORD, created.hashed_password)
    assert created.must_change_password is True

    event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.create",
            AuditEvent.resource_id == created.id,
        )
        .one()
    )
    assert event.actor_id == admin.id
    assert event.details is not None
    details = json.loads(event.details)
    assert details["email"] == "new.owner@example.com"
    assert details["role"] == UserRole.OWNER
    assert "password" not in details


@pytest.mark.asyncio
async def test_non_admin_cannot_create_accounts(
    async_client: AsyncClient, db_session: Session
):
    viewer = make_user(
        db_session,
        "viewer.creator@example.com",
        password=INITIAL_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()
    await login(async_client, viewer.email, INITIAL_PASSWORD)

    response = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(),
    )

    assert response.status_code == 403
    db_session.expire_all()
    assert (
        db_session.query(User).filter(User.email == "new.owner@example.com").first()
        is None
    )


@pytest.mark.asyncio
async def test_duplicate_email_is_rejected_without_overwriting(
    async_client: AsyncClient, db_session: Session
):
    admin = make_user(db_session, "duplicate.creator@example.com")
    db_session.commit()
    await login(async_client, admin.email)

    first = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(email="taken@example.com"),
    )
    assert first.status_code == 201

    second = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(email="TAKEN@example.com", full_name="Impostor"),
    )

    assert second.status_code == 409
    db_session.expire_all()
    accounts = db_session.query(User).filter(User.email == "taken@example.com").all()
    assert len(accounts) == 1
    assert accounts[0].full_name == "New Owner"


@pytest.mark.asyncio
async def test_create_user_validates_role_and_password(
    async_client: AsyncClient, db_session: Session
):
    admin = make_user(db_session, "validation.creator@example.com")
    db_session.commit()
    await login(async_client, admin.email)

    invalid_role = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(role="superuser"),
    )
    weak_password = await async_client.post(
        "/api/v1/admin/users",
        json=create_payload(email="weak@example.com", password="short"),
    )

    assert invalid_role.status_code == 422
    assert weak_password.status_code == 422
    db_session.expire_all()
    assert db_session.query(User).filter(User.email == "weak@example.com").first() is None


@pytest.mark.asyncio
async def test_unauthenticated_create_user_is_rejected(async_client: AsyncClient):
    response = await async_client.post("/api/v1/admin/users", json=create_payload())

    assert response.status_code == 401
