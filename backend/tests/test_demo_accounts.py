"""Staging-only demo account discovery endpoint tests."""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.user import User, UserRole
from backend.app.security.passwords import hash_password

DEMO_PASSWORDS = {
    "admin": "DemoAdminPassword123!",
    "owner": "DemoOwnerPassword123!",
    "viewer": "DemoViewerPassword123!",
}


def make_user(
    db: Session,
    *,
    email: str,
    password: str,
    role: str,
    is_active: bool = True,
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name=f"Demo {role.title()}",
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.flush()
    return user


def enable_demo_login(monkeypatch, environment: str = "testing") -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", environment)
    monkeypatch.setattr(settings, "DEMO_LOGIN_ENABLED", True)
    monkeypatch.setattr(settings, "DEMO_ADMIN_EMAIL", "demo.admin@example.com")
    monkeypatch.setattr(settings, "DEMO_ADMIN_PASSWORD", DEMO_PASSWORDS["admin"])
    monkeypatch.setattr(settings, "DEMO_OWNER_EMAIL", "demo.owner@example.com")
    monkeypatch.setattr(settings, "DEMO_OWNER_PASSWORD", DEMO_PASSWORDS["owner"])
    monkeypatch.setattr(settings, "DEMO_VIEWER_EMAIL", "demo.viewer@example.com")
    monkeypatch.setattr(settings, "DEMO_VIEWER_PASSWORD", DEMO_PASSWORDS["viewer"])


def provision_accounts(db: Session) -> None:
    make_user(
        db,
        email="demo.admin@example.com",
        password=DEMO_PASSWORDS["admin"],
        role=UserRole.ADMIN,
    )
    make_user(
        db,
        email="demo.owner@example.com",
        password=DEMO_PASSWORDS["owner"],
        role=UserRole.OWNER,
    )
    make_user(
        db,
        email="demo.viewer@example.com",
        password=DEMO_PASSWORDS["viewer"],
        role=UserRole.VIEWER,
    )


@pytest.mark.asyncio
async def test_demo_accounts_disabled_returns_404(
    async_client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "DEMO_LOGIN_ENABLED", False)

    response = await async_client.get("/api/v1/auth/demo-accounts")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_demo_accounts_production_returns_404_even_if_enabled(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
):
    enable_demo_login(monkeypatch, environment="production")
    provision_accounts(db_session)

    response = await async_client.get("/api/v1/auth/demo-accounts")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_demo_accounts_returns_verified_staging_credentials(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
):
    enable_demo_login(monkeypatch, environment="staging")
    provision_accounts(db_session)

    response = await async_client.get("/api/v1/auth/demo-accounts")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.json() == [
        {
            "role": "admin",
            "email": "demo.admin@example.com",
            "password": DEMO_PASSWORDS["admin"],
        },
        {
            "role": "owner",
            "email": "demo.owner@example.com",
            "password": DEMO_PASSWORDS["owner"],
        },
        {
            "role": "viewer",
            "email": "demo.viewer@example.com",
            "password": DEMO_PASSWORDS["viewer"],
        },
    ]


@pytest.mark.asyncio
async def test_demo_accounts_omits_inactive_mismatched_and_wrong_passwords(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
):
    enable_demo_login(monkeypatch)
    make_user(
        db_session,
        email="demo.admin@example.com",
        password=DEMO_PASSWORDS["admin"],
        role=UserRole.ADMIN,
        is_active=False,
    )
    make_user(
        db_session,
        email="demo.owner@example.com",
        password=DEMO_PASSWORDS["owner"],
        role=UserRole.VIEWER,
    )
    make_user(
        db_session,
        email="demo.viewer@example.com",
        password="DifferentDemoPassword123!",
        role=UserRole.VIEWER,
    )
    db_session.commit()

    response = await async_client.get("/api/v1/auth/demo-accounts")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_demo_accounts_returns_empty_when_unprovisioned(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
):
    enable_demo_login(monkeypatch)

    response = await async_client.get("/api/v1/auth/demo-accounts")

    assert response.status_code == 200
    assert response.json() == []
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_demo_accounts_hidden_from_openapi(async_client: AsyncClient):
    response = await async_client.get("/openapi.json")

    assert response.status_code == 200
    assert "/api/v1/auth/demo-accounts" not in response.json()["paths"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "expected_status"),
    [
        ("admin", 200),
        ("owner", 403),
        ("viewer", 403),
    ],
)
async def test_demo_account_can_log_in_with_normal_rbac(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch,
    role: str,
    expected_status: int,
):
    enable_demo_login(monkeypatch)
    provision_accounts(db_session)
    db_session.commit()

    accounts = (await async_client.get("/api/v1/auth/demo-accounts")).json()
    account = next(item for item in accounts if item["role"] == role)

    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )
    assert login_response.status_code == 200

    admin_response = await async_client.get("/api/v1/admin/users")

    assert admin_response.status_code == expected_status
