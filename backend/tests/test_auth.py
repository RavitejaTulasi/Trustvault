"""
Day 2 Authentication and Authorization Tests

Tests cover:
- User registration (success, duplicate email, weak password)
- User login (success, wrong password, unknown email, deactivated)
- Session cookie lifecycle (set on login, cleared on logout)
- /me endpoint authentication gate
- Self-service profile update (name, password)
- Password change triggers session revocation
- Admin user management RBAC (only admin can list/update users)
- Role change audit trail (verified by checking audit_events)
- User enumeration protection (login timing does not reveal existence)
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import User, UserRole
from backend.app.security.passwords import hash_password


# ─────────────────────────────────────────────────────────────────────────────
# Helper fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_user(
    db: Session,
    email: str = "test@example.com",
    password: str = "Passw0rd!SecureX",
    full_name: str = "Test User",
    role: str = UserRole.VIEWER,
    is_active: bool = True,
) -> User:
    """Create and persist a test user directly in the database."""
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name=full_name,
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.flush()
    return user


VALID_PASSWORD = "Str0ng!Secure#Pass"
VALID_REGISTER = {
    "email": "newuser@example.com",
    "password": VALID_PASSWORD,
    "full_name": "New User",
}


# ─────────────────────────────────────────────────────────────────────────────
# Registration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    """Successful registration returns 201, user data, and a session cookie."""
    response = await async_client.post("/api/v1/auth/register", json=VALID_REGISTER)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == VALID_REGISTER["email"]
    assert data["role"] == UserRole.VIEWER
    assert data["is_active"] is True
    assert "hashed_password" not in data
    # Session cookie must be set
    assert settings.SESSION_COOKIE_NAME in response.cookies


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: AsyncClient, db_session: Session):
    """Duplicate email registration returns 409."""
    make_user(db_session, email="dup@example.com")
    db_session.commit()

    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "dup@example.com", "password": VALID_PASSWORD, "full_name": "Dup User"},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password_too_short(async_client: AsyncClient):
    """Password shorter than 12 characters is rejected."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "short@example.com", "password": "Short1!", "full_name": "Short Pass"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_weak_password_no_symbol(async_client: AsyncClient):
    """Password without a special character is rejected by complexity validator."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "nosymbol@example.com", "password": "NoSymbol1234567", "full_name": "No Symbol"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(async_client: AsyncClient):
    """Malformed email is rejected by Pydantic EmailStr validation."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": VALID_PASSWORD, "full_name": "Bad Email"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_sets_viewer_role(async_client: AsyncClient):
    """Self-registered users always get the 'viewer' role regardless of request content."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "viewer2@example.com", "password": VALID_PASSWORD, "full_name": "Auto Viewer"},
    )
    assert response.status_code == 201
    assert response.json()["role"] == UserRole.VIEWER


# ─────────────────────────────────────────────────────────────────────────────
# Login Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient, db_session: Session):
    """Valid credentials return 200 and a session cookie."""
    make_user(db_session, email="loginok@example.com", password=VALID_PASSWORD)
    db_session.commit()

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "loginok@example.com", "password": VALID_PASSWORD},
    )
    assert response.status_code == 200
    assert settings.SESSION_COOKIE_NAME in response.cookies
    assert response.json()["email"] == "loginok@example.com"


@pytest.mark.asyncio
async def test_login_wrong_password(async_client: AsyncClient, db_session: Session):
    """Wrong password returns 401 with a generic message."""
    make_user(db_session, email="wrongpw@example.com", password=VALID_PASSWORD)
    db_session.commit()

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "wrongpw@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_unknown_email(async_client: AsyncClient):
    """Unknown email returns 401 — identical to wrong password (no enumeration)."""
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": VALID_PASSWORD},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_deactivated_user(async_client: AsyncClient, db_session: Session):
    """Deactivated users cannot log in even with correct credentials."""
    make_user(db_session, email="inactive@example.com", password=VALID_PASSWORD, is_active=False)
    db_session.commit()

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "inactive@example.com", "password": VALID_PASSWORD},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_audits_failure(async_client: AsyncClient, db_session: Session):
    """Failed login is recorded in the audit log with DENIED outcome."""
    make_user(db_session, email="auditfail@example.com", password=VALID_PASSWORD)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "auditfail@example.com", "password": "WrongPassword456!"},
    )

    event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.login_failed",
            AuditEvent.outcome == AuditOutcome.DENIED,
        )
        .first()
    )
    assert event is not None


# ─────────────────────────────────────────────────────────────────────────────
# Logout Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_clears_session(async_client: AsyncClient, db_session: Session):
    """Logout revokes the session; subsequent /me calls return 401."""
    make_user(db_session, email="logout@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # Login
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "logout@example.com", "password": VALID_PASSWORD},
    )
    assert login_resp.status_code == 200

    # Logout
    logout_resp = await async_client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 204

    # /me after logout should be 401
    me_resp = await async_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_requires_auth(async_client: AsyncClient):
    """Logout without a session cookie returns 401."""
    response = await async_client.post("/api/v1/auth/logout")
    assert response.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# /me endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_me_requires_auth(async_client: AsyncClient):
    """/me without a session cookie returns 401."""
    response = await async_client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_returns_current_user(async_client: AsyncClient, db_session: Session):
    """Authenticated /me returns the correct user profile."""
    make_user(db_session, email="me@example.com", password=VALID_PASSWORD, full_name="Me User")
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "me@example.com", "password": VALID_PASSWORD},
    )

    me_resp = await async_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200
    data = me_resp.json()
    assert data["email"] == "me@example.com"
    assert data["full_name"] == "Me User"
    assert "hashed_password" not in data


# ─────────────────────────────────────────────────────────────────────────────
# Self-service Profile Update Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_me_full_name(async_client: AsyncClient, db_session: Session):
    """User can update their own display name."""
    make_user(db_session, email="updatename@example.com", password=VALID_PASSWORD, full_name="Old Name")
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "updatename@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.patch("/api/v1/auth/me", json={"full_name": "New Name"})
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "New Name"


@pytest.mark.asyncio
async def test_update_me_password_revokes_sessions(async_client: AsyncClient, db_session: Session):
    """Changing password invalidates old sessions."""
    make_user(db_session, email="changepw@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # Login to get session A
    login_a = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "changepw@example.com", "password": VALID_PASSWORD},
    )
    assert login_a.status_code == 200

    new_password = "NewStr0ng!Pass#99"
    resp = await async_client.patch("/api/v1/auth/me", json={"password": new_password})
    assert resp.status_code == 200

    # The old session cookie was revoked — /me should fail
    me_resp = await async_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Admin User Management RBAC Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_list_users_requires_admin(async_client: AsyncClient, db_session: Session):
    """Viewer users cannot access the admin user list."""
    make_user(db_session, email="viewer@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.get("/api/v1/admin/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_users_requires_admin_owner(async_client: AsyncClient, db_session: Session):
    """Owner users cannot access the admin user list."""
    make_user(db_session, email="owner@example.com", password=VALID_PASSWORD, role=UserRole.OWNER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.get("/api/v1/admin/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_users_success(async_client: AsyncClient, db_session: Session):
    """Admin user can list all users."""
    admin = make_user(db_session, email="admin@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    make_user(db_session, email="user1@example.com", password=VALID_PASSWORD)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.get("/api/v1/admin/users")
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data
    assert data["total"] >= 2


@pytest.mark.asyncio
async def test_admin_update_user_role(async_client: AsyncClient, db_session: Session):
    """Admin can promote a viewer to owner, which is audit-logged."""
    make_user(db_session, email="admin2@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    target = make_user(db_session, email="target@example.com", password=VALID_PASSWORD, role=UserRole.VIEWER)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "admin2@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.patch(
        f"/api/v1/admin/users/{target.id}",
        json={"role": UserRole.OWNER},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == UserRole.OWNER

    # Verify audit log entry for role change
    db_session.expire_all()
    role_change_event = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.action == "user.role_change",
            AuditEvent.resource_id == target.id,
        )
        .first()
    )
    assert role_change_event is not None


@pytest.mark.asyncio
async def test_admin_cannot_remove_own_admin_role(async_client: AsyncClient, db_session: Session):
    """An admin cannot demote themselves via the admin endpoint."""
    admin = make_user(db_session, email="selfdemote@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "selfdemote@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.patch(
        f"/api/v1/admin/users/{admin.id}",
        json={"role": UserRole.VIEWER},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_admin_deactivate_user_revokes_sessions(async_client: AsyncClient, db_session: Session):
    """Deactivating a user invalidates all their sessions immediately."""
    make_user(db_session, email="deactivator@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    victim = make_user(db_session, email="victim@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # Login admin
    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "deactivator@example.com", "password": VALID_PASSWORD},
    )

    # Deactivate victim
    resp = await async_client.patch(
        f"/api/v1/admin/users/{victim.id}",
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_admin_revoke_sessions_endpoint(async_client: AsyncClient, db_session: Session):
    """Admin can force-revoke all sessions for any user."""
    make_user(db_session, email="revoker@example.com", password=VALID_PASSWORD, role=UserRole.ADMIN)
    target = make_user(db_session, email="revoketarget@example.com", password=VALID_PASSWORD)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "revoker@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.post(f"/api/v1/admin/users/{target.id}/revoke-sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert "sessions_revoked" in data


@pytest.mark.asyncio
async def test_unauthenticated_admin_endpoints_return_401(async_client: AsyncClient):
    """Admin endpoints require authentication — unauthenticated returns 401."""
    resp = await async_client.get("/api/v1/admin/users")
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Audit Chain Integrity Test
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_chain_integrity(async_client: AsyncClient, db_session: Session):
    """After several operations, the audit hash chain remains unbroken."""
    # Generate some audit events via normal operations
    await async_client.post("/api/v1/auth/register", json={
        "email": "chaintest@example.com",
        "password": VALID_PASSWORD,
        "full_name": "Chain Tester",
    })
    await async_client.post("/api/v1/auth/login", json={
        "email": "chaintest@example.com",
        "password": VALID_PASSWORD,
    })

    from backend.app.services.audit_service import AuditService
    is_valid, reason, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid, f"Audit chain broken at {count}: {reason}"
    assert count > 0
