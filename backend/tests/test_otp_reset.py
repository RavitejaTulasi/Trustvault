"""OTP password reset flow tests."""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.api import auth as auth_api
from backend.app.models.audit import AuditEvent
from backend.app.models.otp import PasswordResetOTP
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.models.user import User, UserRole
from backend.app.security.otp import verify_otp_code
from backend.app.security.passwords import hash_password
from backend.app.security.rate_limiter import (
    LoginRateLimitDecision,
    otp_request_rate_limiter,
)


def make_user(
    db: Session,
    email: str,
    password: str = "Initial!Secure#123",
    role: str = UserRole.VIEWER,
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        full_name="OTP Test User",
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def captured_otp_codes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture development-delivery OTP codes instead of reading plaintext from the DB."""
    codes: list[str] = []

    def fake_send(recipient: str, code: str, expires_minutes: int = 15) -> None:
        codes.append(code)

    monkeypatch.setattr(auth_api, "send_password_reset_otp", fake_send)
    return codes


@pytest.mark.asyncio
async def test_otp_password_reset_flow(
    async_client: AsyncClient,
    db_session: Session,
    captured_otp_codes: list[str],
):
    email = "otp.user@example.com"
    make_user(db_session, email, password="Old!Password123")

    # 1. Request reset
    req_resp = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert req_resp.status_code == 200
    assert "sent" in req_resp.json()["message"]

    # The code is delivered out of band; the database stores only a keyed hash.
    assert len(captured_otp_codes) == 1
    code = captured_otp_codes[0]
    assert len(code) == 6
    db_session.expire_all()
    otp_record = db_session.query(PasswordResetOTP).filter(
        PasswordResetOTP.email == email,
        PasswordResetOTP.is_used == False,
    ).first()
    assert otp_record is not None
    assert len(otp_record.otp_code) == 64
    assert otp_record.otp_code != code
    assert verify_otp_code(code, otp_record.otp_code)

    # 2. Verify OTP
    verify_resp = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": code},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json() == {"valid": True}

    # 3. Confirm reset with new password
    new_password = "New!SecurePassword999"
    confirm_resp = await async_client.post(
        "/api/v1/auth/confirm-reset",
        json={
            "email": email,
            "otp_code": code,
            "new_password": new_password,
        },
    )
    assert confirm_resp.status_code == 200
    assert "successfully reset" in confirm_resp.json()["message"]

    # The same code cannot be consumed twice.
    reuse_resp = await async_client.post(
        "/api/v1/auth/confirm-reset",
        json={
            "email": email,
            "otp_code": code,
            "new_password": "Another!SecurePassword999",
        },
    )
    assert reuse_resp.status_code == 400

    # Verify user can now log in with new password
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": new_password},
    )
    assert login_resp.status_code == 200

    # Verify old password no longer works
    login_old = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Old!Password123"},
    )
    assert login_old.status_code == 401


@pytest.mark.asyncio
async def test_otp_locks_after_five_wrong_attempts(
    async_client: AsyncClient,
    db_session: Session,
    captured_otp_codes: list[str],
):
    email = "otp.bruteforce@example.com"
    make_user(db_session, email)

    request_resp = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert request_resp.status_code == 200

    code = captured_otp_codes[0]

    for _ in range(5):
        attempt = await async_client.post(
            "/api/v1/auth/verify-otp",
            json={"email": email, "otp_code": "000000"},
        )
        assert attempt.status_code == 400
        assert attempt.json()["detail"] == "Invalid or expired OTP code"

    db_session.expire_all()
    otp_record = (
        db_session.query(PasswordResetOTP)
        .filter(PasswordResetOTP.email == email)
        .one()
    )
    assert otp_record.attempts == 5
    assert otp_record.is_used is True

    correct_after_lock = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": code},
    )
    assert correct_after_lock.status_code == 400


@pytest.mark.asyncio
async def test_new_reset_request_invalidates_the_previous_code(
    async_client: AsyncClient,
    db_session: Session,
    captured_otp_codes: list[str],
):
    email = "otp.reissue@example.com"
    make_user(db_session, email)

    first_request = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert first_request.status_code == 200

    first_code = captured_otp_codes[0]

    second_request = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert second_request.status_code == 200

    db_session.expire_all()
    records = (
        db_session.query(PasswordResetOTP)
        .filter(PasswordResetOTP.email == email)
        .order_by(PasswordResetOTP.created_at)
        .all()
    )
    assert len(records) == 2
    assert records[0].is_used is True
    assert records[1].is_used is False
    assert len(captured_otp_codes) == 2
    second_code = captured_otp_codes[1]

    stale_verify = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": first_code},
    )
    assert stale_verify.status_code == 400

    current_verify = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": second_code},
    )
    assert current_verify.status_code == 200
    assert current_verify.json() == {"valid": True}


@pytest.mark.asyncio
async def test_password_reset_requests_are_rate_limited(
    async_client: AsyncClient,
    db_session: Session,
):
    email = "otp.request.limit@example.com"
    make_user(db_session, email)

    for _ in range(5):
        response = await async_client.post(
            "/api/v1/auth/request-reset",
            json={"email": email},
        )
        assert response.status_code == 200

    limited = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert limited.status_code == 429
    assert limited.json()["detail"] == (
        "Too many password reset requests. Please try again later."
    )
    assert int(limited.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_otp_rate_limit_denial_emits_audit_event(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    email = "otp.request.audit@example.com"
    make_user(db_session, email)

    now = int(otp_request_rate_limiter.time_func())
    ip_key = otp_request_rate_limiter._build_keys("127.0.0.1", email)[1][0]
    db_session.add(
        LoginRateLimitBucket(
            key_hash=ip_key,
            scope="ip",
            attempt_count=otp_request_rate_limiter.max_attempts,
            window_started_at=now,
            expires_at=now + otp_request_rate_limiter.window_seconds,
            denial_audit_recorded=False,
        )
    )
    db_session.commit()

    monkeypatch.setattr(
        otp_request_rate_limiter,
        "reserve",
        lambda *args, **kwargs: LoginRateLimitDecision(
            allowed=False, retry_after=60
        ),
    )

    limited = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert limited.status_code == 429

    db_session.expire_all()
    denial_event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "auth.password_reset_rate_limited")
        .first()
    )
    assert denial_event is not None
    assert denial_event.outcome == "DENIED"


@pytest.mark.asyncio
async def test_otp_verification_attempts_are_rate_limited(
    async_client: AsyncClient,
    db_session: Session,
    captured_otp_codes: list[str],
):
    email = "otp.verify.limit@example.com"
    make_user(db_session, email)

    request_resp = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert request_resp.status_code == 200

    code = captured_otp_codes[0]

    for _ in range(10):
        attempt = await async_client.post(
            "/api/v1/auth/verify-otp",
            json={"email": email, "otp_code": "000000"},
        )
        assert attempt.status_code == 400

    limited = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": code},
    )
    assert limited.status_code == 429
    assert limited.json()["detail"] == (
        "Too many verification attempts. Please try again later."
    )
    assert int(limited.headers["Retry-After"]) > 0
