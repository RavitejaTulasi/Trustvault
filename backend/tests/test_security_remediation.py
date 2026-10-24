"""
Security Remediation Tests for Day 2.1
Tests CSRF enforcement (HIGH-01) and login rate limiting (HIGH-02).
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.tests.test_auth import VALID_PASSWORD, make_user


@pytest.mark.asyncio
async def test_csrf_missing_header_rejected(async_client: AsyncClient, db_session: Session):
    """State-changing request without X-CSRF-Token header returns 403 Forbidden."""
    make_user(db_session, email="csrftest@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # Login to obtain cookies (session + csrf)
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "csrftest@example.com", "password": VALID_PASSWORD},
    )
    assert login_resp.status_code == 200

    resp = await async_client.patch(
        "/api/v1/auth/me",
        json={"full_name": "Hacker Attempt"},
        headers={"X-CSRF-Token": ""},
    )
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_csrf_mismatched_token_rejected(async_client: AsyncClient, db_session: Session):
    """State-changing request with mismatched X-CSRF-Token header returns 403 Forbidden."""
    make_user(db_session, email="csrfbad@example.com", password=VALID_PASSWORD)
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "csrfbad@example.com", "password": VALID_PASSWORD},
    )

    resp = await async_client.patch(
        "/api/v1/auth/me",
        json={"full_name": "Bad Token"},
        headers={"X-CSRF-Token": "invalid_fake_csrf_token_value_123456789"},
    )
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_csrf_valid_token_succeeds(async_client: AsyncClient, db_session: Session):
    """State-changing request with valid matching CSRF token succeeds."""
    make_user(db_session, email="csrfok@example.com", password=VALID_PASSWORD, full_name="Original Name")
    db_session.commit()

    await async_client.post(
        "/api/v1/auth/login",
        json={"email": "csrfok@example.com", "password": VALID_PASSWORD},
    )

    # async_client event hook automatically extracts trustvault_csrf cookie and sets X-CSRF-Token
    resp = await async_client.patch(
        "/api/v1/auth/me",
        json={"full_name": "Updated Name"},
    )
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "Updated Name"


@pytest.mark.asyncio
async def test_login_rate_limiting_exceeded(async_client: AsyncClient, db_session: Session):
    """Exceeding max failed login attempts returns 429 Too Many Requests."""
    make_user(db_session, email="ratelimit@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # Attempt 5 failed logins (max_attempts = 5)
    for _ in range(5):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": "ratelimit@example.com", "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401

    # 6th attempt should be rate limited -> 429
    resp_limited = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "ratelimit@example.com", "password": "WrongPassword123!"},
    )
    assert resp_limited.status_code == 429
    assert "Retry-After" in resp_limited.headers
    assert "Too many failed login attempts" in resp_limited.json()["detail"]


@pytest.mark.asyncio
async def test_login_success_does_not_reset_ip_wide_failures(
    async_client: AsyncClient, db_session: Session
):
    """Successful login clears the account bucket but preserves IP-wide failures."""
    make_user(db_session, email="resetrate@example.com", password=VALID_PASSWORD)
    db_session.commit()

    for _ in range(3):
        await async_client.post(
            "/api/v1/auth/login",
            json={"email": "resetrate@example.com", "password": "WrongPassword123!"},
        )

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "resetrate@example.com", "password": VALID_PASSWORD},
    )
    assert login_resp.status_code == 200

    # The account bucket was cleared, so these remain account-level failures,
    # but the IP-wide counter already held three failures.
    for _ in range(2):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": "resetrate@example.com", "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401

    limited = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "resetrate@example.com", "password": "WrongPassword123!"},
    )
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers


@pytest.mark.asyncio
async def test_spoofed_forwarded_for_does_not_bypass_rate_limit(
    async_client: AsyncClient, db_session: Session, monkeypatch
):
    """An untrusted peer cannot rotate X-Forwarded-For to escape the IP limit."""
    from backend.app.config import settings

    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "")
    make_user(db_session, email="spoofrate@example.com", password=VALID_PASSWORD)
    db_session.commit()

    for index in range(5):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": "spoofrate@example.com", "password": "WrongPassword123!"},
            headers={"X-Forwarded-For": f"203.0.113.{index + 1}"},
        )
        assert resp.status_code == 401

    limited = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "spoofrate@example.com", "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "203.0.113.250"},
    )
    assert limited.status_code == 429


@pytest.mark.asyncio
async def test_login_fails_closed_when_shared_limiter_is_unavailable(
    async_client: AsyncClient, db_session: Session, monkeypatch
):
    """A limiter storage failure must deny authentication, not bypass limits."""
    from backend.app.security.rate_limiter import (
        LoginRateLimitUnavailable,
        login_rate_limiter,
    )

    make_user(db_session, email="failclosed@example.com", password=VALID_PASSWORD)
    db_session.commit()

    def unavailable(*args, **kwargs):
        raise LoginRateLimitUnavailable("simulated storage failure")

    monkeypatch.setattr(login_rate_limiter, "reserve", unavailable)

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "failclosed@example.com", "password": VALID_PASSWORD},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication temporarily unavailable"


@pytest.mark.asyncio
async def test_trusted_proxy_address_is_used_for_audit_and_limits(
    async_client: AsyncClient, db_session: Session, monkeypatch
):
    """A configured trusted proxy can supply the client address used for auditing."""
    from backend.app.config import settings
    from backend.app.models.audit import AuditEvent

    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "127.0.0.1/32")
    make_user(db_session, email="proxyrate@example.com", password=VALID_PASSWORD)
    db_session.commit()

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "proxyrate@example.com", "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "203.0.113.77"},
    )
    assert response.status_code == 401

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "user.login_failed")
        .order_by(AuditEvent.sequence_number.desc())
        .first()
    )
    assert event is not None
    assert event.ip_address == "203.0.113.77"


@pytest.mark.asyncio
async def test_csrf_rejects_origin_with_unapproved_port(
    async_client: AsyncClient,
    db_session: Session,
):
    """Reject an origin whose port differs from the configured allowed origin."""
    make_user(
        db_session,
        email="csrfport@example.com",
        password=VALID_PASSWORD,
    )
    db_session.commit()

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "csrfport@example.com",
            "password": VALID_PASSWORD,
        },
    )
    assert login_resp.status_code == 200

    resp = await async_client.patch(
        "/api/v1/auth/me",
        json={"full_name": "Origin Test"},
        headers={"Origin": "http://localhost:9999"},
    )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "CSRF Origin validation failed"
