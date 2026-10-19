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
async def test_login_rate_limit_reset_on_success(async_client: AsyncClient, db_session: Session):
    """Successful login resets failed attempt counters for rate limiting."""
    make_user(db_session, email="resetrate@example.com", password=VALID_PASSWORD)
    db_session.commit()

    # 3 failed attempts
    for _ in range(3):
        await async_client.post(
            "/api/v1/auth/login",
            json={"email": "resetrate@example.com", "password": "WrongPassword123!"},
        )

    # Successful login
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "resetrate@example.com", "password": VALID_PASSWORD},
    )
    assert login_resp.status_code == 200

    # Another 3 failed attempts should NOT trigger rate limiting because failure counter was reset on success
    for _ in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": "resetrate@example.com", "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401
