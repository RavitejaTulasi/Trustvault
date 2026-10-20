"""Opt-in PostgreSQL concurrency tests for shared login rate limiting."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.security.rate_limiter import (
    LoginRateLimiter,
    LoginRateLimitUnavailable,
)
from backend.app.services.audit_service import AuditService
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    PostgresTestSchema,
    isolated_postgres_schema,
)

pytestmark = POSTGRES_INTEGRATION_MARKERS

NOW = 1_000_000


@pytest.fixture
def pg_schema():
    with isolated_postgres_schema() as schema:
        yield schema


def _limiter(*, max_attempts: int = 3, max_buckets: int = 100) -> LoginRateLimiter:
    return LoginRateLimiter(
        max_attempts=max_attempts,
        window_seconds=60,
        max_buckets=max_buckets,
        time_func=lambda: NOW,
    )


def test_concurrent_reservations_cannot_exceed_exact_limit(
    pg_schema: PostgresTestSchema,
):
    limiter = _limiter(max_attempts=3)
    workers = 8
    barrier = threading.Barrier(workers)
    ip = "203.0.113.10"
    email = "user@example.com"

    def reserve(_index: int) -> bool:
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            return limiter.reserve(session, ip, email).allowed

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(reserve, range(workers)))

    assert results.count(True) == 3
    assert results.count(False) == workers - 3

    keys = limiter._build_keys(ip, email)
    with pg_schema.session_factory() as session:
        account_bucket = session.get(LoginRateLimitBucket, keys[0][0])
        ip_bucket = session.get(LoginRateLimitBucket, keys[1][0])
        assert account_bucket is not None
        assert ip_bucket is not None
        assert account_bucket.attempt_count == 3
        assert ip_bucket.attempt_count == 3
        assert (
            session.scalar(select(func.count()).select_from(LoginRateLimitBucket))
            == 2
        )


def test_denied_second_key_rolls_back_first_key_reservation(
    pg_schema: PostgresTestSchema,
):
    limiter = _limiter(max_attempts=1)
    ip = "203.0.113.11"

    with pg_schema.session_factory() as session:
        assert limiter.reserve(session, ip, "first@example.com").allowed

    with pg_schema.session_factory() as session:
        denied = limiter.reserve(session, ip, "second@example.com")
        assert denied.allowed is False

    second_account_key = limiter._build_keys(ip, "second@example.com")[0][0]
    with pg_schema.session_factory() as session:
        assert session.get(LoginRateLimitBucket, second_account_key) is None


def test_capacity_admission_serializes_new_bucket_creation(
    pg_schema: PostgresTestSchema,
):
    limiter = _limiter(max_attempts=5, max_buckets=2)
    workers = 8
    barrier = threading.Barrier(workers)

    def reserve(index: int) -> str:
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            try:
                decision = limiter.reserve(
                    session,
                    f"198.51.100.{index + 1}",
                    f"capacity-{index}@example.com",
                )
            except LoginRateLimitUnavailable:
                return "unavailable"
            return "allowed" if decision.allowed else "denied"

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(reserve, range(workers)))

    assert results.count("allowed") == 1
    assert results.count("unavailable") == workers - 1
    assert results.count("denied") == 0

    with pg_schema.session_factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(LoginRateLimitBucket))
            == 2
        )


def test_concurrent_denial_claims_append_one_audit_event(
    pg_schema: PostgresTestSchema,
):
    limiter = _limiter(max_attempts=1)
    ip = "203.0.113.12"
    email = "denial@example.com"

    with pg_schema.session_factory() as session:
        assert limiter.reserve(session, ip, email).allowed
        assert limiter.reserve(session, ip, email).allowed is False

    workers = 6
    barrier = threading.Barrier(workers)

    def claim(_index: int) -> bool:
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            claimed = limiter.claim_denial_audit(session, ip, email)
            if claimed:
                AuditService.log_event(
                    session,
                    action="user.login_rate_limited",
                    outcome=AuditOutcome.DENIED,
                )
                session.commit()
            else:
                session.rollback()
            return claimed

    with ThreadPoolExecutor(max_workers=workers) as executor:
        claims = list(executor.map(claim, range(workers)))

    assert claims.count(True) == 1

    ip_key = limiter._build_keys(ip, email)[1][0]
    with pg_schema.session_factory() as session:
        bucket = session.get(LoginRateLimitBucket, ip_key)
        assert bucket is not None
        assert bucket.denial_audit_recorded is True
        assert (
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "user.login_rate_limited"
                )
            )
            == 1
        )
