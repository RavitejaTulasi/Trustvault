"""Shared, database-backed login rate limiter tests."""

import threading
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.database import Base
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.security.rate_limiter import (
    LoginRateLimiter,
    LoginRateLimitUnavailable,
)
from backend.app.services.audit_service import AuditService


@dataclass
class MutableClock:
    value: float

    def __call__(self) -> float:
        return self.value


def make_limiter(
    clock: MutableClock,
    *,
    max_attempts: int = 3,
    window_seconds: int = 60,
    max_buckets: int = 100,
) -> LoginRateLimiter:
    return LoginRateLimiter(
        max_attempts=max_attempts,
        window_seconds=window_seconds,
        max_buckets=max_buckets,
        time_func=clock,
    )


def test_limiter_state_is_shared_between_instances(db_session: Session):
    clock = MutableClock(1_000_000)
    first = make_limiter(clock, max_attempts=2)
    second = make_limiter(clock, max_attempts=2)

    assert first.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    assert second.reserve(db_session, "203.0.113.10", "user@example.com").allowed

    denied = first.reserve(db_session, "203.0.113.10", "user@example.com")

    assert denied.allowed is False
    assert denied.retry_after > 0


def test_successful_reservation_creates_ip_and_account_buckets(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=3)

    decision = limiter.reserve(
        db_session,
        "203.0.113.10",
        "user@example.com",
    )

    assert decision.allowed
    assert decision.reservation is not None
    buckets = db_session.scalars(
        select(LoginRateLimitBucket).order_by(LoginRateLimitBucket.scope)
    ).all()
    assert {bucket.scope for bucket in buckets} == {"ip", "ip_email"}
    assert {bucket.attempt_count for bucket in buckets} == {1}
    assert {bucket.window_started_at for bucket in buckets} == {1_000_000}


def test_success_releases_only_its_ip_slot_and_clears_account(
    db_session: Session,
):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=3)

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    success = limiter.reserve(db_session, "203.0.113.10", "user@example.com")
    assert success.allowed
    assert success.reservation is not None

    limiter.record_success(db_session, success.reservation)

    ip_bucket = db_session.scalar(
        select(LoginRateLimitBucket).where(
            LoginRateLimitBucket.scope == "ip"
        )
    )
    assert ip_bucket is not None
    assert ip_bucket.attempt_count == 2
    account_bucket = db_session.scalar(
        select(LoginRateLimitBucket).where(
            LoginRateLimitBucket.scope == "ip_email"
        )
    )
    assert account_bucket is not None
    assert account_bucket.attempt_count == 0

    # One more failure reaches the IP maximum; the next is rejected.
    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    denied = limiter.reserve(db_session, "203.0.113.10", "user@example.com")
    assert denied.allowed is False


def test_success_does_not_decrement_a_new_window(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=3, window_seconds=60)

    old = limiter.reserve(db_session, "203.0.113.10", "user@example.com")
    assert old.allowed
    assert old.reservation is not None

    clock.value += 61
    assert limiter.reserve(db_session, "203.0.113.10", "other@example.com").allowed

    limiter.record_success(db_session, old.reservation)

    ip_bucket = db_session.scalar(
        select(LoginRateLimitBucket).where(
            LoginRateLimitBucket.scope == "ip"
        )
    )
    assert ip_bucket is not None
    assert ip_bucket.attempt_count == 1


def test_success_does_not_clear_a_concurrently_changed_account_bucket(
    db_session: Session,
):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=5)

    first = limiter.reserve(db_session, "203.0.113.10", "user@example.com")
    second = limiter.reserve(db_session, "203.0.113.10", "user@example.com")
    assert first.allowed and first.reservation is not None
    assert second.allowed and second.reservation is not None

    limiter.record_success(db_session, first.reservation)

    account_bucket = db_session.scalar(
        select(LoginRateLimitBucket).where(
            LoginRateLimitBucket.scope == "ip_email"
        )
    )
    assert account_bucket is not None
    assert account_bucket.attempt_count == 2


def test_ip_denial_rolls_back_account_reservation():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine)
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=2)

    try:
        assert limiter.reserve(session, "203.0.113.10", "first@example.com").allowed
        assert limiter.reserve(session, "203.0.113.10", "first@example.com").allowed

        denied = limiter.reserve(session, "203.0.113.10", "second@example.com")
        assert denied.allowed is False

        account_buckets = session.scalars(
            select(LoginRateLimitBucket).where(
                LoginRateLimitBucket.scope == "ip_email"
            )
        ).all()
        assert len(account_buckets) == 1
        assert account_buckets[0].attempt_count == 2
    finally:
        session.close()
        engine.dispose()


def test_expired_buckets_are_replaced(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=1, window_seconds=60)

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    assert not limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed

    clock.value += 60

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed


def test_bucket_capacity_fails_closed(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=5, max_buckets=2)

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed

    with pytest.raises(LoginRateLimitUnavailable):
        limiter.reserve(db_session, "198.51.100.20", "other@example.com")


def test_reset_clears_shared_state(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=1)

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed
    assert not limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed

    limiter.reset(db_session)

    assert limiter.reserve(db_session, "203.0.113.10", "user@example.com").allowed


def test_invalid_ip_values_do_not_create_unbounded_keys(db_session: Session):
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=2)

    assert limiter.reserve(db_session, "not-an-ip", "user@example.com").allowed
    assert limiter.reserve(db_session, "also-not-an-ip", "user@example.com").allowed

    denied = limiter.reserve(db_session, "third-invalid-value", "user@example.com")
    assert denied.allowed is False


def test_denial_audit_claim_rolls_back_when_event_write_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine)
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=1)
    ip = "203.0.113.10"
    email = "user@example.com"
    ip_key = limiter._build_keys(ip, email)[1][0]

    def failed_log_event(*args, **kwargs):
        raise RuntimeError("simulated audit persistence failure")

    try:
        assert limiter.reserve(session, ip, email).allowed
        assert not limiter.reserve(session, ip, email).allowed

        monkeypatch.setattr(AuditService, "log_event", failed_log_event)
        assert limiter.claim_denial_audit(session, ip, email) is True
        with pytest.raises(RuntimeError, match="simulated audit persistence"):
            AuditService.log_event(
                session,
                action="user.login_rate_limited",
                outcome=AuditOutcome.DENIED,
            )
        session.rollback()

        bucket = session.get(LoginRateLimitBucket, ip_key)
        assert bucket is not None
        assert bucket.denial_audit_recorded is False
        assert session.scalar(select(func.count(AuditEvent.id))) == 0

        monkeypatch.undo()
        assert limiter.claim_denial_audit(session, ip, email) is True
        AuditService.log_event(
            session,
            action="user.login_rate_limited",
            outcome=AuditOutcome.DENIED,
        )
        session.commit()

        assert limiter.claim_denial_audit(session, ip, email) is False
        assert session.scalar(select(func.count(AuditEvent.id))) == 1
    finally:
        session.close()
        engine.dispose()


def test_concurrent_denial_audit_claims_record_one_event(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'denial-claims.sqlite').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 15},
    )
    Base.metadata.create_all(engine)
    clock = MutableClock(1_000_000)
    limiter = make_limiter(clock, max_attempts=1)
    ip = "203.0.113.10"
    email = "user@example.com"

    with Session(engine) as seed:
        assert limiter.reserve(seed, ip, email).allowed
        assert not limiter.reserve(seed, ip, email).allowed

    barrier = threading.Barrier(4)
    claims: list[bool] = []

    def worker() -> None:
        with Session(engine) as session:
            barrier.wait(timeout=10)
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
            claims.append(claimed)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    assert len(claims) == 4
    assert claims.count(True) == 1

    with Session(engine) as verify:
        assert verify.scalar(select(func.count(AuditEvent.id))) == 1
        bucket = verify.get(
            LoginRateLimitBucket,
            limiter._build_keys(ip, email)[1][0],
        )
        assert bucket is not None
        assert bucket.denial_audit_recorded is True
    engine.dispose()
