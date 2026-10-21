"""
Focused regression coverage for the login fail-closed paths behind
"Authentication temporarily unavailable" (HTTP 503) and the boundary of the
successful-login audit write.

POST /api/v1/auth/login has four 503-producing failure branches
(backend/app/api/auth.py):

1. Shared rate-limit reservation storage failure (auth.py:193-201). Existing
   endpoint coverage simulates the limiter raising; this file reproduces the
   same branch with a REAL cross-connection SQLite writer lock so the wrapped
   exception is the actual driver failure, not a simulated one.
2. Rate-limit denial audit-claim storage failure (auth.py:203-237). The
   denial decision is reached without reserve() touching the database, and
   the claim UPDATE then fails against a real SQLite writer lock; the
   endpoint fails closed at 503, appends no denial event, and leaves the
   denial-audit flag unclaimed.
3. Failed-login denial event write/commit failure (auth.py:204-237) has
   existing endpoint and atomicity coverage in test_phase5_controls.py and is
   not duplicated here.
4. record_success() storage failure after valid credentials (auth.py:278-286)
   had no endpoint coverage. A real SQLite writer lock is reproduced at unit
   level and the endpoint glue is covered with the simulated-failure style
   used elsewhere in this repository.

Separately, a failure of the successful-login audit write after
record_success() commits (auth.py:288-315) is NOT converted into a 503 and
NOT converted into a login: the exception escapes the route, the client sees
a generic server error, and no session cookie or user.login event is issued.
That boundary is pinned so it cannot silently change.
"""

import sqlite3

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import settings
from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.audit import AuditEvent
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.models.session import SessionModel
from backend.app.security.rate_limiter import (
    LoginRateLimitDecision,
    LoginRateLimiter,
    LoginRateLimitUnavailable,
    login_rate_limiter,
)
from backend.app.services.audit_service import AuditService
from backend.tests.test_auth import VALID_PASSWORD, make_user


def _file_engine(tmp_path, name: str, timeout: float = 0.3):
    """Create a file-backed SQLite engine with a short real busy timeout."""
    db_path = tmp_path / name
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": timeout},
    )
    Base.metadata.create_all(engine)
    return engine, db_path


def test_reserve_fails_closed_on_real_sqlite_writer_lock(tmp_path):
    """A real cross-connection write lock makes reserve() fail closed with the
    driver error wrapped as LoginRateLimitUnavailable, which the login endpoint
    maps to 503 (auth.py:193-201)."""
    engine, db_path = _file_engine(tmp_path, "reserve-lock.sqlite")
    limiter = LoginRateLimiter(
        max_attempts=5, window_seconds=60, time_func=lambda: 1_000_000
    )
    blocker = sqlite3.connect(str(db_path), timeout=0.3, isolation_level=None)
    session = Session(engine)
    try:
        blocker.execute("BEGIN IMMEDIATE")

        with pytest.raises(LoginRateLimitUnavailable) as excinfo:
            limiter.reserve(session, "203.0.113.10", "lock-repro@example.com")

        cause = excinfo.value.__cause__
        assert cause is not None, "the unavailable error must wrap the real failure"
        assert "locked" in str(cause).lower()
    finally:
        session.close()
        blocker.close()
        engine.dispose()


def test_record_success_fails_closed_on_real_sqlite_writer_lock(tmp_path):
    """A real write lock after valid authentication makes record_success()
    fail closed, which the login endpoint maps to 503 (auth.py:278-286)."""
    engine, db_path = _file_engine(tmp_path, "record-success-lock.sqlite")
    limiter = LoginRateLimiter(
        max_attempts=5, window_seconds=60, time_func=lambda: 1_000_000
    )
    blocker = sqlite3.connect(str(db_path), timeout=0.3, isolation_level=None)
    session = Session(engine)
    try:
        decision = limiter.reserve(session, "203.0.113.10", "success-repro@example.com")
        assert decision.allowed
        assert decision.reservation is not None

        blocker.execute("BEGIN IMMEDIATE")

        with pytest.raises(LoginRateLimitUnavailable) as excinfo:
            limiter.record_success(session, decision.reservation)

        cause = excinfo.value.__cause__
        assert cause is not None
        assert "locked" in str(cause).lower()

        # A fail-closed record success leaves the reserved attempt counted.
        ip_email_key = limiter._build_keys("203.0.113.10", "success-repro@example.com")[0][
            0
        ]
        bucket = session.scalar(
            select(LoginRateLimitBucket).where(
                LoginRateLimitBucket.key_hash == ip_email_key
            )
        )
        assert bucket is not None
        assert bucket.attempt_count == 1
    finally:
        session.close()
        blocker.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_denial_audit_claim_fails_closed_on_real_sqlite_writer_lock(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    """The denial branch fails closed on a real driver-level failure. The
    denial decision arrives without reserve() writing (its reads cannot be
    blocked by a peer's RESERVED lock), then the conditional claim UPDATE in
    claim_denial_audit() blocks on a real SQLite writer lock and wraps the
    OperationalError as LoginRateLimitUnavailable (auth.py:203-237)."""
    engine, db_path = _file_engine(tmp_path, "claim-lock.sqlite")
    request_sessions = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # The override must be a generator like get_db itself. A plain callable
    # override makes FastAPI derive request parameters from the callable's
    # signature; a sessionmaker's __call__ takes *local_kw, which would turn
    # into a demanded query parameter and 422 every request.
    def override_get_db():
        db = request_sessions()
        try:
            yield db
        finally:
            db.close()

    email = "real-lock-denial@example.com"

    def denying_reserve(*args, **kwargs):
        return LoginRateLimitDecision(allowed=False, retry_after=60)

    monkeypatch.setattr(login_rate_limiter, "reserve", denying_reserve)

    app.dependency_overrides[get_db] = override_get_db
    blocker = sqlite3.connect(str(db_path), timeout=0.3, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            bootstrap = await client.get("/api/v1/auth/me")
            assert bootstrap.status_code == 401
            csrf_token = client.cookies.get("trustvault_csrf")
            response = await client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "WrongStoredPassword123!"},
                headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
            )

        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"

        with request_sessions() as check:
            denial_events = check.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "user.login_rate_limited"
                )
            ).all()
            assert denial_events == []
            created = check.scalars(select(LoginRateLimitBucket)).all()
            assert created == []
    finally:
        app.dependency_overrides.clear()
        blocker.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_record_success_failure_returns_503_without_login_session(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Endpoint glue (auth.py:278-286): record_success storage failure after
    valid credentials fails closed at 503 with no session cookie, no
    user.login event, and the reservation still counted."""
    email = "record-success-failure@example.com"
    make_user(db_session, email=email, password=VALID_PASSWORD)
    db_session.commit()

    def failing_record_success(*args, **kwargs):
        raise LoginRateLimitUnavailable(
            "Shared login rate-limit storage is unavailable"
        )

    monkeypatch.setattr(login_rate_limiter, "record_success", failing_record_success)

    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )

    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    cookie_names = {cookie.name for cookie in response.cookies.jar}
    assert settings.SESSION_COOKIE_NAME not in cookie_names

    success_events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "user.login",
            AuditEvent.actor_id.is_not(None),
        )
    ).all()
    assert success_events == []

    ip_email_key = login_rate_limiter._build_keys("127.0.0.1", email)[0][0]
    bucket = db_session.get(LoginRateLimitBucket, ip_email_key)
    assert bucket is not None
    assert bucket.attempt_count == 1


@pytest.mark.asyncio
async def test_successful_login_audit_failure_issues_no_session_and_no_event(
    async_client: AsyncClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
):
    """Pin the successful-login audit boundary (auth.py:288-315): when the
    audit write fails after credentials verified and record_success committed,
    the login is not faked as successful and is not converted to 503. The
    exception escapes the route (generic server error at the client boundary),
    no session cookie is issued, and, once the production get_db failure
    teardown is mirrored (database.py:48-57), neither the pending user.login
    event nor the pending session row survives; only record_success's cleanup
    was committed before the failure."""
    email = "audit-write-failure@example.com"
    user = make_user(db_session, email=email, password=VALID_PASSWORD)
    user_id = user.id
    db_session.commit()

    original_log_event = AuditService.log_event

    def log_event_then_fail(db, **kwargs):
        original_log_event(db, **kwargs)
        raise SQLAlchemyError("simulated successful-login audit failure")

    monkeypatch.setattr(AuditService, "log_event", log_event_then_fail)

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        bootstrap = await client.get("/api/v1/auth/me")
        assert bootstrap.status_code == 401
        csrf_token = client.cookies.get("trustvault_csrf")
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": VALID_PASSWORD},
            headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
        )

        assert response.status_code == 500
        cookie_names = {cookie.name for cookie in response.cookies.jar}
        assert settings.SESSION_COOKIE_NAME not in cookie_names

    # Under the shared-transaction harness the app and fixture sessions are
    # joined in rollback_only mode, so app-level commits are flushes and the
    # rows written before the failure stay visible here. Assert the route
    # reached each write, then mirror the production get_db failure teardown
    # (backend/app/database.py:48-57) and pin that the login session and the
    # audit event do not survive it.
    pending_events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "user.login",
            AuditEvent.actor_id == user_id,
        )
    ).all()
    assert len(pending_events) == 1

    pending_sessions = db_session.scalars(
        select(SessionModel).where(SessionModel.user_id == user_id)
    ).all()
    assert len(pending_sessions) == 1

    bucket = db_session.get(
        LoginRateLimitBucket,
        login_rate_limiter._build_keys("127.0.0.1", email)[0][0],
    )
    assert bucket is not None
    assert bucket.attempt_count == 0

    db_session.rollback()

    assert db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "user.login",
            AuditEvent.actor_id == user_id,
        )
    ).all() == []
    assert db_session.scalars(
        select(SessionModel).where(SessionModel.user_id == user_id)
    ).all() == []
