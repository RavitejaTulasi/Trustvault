"""
Pytest Fixtures and Test Environment Configuration
Sets up isolated in-memory test database, rate limiter resets, and HTTPX async test clients.
"""

import os
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Force testing environment before loading app components
os.environ["ENVIRONMENT"] = "testing"
from backend.app.config import settings

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
settings.DATABASE_URL = os.environ["DATABASE_URL"]

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.storage_object import StorageObject
from backend.app.models.base import utc_now
from backend.app.security.rate_limiter import (
    audit_checkpoint_rate_limiter,
    audit_verification_rate_limiter,
    login_rate_limiter,
)
from backend.app.services.checkpoint_runtime import checkpoint_scheduler


@event.listens_for(Session, "before_flush")
def _register_storage_objects_for_test_fixtures(session, _flush_context, _instances):
    """Keep direct ORM document fixtures consistent with the storage registry."""
    keys = {
        row.storage_key
        for row in (*session.new,)
        if isinstance(row, (Document, DocumentVersion, StorageOperation))
    }
    pending_object_keys = {
        row.storage_key
        for row in session.new
        if isinstance(row, StorageObject)
    }
    for storage_key in keys:
        if storage_key in pending_object_keys:
            continue
        with session.no_autoflush:
            exists = session.get(StorageObject, storage_key) is not None
        if exists:
            continue
        document_reference = any(
            isinstance(row, (Document, DocumentVersion))
            and row.storage_key == storage_key
            for row in session.new
        )
        operation = next(
            (
                row
                for row in session.new
                if isinstance(row, StorageOperation)
                and row.storage_key == storage_key
            ),
            None,
        )
        if document_reference:
            state = "active"
        elif operation is not None and operation.operation_type == "delete":
            state = (
                "deleted"
                if operation.status in {"completed", "cancelled"}
                else "deleting"
            )
        elif operation is not None and operation.status == "uploading":
            state = "uploading"
        elif operation is not None:
            state = "needs_review"
        else:
            state = "active"
        session.connection().execute(
            insert(StorageObject.__table__).values(
                storage_key=storage_key,
                backend="local",
                state=state,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )


def pytest_configure(config):
    """Register opt-in markers so unknown-mark warnings never fail strict runs."""
    config.addinivalue_line(
        "markers",
        "postgres_integration: opt-in tests that use an explicitly approved PostgreSQL test database",
    )
    config.addinivalue_line(
        "markers",
        "postgres_migration_integration: opt-in Alembic tests using an isolated PostgreSQL schema",
    )


async def _inject_upload_idempotency_header_hook(request):
    """Give legacy test requests a unique key unless a case supplies its own."""
    if (
        request.method.upper() == "POST"
        and request.url.path == "/api/v1/documents"
        and "Idempotency-Key" not in request.headers
    ):
        request.headers["Idempotency-Key"] = f"test-{uuid.uuid4().hex}"


# In-memory test engine isolated to test suite
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def _enable_sqlite_constraints(dbapi_connection, _connection_record):
    """Match production SQLite behavior for foreign keys and lock waits."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initializes tables for the test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def reset_rate_limiter_fixture(db_session):
    """Resets rate limiter state before and after each test."""
    login_rate_limiter.reset(db_session)
    audit_verification_rate_limiter.reset()
    audit_checkpoint_rate_limiter.reset()
    checkpoint_scheduler.reset_state()
    yield
    login_rate_limiter.reset(db_session)
    audit_verification_rate_limiter.reset()
    audit_checkpoint_rate_limiter.reset()
    checkpoint_scheduler.reset_state()


@pytest.fixture
def db_session():
    """Provides a fresh transactional database session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection, join_transaction_mode="rollback_only")

    yield session

    session.close()
    # An application-level rollback (for example the audit fail-closed 503 path)
    # ends the shared transaction under rollback_only join mode; rolling back an
    # already-deactivated transaction is invalid and would raise a warning.
    if transaction.is_active:
        transaction.rollback()
    connection.close()


async def _inject_csrf_header_hook(request):
    """
    Simulates frontend/SPA client behavior by extracting the 'trustvault_csrf'
    cookie value and setting the 'X-CSRF-Token' header on state-changing requests,
    unless the test explicitly specifies or overrides the header.
    """
    if "X-CSRF-Token" not in request.headers and "x-csrf-token" not in request.headers:
        cookie_header = request.headers.get("Cookie", "")
        if "trustvault_csrf=" in cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith("trustvault_csrf="):
                    token = part.split("=", 1)[1]
                    request.headers["X-CSRF-Token"] = token
                    break


@pytest_asyncio.fixture
async def async_client(db_session):
    """Provides an HTTPX AsyncClient configured with overridden database dependency and CSRF hook."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        event_hooks={
            "request": [
                _inject_csrf_header_hook,
                _inject_upload_idempotency_header_hook,
            ]
        },
    ) as client:
        yield client

    app.dependency_overrides.clear()
