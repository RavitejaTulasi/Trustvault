"""
Pytest Fixtures and Test Environment Configuration
Sets up isolated in-memory test database, rate limiter resets, and HTTPX async test clients.
"""

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force testing environment before loading app components
os.environ["ENVIRONMENT"] = "testing"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.security.rate_limiter import login_rate_limiter

# In-memory test engine isolated to test suite
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initializes tables for the test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def reset_rate_limiter_fixture():
    """Resets the login rate limiter state before and after each test."""
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()


@pytest.fixture
def db_session():
    """Provides a fresh transactional database session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
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
        event_hooks={"request": [_inject_csrf_header_hook]},
    ) as client:
        yield client

    app.dependency_overrides.clear()
