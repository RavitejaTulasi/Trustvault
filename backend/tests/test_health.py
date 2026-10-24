"""
Integration Tests for Health Check and System Infrastructure
Verifies system health endpoints, security headers, request tracing, and audit service foundation.
"""

from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.models.audit import AuditOutcome
from backend.app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_health_endpoint_healthy(async_client: AsyncClient):
    """Test that the /health endpoint reports healthy status and returns expected fields."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "TrustVault"
    assert data["database"] == "connected"
    assert data["storage"] == "available"
    assert "timestamp" in data
    assert "components" in data
    assert data["components"]["database"]["status"] == "ok"
    assert data["components"]["storage"]["status"] == "ok"
    assert "path" not in data["components"]["storage"]


@pytest.mark.asyncio
async def test_api_v1_health_endpoint(async_client: AsyncClient):
    """Test that the versioned /api/v1/health endpoint also operates correctly."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_security_headers_present(async_client: AsyncClient):
    """Test that defense-in-depth security headers are applied to HTTP responses."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "X-Request-ID" in headers
    assert len(headers.get("X-Request-ID")) > 0


@pytest.mark.asyncio
async def test_health_degraded_when_database_fails(async_client: AsyncClient):
    """Test that 503 Service Unavailable is returned when database check fails."""
    with patch("backend.app.api.health.check_db_connection", return_value=False):
        response = await async_client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "disconnected"


def test_audit_service_initialization_and_verification(db_session: Session):
    """Test that the audit service initializes, logs an event, and verifies chain integrity."""
    # Ensure fresh chain verifies
    is_valid, error, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is True
    assert count == 0

    # Log initial test event
    event = AuditService.log_event(
        db=db_session,
        action="system.startup.test",
        outcome=AuditOutcome.SUCCESS,
        details={"info": "day 1 foundation verification"},
    )
    db_session.commit()

    assert event.sequence_number == 1
    assert len(event.record_hash) == 64
    assert event.previous_hash == "0" * 64

    # Verify integrity of single-item chain
    is_valid, error, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is True, f"Integrity check failed: {error}"
    assert count == 1
    assert error is None


def test_audit_service_detects_tampering(db_session: Session):
    """Test that modifying an audit record breaks hash integrity and is detected."""
    event1 = AuditService.log_event(
        db=db_session,
        action="user.login",
        outcome=AuditOutcome.SUCCESS,
        details={"ip": "127.0.0.1"},
    )
    event2 = AuditService.log_event(
        db=db_session,
        action="document.read",
        outcome=AuditOutcome.SUCCESS,
        details={"doc": "contract.pdf"},
    )
    db_session.commit()

    assert event2.sequence_number == 2

    # Initial chain must be valid
    is_valid, error, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is True
    assert count == 2

    # Maliciously modify the details of event 1 directly in the database
    event1.details = '{"ip": "10.0.0.99", "tampered": true}'
    db_session.commit()

    # Integrity verification must now detect tampering
    is_valid, error, count = AuditService.verify_chain_integrity(db_session)
    assert is_valid is False
    assert error is not None
    assert "Record tampering detected at sequence 1" in error
