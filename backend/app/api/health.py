"""
Health Check API Endpoints
Provides system liveness and readiness verification for orchestrators, monitoring, and deployments.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Response, status

from backend.app.config import settings
from backend.app.database import check_db_connection
from backend.app.schemas.health import HealthResponse

router = APIRouter(tags=["Health & Status"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Readiness Check",
    description="Validates database connectivity, private storage availability, and core service status.",
)
def get_health(response: Response) -> HealthResponse:
    db_ok = check_db_connection()
    
    # Check private persistent storage path
    storage_path = settings.resolved_storage_path
    storage_ok = False
    try:
        storage_path.mkdir(parents=True, exist_ok=True)
        # Test writability by checking if directory is accessible
        test_file = storage_path / ".healthcheck"
        test_file.touch(exist_ok=True)
        if test_file.exists():
            test_file.unlink(missing_ok=True)
            storage_ok = True
    except OSError:
        storage_ok = False

    is_healthy = db_ok and storage_ok
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    anchor_mode = settings.AUDIT_ANCHOR_MODE
    # This reports configuration only; it does not probe the provider. A
    # configured external adapter is not proof that anchoring is live.
    anchor_status = {
        "disabled": "not_configured",
        "local_file": "local_development_only",
        "s3": "external_provider_configured",
    }.get(anchor_mode, "not_configured")

    return HealthResponse(
        status="healthy" if is_healthy else "unhealthy",
        app=settings.APP_NAME,
        environment=settings.ENVIRONMENT,
        version="0.1.0",
        timestamp=datetime.now(UTC),
        database="connected" if db_ok else "disconnected",
        storage="available" if storage_ok else "unavailable",
        components={
            "database": {"status": "ok" if db_ok else "down"},
            "storage": {
                "status": "ok" if storage_ok else "down",
                "path": str(storage_path),
            },
            "audit_anchor": {
                "status": anchor_status,
                "mode": anchor_mode,
                "independent": anchor_mode == "s3",
            },
        },
    )
