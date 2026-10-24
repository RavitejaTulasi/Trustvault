"""
TrustVault FastAPI Application Entrypoint
Applies security middleware, defense-in-depth headers, request tracking,
CSRF protection, and registers API routers.
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from backend.app.api.health import router as health_router
from backend.app.api.router import api_router
from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.security.body_limit import RequestBodyLimitMiddleware
from backend.app.security.client_ip import get_client_ip
from backend.app.security.csrf import CSRFMiddleware
from backend.app.security.request_validation import (
    RequestMetadataValidationError,
    validate_ip_address,
    validate_request_id,
    validate_user_agent,
)
from backend.app.services.checkpoint_runtime import checkpoint_scheduler
from backend.app.services.storage_lifecycle import StorageLifecycleService
from backend.app.services.storage_recovery import storage_recovery_scheduler

logger = logging.getLogger(__name__)
FRONTEND_DIST_DIR = Path(__file__).resolve().parents[2] / "frontend_dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.STORAGE_BACKEND == "local":
        # Ensure private local storage directory exists on startup.
        storage_path = settings.resolved_storage_path
        storage_path.mkdir(parents=True, exist_ok=True)
        try:
            with SessionLocal() as db:
                report = StorageLifecycleService.reconcile(db)
            logger.info(
                "Storage reconciliation completed: orphaned=%d deleted=%d "
                "staging=%d missing_active=%d failures=%d bytes=%d",
                report.removed_orphaned_files,
                report.removed_deleted_files,
                report.removed_staging_files,
                report.missing_active_files,
                report.cleanup_failures,
                report.removed_bytes,
            )
        except Exception:
            logger.exception(
                "Local storage reconciliation failed; application will continue"
            )
    else:
        logger.info(
            "Supabase Storage selected; local filesystem reconciliation skipped"
        )
        try:
            await storage_recovery_scheduler.run_once_async()
        except Exception:
            logger.exception("Initial remote storage recovery cycle failed")
        storage_recovery_scheduler.start()

    checkpoint_scheduler.start()
    try:
        yield
    finally:
        await storage_recovery_scheduler.stop()
        await checkpoint_scheduler.stop()


app = FastAPI(
    title=settings.APP_NAME,
    description="Secure Document Sharing with a Verifiable Audit Trail",
    version="0.1.0",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies security response headers strictly according to OWASP guidelines:
    - Defense against MIME-sniffing
    - Clickjacking prevention (X-Frame-Options)
    - Strict Referrer policies
    - Content Security Policy
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none';"
            )

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Validates persisted request metadata and attaches a tracing request ID.

    Request IDs and user agents are length-checked and control-character free so
    they cannot be silently truncated by database column limits. The resolved
    client IP is canonicalized before any route or audit write can use it.
    """

    async def dispatch(self, request: Request, call_next):
        fallback_request_id = uuid.uuid4().hex
        try:
            request_id = (
                validate_request_id(request.headers.get("X-Request-ID"))
                or fallback_request_id
            )
            user_agent = validate_user_agent(request.headers.get("User-Agent"))
        except RequestMetadataValidationError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers={"X-Request-ID": fallback_request_id},
            )

        try:
            client_ip = validate_ip_address(get_client_ip(request)) or "unknown"
        except RequestMetadataValidationError:
            client_ip = "unknown"

        request.state.request_id = request_id
        request.state.user_agent = user_agent
        request.state.client_ip = client_ip
        start_time = time.time()

        response: Response = await call_next(request)

        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        return response


# Register middleware in order. CORS is outermost; body limits run before CSRF
# or multipart parsing. Security headers wrap validation and limit responses.
app.add_middleware(CSRFMiddleware)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Cross-Origin Resource Sharing (CORS) with strict origin allowlist
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Content-Disposition"],
)

# Root-level health endpoint (useful for load balancers and deployment probes)
app.include_router(health_router, prefix="", tags=["Root Health"])

# Versioned API routes (/api/v1)
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root_info():
    """Root info endpoint."""
    index_path = FRONTEND_DIST_DIR / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return {
        "app": settings.APP_NAME,
        "status": "online",
        "health": "/health",
        "api_v1": settings.API_V1_PREFIX,
    }


class SPAStaticFiles(StaticFiles):
    """Serve the frontend entry point for client-side routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        normalized_path = path.replace("\\", "/").lstrip("/")
        if normalized_path == "api" or normalized_path.startswith("api/"):
            return await super().get_response(path, scope)
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or Path(path).suffix:
                raise
            return await super().get_response("index.html", scope)


if FRONTEND_DIST_DIR.is_dir():
    app.mount(
        "/",
        SPAStaticFiles(directory=str(FRONTEND_DIST_DIR), html=True),
        name="frontend",
    )
