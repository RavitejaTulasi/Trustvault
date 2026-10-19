"""
TrustVault FastAPI Application Entrypoint
Applies security middleware, defense-in-depth headers, request tracking,
CSRF protection, and registers API routers.
"""

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.api.health import router as health_router
from backend.app.api.router import api_router
from backend.app.config import settings
from backend.app.security.csrf import CSRFMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure private storage directory exists on startup
    storage_path = settings.resolved_storage_path
    storage_path.mkdir(parents=True, exist_ok=True)
    yield
    # Shutdown cleanup if necessary


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
    Attaches a unique UUID request ID to every incoming request for tracing in audit logs.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id
        start_time = time.time()

        response: Response = await call_next(request)

        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        return response


# Register middleware in order
app.add_middleware(CSRFMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)

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
    return {
        "app": settings.APP_NAME,
        "status": "online",
        "health": "/health",
        "api_v1": settings.API_V1_PREFIX,
    }
