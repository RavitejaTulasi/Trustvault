"""
TrustVault CSRF Protection Middleware
Implements double-submit cookie validation with constant-time token comparison
and Origin/Referer header verification for defense-in-depth.
"""

import secrets
from typing import ClassVar
from urllib.parse import urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.config import settings


def generate_csrf_token() -> str:
    """Generate a cryptographically secure 256-bit URL-safe CSRF token."""
    return secrets.token_urlsafe(32)


def _normalized_origin(value: str) -> tuple[str, str, int] | None:
    """Return (scheme, hostname, effective_port) for a valid HTTP(S) origin."""
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if scheme not in {"http", "https"} or not hostname:
        return None

    # Origin values must not contain credentials.
    if parsed.username is not None or parsed.password is not None:
        return None

    effective_port = port if port is not None else (
        443 if scheme == "https" else 80
    )
    return scheme, hostname.lower(), effective_port


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Middleware enforcing double-submit cookie verification on state-changing requests.

    Behavior:
    - Safe methods (GET, HEAD, OPTIONS): Allowed. Ensures a CSRF cookie is set on the response if missing.
    - State-changing methods (POST, PUT, PATCH, DELETE):
      - If request has a session cookie or CSRF cookie:
        Requires 'X-CSRF-Token' header to match the 'trustvault_csrf' cookie.
      - Origin / Referer header (if provided) must match request host or allowed CORS origins.
      - Mismatched or missing tokens return HTTP 403 Forbidden.
    """

    SAFE_METHODS: ClassVar[set[str]] = {"GET", "HEAD", "OPTIONS"}
    STATE_CHANGING_METHODS: ClassVar[set[str]] = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method.upper()

        if method in self.STATE_CHANGING_METHODS:
            session_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
            csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)

            # Enforce CSRF token check if request is authenticated or has a CSRF cookie
            if session_cookie or csrf_cookie:
                csrf_header = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")

                if not csrf_cookie or not csrf_header:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing or invalid"},
                    )

                if not secrets.compare_digest(csrf_cookie, csrf_header):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing or invalid"},
                    )

            # Defense-in-depth: validate the full origin, including scheme and port.
            origin = request.headers.get("Origin") or request.headers.get("Referer")
            if origin:
                request_host = request.headers.get("Host", "")
                request_origin = _normalized_origin(
                    f"{request.url.scheme}://{request_host}"
                )
                supplied_origin = _normalized_origin(origin)

                allowed_origins = {
                    normalized
                    for configured in settings.CORS_ORIGINS
                    if (normalized := _normalized_origin(configured)) is not None
                }

                if request_origin is not None:
                    allowed_origins.add(request_origin)

                if (
                    supplied_origin is None
                    or supplied_origin not in allowed_origins
                ):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF Origin validation failed"},
                    )

        response: Response = await call_next(request)

        # Ensure CSRF cookie is set on response if not present in request cookies or response headers
        if (
            settings.CSRF_COOKIE_NAME not in request.cookies
            and settings.CSRF_COOKIE_NAME not in response.headers.get("set-cookie", "")
        ):
            response.set_cookie(
                key=settings.CSRF_COOKIE_NAME,
                value=generate_csrf_token(),
                httponly=False,  # Accessible by frontend JS for X-CSRF-Token header
                secure=settings.SESSION_COOKIE_SECURE,
                samesite=settings.SESSION_COOKIE_SAMESITE,
                max_age=settings.SESSION_MAX_AGE_SECONDS,
                path="/",
            )

        return response
