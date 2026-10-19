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

            # Defense-in-depth: Origin / Referer validation if header present
            origin = request.headers.get("Origin") or request.headers.get("Referer")
            if origin:
                parsed_origin = urlparse(origin)
                origin_host = parsed_origin.netloc or parsed_origin.path
                request_host = request.headers.get("Host", "")

                allowed_hosts = {request_host}
                for allowed in settings.CORS_ORIGINS:
                    parsed_allowed = urlparse(allowed)
                    if parsed_allowed.netloc:
                        allowed_hosts.add(parsed_allowed.netloc)
                    else:
                        allowed_hosts.add(allowed)

                # Strip port or match directly
                if origin_host and not any(
                    origin_host == h or origin_host.split(":")[0] == h.split(":")[0]
                    for h in allowed_hosts if h
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
