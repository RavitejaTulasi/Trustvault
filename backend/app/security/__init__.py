"""
TrustVault Security and Cryptography Utilities

Exports:
- passwords: Argon2id hashing and verification
- sessions: Server-side session lifecycle management
- auth: FastAPI dependency functions for authentication and RBAC
- csrf: CSRF protection middleware and token generator
- rate_limiter: Login rate limiter
"""

from backend.app.security.auth import (
    get_current_user,
    get_current_user_optional,
    require_admin,
    require_owner_or_admin,
)
from backend.app.security.csrf import CSRFMiddleware, generate_csrf_token
from backend.app.security.passwords import hash_password, verify_password
from backend.app.security.rate_limiter import LoginRateLimiter, login_rate_limiter
from backend.app.security.sessions import (
    create_session,
    get_valid_session,
    revoke_all_user_sessions,
    revoke_session,
)

__all__ = [
    "CSRFMiddleware",
    "LoginRateLimiter",
    "create_session",
    "generate_csrf_token",
    "get_current_user",
    "get_current_user_optional",
    "get_valid_session",
    "hash_password",
    "login_rate_limiter",
    "require_admin",
    "require_owner_or_admin",
    "revoke_all_user_sessions",
    "revoke_session",
    "verify_password",
]
