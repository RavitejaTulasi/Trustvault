"""
TrustVault Security and Cryptography Utilities

Exports:
- passwords: Argon2id hashing and verification
- sessions: Server-side session lifecycle management
- auth: FastAPI dependency functions for authentication and RBAC
"""

from backend.app.security.auth import (
    get_current_user,
    get_current_user_optional,
    require_admin,
    require_owner_or_admin,
)
from backend.app.security.passwords import hash_password, verify_password
from backend.app.security.sessions import (
    create_session,
    get_valid_session,
    revoke_all_user_sessions,
    revoke_session,
)

__all__ = [
    "get_current_user",
    "get_current_user_optional",
    "require_admin",
    "require_owner_or_admin",
    "hash_password",
    "verify_password",
    "create_session",
    "get_valid_session",
    "revoke_all_user_sessions",
    "revoke_session",
]
