"""
FastAPI Authentication Dependencies for TrustVault

Provides reusable dependency functions that:
- Extract and validate the server-side session cookie
- Load and return the authenticated User object
- Enforce role-based access control (RBAC)

Security principles:
- Constant-time session token hashing prevents timing side channels
- All auth failures return identical 401 responses (no enumeration)
- Deactivated accounts are rejected even with a valid session
"""

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.user import User, UserRole
from backend.app.security.sessions import get_valid_session


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency that authenticates the current request via session cookie.

    Raises HTTP 401 if:
    - No session cookie is present
    - The session token is invalid, expired, or revoked
    - The associated user account is deactivated

    Returns the User ORM object on success.
    """
    raw_token: str | None = request.cookies.get(settings.SESSION_COOKIE_NAME)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Cookie"},
        )

    session = get_valid_session(db, raw_token)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Cookie"},
        )

    user: User | None = db.get(User, session.user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Cookie"},
        )

    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> User | None:
    """
    Like get_current_user but returns None instead of raising 401 on missing auth.
    Useful for endpoints that serve both authenticated and anonymous users differently.
    """
    try:
        return get_current_user(request=request, db=db)
    except HTTPException:
        return None


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency that ensures the current user has the 'admin' role.
    Raises HTTP 403 if the role is insufficient.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return current_user


def require_owner_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency that allows Document Owners and Administrators.
    Viewers are denied.
    """
    if current_user.role not in {UserRole.ADMIN, UserRole.OWNER}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document owner or administrator privileges required",
        )
    return current_user
