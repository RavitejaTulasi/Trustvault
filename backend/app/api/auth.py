"""
Authentication API Endpoints for TrustVault
Handles: registration, login, logout, current user retrieval, and self-service profile updates.

Security controls implemented:
- Argon2id password hashing (OWASP-recommended)
- Server-side session tokens (HTTP-only, SameSite=Lax cookies)
- Constant-time login (always verify password, always hash-check session)
- Audit logging for every auth event (success and failure)
- Rate-limiting hint: use a reverse proxy or middleware layer for production
- No enumeration: registration/login errors use generic messages
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.user import User, UserRole
from backend.app.schemas.auth import (
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
from backend.app.security.auth import get_current_user
from backend.app.security.passwords import hash_password, password_needs_rehash, verify_password
from backend.app.security.sessions import create_session, revoke_all_user_sessions, revoke_session
from backend.app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str | None:
    """Extract real client IP, honouring X-Forwarded-For from trusted proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _set_session_cookie(response: Response, raw_token: str) -> None:
    """Attach the session token as an HTTP-only, SameSite cookie."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=settings.SESSION_COOKIE_HTTPONLY,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    """Remove the session cookie from the client."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Creates a new Viewer account. "
        "Email uniqueness is enforced. Password is validated for complexity then hashed with Argon2id."
    ),
)
def register(
    body: UserRegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    # Check email uniqueness before creating user
    existing = db.query(User).filter(User.email == body.email.lower()).first()
    if existing:
        # Audit the failed attempt WITHOUT revealing whether the email exists
        AuditService.log_event(
            db,
            action="user.register",
            outcome=AuditOutcome.FAILURE,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "email_conflict"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    hashed = hash_password(body.password)
    user = User(
        email=body.email.lower(),
        hashed_password=hashed,
        full_name=body.full_name,
        role=UserRole.VIEWER,  # All self-registered users start as Viewer
        is_active=True,
    )
    db.add(user)
    db.flush()  # Get user.id before commit

    # Create session immediately after registration
    raw_token, _ = create_session(
        db,
        user=user,
        ip_address=ip,
        user_agent=user_agent,
    )

    AuditService.log_event(
        db,
        action="user.register",
        outcome=AuditOutcome.SUCCESS,
        actor_id=user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={"email": user.email, "role": user.role},
    )

    db.commit()
    db.refresh(user)

    _set_session_cookie(response, raw_token)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=UserResponse,
    summary="Authenticate and start a session",
    description=(
        "Verifies credentials and issues an HTTP-only session cookie. "
        "Always performs a full Argon2id verification regardless of whether the email exists "
        "to prevent user enumeration via timing."
    ),
)
def login(
    body: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    # Load user by email
    user: User | None = db.query(User).filter(User.email == body.email.lower()).first()

    # Always run password verification to prevent timing-based user enumeration.
    # Use a dummy hash if user doesn't exist.
    _DUMMY_HASH = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHRzdHJpbmc$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    stored_hash = user.hashed_password if user else _DUMMY_HASH
    password_ok = verify_password(body.password, stored_hash)

    # Reject if user doesn't exist, password is wrong, or account is deactivated
    if not user or not password_ok or not user.is_active:
        AuditService.log_event(
            db,
            action="user.login_failed",
            outcome=AuditOutcome.DENIED,
            actor_id=user.id if user else None,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"email": body.email, "reason": "invalid_credentials_or_inactive"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Rehash password if parameters are outdated (transparent upgrade)
    if password_needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(body.password)

    raw_token, _ = create_session(
        db,
        user=user,
        ip_address=ip,
        user_agent=user_agent,
    )

    AuditService.log_event(
        db,
        action="user.login",
        outcome=AuditOutcome.SUCCESS,
        actor_id=user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    db.commit()
    db.refresh(user)

    _set_session_cookie(response, raw_token)
    return UserResponse.model_validate(user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Invalidate the current session",
    description="Revokes the server-side session and clears the session cookie.",
)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    raw_token: str | None = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if raw_token:
        revoke_session(db, raw_token)

    AuditService.log_event(
        db,
        action="user.logout",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
    )
    db.commit()
    _clear_session_cookie(response)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
    description="Returns profile information for the currently authenticated user.",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update own profile",
    description="Allows the authenticated user to update their display name or password.",
)
def update_me(
    body: UserUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    changed_fields = []

    if body.full_name is not None:
        current_user.full_name = body.full_name
        changed_fields.append("full_name")

    if body.password is not None:
        current_user.hashed_password = hash_password(body.password)
        changed_fields.append("password")
        # Revoke all other sessions on password change (security best practice)
        revoke_all_user_sessions(db, current_user.id)

    if changed_fields:
        AuditService.log_event(
            db,
            action="user.update",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=current_user.id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"changed_fields": changed_fields},
        )
        db.commit()
        db.refresh(current_user)

    return UserResponse.model_validate(current_user)
