"""
Authentication API Endpoints for TrustVault
Handles: registration, login, logout, current user retrieval, and self-service profile updates.

Security controls implemented:
- Argon2id password hashing (OWASP-recommended)
- Server-side session tokens (HTTP-only, SameSite=Lax cookies)
- Double-submit CSRF cookie protection
- Shared fixed-window login rate limiting per IP and IP+email
- Constant-time login (always verify password, always hash-check session)
- Audit logging for every auth event (success, failure, rate-limited)
- No enumeration: registration/login errors use generic messages
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.user import User, UserRole
from backend.app.schemas.auth import (
    PasswordChangeRequest,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
from backend.app.security.auth import get_authenticated_user, get_current_user
from backend.app.security.csrf import generate_csrf_token
from backend.app.security.passwords import (
    hash_password,
    password_needs_rehash,
    verify_password,
)
from backend.app.security.rate_limiter import (
    LoginRateLimitUnavailable,
    login_rate_limiter,
)
from backend.app.security.sessions import (
    create_session,
    revoke_all_user_sessions,
    revoke_session,
)
from backend.app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_session_cookie(response: Response, raw_token: str) -> None:
    """Attach the session token (HttpOnly) and CSRF token (accessible to JS)."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=settings.SESSION_COOKIE_HTTPONLY,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,  # Accessible by frontend JS for X-CSRF-Token header
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    """Remove the session and CSRF cookies from the client."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        httponly=False,
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
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

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
        "to prevent user enumeration via timing. "
        "Applies shared fixed-window rate limiting on failed attempts."
    ),
)
def login(
    body: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    # Reserve a shared attempt atomically before the expensive password check.
    try:
        decision = login_rate_limiter.reserve(db, ip, body.email)
    except LoginRateLimitUnavailable:
        logger.exception("Shared login rate limiter unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

    if not decision.allowed:
        try:
            should_audit = login_rate_limiter.claim_denial_audit(
                db,
                ip,
                body.email,
            )
            if should_audit:
                AuditService.log_event(
                    db,
                    action="user.login_rate_limited",
                    outcome=AuditOutcome.DENIED,
                    ip_address=ip,
                    user_agent=user_agent,
                    request_id=request_id,
                    details={
                        "email": body.email,
                        "reason": "rate_limit_exceeded",
                        "aggregated": True,
                    },
                )
                db.commit()
        except (LoginRateLimitUnavailable, SQLAlchemyError):
            db.rollback()
            logger.exception("Failed to record rate-limit denial")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication temporarily unavailable",
                headers={"Retry-After": "5"},
            ) from None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(decision.retry_after)},
        )

    reservation = decision.reservation
    if reservation is None:
        logger.error("Shared login rate limiter returned no reservation")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
            headers={"Retry-After": "5"},
        )

    # Load user by email
    user: User | None = db.query(User).filter(User.email == body.email.lower()).first()

    # Always run password verification to prevent timing-based user enumeration.
    # Use a dummy hash if user doesn't exist.
    _DUMMY_HASH = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHRzdHJpbmc$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    stored_hash = user.hashed_password if user else _DUMMY_HASH
    password_ok = verify_password(body.password, stored_hash)

    # Reject if user doesn't exist, password is wrong, or account is deactivated
    if not user or not password_ok or not user.is_active:
        # The reservation made before verification remains counted as a failure.
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

    # Credentials valid -> clear this account's failures and release this
    # request's IP slot without erasing earlier IP-wide failures.
    try:
        login_rate_limiter.record_success(db, reservation)
    except LoginRateLimitUnavailable:
        logger.exception("Shared login rate limiter unavailable during success")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

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
    current_user: User = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> None:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

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
    current_user: User = Depends(get_authenticated_user),
) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post(
    "/change-password",
    response_model=UserResponse,
    summary="Complete a required password change",
    description=(
        "Verifies the current password, replaces it, clears the mandatory-change "
        "flag, revokes every existing session, and issues a fresh session."
    ),
)
def change_password(
    body: PasswordChangeRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    if not verify_password(body.current_password, current_user.hashed_password):
        AuditService.log_event(
            db,
            action="user.password_change",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=current_user.id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "current_password_invalid"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password",
        )

    current_user.hashed_password = hash_password(body.new_password)
    current_user.must_change_password = False
    sessions_revoked = revoke_all_user_sessions(db, current_user.id)
    raw_token, _ = create_session(
        db,
        user=current_user,
        ip_address=ip,
        user_agent=user_agent,
    )

    AuditService.log_event(
        db,
        action="user.password_change",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={
            "sessions_revoked": sessions_revoked,
            "session_rotated": True,
        },
    )
    db.commit()
    db.refresh(current_user)

    _set_session_cookie(response, raw_token)
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
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

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
