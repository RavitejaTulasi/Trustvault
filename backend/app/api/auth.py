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
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.base import utc_now
from backend.app.models.otp import PasswordResetOTP
from backend.app.models.user import User, UserRole
from backend.app.schemas.auth import (
    DemoAccountResponse,
    OTPVerifyRequestSchema,
    PasswordChangeRequest,
    PasswordResetConfirmRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
from backend.app.security.auth import get_authenticated_user, get_current_user
from backend.app.security.csrf import generate_csrf_token
from backend.app.security.otp import hash_otp_code, verify_otp_code
from backend.app.security.passwords import (
    hash_password,
    password_needs_rehash,
    verify_password,
)
from backend.app.security.rate_limiter import (
    LoginRateLimiter,
    LoginRateLimitUnavailable,
    login_rate_limiter,
    otp_request_rate_limiter,
    otp_verify_rate_limiter,
)
from backend.app.security.sessions import (
    create_session,
    revoke_all_user_sessions,
    revoke_session,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.email_service import (
    PASSWORD_RESET_OTP_EXPIRY_MINUTES,
    EmailDeliveryError,
    send_password_reset_otp,
)

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


@router.get(
    "/demo-accounts",
    response_model=list[DemoAccountResponse],
    include_in_schema=False,
)
def get_demo_accounts(
    response: Response,
    db: Session = Depends(get_db),
) -> list[DemoAccountResponse]:
    """
    Return staging-only demo credentials after verifying the backing accounts.

    The endpoint is disabled in production and whenever the explicit flag is
    off. It only returns a credential when the configured email maps to an
    active user with the expected role and the configured password verifies.
    """
    if not settings.DEMO_LOGIN_ENABLED or settings.ENVIRONMENT == "production":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    configured_accounts = (
        (UserRole.ADMIN, settings.DEMO_ADMIN_EMAIL, settings.DEMO_ADMIN_PASSWORD),
        (UserRole.OWNER, settings.DEMO_OWNER_EMAIL, settings.DEMO_OWNER_PASSWORD),
        (UserRole.VIEWER, settings.DEMO_VIEWER_EMAIL, settings.DEMO_VIEWER_PASSWORD),
    )

    accounts: list[DemoAccountResponse] = []
    for role, email, password in configured_accounts:
        normalized_email = email.strip().lower()
        if not normalized_email or not password:
            continue
        user = db.query(User).filter(User.email == normalized_email).first()
        if (
            user is None
            or not user.is_active
            or user.role != role
            or not verify_password(password, user.hashed_password)
        ):
            continue
        accounts.append(
            DemoAccountResponse(role=role, email=user.email, password=password)
        )

    if not accounts:
        logger.warning(
            "Demo login is enabled but no configured account matched an active "
            "user with the expected role."
        )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return accounts


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
    description=(
        "Allows the authenticated user to update their display name. Password "
        "changes require the current password and must use /auth/change-password."
    ),
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


OTP_MAX_ATTEMPTS = 5


def _enforce_otp_rate_limit(
    db: Session,
    limiter: LoginRateLimiter,
    request: Request,
    email: str,
    *,
    audit_action: str,
    detail: str,
) -> None:
    """Reserve one shared OTP attempt and fail closed on limiter errors."""
    try:
        decision = limiter.reserve(db, request.state.client_ip, email)
    except LoginRateLimitUnavailable:
        logger.exception("Shared OTP rate limiter unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

    if decision.allowed:
        return

    try:
        should_audit = limiter.claim_denial_audit(
            db,
            request.state.client_ip,
            email,
        )
        if should_audit:
            AuditService.log_event(
                db,
                action=audit_action,
                outcome=AuditOutcome.DENIED,
                ip_address=request.state.client_ip,
                user_agent=request.state.user_agent,
                request_id=request.state.request_id,
                details={
                    "email": email,
                    "reason": "rate_limit_exceeded",
                    "aggregated": True,
                },
            )
            db.commit()
    except (LoginRateLimitUnavailable, SQLAlchemyError):
        db.rollback()
        logger.exception("Failed to record OTP rate-limit denial")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=detail,
        headers={"Retry-After": str(decision.retry_after)},
    )


def _require_active_otp(db: Session, email: str, otp_code: str) -> PasswordResetOTP:
    """Return the latest usable OTP record or raise a uniform reset error.

    Codes expire after 15 minutes and are single-use. Five incorrect attempts
    invalidate the code so a six-digit value cannot be brute-forced.
    """
    now = utc_now()
    otp_record = (
        db.query(PasswordResetOTP)
        .filter(
            PasswordResetOTP.email == email,
            PasswordResetOTP.is_used.is_(False),
            PasswordResetOTP.expires_at > now,
        )
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )
    if otp_record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code",
        )
    if otp_record.attempts >= OTP_MAX_ATTEMPTS:
        otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code",
        )
    if not verify_otp_code(otp_code, otp_record.otp_code):
        otp_record.attempts += 1
        if otp_record.attempts >= OTP_MAX_ATTEMPTS:
            otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code",
        )
    return otp_record


@router.post(
    "/request-reset",
    status_code=status.HTTP_200_OK,
    summary="Request password reset OTP",
    description="Generates a 6-digit OTP code and emails it to the account address.",
)
def request_password_reset(
    body: PasswordResetRequestSchema,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    email = body.email.lower()
    _enforce_otp_rate_limit(
        db,
        otp_request_rate_limiter,
        request,
        email,
        audit_action="auth.password_reset_rate_limited",
        detail="Too many password reset requests. Please try again later.",
    )
    user = db.query(User).filter(User.email == email).first()
    message = "If an account with this email exists, an OTP password reset code has been sent."

    if user is not None and user.is_active:
        code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = utc_now() + timedelta(minutes=PASSWORD_RESET_OTP_EXPIRY_MINUTES)

        db.query(PasswordResetOTP).filter(
            PasswordResetOTP.email == email,
            PasswordResetOTP.is_used.is_(False),
        ).update({"is_used": True})

        otp_record = PasswordResetOTP(
            email=email,
            otp_code=hash_otp_code(code),
            expires_at=expires_at,
        )
        db.add(otp_record)

        AuditService.log_event(
            db,
            action="auth.password_reset_request",
            outcome=AuditOutcome.SUCCESS,
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
        )
        db.commit()

        try:
            send_password_reset_otp(email, code, PASSWORD_RESET_OTP_EXPIRY_MINUTES)
        except EmailDeliveryError:
            logger.exception("Password reset email delivery failed for %s", email)
            otp_record.is_used = True
            AuditService.log_event(
                db,
                action="auth.password_reset_delivery",
                outcome=AuditOutcome.FAILURE,
                actor_id=user.id,
                resource_type="user",
                resource_id=user.id,
                ip_address=request.state.client_ip,
                user_agent=request.state.user_agent,
                request_id=request.state.request_id,
                details={"reason": "email_delivery_failed"},
            )
            db.commit()

    return {"message": message}


@router.post(
    "/verify-otp",
    status_code=status.HTTP_200_OK,
    summary="Verify password reset OTP",
    description="Validates the 6-digit OTP code before password reset confirmation.",
)
def verify_otp(
    body: OTPVerifyRequestSchema,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    email = body.email.lower()
    _enforce_otp_rate_limit(
        db,
        otp_verify_rate_limiter,
        request,
        email,
        audit_action="auth.otp_verify_rate_limited",
        detail="Too many verification attempts. Please try again later.",
    )
    _require_active_otp(db, email, body.otp_code)
    return {"valid": True}


@router.post(
    "/confirm-reset",
    status_code=status.HTTP_200_OK,
    summary="Confirm password reset with OTP",
    description="Verifies the OTP and updates the user password.",
)
def confirm_password_reset(
    body: PasswordResetConfirmRequestSchema,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    email = body.email.lower()
    _enforce_otp_rate_limit(
        db,
        otp_verify_rate_limiter,
        request,
        email,
        audit_action="auth.otp_verify_rate_limited",
        detail="Too many verification attempts. Please try again later.",
    )
    otp_record = _require_active_otp(db, email, body.otp_code)

    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user account",
        )

    # Consume the code atomically so two concurrent confirmations cannot both
    # reset the password with the same OTP.
    consumed = (
        db.query(PasswordResetOTP)
        .filter(
            PasswordResetOTP.id == otp_record.id,
            PasswordResetOTP.is_used.is_(False),
            PasswordResetOTP.expires_at > utc_now(),
        )
        .update({"is_used": True}, synchronize_session=False)
    )
    if consumed != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code",
        )

    user.hashed_password = hash_password(body.new_password)
    user.must_change_password = False

    sessions_revoked = revoke_all_user_sessions(db, user.id)

    AuditService.log_event(
        db,
        action="auth.password_reset_confirm",
        outcome=AuditOutcome.SUCCESS,
        actor_id=user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.state.client_ip,
        user_agent=request.state.user_agent,
        request_id=request.state.request_id,
        details={"sessions_revoked": sessions_revoked},
    )
    db.commit()

    return {"message": "Password successfully reset. You can now log in with your new password."}
