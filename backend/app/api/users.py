"""
Admin User Management API Endpoints
Only accessible to users with the 'admin' role.

Provides:
- List all users (paginated)
- Get a specific user's profile
- Update a user's role or activation status
- Force-revoke all sessions for a user
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.user import User, UserRole
from backend.app.schemas.auth import (
    AdminPasswordResetRequest,
    AdminPasswordResetResponse,
    AdminUserCreateRequest,
    AdminUserUpdateRequest,
    UserListResponse,
    UserResponse,
)
from backend.app.security.auth import require_admin
from backend.app.security.passwords import hash_password
from backend.app.security.sessions import revoke_all_user_sessions
from backend.app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/users", tags=["Admin – User Management"])


@router.get(
    "",
    response_model=UserListResponse,
    summary="List all users",
    description="Admin only. Returns a paginated list of all registered users.",
)
def list_users(
    request: Request,
    page: int = 1,
    page_size: int = 25,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserListResponse:
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="page must be >= 1; page_size must be 1–100",
        )

    total = db.query(User).count()
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/role-counts",
    summary="Get user counts by role",
    description="Admin only. Returns the count of users assigned to each supported role.",
)
def get_user_role_counts(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    from sqlalchemy import func
    results = db.query(User.role, func.count(User.id)).group_by(User.role).all()
    counts = {"admin": 0, "owner": 0, "viewer": 0}
    for role, count in results:
        if role in counts:
            counts[role] = count
    return counts


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user account",
    description=(
        "Admin only. Creates an account with an explicit role and initial password. "
        "The password is hashed with Argon2id and is never returned or logged. "
        "The user must replace the administrator-issued password before accessing "
        "workspace data. Account creation is recorded in the audit trail."
    ),
)
def create_user(
    body: AdminUserCreateRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id
    email = body.email.lower()

    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        AuditService.log_event(
            db,
            action="user.create",
            outcome=AuditOutcome.FAILURE,
            actor_id=current_user.id,
            resource_type="user",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"email": email, "reason": "email_conflict"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
        is_active=body.is_active,
        must_change_password=True,
    )
    db.add(user)
    db.flush()

    AuditService.log_event(
        db,
        action="user.create",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={"email": user.email, "role": user.role},
    )
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get a user's profile",
    description="Admin only. Returns full profile for any user by ID.",
)
def get_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserResponse:
    user: User | None = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update a user's role or activation status",
    description=(
        "Admin only. Allows changing a user's role or activating/deactivating their account. "
        "All changes are audit-logged. "
        "Admins cannot remove their own admin role via this endpoint."
    ),
)
def update_user(
    user_id: str,
    body: AdminUserUpdateRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    user: User | None = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent admin self-demotion (would lock out the admin)
    if user_id == current_user.id and body.role is not None and body.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot remove their own admin role",
        )

    changed_fields = []

    if body.role is not None and body.role != user.role:
        old_role = user.role
        user.role = body.role
        changed_fields.append("role")
        AuditService.log_event(
            db,
            action="user.role_change",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"from_role": old_role, "to_role": body.role},
        )

    if body.is_active is not None and body.is_active != user.is_active:
        user.is_active = body.is_active
        changed_fields.append("is_active")
        action = "user.reactivate" if body.is_active else "user.deactivate"
        AuditService.log_event(
            db,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        # When deactivating, revoke all active sessions immediately
        if not body.is_active:
            revoke_all_user_sessions(db, user.id)

    if not changed_fields:
        return UserResponse.model_validate(user)

    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@router.post(
    "/{user_id}/reset-password",
    response_model=AdminPasswordResetResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset another user's password",
    description=(
        "Admin only. Replaces the target account's password using Argon2id and revokes "
        "all of that user's active sessions. The target must replace the temporary "
        "password after signing in. The password is never returned or logged. "
        "Administrators must use their own account settings to change their password."
    ),
)
def reset_user_password(
    user_id: str,
    body: AdminPasswordResetRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminPasswordResetResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    if user_id == current_user.id:
        AuditService.log_event(
            db,
            action="user.password_reset",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=user_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "self_reset_not_allowed"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use account settings to change your own password",
        )

    user: User | None = db.get(User, user_id)
    if user is None:
        AuditService.log_event(
            db,
            action="user.password_reset",
            outcome=AuditOutcome.FAILURE,
            actor_id=current_user.id,
            resource_type="user",
            resource_id=user_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "target_not_found"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = hash_password(body.password)
    user.must_change_password = True
    sessions_revoked = revoke_all_user_sessions(db, user_id)

    AuditService.log_event(
        db,
        action="user.password_reset",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={"sessions_revoked": sessions_revoked},
    )
    db.commit()

    return AdminPasswordResetResponse(
        user_id=user.id,
        sessions_revoked=sessions_revoked,
    )


@router.post(
    "/{user_id}/revoke-sessions",
    status_code=status.HTTP_200_OK,
    summary="Force-revoke all sessions for a user",
    description="Admin only. Immediately invalidates all active sessions for the target user.",
)
def revoke_user_sessions(
    user_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    user: User | None = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    count = revoke_all_user_sessions(db, user_id)

    AuditService.log_event(
        db,
        action="user.sessions_revoked",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={"sessions_revoked": count},
    )
    db.commit()

    return {"user_id": user_id, "sessions_revoked": count}
