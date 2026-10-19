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
from backend.app.schemas.auth import AdminUserUpdateRequest, UserListResponse, UserResponse
from backend.app.security.auth import get_current_user, require_admin
from backend.app.security.sessions import revoke_all_user_sessions
from backend.app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/users", tags=["Admin – User Management"])


def _get_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


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
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

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
    ip = _get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

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
