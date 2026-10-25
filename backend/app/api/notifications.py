"""Notification inbox endpoints.

Every endpoint is scoped to the authenticated user; notifications belonging to
another account are never returned or mutated.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.notification import Notification
from backend.app.models.user import User
from backend.app.schemas.notification import (
    NotificationListResponse,
    NotificationResponse,
)
from backend.app.security.auth import get_current_user
from backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get(
    "",
    response_model=NotificationListResponse,
    summary="List recent notifications",
    description=(
        "Returns the signed-in user's most recent notifications and the total "
        "number of unread notifications."
    ),
)
def list_notifications(
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationListResponse:
    base_query = db.query(Notification).filter(
        Notification.user_id == current_user.id
    )
    unread_count = base_query.filter(Notification.is_read.is_(False)).count()
    rows = (
        base_query.order_by(Notification.created_at.desc())
        .limit(limit)
        .all()
    )
    return NotificationListResponse(
        notifications=[
            NotificationResponse.model_validate(row) for row in rows
        ],
        unread_count=unread_count,
    )


@router.post(
    "/read-all",
    status_code=status.HTTP_200_OK,
    summary="Mark all notifications as read",
)
def mark_all_notifications_read(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, int]:
    updated = (
        db.query(Notification)
        .filter(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
        .update({"is_read": True}, synchronize_session=False)
    )
    if updated:
        AuditService.log_event(
            db,
            action="notification.read_all",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="notification",
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
            details={"updated": updated},
        )
    db.commit()
    return {"updated": updated}


@router.post(
    "/{notification_id}/read",
    response_model=NotificationResponse,
    summary="Mark one notification as read",
)
def mark_notification_read(
    notification_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationResponse:
    notification = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )
    if notification is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )
    if not notification.is_read:
        notification.is_read = True
        AuditService.log_event(
            db,
            action="notification.read",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="notification",
            resource_id=notification.id,
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
        )
        db.commit()
        db.refresh(notification)
    return NotificationResponse.model_validate(notification)
