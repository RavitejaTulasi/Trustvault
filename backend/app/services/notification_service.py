"""Helpers for creating in-app notifications."""

from sqlalchemy.orm import Session

from backend.app.models.notification import Notification
from backend.app.models.user import User, UserRole


def notify_user(
    db: Session,
    user_id: str,
    *,
    title: str,
    message: str,
    link: str | None = None,
) -> Notification:
    """Queue a notification for a single user."""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        link=link,
    )
    db.add(notification)
    return notification


def notify_admins(
    db: Session,
    *,
    title: str,
    message: str,
    link: str | None = None,
    exclude_user_id: str | None = None,
) -> int:
    """Queue a notification for every active administrator.

    Returns the number of notifications created. Administrators can be excluded
    so a user does not receive a notification for their own action.
    """
    admin_ids = [
        row[0]
        for row in db.query(User.id)
        .filter(User.role == UserRole.ADMIN, User.is_active.is_(True))
        .all()
    ]
    created = 0
    for admin_id in admin_ids:
        if admin_id == exclude_user_id:
            continue
        notify_user(db, admin_id, title=title, message=message, link=link)
        created += 1
    return created
