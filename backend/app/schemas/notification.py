"""Pydantic schemas for the notification inbox."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NotificationResponse(BaseModel):
    """A single notification addressed to the signed-in user."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    message: str
    link: str | None
    is_read: bool
    created_at: datetime


class NotificationListResponse(BaseModel):
    """Recent notifications plus the total unread count for the user."""

    notifications: list[NotificationResponse]
    unread_count: int
