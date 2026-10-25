from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PermissionRequestCreate(BaseModel):
    """Payload for creating a new permission request.

    * ``document_id`` – ID of the target document.
    * ``requested_role`` – Role the requester is asking for (e.g., "download_activity").
    """

    document_id: str = Field(..., description="Target document ID")
    requested_role: str = Field("download_activity", description="Role being requested")


class PermissionRequestUpdate(BaseModel):
    """Payload used by admins to change the status of a request.

    Only ``status`` is mutable – it must be one of the values defined in the
    ``PermissionRequestStatus`` enum.
    """

    status: str = Field(..., description="New status: pending, approved, rejected, or canceled")


class PermissionRequestOut(BaseModel):
    """Full representation of a permission request for API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    requester_id: str
    document_id: str
    requested_role: str
    status: str
    created_at: datetime
    updated_at: datetime
    requester_email: str | None = None
    document_title: str | None = None
