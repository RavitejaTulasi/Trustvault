"""
Pydantic Schemas for Document Grants and Permission Sharing
"""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from backend.app.models.grant import PermissionLevel


class GrantCreateRequest(BaseModel):
    """Request body for creating or updating a document permission grant."""

    user_id: str = Field(description="ID of the recipient user")
    permission: str = Field(description="Permission level: 'read' or 'edit'")

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        norm = v.strip().lower()
        if norm not in PermissionLevel.ALL_PERMISSIONS:
            raise ValueError(f"Permission must be one of: {sorted(PermissionLevel.ALL_PERMISSIONS)}")
        return norm


class GrantResponse(BaseModel):
    """Safe grant representation for API responses."""

    id: str
    document_id: str
    user_id: str
    permission: str
    granted_by_id: str | None
    is_revoked: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class GrantListResponse(BaseModel):
    """List of permission grants for a document."""

    grants: list[GrantResponse]
