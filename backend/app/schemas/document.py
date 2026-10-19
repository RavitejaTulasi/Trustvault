"""
Pydantic Schemas for Document Management and Storage
"""

from datetime import datetime

from pydantic import BaseModel, Field


class DocumentResponse(BaseModel):
    """Safe document representation for API responses."""

    id: str
    title: str
    original_filename: str
    file_size_bytes: int
    mime_type: str
    category: str
    owner_id: str
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DocumentUpdateRequest(BaseModel):
    """Request body for updating document metadata."""

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Updated document title",
    )
    category: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Updated document category",
    )


class DocumentListResponse(BaseModel):
    """Paginated document list response."""

    documents: list[DocumentResponse]
    total: int
    page: int
    page_size: int
