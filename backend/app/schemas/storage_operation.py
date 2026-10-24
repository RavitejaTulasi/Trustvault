"""Safe administrator-facing storage recovery schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class StorageOperationReviewItem(BaseModel):
    id: str
    operation_type: str
    status: str
    retry_count: int
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class StorageOperationReviewList(BaseModel):
    operations: list[StorageOperationReviewItem]
    total: int


class StorageOperationResolutionRequest(BaseModel):
    action: Literal["retry_delete"]
    reason: Literal[
        "document_marked_deleted",
        "provider_issue_resolved",
        "operator_verified_cleanup",
    ]


class StorageOperationResolutionResponse(BaseModel):
    id: str
    status: str
