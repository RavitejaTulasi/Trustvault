"""
Pydantic Schemas for Administrative Audit Trail Queries
"""

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, field_validator

REDACTED_VALUE = "[redacted]"
SAFE_DETAIL_KEYS = frozenset(
    {
        "already_present",
        "changed_fields",
        "checkpoint_sequence",
        "document_id",
        "email",
        "from_role",
        "permission",
        "reason",
        "recipient_id",
        "role",
        "sessions_revoked",
        "target_user_id",
        "to_role",
        "verification_status",
    }
)


def _sanitize_details(value: Any) -> Any:
    """Apply a default-deny allowlist to audit detail values."""
    if isinstance(value, dict):
        return {
            key: _sanitize_details(item)
            if str(key).lower() in SAFE_DETAIL_KEYS
            else REDACTED_VALUE
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_details(item) for item in value]
    return value


class AuditEventResponse(BaseModel):
    """Safe audit-event representation without internal hash-chain fields."""

    id: str
    sequence_number: int
    timestamp: datetime
    actor_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    request_id: str | None
    ip_address: str | None
    user_agent: str | None
    details: dict[str, Any] | None

    model_config = {"from_attributes": True}

    @field_validator("details", mode="before")
    @classmethod
    def parse_details(cls, value: Any) -> dict[str, Any] | None:
        """Convert the stored JSON text into an object without exposing malformed data."""
        if value is None:
            return None
        if isinstance(value, dict):
            return _sanitize_details(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                return None
            return _sanitize_details(parsed) if isinstance(parsed, dict) else None
        return None


class AuditEventListResponse(BaseModel):
    """Paginated audit-event query response."""

    events: list[AuditEventResponse]
    total: int
    page: int
    page_size: int


class AuditVerificationResponse(BaseModel):
    """Result of a bounded audit hash-chain verification pass."""

    status: Literal["VALID", "INVALID", "INCOMPLETE"]
    is_valid: bool
    records_verified: int
    failure_reason: str | None = None


class CheckpointCreateResponse(BaseModel):
    """Result of an audit checkpoint creation request."""

    status: Literal["CREATED", "ALREADY_PRESENT"]
    anchor_mode: str
    stream_id: str
    sequence_number: int
    created_at: datetime


class CheckpointInfoResponse(BaseModel):
    """Metadata for the most recently stored checkpoint without raw hashes."""

    anchor_mode: str
    available: bool
    stream_id: str | None = None
    sequence_number: int | None = None
    created_at: datetime | None = None
    format_version: int | None = None


class CheckpointVerificationResponse(BaseModel):
    """Result of comparing the live audit chain with a stored checkpoint."""

    status: Literal["VALID", "INVALID", "INCOMPLETE"]
    is_valid: bool
    records_verified: int
    checkpoint_sequence: int | None = None
    chain_head_sequence: int | None = None
    failure_reason: str | None = None
    anchor_mode: str
