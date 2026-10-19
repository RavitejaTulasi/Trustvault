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
        "changed_fields",
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
