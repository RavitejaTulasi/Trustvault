"""
Administrative Audit Trail and Document Activity API Endpoints

Provides read-only, administrator-only access to the tamper-evident audit log,
hash-chain verification, and document-focused activity history.

Security controls:
- Every endpoint requires the authenticated administrator role.
- Responses expose an allowlisted event shape without hash-chain internals.
- Filters use bound SQLAlchemy expressions and literal LIKE escaping.
- Document activity is authorization independent and never returns document bytes.
"""

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_
from sqlalchemy.orm import Query as SQLAlchemyQuery
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditEvent
from backend.app.models.user import User
from backend.app.schemas.audit import (
    AuditEventListResponse,
    AuditEventResponse,
    AuditVerificationResponse,
)
from backend.app.security.auth import require_admin
from backend.app.security.rate_limiter import audit_verification_rate_limiter
from backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/admin", tags=["Admin – Audit Trail"])

AuditOutcomeFilter = Literal["SUCCESS", "DENIED", "FAILURE"]
_HASH_PATTERN = re.compile(r"\b[0-9a-f]{64}\b")


def _clean_filter(value: str | None, name: str, max_length: int) -> str | None:
    """Trim optional string filters and reject blank or oversized values."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length:
        raise HTTPException(
            status_code=422,
            detail=f"{name} must contain between 1 and {max_length} characters",
        )
    return cleaned


def _to_utc(value: datetime) -> datetime:
    """Normalize query datetimes so naive and timezone-aware values compare safely."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalize_range(
    timestamp_from: datetime | None, timestamp_to: datetime | None
) -> tuple[datetime | None, datetime | None]:
    """Normalize and validate an inclusive audit timestamp range."""
    normalized_from = _to_utc(timestamp_from) if timestamp_from is not None else None
    normalized_to = _to_utc(timestamp_to) if timestamp_to is not None else None
    if (
        normalized_from is not None
        and normalized_to is not None
        and normalized_from > normalized_to
    ):
        raise HTTPException(
            status_code=422,
            detail="timestamp_from must be earlier than or equal to timestamp_to",
        )
    return normalized_from, normalized_to


def _escape_like(value: str) -> str:
    """Escape SQL LIKE metacharacters so user input is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _sanitize_failure_reason(reason: str | None) -> str | None:
    """Redact full record hashes from verification diagnostics."""
    if reason is None:
        return None
    return _HASH_PATTERN.sub("[redacted]", reason)


def _disable_caching(response: Response) -> None:
    """Prevent caching of sensitive audit and activity responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _paginate(
    query: SQLAlchemyQuery[AuditEvent],
    page: int,
    page_size: int,
) -> AuditEventListResponse:
    """Apply deterministic ordering and pagination to an audit-event query."""
    total = query.count()
    events = (
        query.order_by(AuditEvent.sequence_number.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AuditEventListResponse(
        events=[AuditEventResponse.model_validate(event) for event in events],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/audit",
    response_model=AuditEventListResponse,
    summary="List audit events",
    description=(
        "Admin only. Returns a filtered, paginated view of the tamper-evident audit log "
        "ordered by descending sequence number. Hash-chain fields are never exposed."
    ),
)
def list_audit_events(
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    actor_id: Annotated[str | None, Query(max_length=36)] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    resource_type: Annotated[str | None, Query(max_length=50)] = None,
    resource_id: Annotated[str | None, Query(max_length=100)] = None,
    outcome: AuditOutcomeFilter | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
) -> AuditEventListResponse:
    _disable_caching(response)
    actor_id = _clean_filter(actor_id, "actor_id", 36)
    action = _clean_filter(action, "action", 100)
    resource_type = _clean_filter(resource_type, "resource_type", 50)
    resource_id = _clean_filter(resource_id, "resource_id", 100)
    timestamp_from, timestamp_to = _normalize_range(timestamp_from, timestamp_to)

    query = db.query(AuditEvent)
    if actor_id is not None:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if action is not None:
        query = query.filter(AuditEvent.action == action)
    if resource_type is not None:
        query = query.filter(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        query = query.filter(AuditEvent.resource_id == resource_id)
    if outcome is not None:
        query = query.filter(AuditEvent.outcome == outcome)
    if timestamp_from is not None:
        query = query.filter(AuditEvent.timestamp >= timestamp_from)
    if timestamp_to is not None:
        query = query.filter(AuditEvent.timestamp <= timestamp_to)

    return _paginate(query, page, page_size)


@router.get(
    "/audit/verify",
    response_model=AuditVerificationResponse,
    summary="Verify the audit hash chain",
    description=(
        "Admin only. Performs a bounded read-only validation of sequence continuity, "
        "previous-hash links, and recomputed record hashes. Returns VALID, INVALID, "
        "or INCOMPLETE; INCOMPLETE never reports full-chain success."
    ),
)
def verify_audit_chain(
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
) -> AuditVerificationResponse:
    _disable_caching(response)

    allowed, retry_after = audit_verification_rate_limiter.allow(current_user.id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Audit verification rate limit exceeded; retry later",
            headers={
                "Retry-After": str(retry_after),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    result = AuditService.verify_chain_integrity_bounded(
        db,
        max_records=settings.AUDIT_VERIFY_MAX_RECORDS,
        batch_size=settings.AUDIT_VERIFY_BATCH_SIZE,
        timeout_seconds=settings.AUDIT_VERIFY_TIMEOUT_SECONDS,
    )
    return AuditVerificationResponse(
        status=result.status,
        is_valid=result.status == "VALID",
        records_verified=result.records_verified,
        failure_reason=_sanitize_failure_reason(result.failure_reason),
    )


@router.get(
    "/documents/activity",
    response_model=AuditEventListResponse,
    summary="List document activity",
    description=(
        "Admin only. Returns document and document-grant audit activity ordered by "
        "descending sequence number. Document IDs are matched against document events "
        "and the recorded document_id of grant events."
    ),
)
def list_document_activity(
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    document_id: Annotated[str | None, Query(max_length=100)] = None,
    actor_id: Annotated[str | None, Query(max_length=36)] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    outcome: AuditOutcomeFilter | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
) -> AuditEventListResponse:
    _disable_caching(response)
    document_id = _clean_filter(document_id, "document_id", 100)
    actor_id = _clean_filter(actor_id, "actor_id", 36)
    action = _clean_filter(action, "action", 100)
    timestamp_from, timestamp_to = _normalize_range(timestamp_from, timestamp_to)

    query = db.query(AuditEvent).filter(
        AuditEvent.resource_type.in_(("document", "document_grant"))
    )
    if document_id is not None:
        details_fragment = f'"document_id": {json.dumps(document_id)}'
        details_pattern = f"%{_escape_like(details_fragment)}%"
        query = query.filter(
            or_(
                AuditEvent.resource_id == document_id,
                AuditEvent.details.like(details_pattern, escape="\\"),
            )
        )
    if actor_id is not None:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if action is not None:
        query = query.filter(AuditEvent.action == action)
    if outcome is not None:
        query = query.filter(AuditEvent.outcome == outcome)
    if timestamp_from is not None:
        query = query.filter(AuditEvent.timestamp >= timestamp_from)
    if timestamp_to is not None:
        query = query.filter(AuditEvent.timestamp <= timestamp_to)

    return _paginate(query, page, page_size)
