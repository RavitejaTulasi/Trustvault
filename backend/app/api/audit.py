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

import csv
import io
import json
import logging
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Query as SQLAlchemyQuery
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.user import User
from backend.app.schemas.audit import (
    AuditEventListResponse,
    AuditEventResponse,
    AuditVerificationResponse,
    CheckpointCreateResponse,
    CheckpointInfoResponse,
    CheckpointVerificationResponse,
)
from backend.app.security.auth import require_admin
from backend.app.security.rate_limiter import (
    audit_checkpoint_rate_limiter,
    audit_verification_rate_limiter,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.checkpoint_runtime import acquire_checkpoint_writer_lock
from backend.app.services.checkpoint_service import (
    CheckpointCreationError,
    CheckpointService,
)
from backend.app.services.checkpoint_store import (
    CheckpointIntegrityError,
    CheckpointStore,
    CheckpointStoreUnavailableError,
)
from backend.app.services.checkpoint_store_factory import create_checkpoint_store

router = APIRouter(prefix="/admin", tags=["Admin – Audit Trail"])
logger = logging.getLogger(__name__)

AuditOutcomeFilter = Literal["SUCCESS", "DENIED", "FAILURE"]
_HASH_PATTERN = re.compile(r"\b[0-9a-f]{64}\b")
_CHECKPOINT_FAILURE_DETAILS = {
    "chain_invalid": "Checkpoint creation refused: audit chain verification failed",
    "chain_incomplete": (
        "Checkpoint creation refused: audit chain verification was incomplete"
    ),
    "anchor_unavailable": "Checkpoint anchoring is not configured or unavailable",
    "anchor_integrity_failure": (
        "Checkpoint creation refused: stored checkpoint failed its integrity check"
    ),
    "anchor_format_unsupported": (
        "Checkpoint creation refused: stored checkpoint format is not supported"
    ),
    "anchor_stream_mismatch": (
        "Checkpoint creation refused: stored checkpoint belongs to a different audit stream"
    ),
    "anchor_ahead_of_chain": (
        "Checkpoint creation refused: stored checkpoint is ahead of the audit chain"
    ),
    "anchor_chain_mismatch": (
        "Checkpoint creation refused: stored checkpoint conflicts with the audit chain"
    ),
    "anchor_rollback_detected": (
        "Checkpoint creation refused: checkpoint sequence would move backwards"
    ),
    "anchor_conflict": (
        "Checkpoint creation refused: a conflicting checkpoint already exists"
    ),
}


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


def get_checkpoint_store() -> CheckpointStore:
    """
    Instantiate the configured checkpoint adapter.

    Disabled or invalid configuration resolves to a fail-closed store so that
    administrative operations surface unavailability instead of claiming that an
    anchor exists.
    """
    return create_checkpoint_store(settings)


def _enforce_checkpoint_rate_limit(actor_id: str) -> None:
    """Bound expensive checkpoint operations per administrator."""
    allowed, retry_after = audit_checkpoint_rate_limiter.allow(actor_id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Checkpoint operation rate limit exceeded; retry later",
            headers={
                "Retry-After": str(retry_after),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )


def _record_checkpoint_failure(
    db: Session,
    *,
    actor_id: str,
    request: Request,
    reason: str,
) -> None:
    """Best-effort audit record for a refused checkpoint creation."""
    try:
        AuditService.log_event(
            db,
            action="audit.checkpoint_created",
            outcome=AuditOutcome.FAILURE,
            actor_id=actor_id,
            resource_type="audit",
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
            details={"reason": reason},
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.warning("Failed to persist audit checkpoint failure event")


def _record_admin_audit_read(
    db: Session,
    *,
    action: str,
    actor_id: str,
    request: Request,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Append the administrator-read audit event and fail closed on persistence errors.

    The response data is computed by the caller before this call, but the caller
    only returns it if the audit event commits. An administrative read that cannot
    be durably recorded is refused with 503 instead of being served unaudited.
    """
    try:
        AuditService.log_event(
            db,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            actor_id=actor_id,
            resource_type="audit",
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
            details=details,
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Audit trail unavailable",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        ) from None


def _paginate(
    query: SQLAlchemyQuery[AuditEvent],
    page: int,
    page_size: int,
    db: Session | None = None,
) -> AuditEventListResponse:
    """Apply deterministic ordering and pagination to an audit-event query."""
    total = query.count()
    events = (
        query.order_by(AuditEvent.sequence_number.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    actor_emails = {}
    if db is not None:
        actor_ids = {e.actor_id for e in events if e.actor_id}
        if actor_ids:
            users = db.query(User.id, User.email).filter(User.id.in_(actor_ids)).all()
            actor_emails = {uid: email for uid, email in users}

    event_responses = []
    for event in events:
        resp = AuditEventResponse.model_validate(event)
        if event.actor_id and actor_emails:
            resp.actor_email = actor_emails.get(event.actor_id)
        event_responses.append(resp)

    return AuditEventListResponse(
        events=event_responses,
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
    request: Request,
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

    result = _paginate(query, page, page_size, db=db)
    _record_admin_audit_read(
        db, action="audit.read", actor_id=current_user.id, request=request
    )
    return result


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
    request: Request,
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
    _record_admin_audit_read(
        db,
        action="audit.verify",
        actor_id=current_user.id,
        request=request,
        details={"verification_status": result.status},
    )
    return AuditVerificationResponse(
        status=result.status,
        is_valid=result.status == "VALID",
        records_verified=result.records_verified,
        failure_reason=_sanitize_failure_reason(result.failure_reason),
    )


@router.post(
    "/audit/checkpoints",
    response_model=CheckpointCreateResponse,
    summary="Create an audit-chain checkpoint",
    description=(
        "Admin only. Verifies the committed audit chain and stores a checkpoint "
        "binding the highest verified sequence number and its record hash. "
        "Checkpoint creation is refused when the chain cannot be verified, when "
        "the anchor is unavailable, or when the stored checkpoint conflicts with "
        "or is ahead of the live chain. Raw hashes and keys are never returned."
    ),
)
def create_audit_checkpoint(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    store: Annotated[CheckpointStore, Depends(get_checkpoint_store)],
) -> CheckpointCreateResponse:
    _disable_caching(response)
    _enforce_checkpoint_rate_limit(current_user.id)
    acquire_checkpoint_writer_lock(db)

    try:
        result = CheckpointService.create_checkpoint(
            db,
            store,
            max_records=settings.AUDIT_VERIFY_MAX_RECORDS,
            batch_size=settings.AUDIT_VERIFY_BATCH_SIZE,
            timeout_seconds=settings.AUDIT_VERIFY_TIMEOUT_SECONDS,
        )
    except CheckpointCreationError as exc:
        _record_checkpoint_failure(
            db, actor_id=current_user.id, request=request, reason=exc.reason
        )
        status_code = (
            503
            if exc.reason == "anchor_unavailable"
            else 409
        )
        raise HTTPException(
            status_code=status_code,
            detail=_CHECKPOINT_FAILURE_DETAILS.get(
                exc.reason, "Checkpoint creation refused"
            ),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        ) from None

    response.status_code = 200 if result.already_present else 201
    _record_admin_audit_read(
        db,
        action="audit.checkpoint_created",
        actor_id=current_user.id,
        request=request,
        details={
            "checkpoint_sequence": result.checkpoint.sequence_number,
            "already_present": result.already_present,
        },
    )
    return CheckpointCreateResponse(
        status="ALREADY_PRESENT" if result.already_present else "CREATED",
        anchor_mode=settings.AUDIT_ANCHOR_MODE,
        stream_id=result.checkpoint.stream_id,
        sequence_number=result.checkpoint.sequence_number,
        created_at=result.checkpoint.created_at,
    )


@router.get(
    "/audit/checkpoints",
    response_model=CheckpointInfoResponse,
    summary="Inspect the latest audit checkpoint",
    description=(
        "Admin only. Returns non-sensitive metadata for the most recently stored "
        "checkpoint. Raw record hashes, HMAC tags, signing keys, and storage paths "
        "are never returned."
    ),
)
def get_audit_checkpoint(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    store: Annotated[CheckpointStore, Depends(get_checkpoint_store)],
) -> CheckpointInfoResponse:
    _disable_caching(response)
    configured = settings.AUDIT_ANCHOR_MODE != "disabled"
    checkpoint = None
    if configured:
        try:
            checkpoint = store.read_latest()
        except CheckpointStoreUnavailableError:
            raise HTTPException(
                status_code=503,
                detail="Checkpoint store unavailable",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            ) from None
        except CheckpointIntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Checkpoint store integrity check failed",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            ) from None

    _record_admin_audit_read(
        db, action="audit.checkpoint_read", actor_id=current_user.id, request=request
    )
    return CheckpointInfoResponse(
        anchor_mode=settings.AUDIT_ANCHOR_MODE,
        available=checkpoint is not None,
        stream_id=checkpoint.stream_id if checkpoint is not None else None,
        sequence_number=(
            checkpoint.sequence_number if checkpoint is not None else None
        ),
        created_at=checkpoint.created_at if checkpoint is not None else None,
        format_version=(
            checkpoint.format_version if checkpoint is not None else None
        ),
    )


@router.get(
    "/audit/checkpoints/verify",
    response_model=CheckpointVerificationResponse,
    summary="Verify the audit chain against its checkpoint",
    description=(
        "Admin only. Performs a bounded verification of the live audit chain and "
        "compares the checkpointed sequence and hash with the stored "
        "checkpoint. An unavailable checkpoint store produces UNAVAILABLE; "
        "a missing checkpoint, a genesis-only checkpoint, or a bounded verification "
        "limit produces INCOMPLETE; neither is reported as VALID. Raw hashes are "
        "never returned."
    ),
)
def verify_audit_checkpoint(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    store: Annotated[CheckpointStore, Depends(get_checkpoint_store)],
) -> CheckpointVerificationResponse:
    _disable_caching(response)
    _enforce_checkpoint_rate_limit(current_user.id)

    result = CheckpointService.verify_checkpoint(
        db,
        store,
        max_records=settings.AUDIT_VERIFY_MAX_RECORDS,
        batch_size=settings.AUDIT_VERIFY_BATCH_SIZE,
        timeout_seconds=settings.AUDIT_VERIFY_TIMEOUT_SECONDS,
    )
    _record_admin_audit_read(
        db,
        action="audit.checkpoint_verify",
        actor_id=current_user.id,
        request=request,
        details={"verification_status": result.status},
    )
    return CheckpointVerificationResponse(
        status=result.status,
        is_valid=result.status == "VALID",
        records_verified=result.records_verified,
        checkpoint_sequence=result.checkpoint_sequence,
        chain_head_sequence=result.chain_head_sequence,
        failure_reason=_sanitize_failure_reason(result.failure_reason),
        anchor_mode=settings.AUDIT_ANCHOR_MODE,
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
    request: Request,
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

    result = _paginate(query, page, page_size, db=db)
    _record_admin_audit_read(
        db, action="audit.activity_read", actor_id=current_user.id, request=request
    )
    return result


@router.get(
    "/documents/activity/export",
    summary="Export document activity",
    description="Admin only. Exports matching document and document-grant audit activity as CSV.",
)
def export_document_activity(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    document_id: Annotated[str | None, Query(max_length=100)] = None,
    actor_id: Annotated[str | None, Query(max_length=36)] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    outcome: AuditOutcomeFilter | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
) -> StreamingResponse:
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

    events = query.order_by(AuditEvent.sequence_number.desc()).all()
    actor_ids = {e.actor_id for e in events if e.actor_id}
    email_map = {}
    if actor_ids:
        users = db.query(User.id, User.email).filter(User.id.in_(actor_ids)).all()
        email_map = {uid: email for uid, email in users}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Sequence",
        "Timestamp",
        "Action",
        "Outcome",
        "Actor Email",
        "Resource Type",
        "Resource ID",
        "IP Address",
    ])
    for e in events:
        actor_email = email_map.get(e.actor_id, e.actor_id or "System")

        def sanitize_csv(val: Any) -> str:
            s = str(val or "")
            if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
                return "'" + s
            return s

        writer.writerow([
            e.sequence_number,
            e.timestamp.isoformat(),
            sanitize_csv(e.action),
            sanitize_csv(e.outcome),
            sanitize_csv(actor_email),
            sanitize_csv(e.resource_type),
            sanitize_csv(e.resource_id),
            sanitize_csv(e.ip_address),
        ])

    _record_admin_audit_read(
        db, action="audit.activity_export", actor_id=current_user.id, request=request
    )

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trustvault-activity-export.csv"},
    )
