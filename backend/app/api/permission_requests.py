"""FastAPI router for permission-request workflow.

Endpoints:
* POST /permission-requests – create a request (any authenticated user).
* GET  /permission-requests/status – get current user's request status for a document.
* GET  /permission-requests/pending – list pending requests (admin only).
* PATCH /permission-requests/{request_id} – approve/reject a request (admin only).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app import models, schemas
from backend.app.database import get_db
from backend.app.security.auth import get_current_user, require_admin
from backend.app.security.rate_limiter import (
    LoginRateLimitUnavailable,
    permission_request_rate_limiter,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.notification_service import notify_admins, notify_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/permission-requests", tags=["Permission Requests"])


def _enforce_create_rate_limit(
    db: Session,
    request: Request,
    current_user: models.user.User,
) -> None:
    """Reserve one permission-request creation or return a safe 429/503."""
    email = current_user.email
    try:
        decision = permission_request_rate_limiter.reserve(
            db,
            request.state.client_ip,
            email,
        )
    except LoginRateLimitUnavailable:
        logger.exception("Shared permission-request rate limiter unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

    if decision.allowed:
        return

    try:
        should_audit = permission_request_rate_limiter.claim_denial_audit(
            db,
            request.state.client_ip,
            email,
        )
        if should_audit:
            AuditService.log_event(
                db,
                action="permission_request.rate_limited",
                outcome=models.audit.AuditOutcome.DENIED,
                actor_id=current_user.id,
                resource_type="permission_request",
                ip_address=request.state.client_ip,
                user_agent=request.state.user_agent,
                request_id=request.state.request_id,
                details={
                    "reason": "rate_limit_exceeded",
                    "aggregated": True,
                },
            )
            db.commit()
    except (LoginRateLimitUnavailable, SQLAlchemyError):
        db.rollback()
        logger.exception("Failed to record permission-request rate-limit denial")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many permission requests. Please try again later.",
        headers={"Retry-After": str(decision.retry_after)},
    )


def _to_out_schema(
    pr: models.permission_request.PermissionRequest,
    db: Session,
    *,
    include_private_details: bool = False,
) -> schemas.permission_request.PermissionRequestOut:
    requester_email = None
    document_title = None
    if include_private_details:
        requester = db.get(models.user.User, pr.requester_id)
        doc = db.get(models.document.Document, pr.document_id)
        requester_email = requester.email if requester else None
        document_title = doc.title if doc else None

    return schemas.permission_request.PermissionRequestOut(
        id=pr.id,
        requester_id=pr.requester_id,
        document_id=pr.document_id,
        requested_role=pr.requested_role,
        status=pr.status.value if hasattr(pr.status, "value") else str(pr.status),
        created_at=pr.created_at,
        updated_at=pr.updated_at,
        requester_email=requester_email,
        document_title=document_title,
    )


@router.post("/", response_model=schemas.permission_request.PermissionRequestOut,
             status_code=status.HTTP_201_CREATED)
def create_permission_request(
    payload: schemas.permission_request.PermissionRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.user.User = Depends(get_current_user),
):
    """Create a new permission request.

    The requester becomes the ``requester_id``. ``status`` defaults to ``pending``.
    If an existing pending request exists for the same document and role, it is returned.
    """
    _enforce_create_rate_limit(db, request, current_user)

    document = db.get(models.document.Document, payload.document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Document not found")

    existing = (
        db.query(models.permission_request.PermissionRequest)
        .filter(
            models.permission_request.PermissionRequest.requester_id == current_user.id,
            models.permission_request.PermissionRequest.document_id == payload.document_id,
            models.permission_request.PermissionRequest.requested_role == payload.requested_role,
        )
        .order_by(models.permission_request.PermissionRequest.id.desc())
        .first()
    )
    if existing and existing.status in (
        models.permission_request.PermissionRequestStatus.PENDING,
        models.permission_request.PermissionRequestStatus.APPROVED,
    ):
        return _to_out_schema(existing, db)

    pr = models.permission_request.PermissionRequest(
        requester_id=current_user.id,
        document_id=payload.document_id,
        requested_role=payload.requested_role,
        status=models.permission_request.PermissionRequestStatus.PENDING,
    )
    db.add(pr)
    db.flush()

    notify_admins(
        db,
        title="New permission request",
        message=(
            f"{current_user.full_name} requested "
            f"{payload.requested_role.replace('_', ' ')} access to "
            f"'{document.title}'."
        ),
        link="/dashboard",
        exclude_user_id=current_user.id,
    )

    AuditService.log_event(
        db,
        action="permission_request.create",
        outcome=models.audit.AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="permission_request",
        resource_id=str(pr.id),
        details={"document_id": payload.document_id, "requested_role": payload.requested_role},
    )
    db.commit()
    db.refresh(pr)
    return _to_out_schema(pr, db)


@router.get("/status", response_model=schemas.permission_request.PermissionRequestOut | None)
def get_permission_request_status(
    document_id: str = Query(..., description="Target document ID"),
    db: Session = Depends(get_db),
    current_user: models.user.User = Depends(get_current_user),
):
    """Check the latest permission request status for the current user and document."""
    pr = (
        db.query(models.permission_request.PermissionRequest)
        .filter(
            models.permission_request.PermissionRequest.requester_id == current_user.id,
            models.permission_request.PermissionRequest.document_id == document_id,
        )
        .order_by(models.permission_request.PermissionRequest.id.desc())
        .first()
    )
    if pr is None:
        return None
    return _to_out_schema(pr, db)


@router.get("/pending", response_model=list[schemas.permission_request.PermissionRequestOut])
def list_pending_requests(
    document_id: str | None = Query(None, description="Optional document filter"),
    db: Session = Depends(get_db),
    admin: models.user.User = Depends(require_admin),
):
    """Return all pending permission requests (admin only)."""
    query = (
        db.query(models.permission_request.PermissionRequest)
        .filter(models.permission_request.PermissionRequest.status == models.permission_request.PermissionRequestStatus.PENDING)
    )
    if document_id:
        query = query.filter(models.permission_request.PermissionRequest.document_id == document_id)
    requests = query.order_by(models.permission_request.PermissionRequest.created_at.desc()).all()
    return [
        _to_out_schema(pr, db, include_private_details=True)
        for pr in requests
    ]


@router.patch("/{request_id}", response_model=schemas.permission_request.PermissionRequestOut)
def update_permission_request_status(
    request_id: int,
    payload: schemas.permission_request.PermissionRequestUpdate,
    db: Session = Depends(get_db),
    admin: models.user.User = Depends(require_admin),
):
    """Admin updates the status of a permission request.

    Accepted ``status`` values are ``approved``, ``rejected`` or ``canceled``.
    """
    pr = db.get(models.permission_request.PermissionRequest, request_id)
    if pr is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Permission request not found")
    try:
        new_status = models.permission_request.PermissionRequestStatus(payload.status.lower())
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid status value")
    if new_status == models.permission_request.PermissionRequestStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Requests can only be approved, rejected, or canceled")
    if pr.status != models.permission_request.PermissionRequestStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Only pending permission requests can be updated")
    pr.status = new_status
    db.add(pr)

    if pr.requester_id != admin.id:
        document = db.get(models.document.Document, pr.document_id)
        document_title = document.title if document is not None else "the document"
        notify_user(
            db,
            pr.requester_id,
            title=f"Permission request {new_status.value}",
            message=f"Your request for '{document_title}' was {new_status.value}.",
            link=f"/documents/{pr.document_id}",
        )

    AuditService.log_event(
        db,
        action="permission_request.update_status",
        outcome=models.audit.AuditOutcome.SUCCESS,
        actor_id=admin.id,
        resource_type="permission_request",
        resource_id=str(pr.id),
        details={"new_status": new_status.value, "document_id": pr.document_id, "requester_id": pr.requester_id},
    )
    db.commit()
    db.refresh(pr)
    return _to_out_schema(pr, db, include_private_details=True)
