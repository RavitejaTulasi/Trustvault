"""Administrator visibility and safe retry controls for storage recovery."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.api.audit import _record_admin_audit_read
from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.user import User
from backend.app.schemas.storage_operation import (
    StorageOperationResolutionRequest,
    StorageOperationResolutionResponse,
    StorageOperationReviewItem,
    StorageOperationReviewList,
)
from backend.app.security.auth import require_admin
from backend.app.services.audit_service import AuditService
from backend.app.services.storage_recovery import (
    NEEDS_REVIEW,
    RETRY_WAIT,
    _now,
)
from backend.app.services.storage_service import is_valid_storage_key

router = APIRouter(
    prefix="/admin/storage-operations",
    tags=["Admin – Storage Recovery"],
)


def _record_retry_rejection(
    db: Session,
    *,
    operation_id: str,
    current_user: User,
    request: Request,
    previous_state: str | None,
    reason: str,
) -> None:
    try:
        AuditService.log_event(
            db,
            action="storage_operation.resolve",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="storage_operation",
            resource_id=operation_id,
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
            details={
                "action": "retry_delete",
                "previous_state": previous_state,
                "reason": reason,
            },
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit trail unavailable",
        ) from None


@router.get(
    "/review",
    response_model=StorageOperationReviewList,
    summary="List storage operations requiring review",
)
def list_storage_operations_for_review(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    _current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> StorageOperationReviewList:
    total = db.scalar(
        select(func.count()).select_from(StorageOperation).where(
            StorageOperation.status == NEEDS_REVIEW
        )
    )
    if total is None:
        raise RuntimeError("Unable to count storage operations awaiting review")

    operations = list(
        db.scalars(
            select(StorageOperation)
            .where(StorageOperation.status == NEEDS_REVIEW)
            .order_by(StorageOperation.created_at, StorageOperation.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    result = StorageOperationReviewList(
        operations=[
            StorageOperationReviewItem.model_validate(operation)
            for operation in operations
        ],
        total=total,
    )
    _record_admin_audit_read(
        db,
        action="storage_operations.review_read",
        actor_id=_current_user.id,
        request=request,
    )
    return result


@router.post(
    "/{operation_id}/resolve",
    response_model=StorageOperationResolutionResponse,
    summary="Queue a reviewed remote deletion for safe retry",
)
def resolve_storage_operation(
    operation_id: str,
    body: StorageOperationResolutionRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> StorageOperationResolutionResponse:
    """Requeue a reviewed delete; uncertain uploads stay blocked for review.

    Supabase does not provide a verified bound on an in-flight upload's lifetime,
    so this API never removes an ambiguous upload or its staged bytes.
    """
    if settings.STORAGE_BACKEND != "supabase":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote storage recovery is not active",
        )

    operation = db.scalar(
        select(StorageOperation)
        .where(StorageOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None:
        _record_retry_rejection(
            db,
            operation_id=operation_id,
            current_user=current_user,
            request=request,
            previous_state=None,
            reason="operation_not_found",
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operation not found",
        )
    if operation.status != NEEDS_REVIEW:
        _record_retry_rejection(
            db,
            operation_id=operation_id,
            current_user=current_user,
            request=request,
            previous_state=operation.status,
            reason="operation_not_awaiting_review",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Operation is not awaiting review",
        )
    if operation.operation_type != "delete":
        _record_retry_rejection(
            db,
            operation_id=operation_id,
            current_user=current_user,
            request=request,
            previous_state=operation.status,
            reason="ambiguous_upload_not_resolvable",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Ambiguous uploads require external provider-lifetime "
                "verification and cannot be resolved automatically"
            ),
        )
    if not is_valid_storage_key(operation.storage_key):
        _record_retry_rejection(
            db,
            operation_id=operation_id,
            current_user=current_user,
            request=request,
            previous_state=operation.status,
            reason="invalid_storage_key",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Operation has an invalid storage key",
        )

    prior_state = operation.status
    now = _now()
    result = db.execute(
        update(StorageOperation)
        .where(
            StorageOperation.id == operation_id,
            StorageOperation.operation_type == "delete",
            StorageOperation.status == prior_state,
            or_(
                StorageOperation.claim_token.is_(None),
                StorageOperation.lease_until <= now,
            ),
            or_(
                StorageOperation.lease_until.is_(None),
                StorageOperation.lease_until <= now,
            ),
        )
        .execution_options(synchronize_session=False)
        .values(
            status=RETRY_WAIT,
            next_attempt_at=now,
            claim_token=None,
            lease_until=None,
            lease_token=None,
            last_error=None,
            updated_at=now,
        )
    )
    if result.rowcount != 1:
        _record_retry_rejection(
            db,
            operation_id=operation_id,
            current_user=current_user,
            request=request,
            previous_state=prior_state,
            reason="operation_changed_or_claimed",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Operation changed or is currently claimed",
        )
    try:
        AuditService.log_event(
            db,
            action="storage_operation.resolve",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="storage_operation",
            resource_id=operation_id,
            ip_address=request.state.client_ip,
            user_agent=request.state.user_agent,
            request_id=request.state.request_id,
            details={
                "action": body.action,
                "previous_state": prior_state,
                "reason": body.reason,
            },
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit trail unavailable",
        ) from None

    return StorageOperationResolutionResponse(
        id=operation_id,
        status=RETRY_WAIT,
    )
