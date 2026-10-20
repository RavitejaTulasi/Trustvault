"""
Document Management and Storage API Endpoints
Handles: upload, list, metadata retrieval, secure streaming download, metadata updates, deletion, and sharing grants.

Security controls implemented:
- Centralized authorization enforcement via AuthorizationService (default deny)
- Private persistent storage isolation outside web root (StorageService)
- Magic byte validation and extension whitelisting
- Deliberate 404 responses for unauthorized resource access to prevent metadata existence leakage
- Tamper-evident audit logging for all document actions and permission grants (success and denial)
- Immediate revocation enforcement on every request without caching
"""

import logging
from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import or_
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.base import utc_now
from backend.app.models.document import Document
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.app.models.user import User, UserRole
from backend.app.schemas.document import (
    DocumentListItem,
    DocumentListResponse,
    DocumentResponse,
    DocumentUpdateRequest,
)
from backend.app.schemas.grant import (
    GrantCreateRequest,
    GrantListResponse,
    GrantResponse,
)
from backend.app.security.auth import get_current_user
from backend.app.security.request_validation import (
    RequestMetadataValidationError,
    validate_mime_type,
    validate_original_filename,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.authorization import AuthorizationService, DocumentAction
from backend.app.services.storage_quota import (
    StorageQuotaExceeded,
    StorageQuotaService,
)
from backend.app.services.storage_service import StorageService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/documents", tags=["Documents & Storage"])


def _get_active_grant(db: Session, document_id: str, user_id: str) -> DocumentGrant | None:
    return (
        db.query(DocumentGrant)
        .filter(
            DocumentGrant.document_id == document_id,
            DocumentGrant.user_id == user_id,
            DocumentGrant.is_revoked.is_(False),
        )
        .first()
    )


def _escape_like(value: str) -> str:
    """Escape SQL LIKE metacharacters so user input is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _to_utc(value: datetime) -> datetime:
    """Normalize query datetimes so naive and timezone-aware values compare safely."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _get_effective_permissions(
    db: Session, user_id: str, document_ids: list[str]
) -> dict[str, str]:
    """Return active grant permissions for the caller across the given documents."""
    if not document_ids:
        return {}

    rows = (
        db.query(DocumentGrant.document_id, DocumentGrant.permission)
        .filter(
            DocumentGrant.user_id == user_id,
            DocumentGrant.document_id.in_(document_ids),
            DocumentGrant.is_revoked.is_(False),
        )
        .all()
    )
    return {document_id: permission for document_id, permission in rows}


def _upsert_grant(
    db: Session,
    document_id: str,
    user_id: str,
    permission: str,
    granted_by_id: str,
) -> DocumentGrant:
    """
    Atomically create or update a grant.

    SQLite and PostgreSQL both support ON CONFLICT DO UPDATE, which keeps the
    transaction valid when concurrent duplicate requests target the same
    (document_id, user_id) unique constraint. Other dialects fall back to a
    query-then-write flow and retain the database uniqueness constraint.
    """
    values = {
        "document_id": document_id,
        "user_id": user_id,
        "permission": permission,
        "granted_by_id": granted_by_id,
        "is_revoked": False,
    }

    dialect = db.get_bind().dialect.name
    insert_statement = None
    if dialect == "postgresql":
        insert_statement = postgresql_insert(DocumentGrant).values(**values)
    elif dialect == "sqlite":
        insert_statement = sqlite_insert(DocumentGrant).values(**values)

    if insert_statement is not None:
        db.execute(
            insert_statement.on_conflict_do_update(
                index_elements=[DocumentGrant.document_id, DocumentGrant.user_id],
                set_={
                    "permission": permission,
                    "granted_by_id": granted_by_id,
                    "is_revoked": False,
                    "updated_at": utc_now(),
                },
            )
        )
    else:
        grant = (
            db.query(DocumentGrant)
            .filter(
                DocumentGrant.document_id == document_id,
                DocumentGrant.user_id == user_id,
            )
            .first()
        )
        if grant is None:
            grant = DocumentGrant(
                document_id=document_id,
                user_id=user_id,
                permission=permission,
                granted_by_id=granted_by_id,
                is_revoked=False,
            )
            db.add(grant)
        else:
            grant.permission = permission
            grant.granted_by_id = granted_by_id
            grant.is_revoked = False
        db.flush()

    return (
        db.query(DocumentGrant)
        .filter(
            DocumentGrant.document_id == document_id,
            DocumentGrant.user_id == user_id,
        )
        .one()
    )


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a new document",
    description=(
        "Uploads a document file with title and category. "
        "Enforces request, metadata, quota, and size limits with extension whitelisting "
        "and magic byte content sniffing. File bytes are staged privately, atomically "
        "published outside the web root, and cleaned up if the audit or database commit fails."
    ),
)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(..., min_length=1, max_length=255),
    category: str = Form(default="General", min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    # Enforce least privilege: Uploaders must be owners or admins
    if current_user.role not in {UserRole.OWNER, UserRole.ADMIN}:
        AuditService.log_event(
            db,
            action="document.upload",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "insufficient_role"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document owner or administrator privileges required to upload documents",
        )

    try:
        normalized_filename = validate_original_filename(file.filename)
    except RequestMetadataValidationError as exc:
        AuditService.log_event(
            db,
            action="document.upload",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={
                "reason": (
                    "missing_filename" if not file.filename else "invalid_filename"
                )
            },
        )
        db.commit()
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
        ) from None

    try:
        mime_type = validate_mime_type(file.content_type)
    except RequestMetadataValidationError as exc:
        AuditService.log_event(
            db,
            action="document.upload",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": "invalid_mime_type"},
        )
        db.commit()
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
        ) from None

    try:
        staged = StorageService.stage_file(file.file, normalized_filename)
    except HTTPException as exc:
        reason = (
            "size_limit_exceeded"
            if exc.status_code == status.HTTP_413_CONTENT_TOO_LARGE
            else "invalid_upload"
        )
        AuditService.log_event(
            db,
            action="document.upload",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"reason": reason},
        )
        db.commit()
        raise
    except OSError:
        logger.exception("Private storage staging failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document storage is temporarily unavailable",
        ) from None

    try:
        StorageQuotaService.acquire_upload_slot(
            db,
            current_user.id,
            staged.size_bytes,
        )
    except StorageQuotaExceeded as exc:
        try:
            AuditService.log_event(
                db,
                action="document.upload",
                outcome=AuditOutcome.DENIED,
                actor_id=current_user.id,
                resource_type="document",
                ip_address=ip,
                user_agent=user_agent,
                request_id=request_id,
                details={"reason": exc.reason},
            )
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Failed to audit storage-quota denial")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Document storage transaction failed",
            ) from None
        finally:
            staged.discard()
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
        ) from None
    except SQLAlchemyError:
        db.rollback()
        staged.discard()
        logger.exception("Storage quota admission failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document storage transaction failed",
        ) from None
    except Exception:
        db.rollback()
        staged.discard()
        raise

    document = Document(
        title=title.strip(),
        original_filename=normalized_filename,
        storage_key=staged.storage_key,
        file_size_bytes=staged.size_bytes,
        mime_type=mime_type,
        category=category.strip(),
        owner_id=current_user.id,
        is_deleted=False,
    )

    try:
        db.add(document)
        db.flush()

        AuditService.log_event(
            db,
            action="document.upload",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document.id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={
                "title": document.title,
                "filename": document.original_filename,
                "size": document.file_size_bytes,
                "category": document.category,
            },
        )
        staged.finalize()
        db.commit()
    except (SQLAlchemyError, OSError):
        db.rollback()
        staged.discard()
        logger.exception("Document upload transaction failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document storage transaction failed",
        ) from None
    except Exception:
        db.rollback()
        staged.discard()
        raise

    db.refresh(document)
    return DocumentResponse.model_validate(document)


@router.get(
    "",
    response_model=DocumentListResponse,
    summary="List, search, and filter authorized documents",
    description=(
        "Returns a paginated list of documents the authenticated user owns or has an active, "
        "non-revoked grant for. Filters never expand this visibility scope, and administrators "
        "are not exempt. Each entry includes the caller's server-derived effective permission."
    ),
)
def list_documents(
    request: Request,
    page: int = 1,
    page_size: int = 25,
    q: str | None = None,
    category: str | None = None,
    owner_id: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentListResponse:
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(
            status_code=422,
            detail="page must be >= 1; page_size must be 1–100",
        )

    if q is not None:
        q = q.strip()
        if not q or len(q) > 255:
            raise HTTPException(
                status_code=422,
                detail="q must contain between 1 and 255 characters",
            )

    if category is not None:
        category = category.strip()
        if not category or len(category) > 100:
            raise HTTPException(
                status_code=422,
                detail="category must contain between 1 and 100 characters",
            )

    if owner_id is not None:
        owner_id = owner_id.strip()
        if not owner_id or len(owner_id) > 64:
            raise HTTPException(
                status_code=422,
                detail="owner_id must contain between 1 and 64 characters",
            )

    if created_from is not None:
        created_from = _to_utc(created_from)
    if created_to is not None:
        created_to = _to_utc(created_to)
    if created_from is not None and created_to is not None and created_from > created_to:
        raise HTTPException(
            status_code=422,
            detail="created_from must be earlier than or equal to created_to",
        )

    query = db.query(Document).filter(Document.is_deleted.is_(False))

    # Least privilege: every caller, including administrators, sees only
    # documents they own or hold an active grant for. Apply this before filters.
    granted_doc_ids = db.query(DocumentGrant.document_id).filter(
        DocumentGrant.user_id == current_user.id,
        DocumentGrant.is_revoked.is_(False),
    )
    query = query.filter(
        or_(
            Document.owner_id == current_user.id,
            Document.id.in_(granted_doc_ids),
        )
    )

    if q:
        pattern = f"%{_escape_like(q)}%"
        query = query.filter(
            or_(
                Document.title.ilike(pattern, escape="\\"),
                Document.original_filename.ilike(pattern, escape="\\"),
            )
        )
    if category:
        query = query.filter(Document.category == category)
    if owner_id:
        query = query.filter(Document.owner_id == owner_id)
    if created_from is not None:
        query = query.filter(Document.created_at >= created_from)
    if created_to is not None:
        query = query.filter(Document.created_at <= created_to)

    total = query.count()
    documents = (
        query.order_by(Document.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    grant_permissions = _get_effective_permissions(
        db=db,
        user_id=current_user.id,
        document_ids=[document.id for document in documents],
    )

    items = []
    for document in documents:
        if document.owner_id == current_user.id:
            effective_permission = "owner"
        else:
            effective_permission = grant_permissions.get(document.id)
            if effective_permission not in {PermissionLevel.READ, PermissionLevel.EDIT}:
                continue

        items.append(
            DocumentListItem(
                **DocumentResponse.model_validate(document).model_dump(),
                effective_permission=effective_permission,
            )
        )

    return DocumentListResponse(
        documents=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get document metadata",
    description="Returns metadata for a specific document if authorized (owner or active grant). Unshared documents return 404.",
)
def get_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.READ,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="document.read",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    AuditService.log_event(
        db,
        action="document.read",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="document",
        resource_id=document_id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
    )
    db.commit()

    return DocumentResponse.model_validate(document)


@router.get(
    "/{document_id}/download",
    summary="Download document file bytes",
    description="Streams authorized document file bytes as an attachment.",
)
def download_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.DOWNLOAD,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="document.download",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    try:
        file_path = StorageService.get_file_path(document.storage_key)
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document file not found in storage")

    AuditService.log_event(
        db,
        action="document.download",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="document",
        resource_id=document_id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
    )
    db.commit()

    return FileResponse(
        path=file_path,
        filename=document.original_filename,
        media_type=document.mime_type,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@router.patch(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Update document metadata",
    description="Updates document title or category if authorized (owner or edit grant).",
)
def update_document(
    document_id: str,
    body: DocumentUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.EDIT,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="document.edit",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    changed_fields = []
    if body.title is not None and body.title.strip() != document.title:
        document.title = body.title.strip()
        changed_fields.append("title")
    if body.category is not None and body.category.strip() != document.category:
        document.category = body.category.strip()
        changed_fields.append("category")

    if changed_fields:
        AuditService.log_event(
            db,
            action="document.edit",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"changed_fields": changed_fields},
        )
        db.commit()
        db.refresh(document)

    return DocumentResponse.model_validate(document)


@router.delete(
    "/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a document",
    description="Soft-deletes a document and removes physical storage file (Document Owner ONLY).",
)
def delete_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.DELETE,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="document.delete",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Commit the authoritative soft-delete and audit event before removing bytes.
    # If audit persistence fails, the transaction rolls back and the file remains
    # consistent with an active document. If physical cleanup fails after commit,
    # startup reconciliation retries it from the persisted deleted state.
    document.is_deleted = True
    try:
        AuditService.log_event(
            db,
            action="document.delete",
            outcome=AuditOutcome.SUCCESS,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"title": document.title},
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document delete transaction failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document deletion transaction failed",
        ) from None

    if not StorageService.delete_file(document.storage_key):
        logger.warning(
            "Physical cleanup deferred for a soft-deleted document; "
            "startup reconciliation will retry"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Grant Management / Sharing Endpoints (Day 4)
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/{document_id}/permissions",
    response_model=GrantListResponse,
    summary="List document permissions",
    description="Returns all permission grants for a document (Document Owner ONLY).",
)
def list_document_permissions(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GrantListResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.VIEW_PERMISSIONS,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="permission.list_denied",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    grants = db.query(DocumentGrant).filter(DocumentGrant.document_id == document.id).all()
    return GrantListResponse(grants=[GrantResponse.model_validate(g) for g in grants])


@router.post(
    "/{document_id}/permissions",
    response_model=GrantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Grant access to a document",
    description="Grants read or edit permission to a named existing user (Document Owner ONLY).",
)
def create_document_permission(
    document_id: str,
    body: GrantCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GrantResponse:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.SHARE,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="permission.grant",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"recipient_id": body.user_id},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Prevent owner granting to themselves
    if body.user_id == document.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document owner already has full ownership rights",
        )

    # Verify recipient user exists and is active
    recipient = db.get(User, body.user_id)
    if recipient is None or not recipient.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient user not found or inactive",
        )

    grant = _upsert_grant(
        db=db,
        document_id=document.id,
        user_id=recipient.id,
        permission=body.permission,
        granted_by_id=current_user.id,
    )

    AuditService.log_event(
        db,
        action="permission.grant",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="document_grant",
        resource_id=grant.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={
            "document_id": document.id,
            "recipient_id": recipient.id,
            "permission": grant.permission,
        },
    )
    db.commit()
    db.refresh(grant)

    return GrantResponse.model_validate(grant)


@router.delete(
    "/{document_id}/permissions/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke document access",
    description="Immediately revokes a user's active grant for a document (Document Owner ONLY).",
)
def revoke_document_permission(
    document_id: str,
    user_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    ip = request.state.client_ip
    user_agent = request.state.user_agent
    request_id = request.state.request_id

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    active_grant = _get_active_grant(db, document.id, current_user.id)
    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.SHARE,
        active_grant=active_grant,
    )

    if not authorized:
        AuditService.log_event(
            db,
            action="permission.revoke",
            outcome=AuditOutcome.DENIED,
            actor_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"target_user_id": user_id},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    grant = _get_active_grant(db, document.id, user_id)
    if grant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active permission grant not found for this user",
        )

    grant.is_revoked = True
    db.flush()

    AuditService.log_event(
        db,
        action="permission.revoke",
        outcome=AuditOutcome.SUCCESS,
        actor_id=current_user.id,
        resource_type="document_grant",
        resource_id=grant.id,
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details={
            "document_id": document.id,
            "target_user_id": user_id,
        },
    )
    db.commit()

    return {"detail": "Permission successfully revoked"}
