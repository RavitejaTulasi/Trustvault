"""
Document Management and Storage API Endpoints
Handles: upload, list, metadata retrieval, secure streaming download, metadata updates, and deletion.

Security controls implemented:
- Centralized authorization enforcement via AuthorizationService (default deny)
- Private persistent storage isolation outside web root (StorageService)
- Magic byte validation and extension whitelisting
- Deliberate 404 responses for unauthorized resource access to prevent metadata existence leakage
- Tamper-evident audit logging for all document actions (success and denial)
- Defense-in-depth security headers and cache control enforcement
"""

import logging

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
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.audit import AuditOutcome
from backend.app.models.document import Document
from backend.app.models.user import User, UserRole
from backend.app.schemas.document import (
    DocumentListResponse,
    DocumentResponse,
    DocumentUpdateRequest,
)
from backend.app.security.auth import get_current_user
from backend.app.services.audit_service import AuditService
from backend.app.services.authorization import AuthorizationService, DocumentAction
from backend.app.services.storage_service import StorageService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/documents", tags=["Documents & Storage"])


def _get_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a new document",
    description=(
        "Uploads a document file with title and category. "
        "Enforces max size limits, extension whitelisting, and magic byte content sniffing. "
        "Persists file bytes outside web root with a 256-bit unguessable storage key."
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
    ip = _get_client_ip(request) or "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    # Enforce least privilege: Uploaders must be owners or admins
    if current_user.role not in {UserRole.OWNER, UserRole.ADMIN}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document owner or administrator privileges required to upload documents",
        )

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )

    # Save and validate file via StorageService
    try:
        storage_key, file_size = StorageService.save_file(file.file, file.filename)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload storage error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file",
        )

    mime_type = file.content_type or "application/octet-stream"

    document = Document(
        title=title.strip(),
        original_filename=file.filename,
        storage_key=storage_key,
        file_size_bytes=file_size,
        mime_type=mime_type,
        category=category.strip(),
        owner_id=current_user.id,
        is_deleted=False,
    )
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
    db.commit()
    db.refresh(document)

    return DocumentResponse.model_validate(document)


@router.get(
    "",
    response_model=DocumentListResponse,
    summary="List authorized documents",
    description="Returns a paginated list of documents the authenticated user is authorized to view.",
)
def list_documents(
    request: Request,
    page: int = 1,
    page_size: int = 25,
    category: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentListResponse:
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="page must be >= 1; page_size must be 1–100",
        )

    query = db.query(Document).filter(Document.is_deleted.is_(False))

    # Scope documents based on user role and ownership
    if current_user.role == UserRole.ADMIN:
        # Admins see system-wide active documents metadata
        pass
    else:
        # Owners see their own documents; viewers see granted docs (Day 3: owner-only until grants)
        query = query.filter(Document.owner_id == current_user.id)

    if category:
        query = query.filter(Document.category == category)

    total = query.count()
    documents = (
        query.order_by(Document.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return DocumentListResponse(
        documents=[DocumentResponse.model_validate(d) for d in documents],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get document metadata",
    description="Returns metadata for a specific document if authorized. Unshared or non-existent documents return 404.",
)
def get_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    ip = _get_client_ip(request) or "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.READ,
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
    ip = _get_client_ip(request) or "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.DOWNLOAD,
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
    description="Updates document title or category if authorized.",
)
def update_document(
    document_id: str,
    body: DocumentUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    ip = _get_client_ip(request) or "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.EDIT,
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
    description="Soft-deletes a document and removes physical storage file (Owner only).",
)
def delete_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    ip = _get_client_ip(request) or "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    document = db.get(Document, document_id)
    if document is None or document.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    authorized = AuthorizationService.authorize_document_access(
        user=current_user,
        document=document,
        action=DocumentAction.DELETE,
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

    # Soft delete in DB and remove physical file
    document.is_deleted = True
    StorageService.delete_file(document.storage_key)

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
