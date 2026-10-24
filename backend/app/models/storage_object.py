"""Canonical ownership and lifecycle state for private storage keys."""

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import DDL

from backend.app.database import Base
from backend.app.models.base import generate_uuid, utc_now


class StorageObject(Base):
    __tablename__ = "storage_objects"

    storage_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    backend: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    owner_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "backend IN ('local', 'supabase', 'unknown')",
            name="ck_storage_objects_backend",
        ),
        CheckConstraint(
            "state IN ('uploading', 'active', 'deleting', 'deleted', 'needs_review')",
            name="ck_storage_objects_state",
        ),
        CheckConstraint(
            "owner_type IS NULL OR owner_type IN ('document', 'version')",
            name="ck_storage_objects_owner_type",
        ),
        CheckConstraint(
            "(owner_type IS NULL AND owner_id IS NULL) OR "
            "(owner_type IS NOT NULL AND owner_id IS NOT NULL)",
            name="ck_storage_objects_owner_pair",
        ),
        UniqueConstraint("owner_type", "owner_id", name="uq_storage_objects_owner"),
        Index("ix_storage_objects_state_updated", "state", "updated_at"),
    )


class UploadRequest(Base):
    __tablename__ = "upload_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("storage_objects.storage_key", ondelete="RESTRICT"),
        nullable=False,
    )
    operation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("storage_operations.id", ondelete="RESTRICT")
    )
    document_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="RESTRICT")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    response_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('in_progress', 'completed', 'needs_review')",
            name="ck_upload_requests_status",
        ),
        UniqueConstraint(
            "owner_id", "idempotency_key", name="uq_upload_requests_owner_key"
        ),
        Index("ix_upload_requests_document_id", "document_id"),
    )


event.listen(
    UploadRequest.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER IF NOT EXISTS trg_documents_storage_key_owner_insert
        BEFORE INSERT ON documents
        BEGIN
          UPDATE storage_objects
          SET owner_type = 'document', owner_id = NEW.id
          WHERE storage_key = NEW.storage_key
            AND state = 'active' AND owner_type IS NULL;
          SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'storage object is not active or already owned')
          END;
        END;
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    UploadRequest.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER IF NOT EXISTS trg_storage_objects_prevent_delete
        BEFORE DELETE ON storage_objects
        BEGIN
          SELECT CASE WHEN OLD.owner_type IS NOT NULL OR EXISTS (
            SELECT 1 FROM documents WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM document_versions WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM storage_operations WHERE storage_key = OLD.storage_key
            UNION ALL
            SELECT 1 FROM upload_requests WHERE storage_key = OLD.storage_key
          ) THEN RAISE(ABORT, 'storage object is still owned') END;
        END;
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    UploadRequest.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER IF NOT EXISTS trg_documents_storage_key_owner_update
        BEFORE UPDATE OF storage_key ON documents
        BEGIN
          SELECT CASE WHEN NEW.storage_key != OLD.storage_key
            THEN RAISE(ABORT, 'storage key ownership is immutable')
          END;
        END;
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    UploadRequest.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER IF NOT EXISTS trg_document_versions_storage_key_owner_insert
        BEFORE INSERT ON document_versions
        BEGIN
          UPDATE storage_objects
          SET owner_type = 'version', owner_id = NEW.id
          WHERE storage_key = NEW.storage_key
            AND state = 'active' AND owner_type IS NULL;
          SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'storage object is not active or already owned')
          END;
        END;
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    UploadRequest.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER IF NOT EXISTS trg_document_versions_storage_key_owner_update
        BEFORE UPDATE OF storage_key ON document_versions
        BEGIN
          SELECT CASE WHEN NEW.storage_key != OLD.storage_key
            THEN RAISE(ABORT, 'storage key ownership is immutable')
          END;
        END;
        """
    ).execute_if(dialect="sqlite"),
)
