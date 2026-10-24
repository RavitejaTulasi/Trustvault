"""
Document and DocumentVersion Models
Implements secure metadata tracking with unguessable storage keys and version history.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.limits import (
    MAX_MIME_TYPE_LENGTH,
    MAX_ORIGINAL_FILENAME_LENGTH,
)
from backend.app.models.base import TimestampMixin, generate_uuid, utc_now

if TYPE_CHECKING:
    from backend.app.models.audit import AuditEvent
    from backend.app.models.grant import DocumentGrant
    from backend.app.models.user import User


class Document(Base, TimestampMixin):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    original_filename: Mapped[str] = mapped_column(
        String(MAX_ORIGINAL_FILENAME_LENGTH), nullable=False
    )
    
    # Internal random key used in private storage - physical paths are NEVER exposed to clients
    storage_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(
        String(MAX_MIME_TYPE_LENGTH), nullable=False
    )
    category: Mapped[str] = mapped_column(String(100), default="General", index=True, nullable=False)
    
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)

    # Relationships
    owner: Mapped["User"] = relationship(
        "User", back_populates="owned_documents", foreign_keys=[owner_id]
    )
    grants: Mapped[list["DocumentGrant"]] = relationship(
        "DocumentGrant", back_populates="document", cascade="all, delete-orphan"
    )
    versions: Mapped[list["DocumentVersion"]] = relationship(
        "DocumentVersion", back_populates="document", cascade="all, delete-orphan", order_by="DocumentVersion.version_number.desc()"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent",
        primaryjoin="and_(foreign(AuditEvent.resource_id) == Document.id, AuditEvent.resource_type == 'document')",
        viewonly=True,
    )

    __table_args__ = (
        Index("ix_documents_owner_deleted", "owner_id", "is_deleted"),
        Index("ix_documents_category_deleted", "category", "is_deleted"),
    )

    def __repr__(self) -> str:
        return f"<Document id={self.id} title={self.title} owner_id={self.owner_id}>"


class DocumentVersion(Base):
    __tablename__ = "document_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="versions")

    __table_args__ = (
        Index("ix_doc_version_unique", "document_id", "version_number", unique=True),
    )

    def __repr__(self) -> str:
        return f"<DocumentVersion doc_id={self.document_id} v={self.version_number}>"
