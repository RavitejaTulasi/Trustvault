"""
Document Grant Model for TrustVault
Manages fine-grained document-level permissions (read, edit) for named users.
Supports immediate revocation and transaction-safe modifications.
"""

from typing import TYPE_CHECKING, ClassVar, Optional

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.models.base import TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from backend.app.models.document import Document
    from backend.app.models.user import User


class PermissionLevel:
    READ = "read"
    EDIT = "edit"

    ALL_PERMISSIONS: ClassVar[set[str]] = {READ, EDIT}


class DocumentGrant(Base, TimestampMixin):
    __tablename__ = "document_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    permission: Mapped[str] = mapped_column(String(20), nullable=False, default=PermissionLevel.READ)
    granted_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    revocation_version: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="grants")
    user: Mapped["User"] = relationship(
        "User", back_populates="grants_received", foreign_keys=[user_id]
    )
    granted_by: Mapped[Optional["User"]] = relationship(
        "User", back_populates="grants_issued", foreign_keys=[granted_by_id]
    )

    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_doc_user_grant"),
        Index("ix_active_grants", "document_id", "user_id", "is_revoked"),
    )

    def __repr__(self) -> str:
        return f"<DocumentGrant doc={self.document_id} user={self.user_id} perm={self.permission} revoked={self.is_revoked}>"
