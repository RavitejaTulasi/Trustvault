"""
User Model for TrustVault
Supports three roles: Administrator, Document Owner, Viewer.
"""

from typing import TYPE_CHECKING, ClassVar

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.models.base import TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from backend.app.models.audit import AuditEvent
    from backend.app.models.document import Document
    from backend.app.models.grant import DocumentGrant
    from backend.app.models.session import SessionModel


class UserRole:
    ADMIN = "admin"
    OWNER = "owner"
    VIEWER = "viewer"

    ALL_ROLES: ClassVar[set[str]] = {ADMIN, OWNER, VIEWER}


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default=UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    sessions: Mapped[list["SessionModel"]] = relationship(
        "SessionModel", back_populates="user", cascade="all, delete-orphan"
    )
    owned_documents: Mapped[list["Document"]] = relationship(
        "Document", back_populates="owner", foreign_keys="Document.owner_id"
    )
    grants_received: Mapped[list["DocumentGrant"]] = relationship(
        "DocumentGrant", back_populates="user", foreign_keys="DocumentGrant.user_id", cascade="all, delete-orphan"
    )
    grants_issued: Mapped[list["DocumentGrant"]] = relationship(
        "DocumentGrant", back_populates="granted_by", foreign_keys="DocumentGrant.granted_by_id"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent",
        back_populates="actor",
        foreign_keys="AuditEvent.actor_id",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"
