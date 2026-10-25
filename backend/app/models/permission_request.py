"""Permission request model for TrustVault.

This model represents a user‑initiated request for additional access to a
document. It tracks the requesting user, the target document, the role being
requested, the current status of the request, and timestamps.
"""

from enum import Enum

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy import Enum as SaEnum
from sqlalchemy.orm import relationship

from backend.app.database import Base
from backend.app.models.base import TimestampMixin
from backend.app.models.document import Document
from backend.app.models.user import User


class PermissionRequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELED = "canceled"


class PermissionRequest(Base, TimestampMixin):
    __tablename__ = "permission_requests"

    id: int = Column(Integer, primary_key=True, index=True)
    requester_id: str = Column(
        String(36), ForeignKey("users.id"), index=True, nullable=False
    )
    document_id: str = Column(
        String(36), ForeignKey("documents.id"), index=True, nullable=False
    )
    requested_role: str = Column(String(100), nullable=False)  # e.g., "download_activity"
    status: PermissionRequestStatus = Column(
        SaEnum(PermissionRequestStatus),
        default=PermissionRequestStatus.PENDING,
        index=True,
        nullable=False,
    )

    # Relationships for convenient access
    requester = relationship(User, backref="permission_requests")
    document = relationship(Document, backref="permission_requests")

    def __repr__(self) -> str:
        return f"<PermissionRequest id={self.id} requester_id={self.requester_id} document_id={self.document_id} role={self.requested_role} status={self.status}>"
