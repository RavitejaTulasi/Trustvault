"""
TrustVault Database Models
Exports all models for SQLAlchemy and Alembic metadata reflection.
"""

from backend.app.database import Base
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.base import TimestampMixin, generate_uuid, utc_now
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.app.models.session import SessionModel
from backend.app.models.user import User, UserRole

__all__ = [
    "AuditEvent",
    "AuditOutcome",
    "Base",
    "Document",
    "DocumentGrant",
    "DocumentVersion",
    "PermissionLevel",
    "SessionModel",
    "TimestampMixin",
    "User",
    "UserRole",
    "generate_uuid",
    "utc_now",
]
