"""
TrustVault Database Models
Exports all models for SQLAlchemy and Alembic metadata reflection.
"""

from backend.app.database import Base
from backend.app.models.audit import AuditEvent, AuditOutcome
from backend.app.models.base import TimestampMixin, generate_uuid, utc_now
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.app.models.notification import Notification
from backend.app.models.otp import PasswordResetOTP
from backend.app.models.rate_limit import LoginRateLimitBucket
from backend.app.models.session import SessionModel
from backend.app.models.storage_object import StorageObject, UploadRequest
from backend.app.models.storage_operation import StorageOperation
from backend.app.models.storage_quota import StorageQuotaState
from backend.app.models.user import User, UserRole

__all__ = [
    "AuditEvent",
    "AuditOutcome",
    "Base",
    "Document",
    "DocumentGrant",
    "DocumentVersion",
    "LoginRateLimitBucket",
    "Notification",
    "PasswordResetOTP",
    "PermissionLevel",
    "SessionModel",
    "StorageQuotaState",
    "StorageOperation",
    "StorageObject",
    "UploadRequest",
    "TimestampMixin",
    "User",
    "UserRole",
    "generate_uuid",
    "utc_now",
]
