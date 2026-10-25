"""
Pydantic Schemas Package for TrustVault
"""

from backend.app.schemas.audit import (
    AuditEventListResponse,
    AuditEventResponse,
    AuditVerificationResponse,
)
from backend.app.schemas.auth import (
    AdminUserUpdateRequest,
    UserListResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
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
from backend.app.schemas.health import HealthResponse
from backend.app.schemas.notification import (
    NotificationListResponse,
    NotificationResponse,
)
from backend.app.schemas.permission_request import (
    PermissionRequestCreate,
    PermissionRequestOut,
    PermissionRequestUpdate,
)

__all__ = [
    "AdminUserUpdateRequest",
    "AuditEventListResponse",
    "AuditEventResponse",
    "AuditVerificationResponse",
    "DocumentListItem",
    "DocumentListResponse",
    "DocumentResponse",
    "DocumentUpdateRequest",
    "GrantCreateRequest",
    "GrantListResponse",
    "GrantResponse",
    "HealthResponse",
    "NotificationListResponse",
    "NotificationResponse",
    "PermissionRequestCreate",
    "PermissionRequestOut",
    "PermissionRequestUpdate",
    "UserListResponse",
    "UserLoginRequest",
    "UserRegisterRequest",
    "UserResponse",
    "UserUpdateRequest",
]
