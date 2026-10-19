"""
TrustVault Centralized Authorization Service
Enforces the principle of least privilege, default-deny security posture,
and role/permission matrix across all protected resources.

Roles:
- Administrator: Account management, audit viewing, restricted/audited admin actions.
  * Administrators do NOT have automatic bypass to read or download confidential document contents!
- Document Owner: Full control over owned documents (read, download, edit, delete, grant, revoke).
- Viewer: Read and download documents only when an active grant exists.

Actions:
- read: view document metadata and download bytes
- edit: update metadata or upload new versions
- delete: soft-delete or remove document (Owner only)
- share: manage permissions and grants (Owner only)
"""

from enum import Enum

from fastapi import HTTPException, status

from backend.app.models.document import Document
from backend.app.models.grant import DocumentGrant, PermissionLevel
from backend.app.models.user import User


class DocumentAction(str, Enum):
    READ = "read"
    DOWNLOAD = "download"
    EDIT = "edit"
    DELETE = "delete"
    SHARE = "share"
    VIEW_PERMISSIONS = "view_permissions"


class AuthorizationService:
    """
    Central authorization authority for TrustVault.
    All policy decisions are made on fresh database state to prevent stale-authorization races.
    """

    @staticmethod
    def verify_active_user(user: User | None) -> User:
        """Denies access if user is missing, unauthenticated, or deactivated."""
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Cookie"},
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated",
            )
        return user

    @staticmethod
    def require_role(user: User, allowed_roles: set[str]) -> None:
        """Enforces role-based function access."""
        AuthorizationService.verify_active_user(user)
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient administrative privileges",
            )

    @staticmethod
    def authorize_document_access(
        user: User,
        document: Document,
        action: DocumentAction,
        active_grant: DocumentGrant | None = None,
    ) -> bool:
        """
        Evaluates whether `user` is authorized to perform `action` on `document`.
        
        Rules:
        1. Default deny.
        2. Deactivated user -> deny.
        3. Document is deleted -> deny (unless admin investigation / restoration flow).
        4. Owner has full access to their documents (read, download, edit, delete, share, view_permissions).
        5. Active grant:
           - Permission 'edit' allows: read, download, edit.
           - Permission 'read' allows: read, download.
           - Grant does NOT allow: delete, share, view_permissions.
        6. Administrator does NOT automatically bypass confidentiality for file content reads or downloads.
           Admin access is restricted to audit inspections and user management unless explicitly delegated.
        """
        AuthorizationService.verify_active_user(user)

        if document.is_deleted:
            return False

        # Owner check
        if document.owner_id == user.id:
            return True

        # Grant check for non-owners
        if active_grant and not active_grant.is_revoked:
            if action in {DocumentAction.READ, DocumentAction.DOWNLOAD}:
                return active_grant.permission in {PermissionLevel.READ, PermissionLevel.EDIT}
            if action == DocumentAction.EDIT:
                return active_grant.permission == PermissionLevel.EDIT
            # Non-owners can never delete or share
            return False

        # Deny by default
        return False
