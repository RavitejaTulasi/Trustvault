"""
Startup reconciliation for private storage after interrupted operations.

Uploads finalize their file before committing the document row. Deletes commit
the soft-delete before unlinking the file. Those orderings intentionally favor
a recoverable state, but a process crash can leave either an unreferenced file
or a file belonging to a soft-deleted document. This service removes finalized
files belonging to soft-deleted documents. Unreferenced finalized and staging
files are preserved because local uploads do not have durable leases that can
distinguish an abandoned upload from a slow, in-flight upload.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.document import Document, DocumentVersion
from backend.app.services.storage_service import (
    StorageService,
    is_valid_storage_key,
)


@dataclass(frozen=True)
class StorageReconciliationReport:
    removed_orphaned_files: int = 0
    removed_deleted_files: int = 0
    removed_staging_files: int = 0
    removed_bytes: int = 0
    cleanup_failures: int = 0
    missing_active_files: int = 0


class StorageLifecycleService:
    @classmethod
    def reconcile(cls, db: Session) -> StorageReconciliationReport:
        """Remove recoverable storage debris without deleting active files."""
        storage_dir = StorageService.get_storage_path().resolve()

        active_document_keys = set(
            db.scalars(
                select(Document.storage_key).where(Document.is_deleted.is_(False))
            ).all()
        )
        deleted_document_keys = set(
            db.scalars(
                select(Document.storage_key).where(Document.is_deleted.is_(True))
            ).all()
        )
        active_version_keys = set(
            db.scalars(
                select(DocumentVersion.storage_key)
                .join(Document, Document.id == DocumentVersion.document_id)
                .where(Document.is_deleted.is_(False))
            ).all()
        )
        deleted_version_keys = set(
            db.scalars(
                select(DocumentVersion.storage_key)
                .join(Document, Document.id == DocumentVersion.document_id)
                .where(Document.is_deleted.is_(True))
            ).all()
        )

        active_keys = active_document_keys | active_version_keys
        deleted_keys = deleted_document_keys | deleted_version_keys
        removed_orphans = 0
        removed_deleted = 0
        removed_staging = 0
        removed_bytes = 0
        cleanup_failures = 0

        # Unreferenced files may belong to an upload whose DB transaction has
        # not committed yet, so age alone is not sufficient to delete them.
        for path in storage_dir.iterdir():
            if path.is_dir() or not is_valid_storage_key(path.name):
                continue
            is_deleted = path.name in deleted_keys
            if path.name in active_keys or not is_deleted:
                continue
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                cleanup_failures += 1
                continue
            removed_bytes += size
            removed_deleted += 1

        missing_active = sum(
            1
            for storage_key in active_keys
            if not (storage_dir / storage_key).is_file()
        )

        return StorageReconciliationReport(
            removed_orphaned_files=removed_orphans,
            removed_deleted_files=removed_deleted,
            removed_staging_files=removed_staging,
            removed_bytes=removed_bytes,
            cleanup_failures=cleanup_failures,
            missing_active_files=missing_active,
        )
