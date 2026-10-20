"""
Startup reconciliation for private storage after interrupted operations.

Uploads finalize their file before committing the document row. Deletes commit
the soft-delete before unlinking the file. Those orderings intentionally favor
a recoverable state, but a process crash can leave either an unreferenced file
or a file belonging to a soft-deleted document. This service removes those
files. Unreferenced files younger than the configured grace period are kept so
a concurrently starting worker cannot delete an in-flight upload.
"""

import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.config import settings
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
    @staticmethod
    def _file_age_seconds(path: Path, now: float) -> float:
        try:
            return max(0.0, now - path.stat().st_mtime)
        except OSError:
            return 0.0

    @classmethod
    def reconcile(cls, db: Session) -> StorageReconciliationReport:
        """Remove recoverable storage debris without deleting active files."""
        storage_dir = StorageService.get_storage_path().resolve()
        staging_dir = StorageService.get_staging_path().resolve()
        grace_seconds = settings.STORAGE_ORPHAN_GRACE_SECONDS
        now = time.time()

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
        referenced_keys = active_keys | deleted_keys

        removed_orphans = 0
        removed_deleted = 0
        removed_staging = 0
        removed_bytes = 0
        cleanup_failures = 0

        for path in storage_dir.iterdir():
            if path.is_dir() or not is_valid_storage_key(path.name):
                continue
            if path.name in active_keys:
                continue
            is_deleted = path.name in deleted_keys
            is_unreferenced = path.name not in referenced_keys
            if not is_deleted and not is_unreferenced:
                continue
            if (
                is_unreferenced
                and not is_deleted
                and cls._file_age_seconds(path, now) < grace_seconds
            ):
                continue
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                cleanup_failures += 1
                continue
            removed_bytes += size
            if is_deleted:
                removed_deleted += 1
            else:
                removed_orphans += 1

        for path in staging_dir.iterdir():
            if path.is_dir() or not path.name.endswith(".part"):
                continue
            if not is_valid_storage_key(path.name[: -len(".part")]):
                continue
            if cls._file_age_seconds(path, now) < grace_seconds:
                continue
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                cleanup_failures += 1
                continue
            removed_bytes += size
            removed_staging += 1

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
