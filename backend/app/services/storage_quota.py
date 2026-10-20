"""
Serialized storage-quota admission.

A singleton coordination row is updated at the start of the caller's database
transaction. PostgreSQL holds a row lock until commit; SQLite holds its write
lock. The quota snapshot and the document insert therefore share one serialized
critical section across workers.
"""

from fastapi import status
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.base import utc_now
from backend.app.models.document import Document
from backend.app.models.storage_quota import StorageQuotaState


class StorageQuotaExceeded(Exception):
    """A quota rejection that is safe to return to the client."""

    def __init__(self, reason: str, detail: str, status_code: int):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.status_code = status_code


class StorageQuotaService:
    @staticmethod
    def _ensure_state(db: Session) -> None:
        db.execute(
            text(
                "INSERT INTO storage_quota_state (id, updated_at) "
                "VALUES (1, CURRENT_TIMESTAMP) "
                "ON CONFLICT (id) DO NOTHING"
            )
        )

    @classmethod
    def acquire_upload_slot(
        cls,
        db: Session,
        owner_id: str,
        incoming_bytes: int,
    ) -> None:
        """
        Serialize an upload admission check against active document usage.

        This does not mutate document usage itself. The caller must insert the
        document and commit in the same transaction. On PostgreSQL the lock is
        held until that commit; on SQLite the write lock is held equivalently.
        """
        if incoming_bytes <= 0:
            raise ValueError("incoming_bytes must be positive")

        cls._ensure_state(db)
        lock_result = db.execute(
            update(StorageQuotaState)
            .where(StorageQuotaState.id == 1)
            .values(updated_at=utc_now())
        )
        if lock_result.rowcount != 1:
            raise RuntimeError("Storage quota coordination row is missing")

        user_bytes, user_count = db.execute(
            select(
                func.coalesce(func.sum(Document.file_size_bytes), 0),
                func.count(Document.id),
            ).where(
                Document.owner_id == owner_id,
                Document.is_deleted.is_(False),
            )
        ).one()
        global_bytes = db.scalar(
            select(func.coalesce(func.sum(Document.file_size_bytes), 0)).where(
                Document.is_deleted.is_(False)
            )
        ) or 0

        if int(user_count) + 1 > settings.MAX_UPLOADS_PER_USER:
            raise StorageQuotaExceeded(
                reason="upload_count_quota",
                detail="Active document limit reached for this account",
                status_code=status.HTTP_409_CONFLICT,
            )
        if int(user_bytes) + incoming_bytes > settings.MAX_USER_STORAGE_BYTES:
            raise StorageQuotaExceeded(
                reason="user_storage_quota",
                detail="Account storage quota would be exceeded",
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
        if int(global_bytes) + incoming_bytes > settings.MAX_GLOBAL_STORAGE_BYTES:
            raise StorageQuotaExceeded(
                reason="global_storage_quota",
                detail="Platform storage capacity is temporarily unavailable",
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
