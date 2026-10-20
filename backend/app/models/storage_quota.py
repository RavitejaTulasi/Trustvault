"""Singleton coordination row for serialized storage-quota admission."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import utc_now


class StorageQuotaState(Base):
    """A single row whose update lock serializes quota snapshots across workers."""

    __tablename__ = "storage_quota_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_storage_quota_state_singleton"),
    )

    def __repr__(self) -> str:
        return f"<StorageQuotaState updated_at={self.updated_at}>"
