"""Durable intent and retry state for remote storage operations."""

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import generate_uuid, utc_now


class StorageOperation(Base):
    __tablename__ = "storage_operations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    operation_type: Mapped[str] = mapped_column(String(10), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "operation_type IN ('upload', 'delete')",
            name="ck_storage_operations_type",
        ),
        CheckConstraint(
            "status IN ('uploading', 'upload_uncertain', 'upload_committed', "
            "'delete_pending', 'retry_wait', 'completed', 'cancelled', "
            "'needs_review', 'exhausted')",
            name="ck_storage_operations_status",
        ),
        CheckConstraint("retry_count >= 0", name="ck_storage_operations_retry_count"),
        UniqueConstraint(
            "operation_type",
            "storage_key",
            name="uq_storage_operations_type_key",
        ),
        Index(
            "ix_storage_operations_due",
            "status",
            "next_attempt_at",
            "lease_until",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<StorageOperation id={self.id} type={self.operation_type} "
            f"status={self.status} retries={self.retry_count}>"
        )
