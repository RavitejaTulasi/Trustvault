"""
Audit Event Model with Cryptographic Hash Chaining
Provides a tamper-evident audit trail for all security-relevant and access actions.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.models.base import generate_uuid, utc_now

if TYPE_CHECKING:
    from backend.app.models.user import User


class AuditOutcome:
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILURE = "FAILURE"


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    sequence_number: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )
    actor_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(100), index=True, nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tamper-evidence: Hash-chaining mechanism
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Relationships
    actor: Mapped[Optional["User"]] = relationship(
        "User", back_populates="audit_events", foreign_keys=[actor_id]
    )

    __table_args__ = (
        Index("ix_audit_events_action_outcome", "action", "outcome"),
        Index("ix_audit_events_res_seq", "resource_type", "resource_id", "sequence_number"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent seq={self.sequence_number} action={self.action} outcome={self.outcome}>"
