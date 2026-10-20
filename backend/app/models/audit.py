"""
Audit Event Model with Cryptographic Hash Chaining
Provides a tamper-evident audit trail for all security-relevant and access actions.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.limits import (
    MAX_IP_ADDRESS_LENGTH,
    MAX_REQUEST_ID_LENGTH,
    MAX_USER_AGENT_LENGTH,
)
from backend.app.models.base import generate_uuid, utc_now

if TYPE_CHECKING:
    from backend.app.models.user import User


AUDIT_HASH_VERSION_LEGACY = 1
AUDIT_HASH_VERSION_CURRENT = 2
SUPPORTED_AUDIT_HASH_VERSIONS = frozenset(
    {AUDIT_HASH_VERSION_LEGACY, AUDIT_HASH_VERSION_CURRENT}
)


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
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT", onupdate="RESTRICT"),
        index=True,
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(100), index=True, nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    request_id: Mapped[str | None] = mapped_column(
        String(MAX_REQUEST_ID_LENGTH), index=True, nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(MAX_IP_ADDRESS_LENGTH), nullable=True
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(MAX_USER_AGENT_LENGTH), nullable=True
    )
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tamper-evidence: Hash-chaining mechanism
    hash_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=AUDIT_HASH_VERSION_CURRENT,
        server_default=str(AUDIT_HASH_VERSION_LEGACY),
    )
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


class AuditChainState(Base):
    """Singleton row serializing audit append allocation and binding the chain head."""

    __tablename__ = "audit_chain_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditChainState seq={self.last_sequence} hash={self.last_hash[:12]}...>"
        )
