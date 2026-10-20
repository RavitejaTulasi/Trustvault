"""
Session Model for TrustVault
Implements server-side session persistence with token hashing and revocation support.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.app.limits import MAX_IP_ADDRESS_LENGTH, MAX_USER_AGENT_LENGTH
from backend.app.models.base import TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from backend.app.models.user import User


class SessionModel(Base, TimestampMixin):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # The SHA-256 hash of the random session token sent in the HTTP-only cookie
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(
        String(MAX_IP_ADDRESS_LENGTH), nullable=True
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(MAX_USER_AGENT_LENGTH), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<Session id={self.id} user_id={self.user_id} expired={self.expires_at}>"
