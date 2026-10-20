"""
Shared Login Rate-Limit Buckets
Stores bounded, expiring login-attempt counters in the application database so
limits are enforced consistently across workers and application instances.
"""

from sqlalchemy import BigInteger, Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base


class LoginRateLimitBucket(Base):
    __tablename__ = "login_rate_limit_buckets"

    # SHA-256 digest of the scope and normalized identity; raw IP addresses and
    # email addresses are not stored in this table.
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_started_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    denial_audit_recorded: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<LoginRateLimitBucket scope={self.scope} "
            f"attempts={self.attempt_count} expires={self.expires_at}>"
        )
