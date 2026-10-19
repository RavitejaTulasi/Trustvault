"""
Base SQLAlchemy Model Definitions
Provides standard timestamp mixins and UUID helper functions.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


def generate_uuid() -> str:
    """Generate a lowercase 32-character hexadecimal UUID string."""
    return uuid.uuid4().hex


def utc_now() -> datetime:
    """Returns current UTC datetime."""
    return datetime.now(UTC)


class TimestampMixin:
    """Standard timestamp fields for auditability."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
