"""
Server-Side Session Management for TrustVault
Implements cryptographically secure token generation, SHA-256 token hashing for DB storage,
and session lifecycle (creation, validation, revocation).

Design principle:
- The raw token is sent once in an HTTP-only cookie (never stored in DB).
- Only the SHA-256 hash of the token is persisted — a DB breach cannot replay sessions.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.session import SessionModel
from backend.app.models.user import User

_TOKEN_BYTES = 32  # 256 bits of entropy


def generate_session_token() -> str:
    """Generate a cryptographically secure URL-safe random token string."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of the raw session token."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    db: Session,
    user: User,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, SessionModel]:
    """
    Create a new server-side session for the authenticated user.

    Returns (raw_token, SessionModel).
    The caller must set the raw_token in the HTTP-only session cookie.
    Only the hash is stored in the database.
    """
    raw_token = generate_session_token()
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS)

    session = SessionModel(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        is_revoked=False,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    db.flush()  # get session.id without full commit; caller commits

    return raw_token, session


def get_valid_session(db: Session, raw_token: str) -> SessionModel | None:
    """
    Look up a session by its raw token.
    Returns the SessionModel only if it is active, not expired, and not revoked.
    Returns None in all other cases (constant-time hash comparison via DB index lookup).
    """
    token_hash = hash_token(raw_token)
    now = datetime.now(UTC)

    session: SessionModel | None = (
        db.query(SessionModel)
        .filter(
            SessionModel.token_hash == token_hash,
            SessionModel.is_revoked.is_(False),
            SessionModel.expires_at > now,
        )
        .first()
    )
    return session


def revoke_session(db: Session, raw_token: str) -> bool:
    """
    Revoke a specific session by its raw token.
    Returns True if a session was found and revoked, False otherwise.
    """
    token_hash = hash_token(raw_token)
    session = db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()
    if session and not session.is_revoked:
        session.is_revoked = True
        db.flush()
        return True
    return False


def revoke_all_user_sessions(db: Session, user_id: str) -> int:
    """
    Revoke all active sessions for a user (e.g., on password change, admin action).
    Returns the number of sessions revoked.
    """
    updated = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user_id,
            SessionModel.is_revoked.is_(False),
        )
        .all()
    )
    count = 0
    for s in updated:
        s.is_revoked = True
        count += 1
    db.flush()
    return count
