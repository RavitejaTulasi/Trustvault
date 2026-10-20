"""
Shared Rate Limiters for TrustVault

The login limiter uses expiring counter buckets in the application database so
limits are enforced atomically across workers and application instances. The
generic in-process limiter remains available for administrator-scoped audit
operations, where it is documented as process-local.

Notice:
The login limiter fails closed if its shared storage is unavailable or if the
bounded bucket table is full. It never falls back to unrestricted in-memory
state.
"""

import hashlib
import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.rate_limit import LoginRateLimitBucket


class LoginRateLimitUnavailable(RuntimeError):
    """Raised when the shared login limiter cannot make a safe decision."""


@dataclass(frozen=True)
class LoginRateLimitReservation:
    """A successful reservation that counts as one in-flight login attempt."""

    ip_key_hash: str
    ip_email_key_hash: str
    ip_window_started_at: int
    ip_email_window_started_at: int
    ip_attempt_count: int
    ip_email_attempt_count: int


@dataclass(frozen=True)
class LoginRateLimitDecision:
    """Result of an atomic login-attempt reservation."""

    allowed: bool
    retry_after: int = 0
    reservation: LoginRateLimitReservation | None = None


class LoginRateLimiter:
    """
    Database-backed fixed-window limiter for login attempts.

    Keying strategy:
    - Tracks attempts by both IP+Email (`ip_email`) and IP alone (`ip`).
    - Limits are reserved before password verification so concurrent requests
      cannot all pass a stale pre-check and then exceed the configured maximum.
    - A successful login resets the IP+Email bucket and returns only its own
      reservation to the IP bucket; prior IP-wide failures remain counted.
    """

    CAPACITY_LOCK_KEY = 0x5456524C

    def __init__(
        self,
        max_attempts: int | None = None,
        window_seconds: int | None = None,
        max_buckets: int | None = None,
        time_func: Callable[[], float] = time.time,
    ):
        self.max_attempts = (
            max_attempts if max_attempts is not None else settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS
        )
        self.window_seconds = (
            window_seconds if window_seconds is not None else settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS
        )
        self.max_buckets = (
            max_buckets if max_buckets is not None else settings.LOGIN_RATE_LIMIT_MAX_BUCKETS
        )
        self.time_func = time_func

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        candidate = (ip or "").strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return "unknown"

    @staticmethod
    def _normalize_email(email: str) -> str:
        return (email or "").strip().lower() or "unknown"

    @staticmethod
    def _key_hash(scope: str, value: str) -> str:
        return hashlib.sha256(f"{scope}:{value}".encode()).hexdigest()

    def _build_keys(self, ip: str, email: str) -> list[tuple[str, str]]:
        normalized_ip = self._normalize_ip(ip)
        normalized_email = self._normalize_email(email)
        return [
            (self._key_hash("ip_email", f"{normalized_ip}:{normalized_email}"), "ip_email"),
            (self._key_hash("ip", normalized_ip), "ip"),
        ]

    @staticmethod
    def _insert_factory(db: Session):
        dialect = db.get_bind().dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert
        else:
            raise LoginRateLimitUnavailable(
                "Unsupported database dialect for shared login rate limiting"
            )
        return insert

    def _delete_expired(self, db: Session, now: int) -> None:
        db.execute(
            delete(LoginRateLimitBucket).where(
                LoginRateLimitBucket.expires_at <= now
            )
        )

    def _acquire_capacity_lock(self, db: Session) -> None:
        """Serialize new-bucket admission on PostgreSQL without affecting existing keys."""
        if db.get_bind().dialect.name != "postgresql":
            return
        db.execute(select(func.pg_advisory_xact_lock(self.CAPACITY_LOCK_KEY)))

    def _ensure_capacity(
        self,
        db: Session,
        keys: list[tuple[str, str]],
        now: int,
    ) -> None:
        key_hashes = [key_hash for key_hash, _ in keys]
        existing = db.scalar(
            select(func.count())
            .select_from(LoginRateLimitBucket)
            .where(LoginRateLimitBucket.key_hash.in_(key_hashes))
        ) or 0
        missing = len(keys) - existing
        if missing <= 0:
            return

        self._acquire_capacity_lock(db)
        existing = db.scalar(
            select(func.count())
            .select_from(LoginRateLimitBucket)
            .where(LoginRateLimitBucket.key_hash.in_(key_hashes))
        ) or 0
        missing = len(keys) - existing
        if missing <= 0:
            return

        total = db.scalar(
            select(func.count()).select_from(LoginRateLimitBucket)
        ) or 0
        if total + missing <= self.max_buckets:
            return

        self._delete_expired(db, now)
        existing = db.scalar(
            select(func.count())
            .select_from(LoginRateLimitBucket)
            .where(LoginRateLimitBucket.key_hash.in_(key_hashes))
        ) or 0
        total = db.scalar(
            select(func.count()).select_from(LoginRateLimitBucket)
        ) or 0
        if total + (len(keys) - existing) > self.max_buckets:
            raise LoginRateLimitUnavailable(
                "Shared login rate-limit bucket capacity is exhausted"
            )

    def _reserve_key(
        self,
        db: Session,
        key_hash: str,
        scope: str,
        now: int,
    ) -> dict | None:
        """
        Atomically increment one bucket, resetting it if its window expired.

        Returns the updated row, or None when the active window is already at
        the configured maximum.
        """
        insert = self._insert_factory(db)
        expired = LoginRateLimitBucket.expires_at <= now
        window_end = now + self.window_seconds
        statement = (
            insert(LoginRateLimitBucket)
            .values(
                key_hash=key_hash,
                scope=scope,
                attempt_count=1,
                window_started_at=now,
                expires_at=window_end,
                denial_audit_recorded=False,
            )
            .on_conflict_do_update(
                index_elements=["key_hash"],
                set_={
                    "attempt_count": case(
                        (expired, 1),
                        else_=LoginRateLimitBucket.attempt_count + 1,
                    ),
                    "window_started_at": case(
                        (expired, now),
                        else_=LoginRateLimitBucket.window_started_at,
                    ),
                    "expires_at": case(
                        (expired, window_end),
                        else_=LoginRateLimitBucket.expires_at,
                    ),
                    "denial_audit_recorded": case(
                        (expired, False),
                        else_=LoginRateLimitBucket.denial_audit_recorded,
                    ),
                },
                where=or_(
                    expired,
                    LoginRateLimitBucket.attempt_count < self.max_attempts,
                ),
            )
            .returning(
                LoginRateLimitBucket.key_hash,
                LoginRateLimitBucket.attempt_count,
                LoginRateLimitBucket.window_started_at,
                LoginRateLimitBucket.expires_at,
            )
        )
        return db.execute(statement).mappings().first()

    def reserve(self, db: Session, ip: str, email: str) -> LoginRateLimitDecision:
        """
        Atomically reserve one login attempt for the IP+email and IP buckets.

        The reservation is committed before password verification. A failed
        authentication leaves it counted; a successful authentication calls
        record_success() to reset the account bucket and release its own IP slot.
        """
        now = int(self.time_func())
        keys = self._build_keys(ip, email)

        try:
            self._ensure_capacity(db, keys, now)

            reserved: dict[str, dict] = {}
            for key_hash, scope in keys:
                row = self._reserve_key(db, key_hash, scope, now)
                if row is None:
                    denied_row = db.execute(
                        select(LoginRateLimitBucket.expires_at).where(
                            LoginRateLimitBucket.key_hash == key_hash
                        )
                    ).scalar_one_or_none()
                    db.rollback()
                    retry_after = max(
                        1,
                        (denied_row or (now + self.window_seconds)) - now,
                    )
                    return LoginRateLimitDecision(
                        allowed=False, retry_after=retry_after
                    )
                reserved[key_hash] = dict(row)

            db.commit()
        except LoginRateLimitUnavailable:
            db.rollback()
            raise
        except SQLAlchemyError as exc:
            db.rollback()
            raise LoginRateLimitUnavailable(
                "Shared login rate-limit storage is unavailable"
            ) from exc

        ip_key_hash = keys[1][0]
        ip_email_key_hash = keys[0][0]
        return LoginRateLimitDecision(
            allowed=True,
            reservation=LoginRateLimitReservation(
                ip_key_hash=ip_key_hash,
                ip_email_key_hash=ip_email_key_hash,
                ip_window_started_at=reserved[ip_key_hash]["window_started_at"],
                ip_email_window_started_at=reserved[ip_email_key_hash][
                    "window_started_at"
                ],
                ip_attempt_count=reserved[ip_key_hash]["attempt_count"],
                ip_email_attempt_count=reserved[ip_email_key_hash]["attempt_count"],
            ),
        )

    def claim_denial_audit(self, db: Session, ip: str, email: str) -> bool:
        """
        Claim the single aggregate rate-limit audit event for the active window.

        The claim is an atomic conditional update and is deliberately left in
        the caller's transaction: the caller must append the corresponding
        audit event and commit both together. If that write or commit fails and
        the transaction rolls back, the flag reverts to False so a later denial
        can retry without producing a duplicate event. Concurrent workers block
        on the bucket row; after the winner commits, their conditional update
        matches no row and they do not append an event.

        The event is gated by the IP bucket so a client cannot multiply audit
        events by rotating email addresses. Returns True at most once per IP
        window; the flag is reset automatically when the window expires.
        """
        now = int(self.time_func())
        ip_key_hash = self._build_keys(ip, email)[1][0]
        try:
            rows = db.execute(
                update(LoginRateLimitBucket)
                .where(
                    LoginRateLimitBucket.key_hash == ip_key_hash,
                    LoginRateLimitBucket.expires_at > now,
                    LoginRateLimitBucket.denial_audit_recorded.is_(False),
                )
                .values(denial_audit_recorded=True)
                .returning(LoginRateLimitBucket.key_hash)
            ).all()
        except SQLAlchemyError as exc:
            db.rollback()
            raise LoginRateLimitUnavailable(
                "Shared login rate-limit storage is unavailable"
            ) from exc
        return bool(rows)

    def record_success(
        self, db: Session, reservation: LoginRateLimitReservation
    ) -> None:
        """
        Finalize a successful authentication.

        The IP+email bucket is reset, preserving the prior per-account reset
        behavior, but only if no concurrent attempt changed that bucket after
        this reservation. The IP bucket only releases the slot reserved by this
        request; earlier IP-wide failures remain counted. If this operation
        fails, the safe outcome is that the attempt remains counted rather than
        silently widening the limit.
        """
        now = int(self.time_func())
        try:
            db.execute(
                update(LoginRateLimitBucket)
                .where(
                    LoginRateLimitBucket.key_hash == reservation.ip_email_key_hash,
                    LoginRateLimitBucket.window_started_at
                    == reservation.ip_email_window_started_at,
                    LoginRateLimitBucket.attempt_count
                    == reservation.ip_email_attempt_count,
                )
                .values(
                    attempt_count=0,
                    window_started_at=now,
                    expires_at=now + self.window_seconds,
                    denial_audit_recorded=False,
                )
            )
            db.execute(
                update(LoginRateLimitBucket)
                .where(
                    LoginRateLimitBucket.key_hash == reservation.ip_key_hash,
                    LoginRateLimitBucket.window_started_at
                    == reservation.ip_window_started_at,
                    LoginRateLimitBucket.attempt_count > 0,
                )
                .values(
                    attempt_count=LoginRateLimitBucket.attempt_count - 1
                )
            )
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise LoginRateLimitUnavailable(
                "Shared login rate-limit storage is unavailable"
            ) from exc

    def reset(self, db: Session) -> None:
        """Delete all shared login rate-limit state (used for test isolation)."""
        try:
            db.rollback()
            db.execute(delete(LoginRateLimitBucket))
            db.flush()
        except SQLAlchemyError as exc:
            db.rollback()
            raise LoginRateLimitUnavailable(
                "Shared login rate-limit storage is unavailable"
            ) from exc


class SlidingWindowRateLimiter:
    """
    Generic process-local sliding-window limiter for expensive authenticated requests.

    Keying is caller-supplied so limits can be scoped to a stable identity (for example,
    an administrator user ID) rather than a spoofable client-supplied value. Like the
    login limiter, state is held in process memory and is not shared across workers or
    application instances.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        time_func: Callable[[], float] = time.monotonic,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.time_func = time_func
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """
        Atomically admits one request for the key if capacity remains.
        Returns: (is_allowed, retry_after_seconds)
        """
        now = self.time_func()
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = [t for t in self._requests.get(key, []) if t > window_start]
            if len(timestamps) >= self.max_requests:
                self._requests[key] = timestamps
                retry_after = int(timestamps[0] + self.window_seconds - now) + 1
                return False, max(retry_after, 1)

            timestamps.append(now)
            self._requests[key] = timestamps
            return True, 0

    def reset(self) -> None:
        """Resets all rate limit state (used for test isolation)."""
        with self._lock:
            self._requests.clear()


# Global singleton instance for app-wide shared login rate limiting
login_rate_limiter = LoginRateLimiter()

# Process-local limiter for expensive administrative audit verification requests
audit_verification_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS,
)

# Process-local limiter for audit checkpoint creation and checkpoint verification
audit_checkpoint_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS,
)
