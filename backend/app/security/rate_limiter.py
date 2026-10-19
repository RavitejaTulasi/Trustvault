"""
In-Memory Rate Limiter for TrustVault Login Endpoint
Applies sliding-window rate limiting on failed login attempts.

Notice:
This in-memory implementation is process-local and resets on application restart.
For multi-worker or multi-instance production environments, this component can be
replaced with a shared Redis-backed or distributed rate limiter using the same interface.
"""

import threading
import time
from collections.abc import Callable

from backend.app.config import settings


class LoginRateLimiter:
    """
    Sliding-window rate limiter for authentication attempts.

    Keying strategy:
    - Tracks failed attempts by both IP+Email (`ip_email:{ip}:{email}`) and IP alone (`ip:{ip}`).
    - Prevents single-account brute-force and multi-account credential spraying.
    """

    def __init__(
        self,
        max_attempts: int | None = None,
        window_seconds: int | None = None,
        time_func: Callable[[], float] = time.time,
    ):
        self.max_attempts = (
            max_attempts if max_attempts is not None else settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS
        )
        self.window_seconds = (
            window_seconds if window_seconds is not None else settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS
        )
        self.time_func = time_func
        self._lock = threading.Lock()
        # Key -> list of float timestamps of failed attempts
        self._attempts: dict[str, list[float]] = {}

    def _get_keys(self, ip: str, email: str) -> list[str]:
        norm_email = email.strip().lower() if email else "unknown"
        norm_ip = ip.strip() if ip else "unknown"
        return [
            f"ip_email:{norm_ip}:{norm_email}",
            f"ip:{norm_ip}",
        ]

    def is_rate_limited(self, ip: str, email: str) -> tuple[bool, int]:
        """
        Checks if the request is rate-limited for the given IP and email.
        Returns: (is_limited, retry_after_seconds)
        """
        now = self.time_func()
        window_start = now - self.window_seconds
        max_retry_after = 0
        is_limited = False

        with self._lock:
            for key in self._get_keys(ip, email):
                timestamps = self._attempts.get(key, [])
                valid_timestamps = [t for t in timestamps if t > window_start]
                self._attempts[key] = valid_timestamps

                if len(valid_timestamps) >= self.max_attempts:
                    is_limited = True
                    oldest = valid_timestamps[0]
                    retry_after = int(oldest + self.window_seconds - now) + 1
                    max_retry_after = max(max_retry_after, retry_after)

        return is_limited, max(max_retry_after, 1) if is_limited else 0

    def record_failure(self, ip: str, email: str) -> None:
        """Records a failed login attempt timestamp."""
        now = self.time_func()
        window_start = now - self.window_seconds

        with self._lock:
            for key in self._get_keys(ip, email):
                timestamps = self._attempts.get(key, [])
                valid_timestamps = [t for t in timestamps if t > window_start]
                valid_timestamps.append(now)
                self._attempts[key] = valid_timestamps

    def record_success(self, ip: str, email: str) -> None:
        """Clears recorded failed attempts upon a successful login."""
        with self._lock:
            for key in self._get_keys(ip, email):
                self._attempts.pop(key, None)

    def reset(self) -> None:
        """Resets all rate limit state (used for test isolation)."""
        with self._lock:
            self._attempts.clear()


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


# Global singleton instance for app-wide login rate limiting
login_rate_limiter = LoginRateLimiter()

# Process-local limiter for expensive administrative audit verification requests
audit_verification_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS,
)
