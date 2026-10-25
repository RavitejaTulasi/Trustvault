"""Keyed hashing helpers for password-reset one-time codes."""

import hashlib
import hmac
import secrets

from backend.app.config import settings


def hash_otp_code(code: str) -> str:
    """Return a keyed SHA-256 digest for a six-digit OTP code.

    A plain digest of a six-digit value is cheap to brute-force offline. Binding
    the digest to the server secret prevents a database-only attacker from
    recovering the code without also compromising the application key.
    """
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        code.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_otp_code(code: str, stored_hash: str) -> bool:
    """Compare an OTP code with a stored keyed digest in constant time."""
    return secrets.compare_digest(hash_otp_code(code), stored_hash)
