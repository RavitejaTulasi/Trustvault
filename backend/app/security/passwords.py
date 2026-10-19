"""
Password Hashing and Verification using Argon2id
Argon2id is the OWASP-recommended algorithm for password hashing.
All parameters follow OWASP's minimum recommendation for Argon2id.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# OWASP-recommended Argon2id parameters (2024):
# - time_cost=2 iterations
# - memory_cost=19456 KiB (~19 MB)
# - parallelism=1
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using Argon2id.
    Returns the full encoded hash string (includes algorithm, params, salt, hash).
    """
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against its Argon2id hash.
    Returns True on match, False on mismatch.
    Never raises — exceptions are caught internally to prevent timing differences.
    """
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed_password: str) -> bool:
    """
    Returns True if the stored hash was created with outdated parameters
    and should be rehashed on next successful login.
    """
    return _ph.check_needs_rehash(hashed_password)
