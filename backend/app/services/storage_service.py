"""
TrustVault Private Storage Service
Manages confidential document byte streams strictly outside the web root.
Enforces unguessable random storage keys, path traversal defenses, and collision resistance.
"""

import secrets
from pathlib import Path
from typing import BinaryIO

from fastapi import HTTPException, status

from backend.app.config import settings


class StorageService:
    @staticmethod
    def get_storage_path() -> Path:
        """Resolves and ensures existence of private persistent storage directory."""
        path = settings.resolved_storage_path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def generate_storage_key() -> str:
        """
        Generates a 256-bit cryptographically secure, unguessable storage key.
        Physical file paths are derived exclusively from this key, decoupling from client filenames.
        """
        return secrets.token_hex(32)

    @classmethod
    def save_file(cls, file_obj: BinaryIO, max_size_bytes: int = settings.MAX_FILE_SIZE_BYTES) -> tuple[str, int]:
        """
        Streams file contents to private storage safely.
        Validates maximum size during streaming to prevent disk exhaustion / DoS attacks.
        Returns: (storage_key, bytes_written)
        """
        storage_key = cls.generate_storage_key()
        storage_dir = cls.get_storage_path()
        target_path = (storage_dir / storage_key).resolve()

        # Strict containment verification against path traversal attacks
        if not target_path.is_relative_to(storage_dir):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security violation: Invalid storage target",
            )

        total_bytes = 0
        chunk_size = 64 * 1024  # 64KB chunks

        try:
            with open(target_path, "wb") as dest:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_size_bytes:
                        dest.close()
                        target_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"File exceeds maximum allowed size of {max_size_bytes} bytes",
                        )
                    dest.write(chunk)
        except Exception:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise

        return storage_key, total_bytes

    @classmethod
    def get_file_path(cls, storage_key: str) -> Path:
        """
        Safely retrieves physical path for an authorized download.
        Guarantees path traversal prevention and file existence.
        """
        # Storage keys must be 64-char hex strings
        if not storage_key or len(storage_key) != 64 or not all(c in "0123456789abcdef" for c in storage_key.lower()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid storage key format",
            )

        storage_dir = cls.get_storage_path()
        target_path = (storage_dir / storage_key).resolve()

        if not target_path.is_relative_to(storage_dir) or not target_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document file not found in storage",
            )

        return target_path

    @classmethod
    def delete_file(cls, storage_key: str) -> bool:
        """Securely removes a file from private storage."""
        try:
            path = cls.get_file_path(storage_key)
            path.unlink(missing_ok=True)
            return True
        except HTTPException:
            return False
