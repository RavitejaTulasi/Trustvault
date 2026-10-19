"""
TrustVault Private Storage Service
Manages confidential document byte streams strictly outside the web root.
Enforces unguessable random storage keys, path traversal defenses,
extension whitelisting, and magic byte validation.
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

    @staticmethod
    def validate_file_header(header_bytes: bytes, filename: str) -> None:
        """
        Validates file extension and inspects magic bytes (content sniffing)
        to prevent malicious or executable uploads disguised as permitted types.
        """
        ext = Path(filename).suffix.lower()
        if ext not in settings.allowed_extensions_set:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '{ext}' is not permitted. Allowed: {settings.ALLOWED_EXTENSIONS}",
            )

        # Check for dangerous executable signatures regardless of extension
        if header_bytes.startswith((b"MZ", b"\x7fELF", b"#!")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security violation: Executable or script content detected",
            )

        # Format-specific magic byte checks for strict verification
        if ext == ".pdf" and not header_bytes.startswith(b"%PDF"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format: File does not match PDF magic bytes",
            )
        elif ext == ".png" and not header_bytes.startswith(b"\x89PNG"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format: File does not match PNG magic bytes",
            )
        elif ext in {".jpg", ".jpeg"} and not header_bytes.startswith(b"\xff\xd8\xff"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format: File does not match JPEG magic bytes",
            )
        elif ext in {".docx", ".xlsx"} and not header_bytes.startswith(b"PK\x03\x04"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format: File does not match Office archive magic bytes",
            )

    @classmethod
    def save_file(
        cls,
        file_obj: BinaryIO,
        original_filename: str,
        max_size_bytes: int = settings.MAX_FILE_SIZE_BYTES,
    ) -> tuple[str, int]:
        """
        Streams file contents to private storage safely.
        Validates maximum size and magic bytes during streaming to prevent DoS and malicious uploads.
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
        first_chunk = True

        try:
            with open(target_path, "wb") as dest:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break
                    
                    if first_chunk:
                        # Validate extension and magic bytes on the first chunk
                        cls.validate_file_header(chunk[:512], original_filename)
                        first_chunk = False

                    total_bytes += len(chunk)
                    if total_bytes > max_size_bytes:
                        dest.close()
                        target_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"File exceeds maximum allowed size of {max_size_bytes} bytes",
                        )
                    dest.write(chunk)
        except HTTPException:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise
        except Exception:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise

        if total_bytes == 0:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        return storage_key, total_bytes

    @classmethod
    def get_file_path(cls, storage_key: str) -> Path:
        """
        Safely retrieves physical path for an authorized download.
        Guarantees path traversal prevention and file existence.
        """
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
