"""
TrustVault Private Storage Service
Manages confidential document byte streams strictly outside the web root.
Enforces unguessable random storage keys, path traversal defenses,
extension whitelisting, and magic byte validation.

Uploads are streamed into a private staging directory and finalized with an
atomic same-filesystem rename before the database transaction commits. This
avoids exposing partially written files under committed storage keys. A crash
between the rename and commit can leave an unreferenced file; startup
reconciliation removes such files after a grace period.
"""

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from fastapi import HTTPException, status

from backend.app.config import settings

logger = logging.getLogger(__name__)

_STORAGE_KEY_HEX_LENGTH = 64
_STAGING_DIRECTORY_NAME = ".staging"


@dataclass
class StagedUpload:
    """A fully written temporary upload that is not yet visible as a document."""

    storage_key: str
    staging_path: Path
    final_path: Path
    size_bytes: int
    _finalized: bool = field(default=False, init=False)

    def finalize(self) -> None:
        """Atomically publish the staged file at its final storage key."""
        if self._finalized:
            raise RuntimeError("Upload has already been finalized")
        if self.final_path.exists():
            raise FileExistsError("Storage key collision")
        os.replace(self.staging_path, self.final_path)
        self._finalized = True
        _fsync_directory(self.final_path.parent)

    def discard(self) -> None:
        """Best-effort removal of both staged and finalized file paths."""
        for path in (self.staging_path, self.final_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Unable to remove incomplete private storage file")


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry where the platform supports directory fsync."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def is_valid_storage_key(storage_key: str | None) -> bool:
    if not storage_key or len(storage_key) != _STORAGE_KEY_HEX_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in storage_key)


class StorageService:
    @staticmethod
    def get_storage_path() -> Path:
        """Resolves and ensures existence of private persistent storage directory."""
        path = settings.resolved_storage_path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def get_staging_path() -> Path:
        """Resolve the same-filesystem staging directory for atomic finalization."""
        path = StorageService.get_storage_path() / _STAGING_DIRECTORY_NAME
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
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
    def stage_file(
        cls,
        file_obj: BinaryIO,
        original_filename: str,
        max_size_bytes: int | None = None,
    ) -> StagedUpload:
        """
        Stream a validated upload into private staging storage.

        The file is flushed and fsynced before return. It becomes visible at its
        final storage key only when StagedUpload.finalize() performs the atomic
        rename. No database state is written by this method.
        """
        effective_limit = (
            max_size_bytes
            if max_size_bytes is not None
            else settings.MAX_FILE_SIZE_BYTES
        )
        storage_key = cls.generate_storage_key()
        storage_dir = cls.get_storage_path().resolve()
        staging_dir = cls.get_staging_path().resolve()
        staging_path = (staging_dir / f"{storage_key}.part").resolve()
        final_path = (storage_dir / storage_key).resolve()

        if (
            not staging_path.is_relative_to(staging_dir)
            or not final_path.is_relative_to(storage_dir)
            or final_path.exists()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security violation: Invalid storage target",
            )

        total_bytes = 0
        chunk_size = 64 * 1024
        first_chunk = True

        try:
            with open(staging_path, "xb") as destination:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break

                    if first_chunk:
                        cls.validate_file_header(chunk[:512], original_filename)
                        first_chunk = False

                    total_bytes += len(chunk)
                    if total_bytes > effective_limit:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail=(
                                "File exceeds maximum allowed size of "
                                f"{effective_limit} bytes"
                            ),
                        )
                    destination.write(chunk)

                destination.flush()
                os.fsync(destination.fileno())
        except HTTPException:
            staging_path.unlink(missing_ok=True)
            raise
        except Exception:
            staging_path.unlink(missing_ok=True)
            raise

        if total_bytes == 0:
            staging_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        return StagedUpload(
            storage_key=storage_key,
            staging_path=staging_path,
            final_path=final_path,
            size_bytes=total_bytes,
        )

    @classmethod
    def save_file(
        cls,
        file_obj: BinaryIO,
        original_filename: str,
        max_size_bytes: int | None = None,
    ) -> tuple[str, int]:
        """Compatibility helper that stages and immediately finalizes an upload."""
        staged = cls.stage_file(file_obj, original_filename, max_size_bytes)
        try:
            staged.finalize()
        except Exception:
            staged.discard()
            raise
        return staged.storage_key, staged.size_bytes

    @classmethod
    def get_file_path(cls, storage_key: str) -> Path:
        """
        Safely retrieves physical path for an authorized download.
        Guarantees path traversal prevention and file existence.
        """
        if not is_valid_storage_key(storage_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid storage key format",
            )

        storage_dir = cls.get_storage_path().resolve()
        target_path = (storage_dir / storage_key).resolve()

        if not target_path.is_relative_to(storage_dir) or not target_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document file not found in storage",
            )

        return target_path

    @classmethod
    def delete_file(cls, storage_key: str) -> bool:
        """Remove a file from private storage, reporting cleanup success."""
        try:
            path = cls.get_file_path(storage_key)
            path.unlink(missing_ok=True)
            return True
        except (HTTPException, OSError):
            logger.warning("Private storage file cleanup failed")
            return False
