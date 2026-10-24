"""Create and restore a verified SQLite plus private-storage backup archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import sqlite3
import stat
import tempfile
from datetime import UTC, datetime
from typing import Any
import zipfile

_DATABASE_ARCHIVE_PATH = "database.sqlite"
_MANIFEST_ARCHIVE_PATH = "manifest.json"
_ARCHIVE_FORMAT_VERSION = 1
_SQLITE_HEADER = b"SQLite format 3\x00"
_MANIFEST_LIMIT = 4 * 1024 * 1024


class BackupRestoreError(Exception):
    """Raised when a backup cannot be safely created or restored."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check_sqlite(path: Path) -> None:
    try:
        with path.open("rb") as source:
            if source.read(len(_SQLITE_HEADER)) != _SQLITE_HEADER:
                raise BackupRestoreError("Database is not a SQLite database")
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        raise BackupRestoreError("SQLite integrity check failed") from exc
    if result != ("ok",):
        raise BackupRestoreError("SQLite integrity check failed")


def _storage_files(root: Path) -> list[Path]:
    if not root.is_dir():
        raise BackupRestoreError("Private storage directory does not exist")
    files: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories + filenames:
            path = current_path / name
            if path.is_symlink():
                raise BackupRestoreError("Private storage contains a symbolic link")
        files.extend(current_path / name for name in filenames)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _safe_archive_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    windows_path = PureWindowsPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or windows_path.drive
        or windows_path.root
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(
            any(char in '<>:"|?*' or ord(char) < 32 for char in part)
            for part in path.parts
        )
    ):
        raise BackupRestoreError("Backup archive contains an unsafe path")
    return path


def _snapshot_sqlite(source_path: Path, snapshot_path: Path) -> None:
    _check_sqlite(source_path)
    source = None
    destination = None
    try:
        source = sqlite3.connect(
            f"{source_path.resolve().as_uri()}?mode=ro", uri=True
        )
        destination = sqlite3.connect(snapshot_path)
        source.backup(destination)
    except sqlite3.Error as exc:
        raise BackupRestoreError("SQLite snapshot could not be created") from exc
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
    _check_sqlite(snapshot_path)


def create_backup(database: Path, storage: Path, destination: Path) -> None:
    database = database.resolve(strict=True)
    storage = storage.resolve(strict=True)
    destination = destination.resolve()
    if destination.exists():
        raise BackupRestoreError("Backup destination already exists")
    if destination.parent != destination.parent.resolve(strict=True):
        raise BackupRestoreError("Backup destination parent must already exist")
    if destination.is_relative_to(storage):
        raise BackupRestoreError("Backup archive must be outside private storage")

    storage_files = _storage_files(storage)
    destination.parent.mkdir(parents=False, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="trustvault-backup-",
        dir=destination.parent,
    ) as temporary_directory:
        snapshot_path = Path(temporary_directory) / _DATABASE_ARCHIVE_PATH
        _snapshot_sqlite(database, snapshot_path)
        entries = [
            {
                "path": _DATABASE_ARCHIVE_PATH,
                "sha256": _sha256_file(snapshot_path),
                "size": snapshot_path.stat().st_size,
            }
        ]
        archive_files = [(snapshot_path, _DATABASE_ARCHIVE_PATH)]
        for source in storage_files:
            archive_name = (
                "storage/" + source.relative_to(storage).as_posix()
            )
            _safe_archive_path(archive_name)
            entries.append(
                {
                    "path": archive_name,
                    "sha256": _sha256_file(source),
                    "size": source.stat().st_size,
                }
            )
            archive_files.append((source, archive_name))

        manifest = {
            "format_version": _ARCHIVE_FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "database_path": _DATABASE_ARCHIVE_PATH,
            "storage_root": "storage",
            "files": entries,
        }
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError as exc:
            raise BackupRestoreError(
                "Backup destination already exists"
            ) from exc
        try:
            with os.fdopen(descriptor, "wb") as output:
                with zipfile.ZipFile(
                    output, "w", compression=zipfile.ZIP_DEFLATED
                ) as archive:
                    archive.writestr(
                        _MANIFEST_ARCHIVE_PATH,
                        json.dumps(
                            manifest, sort_keys=True, separators=(",", ":")
                        ),
                    )
                    for source, archive_name in archive_files:
                        archive.write(source, archive_name)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        try:
            _verify_created_backup(destination)
        except BackupRestoreError:
            destination.unlink(missing_ok=True)
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            destination.unlink(missing_ok=True)
            raise BackupRestoreError(
                "Backup archive could not be verified"
            ) from exc


def _read_manifest(archive: zipfile.ZipFile) -> tuple[dict[str, Any], dict[str, zipfile.ZipInfo]]:
    infos = archive.infolist()
    by_name: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        _safe_archive_path(info.filename)
        if info.is_dir() or info.filename in by_name:
            raise BackupRestoreError("Backup archive contains duplicate or directory entries")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise BackupRestoreError("Backup archive contains a symbolic link")
        by_name[info.filename] = info
    manifest_info = by_name.get(_MANIFEST_ARCHIVE_PATH)
    if manifest_info is None or manifest_info.file_size > _MANIFEST_LIMIT:
        raise BackupRestoreError("Backup manifest is missing or too large")
    try:
        manifest = json.loads(archive.read(manifest_info))
    except (ValueError, zipfile.BadZipFile) as exc:
        raise BackupRestoreError("Backup manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("format_version") != _ARCHIVE_FORMAT_VERSION
        or manifest.get("database_path") != _DATABASE_ARCHIVE_PATH
        or manifest.get("storage_root") != "storage"
        or not isinstance(manifest.get("files"), list)
    ):
        raise BackupRestoreError("Backup manifest has an unsupported format")

    entries: dict[str, dict[str, Any]] = {}
    for item in manifest["files"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
            or not isinstance(item.get("size"), int)
            or item["size"] < 0
        ):
            raise BackupRestoreError("Backup manifest contains an invalid file entry")
        archive_path = _safe_archive_path(item["path"])
        if (
            item["path"] != _DATABASE_ARCHIVE_PATH
            and (not archive_path.parts or archive_path.parts[0] != "storage")
        ):
            raise BackupRestoreError("Backup manifest contains an unexpected file")
        if item["path"] in entries or item["path"] not in by_name:
            raise BackupRestoreError("Backup manifest does not match the archive")
        if len(item["sha256"]) != 64 or any(
            char not in "0123456789abcdef" for char in item["sha256"]
        ):
            raise BackupRestoreError("Backup manifest contains an invalid checksum")
        if by_name[item["path"]].file_size != item["size"]:
            raise BackupRestoreError("Backup archive file size does not match")
        entries[item["path"]] = item
    if set(by_name) != {_MANIFEST_ARCHIVE_PATH, *entries}:
        raise BackupRestoreError("Backup archive contains unmanifested files")
    if _DATABASE_ARCHIVE_PATH not in entries:
        raise BackupRestoreError("Backup archive does not contain its database")
    return manifest, by_name


def _verify_archive_checksums(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    infos: dict[str, zipfile.ZipInfo],
) -> None:
    expected = {
        entry["path"]: entry["sha256"]
        for entry in manifest["files"]
    }
    for name, info in infos.items():
        if name == _MANIFEST_ARCHIVE_PATH:
            continue
        digest = hashlib.sha256()
        with archive.open(info) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected[name]:
            raise BackupRestoreError(
                "Backup archive checksum verification failed"
            )


def _verify_created_backup(path: Path) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        manifest, infos = _read_manifest(archive)
        _verify_archive_checksums(archive, manifest, infos)


def restore_backup(archive_path: Path, destination: Path) -> None:
    archive_path = archive_path.resolve(strict=True)
    destination = destination.resolve()
    if destination.exists():
        raise BackupRestoreError("Restore destination already exists")
    if not destination.parent.is_dir():
        raise BackupRestoreError("Restore destination parent must exist")

    created_destination = False
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            _manifest, infos = _read_manifest(archive)
            _verify_archive_checksums(archive, _manifest, infos)

            destination.mkdir()
            created_destination = True
            for name, info in infos.items():
                if name == _MANIFEST_ARCHIVE_PATH:
                    continue
                archive_path_parts = _safe_archive_path(name).parts
                if name == _DATABASE_ARCHIVE_PATH:
                    output_path = destination / _DATABASE_ARCHIVE_PATH
                else:
                    output_path = destination.joinpath(*archive_path_parts)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, output_path.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            _check_sqlite(destination / _DATABASE_ARCHIVE_PATH)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if created_destination:
            shutil.rmtree(destination)
        if isinstance(exc, BackupRestoreError):
            raise
        raise BackupRestoreError("Backup could not be safely restored") from exc
    except BackupRestoreError:
        if created_destination:
            shutil.rmtree(destination)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup = subparsers.add_parser("backup")
    backup.add_argument("--database", type=Path, required=True)
    backup.add_argument("--storage", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)
    restore = subparsers.add_parser("restore")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    if arguments.command == "backup":
        create_backup(arguments.database, arguments.storage, arguments.destination)
        print("Backup created and SQLite integrity verified.")
    else:
        restore_backup(arguments.archive, arguments.destination)
        print("Backup restored and SQLite integrity verified.")


if __name__ == "__main__":
    main()
