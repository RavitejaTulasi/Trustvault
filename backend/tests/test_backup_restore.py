import sqlite3
from contextlib import closing
from pathlib import Path
import zipfile

import pytest

import backend.scripts.backup_restore as backup_restore
from backend.scripts.backup_restore import (
    BackupRestoreError,
    create_backup,
    restore_backup,
)


def _make_sqlite(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES ('isolated-test-record')")
        connection.commit()


def test_backup_restore_round_trip_copies_database_and_private_storage(
    tmp_path: Path,
):
    database = tmp_path / "source.sqlite"
    storage = tmp_path / "private_storage"
    storage.mkdir()
    (storage / "object-key").write_bytes(b"private-test-document")
    _make_sqlite(database)
    archive = tmp_path / "backup.zip"
    restored = tmp_path / "restored"

    create_backup(database, storage, archive)
    restore_backup(archive, restored)

    with closing(sqlite3.connect(restored / "database.sqlite")) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM records").fetchone() == (
            "isolated-test-record",
        )
    assert (
        (restored / "storage" / "object-key").read_bytes()
        == b"private-test-document"
    )


def test_backup_refuses_existing_destination(tmp_path: Path):
    database = tmp_path / "source.sqlite"
    storage = tmp_path / "private_storage"
    storage.mkdir()
    _make_sqlite(database)
    archive = tmp_path / "backup.zip"
    archive.touch()

    with pytest.raises(BackupRestoreError, match="already exists"):
        create_backup(database, storage, archive)


def test_restore_refuses_existing_destination(tmp_path: Path):
    database = tmp_path / "source.sqlite"
    storage = tmp_path / "private_storage"
    storage.mkdir()
    _make_sqlite(database)
    archive = tmp_path / "backup.zip"
    create_backup(database, storage, archive)
    destination = tmp_path / "restored"
    destination.mkdir()

    with pytest.raises(BackupRestoreError, match="already exists"):
        restore_backup(archive, destination)


def test_backup_rejects_storage_changed_after_manifest_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    database = tmp_path / "source.sqlite"
    storage = tmp_path / "private_storage"
    storage.mkdir()
    storage_file = storage / "object-key"
    storage_file.write_bytes(b"original")
    _make_sqlite(database)
    archive = tmp_path / "backup.zip"
    original_hash_file = backup_restore._sha256_file

    def mutate_after_hash(path: Path) -> str:
        checksum = original_hash_file(path)
        if path == storage_file:
            storage_file.write_bytes(b"changed during backup")
        return checksum

    monkeypatch.setattr(backup_restore, "_sha256_file", mutate_after_hash)

    with pytest.raises(BackupRestoreError, match="checksum"):
        create_backup(database, storage, archive)

    assert not archive.exists()


@pytest.mark.parametrize("member", ["database.sqlite", "storage/object-key"])
def test_restore_rejects_modified_archive_content(
    tmp_path: Path, member: str
):
    database = tmp_path / "source.sqlite"
    storage = tmp_path / "private_storage"
    storage.mkdir()
    (storage / "object-key").write_bytes(b"private-test-document")
    _make_sqlite(database)
    archive = tmp_path / "backup.zip"
    create_backup(database, storage, archive)

    modified_archive = tmp_path / "modified-backup.zip"
    with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(
        modified_archive, "w"
    ) as destination_archive:
        for info in source.infolist():
            content = source.read(info.filename)
            if info.filename == member:
                content = b"X" + content[1:]
            destination_archive.writestr(info, content)

    destination = tmp_path / "restored"
    with pytest.raises(BackupRestoreError, match="checksum"):
        restore_backup(modified_archive, destination)

    assert not destination.exists()


@pytest.mark.parametrize("unsafe_path", ["../escaped", "C:/escaped", "storage/file:stream"])
def test_restore_rejects_unsafe_paths_and_preserves_no_partial_output(
    tmp_path: Path, unsafe_path: str
):
    archive = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(unsafe_path, b"no")
    destination = tmp_path / "restored"

    with pytest.raises(BackupRestoreError, match="unsafe path"):
        restore_backup(archive, destination)

    assert not destination.exists()
    assert not (tmp_path.parent / "escaped").exists()
