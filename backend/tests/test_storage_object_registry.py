"""Regression tests for canonical storage-key ownership."""

import pytest
from sqlalchemy.exc import IntegrityError

from backend.app.models.document import Document, DocumentVersion
from backend.app.models.storage_object import StorageObject
from backend.app.models.user import UserRole
from backend.tests.test_auth import make_user


def _document(owner_id: str, storage_key: str) -> Document:
    return Document(
        title="Registry test",
        original_filename="registry.pdf",
        storage_key=storage_key,
        file_size_bytes=12,
        mime_type="application/pdf",
        category="General",
        owner_id=owner_id,
        is_deleted=False,
    )


def test_storage_key_cannot_be_referenced_by_document_and_version(
    db_session,
):
    owner = make_user(
        db_session,
        email="registry-cross-table@example.com",
        role=UserRole.OWNER,
    )
    storage_key = "a" * 64
    db_session.add(
        StorageObject(storage_key=storage_key, backend="local", state="active")
    )
    db_session.flush()
    document = _document(owner.id, storage_key)
    db_session.add(document)
    db_session.commit()

    db_session.add(
        DocumentVersion(
            document_id=document.id,
            version_number=1,
            storage_key=storage_key,
            file_size_bytes=12,
        )
    )
    with pytest.raises(IntegrityError, match="already owned"):
        db_session.flush()
    db_session.rollback()


def test_new_reference_is_rejected_while_storage_object_is_deleting(db_session):
    owner = make_user(
        db_session,
        email="registry-deleting@example.com",
        role=UserRole.OWNER,
    )
    storage_key = "b" * 64
    db_session.add(
        StorageObject(storage_key=storage_key, backend="local", state="deleting")
    )
    db_session.flush()
    db_session.add(_document(owner.id, storage_key))

    with pytest.raises(IntegrityError, match="not active or already owned"):
        db_session.flush()
    db_session.rollback()
